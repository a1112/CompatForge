#!/usr/bin/env python3
"""Matched, bounded Linux Wine/PreparedLaunch Console measurements (stdlib only)."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import selectors
import signal
import statistics
import subprocess
import sys
import time

LIMIT = 1024 * 1024
REQUEST_ID = '01996d44-12e0-7000-8000-000000000001'


def expected_checksum(iterations):
    if type(iterations) is not int or not 0 <= iterations <= 100_000_000:
        raise ValueError('invalid iteration count')
    multiplier, increment, value = 1664525, 1013904223, 0x12345678
    # Compose the affine recurrence modulo 2**32; independent O(log n) oracle.
    while iterations:
        if iterations & 1:
            value = (multiplier * value + increment) & 0xffffffff
        increment = ((multiplier + 1) * increment) & 0xffffffff
        multiplier = (multiplier * multiplier) & 0xffffffff
        iterations >>= 1
    return f'{value:08x}'


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def validate_probe(text, iterations):
    value = strict_json(text)
    if (not isinstance(value, dict)
            or set(value) != {'probe', 'iterations', 'checksum', 'workNanoseconds'}
            or value['probe'] != 'compatforge-console-v1'
            or type(value['iterations']) is not int or value['iterations'] != iterations
            or value['checksum'] != expected_checksum(iterations)
            or type(value['workNanoseconds']) is not int
            or not 0 <= value['workNanoseconds'] <= 120_000_000_000):
        raise ValueError('invalid probe or checksum')
    return value


def validate_events(events, request_id, iterations):
    if not events or events[0].get('kind') != 'started' or events[-1].get('kind') != 'exited':
        raise ValueError('incomplete lifecycle')
    stdout, kinds = '', []
    previous_ms = -1
    for index, event in enumerate(events):
        elapsed = event.get('elapsedMilliseconds')
        if (event.get('schemaVersion') != '1' or event.get('requestId') != request_id
                or type(event.get('sequence')) is not int or event['sequence'] != index
                or type(elapsed) is not int or elapsed < previous_ms):
            raise ValueError('invalid event identity/order')
        previous_ms = elapsed
        kind = event.get('kind')
        kinds.append(kind)
        if kind == 'output':
            output = event.get('output', {})
            if output.get('stream') not in ('stdout', 'stderr') or not isinstance(output.get('text'), str):
                raise ValueError('invalid output')
            if output['stream'] == 'stdout':
                stdout += output['text']
        elif kind not in ('started', 'wine-server-stop-requested', 'exited'):
            raise ValueError('abnormal lifecycle')
    if any(kinds.count(kind) != 1 for kind in ('started', 'wine-server-stop-requested', 'exited')):
        raise ValueError('duplicate or missing lifecycle event')
    exit_value = events[-1].get('exit', {})
    if (exit_value != {'code': 0, 'success': True} or type(exit_value.get('code')) is not int
            or type(exit_value.get('success')) is not bool):
        raise ValueError('guest failed')
    return validate_probe(stdout, iterations)


def summarize(samples):
    if not 5 <= len(samples) <= 30:
        raise ValueError('need 5..30 complete samples per path and workload')
    for sample in samples:
        elapsed = sample.get('elapsedSeconds')
        if (sample.get('phase') != 'warm' or sample.get('valid') is not True
                or type(sample.get('returnCode')) is not int or sample['returnCode'] != 0
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0):
            raise ValueError('invalid sample; initialization cannot enter warm results')
    values = [item['elapsedSeconds'] for item in samples]
    return {'count': len(values), 'medianSeconds': statistics.median(values),
            'minimumSeconds': min(values), 'maximumSeconds': max(values)}


def direct_spec(plan):
    if (plan['runtime']['provider'] != 'wine' or plan['translator']['provider'] != 'native'
            or plan['graphics']['backend'] != 'wined3d'):
        raise ValueError('only native Wine Console comparisons supported')
    process = plan['process']
    source = PurePosixPath(plan['guestArtifact']['storedPath'])
    alias = source if source.suffix else source.with_name(source.name + '.exe')
    if process['arguments'][0] != str(source):
        raise ValueError('plan artifact mismatch')
    if process['environment']['WINEPREFIX'] != plan['lifecycle']['wineserver']['prefix']:
        raise ValueError('lifecycle prefix mismatch')
    # The process module creates/verifies this hardlink during the excluded initialization.
    return {'argv': [process['executable'], str(alias)] + process['arguments'][1:],
            'environment': dict(process['environment']), 'cwd': process['workingDirectory']}


def validate_match(left, right):
    if left != right:
        raise ValueError('unmatched runtime arguments, environment or working directory')


def digest(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def write_json(path, value):
    temporary = path.with_name('.' + path.name + '.partial')
    with open(temporary, 'x', encoding='utf-8') as output:
        try:
            json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        except BaseException:
            output.close()
            temporary.unlink()
            raise
    try:
        # Atomic publish without replacing an existing receipt.
        os.link(temporary, path)
    finally:
        temporary.unlink()

class Journal:
    def __init__(self, root, timeout):
        self.root, self.timeout, self.commands = root, timeout, []

    def run(self, name, argv, environment=None, cwd=None, root_exit=False, accepted_codes=(0,)):
        argv = list(map(str, argv))
        stdout, stderr = bytearray(), bytearray()
        started = time.perf_counter()
        process = None
        reason = None
        try:
            process = subprocess.Popen(argv, env=environment or {}, cwd=cwd or self.root,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            with selectors.DefaultSelector() as poller:
                for pipe, target in ((process.stdout, stdout), (process.stderr, stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    poller.register(pipe, selectors.EVENT_READ, target)
                while poller.get_map() or process.poll() is None:
                    if root_exit and process.poll() is not None:
                        # Wine's server can inherit pipes after the root exits. Drain available
                        # root output, then let the caller stop/wait the exact prefix server.
                        for key in list(poller.get_map().values()):
                            while True:
                                try:
                                    block = os.read(key.fd, 16384)
                                except BlockingIOError:
                                    break
                                if not block:
                                    break
                                available = LIMIT - len(stdout) - len(stderr)
                                key.data.extend(block[:available])
                                if len(block) > available:
                                    raise ValueError('command output limit')
                        break
                    if time.perf_counter() - started >= self.timeout:
                        raise TimeoutError('command deadline')
                    for key, _ in poller.select(0.01):
                        block = os.read(key.fd, 16384)
                        if not block:
                            poller.unregister(key.fileobj)
                            continue
                        available = LIMIT - len(stdout) - len(stderr)
                        key.data.extend(block[:available])
                        if len(block) > available:
                            raise ValueError('command output limit')
                process.wait()
        except BaseException as error:
            reason = str(error)
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            if process is not None:
                process.stdout.close()
                process.stderr.close()
        record = {'name': name, 'argv': argv, 'environment': environment or {},
                  'cwd': str(cwd or self.root), 'returnCode': process.returncode if process else None,
                  'elapsedSeconds': time.perf_counter() - started, 'failure': reason}
        index = len(self.commands)
        for stream, data in (('stdout', stdout), ('stderr', stderr)):
            filename = f'{index:03d}-{stream}.txt'
            (self.root / filename).write_bytes(data)
            record[stream] = {'file': filename, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        self.commands.append(record)
        with open(self.root / 'commands.jsonl', 'a', encoding='utf-8') as output:
            output.write(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')
            output.flush()
            os.fsync(output.fileno())
        if reason or record['returnCode'] not in accepted_codes:
            raise ValueError(f'command failed: {name}; see commands.jsonl')
        return record, stdout.decode('utf-8', errors='strict')


def stop_server(journal, name, server, spec):
    # Wine 11 returns 1 for -k when the prefix server has already exited.
    # Retain that code; accept it only with successful -w and no same-UID prefix process.
    stop, _ = journal.run(name + '-server-stop', [server, '-k'], spec['environment'], spec['cwd'], accepted_codes=(0, 1))
    wait, _ = journal.run(name + '-server-wait', [server, '-w'], spec['environment'], spec['cwd'])
    expected = os.fsencode('WINEPREFIX=' + spec['environment']['WINEPREFIX'])
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid == os.getuid() and expected in (entry / 'environ').read_bytes().split(b'\0'):
                raise ValueError('prefix process remains after server wait')
        except (FileNotFoundError, ProcessLookupError):
            continue
    return stop['elapsedSeconds'] + wait['elapsedSeconds']


def benchmark(args):
    if sys.platform != 'linux' or platform.machine() != 'x86_64':
        raise ValueError('Linux x86_64 required')
    if not 5 <= args.samples <= 30 or not 1 <= args.iterations <= 100_000_000 or not 5 <= args.timeout <= 120:
        raise ValueError('samples 5..30, iterations 1..100000000, timeout 5..120 required')
    root = Path(args.output)
    if not root.is_absolute() or root.exists():
        raise ValueError('output must be a new absolute directory')
    cli, compiler, runtime = (Path(value) for value in (args.cli, args.compiler, args.materialized_root))
    for path in (cli, compiler, runtime):
        if not path.is_absolute() or not path.exists():
            raise ValueError('explicit existing absolute tool/runtime paths required')
    for relative in (args.wine, args.wineserver):
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError('runtime entries must be relative')
    source = Path(__file__).resolve().parents[1] / 'tests/fixtures/performance/console.c'
    root.mkdir(mode=0o700)
    journal = Journal(root, args.timeout)
    samples = []
    spec, server = None, None
    identities = {str(path): digest(path) for path in (cli, compiler, runtime / args.wine,
                  runtime / args.wineserver, source, Path(__file__).resolve())}
    try:
        payload = root / 'console.exe'
        journal.run('compile', [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                    '-Wl,--subsystem,console,--no-insert-timestamp', source, '-o', payload],
                    environment={'PATH': '/usr/bin:/bin'})
        identities[str(payload)] = digest(payload)
        bootstrap = {'schemaVersion': '1', 'runtimeStoreRoot': str(root / 'runtime-store'),
                     'storageRoot': str(root / 'storage'), 'materializedRoot': str(runtime),
                     'wine': args.wine, 'wineserver': args.wineserver, 'version': args.version}
        write_json(root / 'bootstrap.json', bootstrap)
        _, receipt = journal.run('bootstrap', [cli, 'local', 'linux', 'context', root / 'bootstrap.json', root / 'bootstrap-context.json'])
        context = strict_json((root / 'bootstrap-context.json').read_text())
        context.setdefault('supervisor', {})['maximumRuntimeMilliseconds'] = 60000
        write_json(root / 'context.json', context)
        for workload, iterations in (('startup', 0), ('cpu', args.iterations)):
            request = {'schemaVersion': '1', 'requestId': REQUEST_ID, 'bottleId': 'performance-console',
                       'executable': {'path': str(payload), 'architecture': 'x86_64', 'sha256': digest(payload)},
                       'arguments': [str(iterations)], 'environment': {},
                       'constraints': {'allowVirtualMachine': False, 'allowRemote': False,
                       'requiresKernelDriver': False, 'requiresDirectX12': False,
                       'networkPolicy': 'deny', 'requiredCapabilities': ['guest-x86_64']}}
            request_path = root / f'{workload}-request.json'
            write_json(request_path, request)
            for bound_input in (root / 'context.json', request_path):
                identities[str(bound_input)] = digest(bound_input)
            base = [root / 'context.json', payload, request_path]
            _, plan_text = journal.run(workload + '-plan', [cli, 'prepared-plan'] + base)
            plan = strict_json(plan_text)
            write_json(root / f'{workload}-plan.json', plan)
            spec = direct_spec(plan)
            server = plan['lifecycle']['wineserver']['executable']
            # Same initialized prefix for both paths; no bootstrap/compilation in warm samples.
            record, events = journal.run(workload + '-initialization', [cli, 'prepared-launch'] + base)
            probe = validate_events([strict_json(line) for line in events.splitlines()], REQUEST_ID, iterations)
            samples.append(dict(record, phase='initialization', path='compatforge', workload=workload,
                                probe=probe, valid=True))
            marker = Path(spec['environment']['WINEPREFIX']) / 'drive_c/windows/system32/ntdll.dll'
            alias = Path(spec['argv'][1])
            if not marker.is_file() or digest(alias) != digest(payload):
                raise ValueError('missing initialized prefix or mismatched execution alias')
            identities[str(alias)] = digest(alias)
            # Warm-up each path, excluded from statistics, then balanced alternating order.
            for pair in range(-1, args.samples):
                for path in (('direct', 'compatforge') if pair % 2 == 0 else ('compatforge', 'direct')):
                    if not marker.is_file():
                        raise ValueError('prefix initialization would contaminate warm measurement')
                    if any(digest(Path(item)) != value for item, value in identities.items()):
                        raise ValueError('input changed during comparison')
                    name = f'{workload}-{pair + 1}-{path}'
                    if path == 'direct':
                        record, output = journal.run(name, spec['argv'], spec['environment'], spec['cwd'], root_exit=True)
                        # Match the managed lifecycle's stop/wait; include both in end-to-end timing.
                        cleanup_seconds = stop_server(journal, name, server, spec)
                        elapsed = record['elapsedSeconds'] + cleanup_seconds
                        probe = validate_probe(output, iterations)
                    else:
                        record, output = journal.run(name, [cli, 'prepared-launch'] + base)
                        elapsed = record['elapsedSeconds']
                        probe = validate_events([strict_json(line) for line in output.splitlines()], REQUEST_ID, iterations)
                    sample = dict(record, phase='warmup' if pair < 0 else 'warm', path=path,
                                  workload=workload, pair=pair, probe=probe, valid=True,
                                  commandSeconds=record['elapsedSeconds'], elapsedSeconds=elapsed)
                    samples.append(sample)
                    with open(root / 'samples.jsonl', 'a', encoding='utf-8') as stream:
                        stream.write(json.dumps(sample, sort_keys=True) + '\n')
                    print(f'{name}: {elapsed:.6f}s checksum={probe["checksum"]}', flush=True)
            _, post = journal.run(workload + '-post-plan', [cli, 'prepared-plan'] + base)
            validate_match(spec, direct_spec(strict_json(post)))
            if strict_json(post) != plan:
                raise ValueError('plan changed during comparison')
        if any(digest(Path(item)) != value for item, value in identities.items()):
            raise ValueError('input changed at end of comparison')
        stop_server(journal, 'final', server, spec)
        summary = {'schemaVersion': '1', 'scope': args.scope, 'host': platform.uname()._asdict(),
                   'pythonVersion': platform.python_version(), 'runtimeReceipt': strict_json(receipt),
                   'prefixState': 'initialized-prefix; wineserver stopped between samples',
                   'measurement': 'wall time including process startup and lifecycle stop/wait',
                   'networkIsolationValidated': False, 'graphicsValidated': False,
                   'forgeOSSandboxMeasured': False, 'nativeWindowsComparison': False,
                   'identitiesSha256': identities,
                   'results': {workload: {path: summarize([s for s in samples if s['phase'] == 'warm'
                               and s['path'] == path and s['workload'] == workload])
                               for path in ('direct', 'compatforge')} for workload in ('startup', 'cpu')}}
        for workload in ('startup', 'cpu'):
            for path in ('direct', 'compatforge'):
                body = [s['probe']['workNanoseconds'] for s in samples
                        if s['phase'] == 'warm' and s['path'] == path and s['workload'] == workload]
                summary['results'][workload][path]['probeWorkNanoseconds'] = {
                    'median': statistics.median(body), 'minimum': min(body), 'maximum': max(body)}
        write_json(root / 'all-samples.json', samples)
        write_json(root / 'summary.json', summary)
        return summary
    except BaseException as error:
        # Never publish a success summary from partial samples. Existing raw output stays available.
        cleanup_error = None
        if spec and server:
            try:
                stop_server(journal, 'failure', server, spec)
            except BaseException as cleanup:
                cleanup_error = str(cleanup)
        write_json(root / 'failure.json', {'schemaVersion': '1', 'error': str(error),
                   'samplesCompleted': len(samples), 'cleanupError': cleanup_error})
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('cli', 'compiler', 'materialized-root', 'wine', 'wineserver', 'version', 'output'):
        parser.add_argument('--' + flag, required=True)
    parser.add_argument('--scope', choices=('ubuntu-runtime-control', 'forgeos-runtime-control'), required=True)
    parser.add_argument('--samples', type=int, default=7)
    parser.add_argument('--iterations', type=int, default=20_000_000)
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    try:
        print(json.dumps(benchmark(args), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError) as error:
        print(f'benchmark failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
