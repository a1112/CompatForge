# Linux Console performance baseline

`tools/benchmark_linux_console.py` compares the same deterministic Windows PE
under direct Wine and CompatForge `prepared-launch`. It is a developer
measurement tool, not a product performance guarantee or an application support
claim. Only Linux x86_64 native Wine / WineD3D Console plans are accepted.

## Run

Use explicit trusted tools and the existing Linux provider runtime quartet.
The runner does not install or discover a runtime, bypass provider validation,
change machine configuration, or grant ForgeOS permissions. Output must be a new
absolute directory; roots from failed runs remain available for diagnosis.

```sh
python3 -B tools/benchmark_linux_console.py \
  --cli /absolute/compatforge-cli \
  --compiler /usr/bin/x86_64-w64-mingw32-gcc \
  --materialized-root /opt/wine-stable \
  --wine bin/wine --wineserver bin/wineserver --version 11.0 \
  --output /absolute/new-performance-run \
  --scope ubuntu-runtime-control --samples 7 --iterations 20000000
```

Use `--scope forgeos-runtime-control` only when the tool actually runs inside
ForgeOS. This tool itself does not invoke ForgeOS appd, permission, or sandbox
services; neither scope measures their overhead. A Bottle is not a security
sandbox. The plan records network deny, but this harness does not establish
network isolation. Run only the repository fixture in a controlled environment.

Exact-prefix cleanup needs readable `/proc/<pid>/environ` for same-UID processes.
If a desktop service makes that unreadable, use a controlled PID/mount namespace
with Tini to reap orphaned children. On a host where unprivileged user namespaces
are disabled, an administrator may create the namespace and drop back to the
caller's UID/GID **before** running the same Python command:

```sh
sudo unshare --mount --pid --fork --mount-proc \
  --setgid="$(id -g)" --setuid="$(id -u)" /usr/bin/tini -- \
  python3 -B tools/benchmark_linux_console.py ...
```

The ellipsis stands for the explicit arguments above. Namespace teardown is not
accepted as cleanup evidence: stop/wait and process checks must pass inside it.
This does not turn the measurement into a ForgeOS sandbox benchmark.

The default 120-second per-command deadline, 1 MiB combined output cap,
5–30 samples per workload/path, and maximum 100 million loop iterations are
hard bounds. Compiling or initial prefix creation can fail the deadline on a
slow host; failure is retained, not converted into a performance result.

## Matching and measurement boundaries

1. Compile `tests/fixtures/performance/console.c` once with MinGW `-O2` and no PE
   timestamp. Bootstrap the real local Linux provider using its existing CLI.
2. Ask `prepared-plan` for the runtime, immutable guest object, full environment,
   arguments, working directory, prefix and wineserver. Direct Wine uses that
   exact process specification, including the verified `.exe` hardlink created
   by managed initialization. Environment inheritance is disabled for both paths.
3. Initialize the prefix through CompatForge, separately retain that command's
   duration, and execute excluded warm-up runs. Verify the prefix marker before
   each measured launch. Both paths share that private prefix sequentially.
4. Alternate direct/managed order across seven pairs, separately for a zero-work
   startup probe and a deterministic 20-million-step 32-bit recurrence. The
   independent Python checksum oracle uses affine exponentiation rather than the
   C loop; every launch must report the exact expected work count and checksum.
5. Stop and wait for the same prefix's wineserver between samples. Warm here means
   an initialized prefix and warmed host file cache, **not a resident wineserver**.
   Wine `-k` exit 1 is permitted only with successful `-w` and no observed same-UID
   process carrying the exact prefix environment. Every cleanup exit is retained.
6. Compare pre/post plans and recheck tool, fixture, payload, context, request and
   alias digests. Any changed input, failed child, incomplete event stream, timeout,
   output overflow, invalid sample or failed cleanup aborts without a success summary.

The wall metric sums process startup/execution/capture and the stop/wait commands.
The managed side additionally includes CLI startup, PreparedLaunch authorization,
artifact/runtime checks and supervision. Direct Wine receives the same runtime
configuration and includes equivalent stop/wait. Journal writes and filesystem
checks by the harness are outside the metric. The same Python polling mechanism
has up to roughly 10 ms timing granularity. Direct capture ends at the root's
exit, then drains available output: waiting for pipe EOF would incorrectly count
several seconds of inherited pipes held by a still-running wineserver.

The fixture additionally reports time **inside the deterministic loop**, measured
using Windows `QueryPerformanceCounter`. This separates work duration from launch
and lifecycle cost. It is neither CPU utilization nor peak memory measurement.
No FPS, GPU acceleration, D3D11 throughput or native Windows percentage is inferred.

## Evidence and limitations

- `commands.jsonl`: exact argv, environment, cwd, process exit codes, durations,
  failure reason, and digest/size of each bounded raw output file.
- `samples.jsonl`: warm-ups and measured samples, workload, pair/order, checksum,
  internal work duration and outer launch duration.
- `all-samples.json`: includes initialization as well; initialization and warm-ups
  are excluded from every statistical summary.
- `summary.json`: complete-only median/min/max, sample counts, host identity,
  Python version, exact provider receipt, entrypoint/tool/payload/input digests,
  scope and explicit exclusions.
- `failure.json`: unsuccessful run and cleanup diagnostics. Do not aggregate a
  partial run with successful samples or retry into an existing output directory.

Reports contain private absolute paths and environment details. Keep raw runs
outside Git; publish only reviewed projections. Complete runtime dependency-tree
identity is not established by entrypoint hashes. Compiler driver hashes do not
identify its entire toolchain; retain the compiled PE digest for exact repetition.
Pathname TOCTOU remains a developer-harness limitation; the actual provider's
existing trust validation is unchanged. Guest internal loop time is noisy and
not an isolated CPU benchmark. VM scheduling, host load, power policy, cache and
Wine version can dominate small differences; repeat under controlled conditions.

Host or guest updates are not performed by this tool. Rollback/removal consists
of retaining or deleting only the explicitly chosen private output root after
all its processes have exited. Never remove the materialized Wine tree or any
unrelated prefix. No new persistent product format or migration is introduced;
the versioned JSON files are disposable measurement evidence.


## Recorded run: 2026-09-27

The [reviewed evidence projection](evidence/linux-performance/2026-09-27-ubuntu.json)
contains all 34 samples (2 initialization, 4 warm-up, **28 measured**) and the
exit codes, durations and bounded-output SHA-256/size records of all 74 commands.
Its output filenames refer to the private raw evidence archive, not repository
files. The private archive SHA-256 is
`f6c8d34401d691f4841a4313c312ee0ca7ce47045302d451a14a2886faa644d4`.
The runner returned exit 0; all measured checksums and lifecycle exits validated.
The first excluded managed initialization took 13.485 s and created the prefix.
The second workload preparation took 0.649 s using that existing prefix; the
`initialization` phase label excludes it from statistics and does not mean a
second cold prefix. Cold initialization has no direct-Wine comparison here.
An independent reviewer recomputed the four distributions and all output digests.

Environment: Ubuntu 26.04.1 LTS x86_64 under Hyper-V, kernel 7.0.0-34-generic,
Wine 11.0, MinGW-w64 GCC 13-win32, Python 3.14.4. The nested ForgeOS QEMU guest
was explicitly paused and no build/image hashing ran during the measurement.
A PID/mount namespace with Tini was used; the payload ran as the ordinary lab
user. This is an **Ubuntu runtime-control baseline**, not execution inside
ForgeOS, whose current image uses a different Wine version (11.14).

| Workload | Path | Median | Minimum–maximum | Samples |
| --- | --- | ---: | ---: | ---: |
| Startup, zero loop iterations | Direct Wine | 0.505977 s | 0.484307–0.526230 s | 7 |
| Startup, zero loop iterations | CompatForge | 0.548322 s | 0.528011–0.589038 s | 7 |
| Startup + 20 million loop iterations | Direct Wine | 0.534458 s | 0.525059–0.693171 s | 7 |
| Startup + 20 million loop iterations | CompatForge | 0.608418 s | 0.548053–1.057150 s | 7 |

The difference between the two startup medians was about **42 ms** in this run.
The CPU workload's managed maximum shows substantial variability; seven samples
cannot establish an application-wide overhead guarantee. Time inside the CPU
loop had medians **15.740 ms direct** and **16.326 ms managed**. These figures do
not include native Windows, a real GPU, D3D11 frame timing, or ForgeOS sandbox
cost. No claim about gaming FPS or a percentage of native Windows follows.

The lab source checkout was `9f2bfadf6d8c323f45f4eeeff9a9257bd8f50268`.
Its production Rust source is identical to local main
`11a56d117ad7ae3f9017597057ea876fda69dde0`: the two intervening commits alter only
release CI and documentation. CLI SHA-256:
`1be19795693bbf267222c6963d585137755f33d26c9a32e246804519e4a85869`.
Fixture PE SHA-256:
`b410e7c9962e75ba3f1d890477329f22db1a7cd81535dca855772e0bd722aee1`.

Two earlier smoke roots were retained as unsuccessful development evidence.
The first exposed inherited-pipe timing contamination; the second exposed the
normal already-stopped wineserver exit code. Neither contributes a sample to
this report. Default host umask 002 also caused two existing provider permission
tests to fail before their intended mutation point; the documented private
umask 077 passed the complete Rust gate. No product trust checks were relaxed.


### Verification gates

- New performance tests: **9 passed** on Linux (including timeout, output limit,
  nonzero child exit, prefix cleanup and interrupted summary publication).
- Rust workspace: **502 passed, 3 existing integration tests ignored**;
  recursive subprocess self-tests are not double-counted. `cargo fmt --all
  --check` and strict workspace/all-target Clippy passed.
- Repository contract validator passed on a source-only export. The validator's
  bounded scan rejects the lab checkout containing large Cargo build output.
- An additional full Python discovery ran **810 tests**, with **10 skipped**.
  It was not fully green: three pre-existing MacWin tests failed and were all
  reproduced on the unchanged `11a56d1` source without this feature:
  `test_two_converter_instances_bootstrap_without_sys_modules_collision`,
  `test_approved_write_scope_is_exact_and_repeat_is_a_no_op`, and
  `test_repository_scan_revalidates_review_after_final_ordinary_scan`.
  The first source-export attempt also lacked Git metadata and used an open
  regular log descriptor, which the existing audit tests deliberately reject.
  After supplying an index and piped logging, one remaining `HEAD:.gitattributes`
  error was traced to the disposable fixture lacking HEAD; that test passed in
  the focused rerun after attaching the real source commit. These environmental
  retries and baseline failures were preserved; no MacWin code was changed.
