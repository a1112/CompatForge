import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' if (ROOT / 'scripts' / 'version_manager.py').is_file() else ROOT))
import version_manager as vm


def src(path, adapter='text', **kwargs):
    return {'path': path, 'adapter': adapter, **kwargs}


class Versions(unittest.TestCase):
    def test_strict_semver(self):
        for value in ('1.2', 'v1.2.3', '1.02.3', '1.2.3-01', '1.2.3-', '1.2.3\n', '1.2.3+'): 
            with self.subTest(value=value), self.assertRaises(vm.VersionError):
                vm.Version.parse(value)
        self.assertEqual(vm.Version.parse('1.2.3-rc.9+build.01').render(), '1.2.3-rc.9+build.01')

    def test_prerelease_increment(self):
        samples = [('1.2.3-rc.9', None, '1.2.3-rc.10'), ('1.2.3-alpha', None, '1.2.3-alpha.0'), ('1.2.3-alpha.2', 'beta', '1.2.3-beta.0'), ('1.2.3', 'rc', '1.2.4-rc.0')]
        for before, preid, after in samples:
            self.assertEqual(vm.Version.parse(before).bump('prerelease', preid).render(), after)
        with self.assertRaises(vm.VersionError):
            vm.Version.parse('1.2.3').bump('prerelease')

    def test_major_minor_patch_prerelease_semantics(self):
        for before, part, after in [('1.2.3-rc.2', 'patch', '1.2.3'), ('1.2.0-rc.2', 'minor', '1.2.0'), ('1.2.3', 'minor', '1.3.0'), ('2.0.0-rc.1', 'major', '2.0.0'), ('0.2.3', 'major', '1.0.0')]:
            self.assertEqual(vm.Version.parse(before).bump(part).render(), after)

    def test_precedence(self):
        ordered = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1']
        keys = [vm.Version.parse(x).precedence_key() for x in ordered]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(vm.Version.parse('1.0.0+one').precedence_key(), vm.Version.parse('1.0.0+two').precedence_key())

    def test_pep440_explicit_small_subset(self):
        self.assertEqual(vm.Version.parse('1.0.0rc3', 'pep440'), vm.Version.parse('1.0.0-rc.3'))
        self.assertEqual(vm.Version.parse('1.0.0-beta.12').render('pep440'), '1.0.0b12')
        for value in ('1.0', '1.0.0.post1', '1.0.0.dev2', '1.0.0+local', '1.0.0-rc.3'):
            with self.assertRaises(vm.VersionError):
                vm.Version.parse(value, 'pep440')
        for value in ('1.0.0-preview.1', '1.0.0-rc', '1.0.0+foo'):
            with self.assertRaises(vm.VersionError):
                vm.Version.parse(value).render('pep440')

    def test_apple_is_numeric_only(self):
        self.assertEqual(vm.Version.parse('1.2.3').render('apple'), '1.2.3')
        for value in ('1.2.3-rc.1', '1.2.3+meta'):
            with self.assertRaises(vm.VersionError):
                vm.Version.parse(value).render('apple')


class Repo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(text.encode('utf-8'))

    def configure(self, canonical=None, mirrors=(), **unit):
        canonical = canonical or src('VERSION')
        self.cfg = {'schema_version': 1, 'units': {'app': {'canonical': canonical, 'mirrors': list(mirrors), **unit}}}
        self.save_config()
        return self.cfg

    def save_config(self):
        self.write('versioning.json', json.dumps(self.cfg))

    def manager(self):
        return vm.Manager(self.root)

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns, stat.S_IMODE(p.stat().st_mode)) for p in self.root.rglob('*') if p.is_file()}

    def test_json_preserves_bom_crlf_and_dependencies(self):
        content = '\ufeff{\r\n  "version" : "1.2.3", "dependencies": {"x": "1.2.3"}\r\n}\r\n'
        self.write('package.json', content)
        self.configure(src('package.json', 'json', pointer='/version'))
        m = self.manager()
        summary, proposed = m.plan(None, part='patch')
        self.assertEqual(proposed['package.json'], content.replace('"version" : "1.2.3"', '"version" : "1.2.4"'))
        m.apply(proposed)
        self.assertEqual((self.root / 'package.json').read_bytes(), proposed['package.json'].encode())

    def test_json_lock_root_and_workspace_root_only(self):
        self.write('package.json', '{"version":"1.2.3"}')
        self.write('package-lock.json', '{"version":"1.2.3","packages":{"":{"version":"1.2.3"},"node_modules/x":{"version":"1.2.3"}}}')
        self.configure(src('package.json', 'json', pointer='/version'), [src('package-lock.json', 'json', pointer='/version'), src('package-lock.json', 'json', pointer='/packages//version')])
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        result = json.loads(proposed['package-lock.json'])
        self.assertEqual(result['version'], '1.2.4')
        self.assertEqual(result['packages']['']['version'], '1.2.4')
        self.assertEqual(result['packages']['node_modules/x']['version'], '1.2.3')

    def test_toml_scope_and_comment_preservation(self):
        content = '# header\r\n[package]\r\nname = "app"\r\nversion = \'1.2.3\' # owned\r\n\r\n[dependencies]\r\nx = "1.2.3"\r\n'
        self.write('Cargo.toml', content)
        self.configure(src('Cargo.toml', 'toml', table=['package'], key='version'))
        _, proposed = self.manager().plan(None, part='minor')
        self.assertEqual(proposed['Cargo.toml'], content.replace("version = '1.2.3'", "version = '1.3.0'"))

    def test_toml_multiline_decoy_is_not_bound(self):
        self.write('Cargo.toml', 'description = """\n[package]\nversion = "8.8.8"\n"""\n[package]\nversion = "1.2.3"\n')
        self.configure(src('Cargo.toml', 'toml', table=['package'], key='version'))
        _, proposed = self.manager().plan(None, part='patch')
        self.assertIn('version = "8.8.8"', proposed['Cargo.toml'])
        self.assertIn('version = "1.2.4"', proposed['Cargo.toml'])

    def test_toml_dynamic_quoted_and_dotted_sources_refused(self):
        for content in ('[package]\nversion.workspace = true\n', '[package]\n"version" = "1.2.3"\n', 'package.version = "1.2.3"\n'):
            self.write('Cargo.toml', content)
            self.configure(src('Cargo.toml', 'toml', table=['package'], key='version'))
            before = self.snapshot()
            with self.assertRaises(vm.VersionError):
                self.manager().plan(None, part='patch')
            self.assertEqual(before, self.snapshot())

    def test_cargo_local_only(self):
        content = 'version = 4\n\n[[package]]\nname = "app"\nversion = "1.2.3"\ndependencies = ["dep"]\n\n[[package]]\nname = "app"\nversion = "9.9.9"\nsource = "registry+https://example.test"\nchecksum = "abc"\n\n[[package]]\nname = "dep"\nversion = "1.2.3"\nsource = "registry+https://example.test"\nchecksum = "def"\n'
        self.write('Cargo.lock', content)
        self.configure(src('Cargo.lock', 'cargo-lock', package='app'))
        _, proposed = self.manager().plan(None, part='patch')
        self.assertEqual(proposed['Cargo.lock'], content.replace('name = "app"\nversion = "1.2.3"', 'name = "app"\nversion = "1.2.4"'))

    def test_cargo_missing_duplicate_and_registry_refused(self):
        for content in ('version = 4\n', '[[package]]\nname="app"\nversion="1.2.3"\nsource="registry+test"\n', '[[package]]\nname="app"\nversion="1.2.3"\n[[package]]\nname="app"\nversion="1.2.3"\n'):
            self.write('Cargo.lock', content)
            self.configure(src('Cargo.lock', 'cargo-lock', package='app'))
            with self.assertRaises(vm.VersionError):
                self.manager().plan(None, part='patch')

    def test_cargo_version_qualified_dependency_refused(self):
        self.write('Cargo.lock', '[[package]]\nname="app"\nversion="1.2.3"\n[[package]]\nname="consumer"\nversion="0.1.0"\ndependencies=["app 1.2.3"]\n')
        self.configure(src('Cargo.lock', 'cargo-lock', package='app'))
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_python_assignment_no_execution(self):
        self.write('_version.py', '# coding: utf-8\n__version__: str = "1.2.3"\nraise RuntimeError("must never execute")\n')
        self.configure(src('_version.py', 'python', name='__version__'))
        _, proposed = self.manager().plan(None, part='patch')
        self.assertIn('__version__: str = "1.2.4"', proposed['_version.py'])

    def test_python_dynamic_conditional_duplicate_refused(self):
        for content in ('__version__ = get_version()\n', 'if True:\n    __version__ = "1.2.3"\n', '__version__ = "1.2.3"\n__version__ = "1.2.3"\n', '__version__ = "1.2.3"\nfrom elsewhere import __version__\n'):
            self.write('_version.py', content)
            self.configure(src('_version.py', 'python', name='__version__'))
            with self.assertRaises(vm.VersionError):
                self.manager()

    def test_cmake_project_rejects_prerelease_and_build(self):
        self.write('CMakeLists.txt', 'project(Demo VERSION 1.2.3 LANGUAGES CXX)\n')
        self.configure(src('CMakeLists.txt', 'line', syntax='cmake-project', prefix='project(Demo VERSION ', suffix=' LANGUAGES CXX)', expected_occurrences=1))
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        self.assertIn('VERSION 1.2.4', proposed['CMakeLists.txt'])
        for kwargs in ({'part': 'prerelease', 'preid': 'rc'}, {'value': '1.2.3+build'}):
            with self.assertRaises(vm.VersionError):
                m.plan(None, **kwargs)

    def test_swift_precise_literal_and_duplicate_refusal(self):
        self.write('Version.swift', 'enum App {\n    static let version = "1.2.3"\n}\n')
        source = src('Version.swift', 'line', syntax='swift', prefix='    static let version = "', suffix='"', expected_occurrences=1)
        self.configure(source)
        _, proposed = self.manager().plan(None, part='patch')
        self.assertIn('version = "1.2.4"', proposed['Version.swift'])
        self.write('Version.swift', '    static let version = "1.2.3"\n    static let version = "1.2.3"\n')
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_line_commented_or_multiline_source_refused(self):
        cases = [
            ('CMakeLists.txt', '#[[\nproject(Demo VERSION 1.2.3)\n]]\n', 'cmake-project', 'project(Demo VERSION ', ')'),
            ('CMakeLists.txt', 'set(DESCRIPTION "hello\nproject(Demo VERSION 1.2.3)\nworld")\n', 'cmake-project', 'project(Demo VERSION ', ')'),
            ('Version.swift', '/*\nlet version = "1.2.3"\n*/\n', 'swift', 'let version = "', '"'),
            ('Version.swift', 'let help = """\nlet version = "1.2.3"\n"""\n', 'swift', 'let version = "', '"'),
        ]
        for path, content, syntax, prefix, suffix in cases:
            self.write(path, content)
            self.configure(src(path, 'line', syntax=syntax, prefix=prefix, suffix=suffix, expected_occurrences=1))
            with self.subTest(content=content), self.assertRaises(vm.VersionError):
                self.manager()

    def test_noop_apply_does_not_touch_files(self):
        self.write('VERSION', '1.2.3\n')
        self.configure()
        before = self.snapshot()
        m = self.manager()
        _, proposed = m.plan(None, value='1.2.3')
        self.assertFalse(proposed)
        m.apply(proposed)
        self.assertEqual(before, self.snapshot())

    def test_dry_run_does_not_touch_files(self):
        self.write('VERSION', '1.2.3\n')
        self.configure()
        before = self.snapshot()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vm.cli(['--root', str(self.root), 'bump', 'patch']), 0)
        self.assertEqual(before, self.snapshot())

    def test_cli_apply_requires_expected_start(self):
        self.write('VERSION', '1.2.3\n')
        self.configure()
        before = self.snapshot()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(vm.cli(['--root', str(self.root), 'bump', 'patch', '--apply']), 2)
        self.assertEqual(before, self.snapshot())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vm.cli(['--root', str(self.root), 'bump', 'patch', '--apply', '--expect', '1.2.3']), 0)
        self.assertEqual((self.root / 'VERSION').read_bytes(), b'1.2.4\n')

    def test_mismatch_and_stale_expect_refuse(self):
        self.write('VERSION', '1.2.3\n')
        self.write('mirror.txt', '1.2.4\n')
        self.configure(mirrors=[src('mirror.txt')])
        before = self.snapshot()
        with self.assertRaises(vm.VersionError):
            self.manager().plan(None, part='patch')
        self.assertEqual(before, self.snapshot())
        self.write('mirror.txt', '1.2.3\n')
        with self.assertRaises(vm.VersionError):
            self.manager().plan(None, part='patch', expect='1.2.2')

    def test_changed_file_after_plan_refuses_all_writes(self):
        self.write('VERSION', '1.2.3\n')
        self.write('mirror.txt', '1.2.3\n')
        self.configure(mirrors=[src('mirror.txt')])
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        self.write('mirror.txt', '1.2.5\n')
        before = self.snapshot()
        with self.assertRaises(vm.VersionError):
            m.apply(proposed)
        self.assertEqual(before, self.snapshot())

    def test_mode_preserved(self):
        self.write('VERSION', '1.2.3\r\n')
        os.chmod(self.root / 'VERSION', 0o755)
        self.configure()
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        m.apply(proposed)
        self.assertEqual((self.root / 'VERSION').read_bytes(), b'1.2.4\r\n')
        self.assertEqual(stat.S_IMODE((self.root / 'VERSION').stat().st_mode), 0o755)

    def test_caught_replace_failure_rolls_back_content_modes(self):
        self.write('VERSION', '1.2.3\n')
        self.write('mirror.txt', '1.2.3\n')
        self.configure(mirrors=[src('mirror.txt')])
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        real_replace = vm.os.replace
        count = 0
        def failing_replace(a, b):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('injected failure')
            return real_replace(a, b)
        with patch.object(vm.os, 'replace', side_effect=failing_replace), self.assertRaises(OSError):
            m.apply(proposed)
        self.assertEqual((self.root / 'VERSION').read_bytes(), b'1.2.3\n')
        self.assertEqual((self.root / 'mirror.txt').read_bytes(), b'1.2.3\n')
        self.assertEqual(sorted(x.name for x in self.root.iterdir()), ['VERSION', 'mirror.txt', 'versioning.json'])

    def test_paths_escape_symlink_and_generated_refused(self):
        self.write('VERSION', '1.2.3\n')
        (self.root / 'link').symlink_to(self.root / 'VERSION')
        for path in ('../VERSION', '/tmp/VERSION', 'a/../../VERSION', 'link', '.git/config', 'vendor/VERSION', 'node_modules/x/package.json', './VERSION', 'a\\VERSION'):
            self.configure(src(path))
            with self.subTest(path=path), self.assertRaises(vm.VersionError):
                self.manager()

    def test_git_root_symlink_root_and_altered_plan_refused(self):
        self.write('.git/VERSION', '1.2.3\n')
        self.write('.git/versioning.json', json.dumps({'schema_version':1,'units':{'app':{'canonical':src('VERSION')}}}))
        with self.assertRaises(vm.VersionError):
            vm.Manager(self.root / '.git')
        self.write('VERSION', '1.2.3\n')
        self.configure()
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(vm.VersionError):
            vm.Manager(self.root / 'alias')
        m = self.manager()
        _, proposed = m.plan(None, part='patch')
        proposed['VERSION'] = '9.0.0\n'
        with self.assertRaises(vm.VersionError):
            m.apply(proposed)

    def test_missing_file_refused(self):
        self.configure(src('missing'))
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_duplicate_bindings_refused(self):
        self.write('VERSION', '1.2.3\n')
        self.configure(mirrors=[src('VERSION', format='semver')])
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_collision_across_units_different_adapter_refused(self):
        self.write('VERSION', '"1.2.3"')
        self.configure(src('VERSION', 'json', pointer=''))
        self.cfg['units']['other'] = {'canonical': src('VERSION')}
        self.save_config()
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_independent_units_require_selection_and_only_change_one(self):
        self.write('a.json', '{"version":"1.2.3","other":"8.0.0"}')
        self.configure(src('a.json', 'json', pointer='/version'))
        self.cfg['units']['other'] = {'canonical': src('a.json', 'json', pointer='/other')}
        self.save_config()
        m = self.manager()
        with self.assertRaises(vm.VersionError):
            m.plan(None, part='patch')
        _, proposed = m.plan('app', part='patch')
        self.assertEqual(json.loads(proposed['a.json']), {'version': '1.2.4', 'other': '8.0.0'})
        m.apply(proposed)

    def test_dependency_bindings_refused(self):
        self.write('package.json', '{"dependencies":{"x":{"version":"1.2.3"}}}')
        self.configure(src('package.json', 'json', pointer='/dependencies/x/version'))
        with self.assertRaises(vm.VersionError):
            self.manager()
        self.write('Cargo.toml', '[dependencies.x]\nversion="1.2.3"\n')
        self.configure(src('Cargo.toml', 'toml', table=['dependencies', 'x'], key='version'))
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_duplicate_json_keys_unknown_fields_and_schema_refused(self):
        self.write('VERSION', '1.2.3\n')
        self.configure()
        for content in ('{"schema_version":1,"schema_version":1,"units":{}}', '{"schema_version":true,"units":{}}', '{"schema_version":1,"units":{},"typo":true}', '{"schema_version":1,"units":{"app":{"canonical":{"path":"VERSION","adapter":"regex","pattern":".*"}}}}'):
            self.write('versioning.json', content)
            with self.assertRaises(vm.VersionError):
                self.manager()

    def test_prerelease_to_stable_requires_explicit_opt_in(self):
        self.write('VERSION', '1.2.3-rc.2\n')
        self.configure()
        m = self.manager()
        with self.assertRaises(vm.VersionError):
            m.plan(None, part='patch')
        summary, _ = m.plan(None, part='patch', allow_stable=True)
        self.assertEqual(summary['target'], '1.2.3')

    def test_downgrade_including_prerelease_reset_refused(self):
        self.write('VERSION', '1.2.3-rc.9\n')
        self.configure()
        m = self.manager()
        with self.assertRaises(vm.VersionError):
            m.plan(None, part='prerelease', preid='alpha')
        with self.assertRaises(vm.VersionError):
            m.plan(None, value='1.0.0', allow_stable=True)
        summary, _ = m.plan(None, value='1.0.0', allow_stable=True, allow_downgrade=True)
        self.assertEqual(summary['target'], '1.0.0')

    def test_readonly_opaque(self):
        self.write('VERSION', '0.1\n')
        self.configure(src('VERSION', format='opaque'), read_only=True)
        m = self.manager()
        self.assertEqual(m.inspect(['app'])[0].version.render(), '0.1')
        with self.assertRaises(vm.VersionError):
            m.plan(None, part='patch')
        self.cfg['units']['app']['read_only'] = False
        self.save_config()
        with self.assertRaises(vm.VersionError):
            self.manager()

    def test_assertions_validate_workspace_and_file_reference(self):
        self.write('Cargo.toml', '[workspace.package]\nversion="1.2.3"\n')
        self.write('member/Cargo.toml', '[package]\nversion.workspace=true\n')
        self.write('tauri.conf.json', '{"version":"../package.json"}')
        self.configure(src('Cargo.toml', 'toml', table=['workspace','package'], key='version'), assertions=[{'path':'member/Cargo.toml','adapter':'toml','table':['package','version'],'key':'workspace','equals':True},{'path':'tauri.conf.json','adapter':'json','pointer':'/version','equals':'../package.json'}])
        m = self.manager()
        summary, proposed = m.plan(None, part='patch')
        self.assertEqual(summary['files'], ['Cargo.toml'])
        self.write('tauri.conf.json', '{"version":"../other.json"}')
        with self.assertRaises(vm.VersionError):
            self.manager().inspect(['app'])

    def test_empty_units_require_documented_unmanaged(self):
        self.cfg = {'schema_version':1,'units':{},'unmanaged':[{'name':'legacy','reason':'No existing release baseline; deployment revision managed elsewhere.'}]}
        self.save_config()
        self.assertEqual(self.manager().inspect([]), [])
        with self.assertRaises(vm.VersionError):
            self.manager().plan(None, part='patch')

    def test_cross_format_incompatibility_refuses_without_changes(self):
        self.write('VERSION', '1.2.3\n')
        self.write('python.txt', '1.2.3\n')
        self.configure(mirrors=[src('python.txt', format='pep440')])
        before = self.snapshot()
        with self.assertRaises(vm.VersionError):
            self.manager().plan(None, part='prerelease', preid='preview')
        self.assertEqual(before, self.snapshot())
        summary, proposed = self.manager().plan(None, part='prerelease', preid='rc')
        self.assertEqual(proposed['python.txt'], '1.2.4rc0\n')


if __name__ == '__main__':
    unittest.main()
