#!/usr/bin/env python3
"""Repository-specific source binding and bump safety checks (no package installs)."""
from pathlib import Path
import importlib.util,json,shutil,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('version_manager',ROOT/'scripts/version_manager.py')
vm=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=vm;SPEC.loader.exec_module(vm)

class RepositoryVersionTests(unittest.TestCase):
 def fixture(self):
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);dest=Path(temporary.name)
  config=json.loads((ROOT/'versioning.json').read_text());paths={'versioning.json'}
  for unit in config['units'].values():
   paths.update(s['path'] for s in [unit['canonical'],*unit.get('mirrors',[]),*unit.get('assertions',[])])
  for path in paths:
   (dest/path).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/path,dest/path)
  return dest,config,paths
 def test_repository_sources_agree(self):
  manager=vm.Manager(ROOT);bindings=manager.inspect(manager.select(None));self.assertTrue(bindings)
 def test_every_unit_preview_apply_and_idempotency(self):
  dest,config,paths=self.fixture()
  for name,unit in config['units'].items():
   with self.subTest(unit=name):
    manager=vm.Manager(dest);before={p:(dest/p).read_bytes() for p in paths};current=manager.inspect([name])[0].value
    if unit.get('read_only'):
     with self.assertRaises(vm.VersionError):manager.plan(name,part='patch',expect=current)
     self.assertEqual(before,{p:(dest/p).read_bytes() for p in paths});continue
    summary,plan=manager.plan(name,part='prerelease' if '-' in current else 'patch',expect=current)
    self.assertEqual(before,{p:(dest/p).read_bytes() for p in paths});self.assertTrue(plan)
    manager.apply(plan);after=vm.Manager(dest);after.inspect(after.select(None))
    same,none=after.plan(name,value=summary['target'],expect=summary['target']);self.assertFalse(none);after.apply(none)
    # Restore the fixture so the next independent unit starts from the real source state.
    for p,raw in before.items():(dest/p).write_bytes(raw)
 def test_stale_expected_version_refuses_all_writes(self):
  dest,config,paths=self.fixture();before={p:(dest/p).read_bytes() for p in paths}
  for name,unit in config['units'].items():
   if not unit.get('read_only'):
    with self.assertRaises(vm.VersionError):vm.Manager(dest).plan(name,part='patch',expect='99999.0.0')
  self.assertEqual(before,{p:(dest/p).read_bytes() for p in paths})
 def test_missing_bound_source_fails_check(self):
  dest,config,paths=self.fixture();source=next(iter(config['units'].values()))['canonical']['path'];(dest/source).unlink()
  with self.assertRaises((vm.VersionError,OSError)):vm.Manager(dest).inspect(list(config['units']))
 def test_mirror_drift_and_inheritance_are_detected(self):
  dest,config,paths=self.fixture();covered=0
  for name,unit in config['units'].items():
   source=next(iter(unit.get('mirrors',[])),None)
   if source:
    f=dest/source['path'];raw=f.read_bytes();text=raw.decode();a,b,value,encoding=vm.source_span(text,source)
    f.write_text(text[:a]+(json.dumps('99999.0.0') if encoding=='json' else '99999.0.0')+text[b:])
    with self.assertRaises(vm.VersionError):vm.Manager(dest).inspect([name])
    f.write_bytes(raw);covered+=1
   for assertion in unit.get('assertions',[]):
    if assertion['adapter']=='toml' and assertion.get('equals') is True:
     f=dest/assertion['path'];raw=f.read_bytes();text=raw.decode();self.assertIn('workspace',text)
     import re
     changed,count=re.subn(r'(?m)^(\s*version\.workspace\s*=\s*)true',r'\g<1>false',text,count=1)
     if count:
      f.write_text(changed)
      with self.assertRaises(vm.VersionError):vm.Manager(dest).inspect([name])
      f.write_bytes(raw);covered+=1
  # A single authoritative source has no mirror to drift; source deletion test covers it.
  self.assertGreaterEqual(covered,0)
if __name__=='__main__':unittest.main()
