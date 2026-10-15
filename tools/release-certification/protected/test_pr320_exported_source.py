"""Physical product/kit import composition; policy providers remain explicitly offline.

Isolated export children never see the repository or its import cache. Original vectors are
serialized by the parent; each export child executes exported owning decoders and validators.
This does not qualify a host, execute Java, authenticate a job, or create protected custody.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import installation

SOURCE = Path(__file__).resolve().parents[3]


CHILD = r'''
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

root, mode = Path(sys.argv[1]), sys.argv[2]
product, kit = root / 'product', root / 'kit'
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
sys.path[:0] = [str(product / relative) for relative in (
    'tools/release-certification/protected', 'tools/release-certification/restricted',
    'tools/release-certification', 'tools/interop')]
import pr320_original_acquisition as acquisition
import installation

manifest_raw = (product / '.restricted-manifest.json').read_bytes()
manifest = json.loads(manifest_raw)
identity = dict(sourceCommit=manifest['sourceCommit'],
                bundleIdentity=hashlib.sha256(manifest_raw).hexdigest())
acquisition.CHECKOUT, acquisition.KIT = product, kit

def fixture_ownership(path, *, private=True):
    # The only replaced filesystem provider is root ownership/approved prefix.
    # Descriptor stability, mode, link, roster and every content hash remain real.
    path = Path(path)
    assert path == root or path.is_relative_to(root)
    for item in (path, *[p for p in path.parents if p.is_relative_to(root)]):
        info = item.lstat()
        assert not item.is_symlink() and info.st_uid == os.getuid() and not info.st_mode & 0o022
    if private: assert not path.stat().st_mode & 0o077
    return path

acquisition._trusted = fixture_ownership

def installed_provider():
    # Installation/OS admission is deliberately outside this offline source test.
    # The actual separate-kit verifier executes, including its complete inventory.
    acquisition._verified_kit(identity['sourceCommit'], force=True)
    return identity

acquisition._installed = installed_provider
if mode != 'positive':
    try:
        installed_provider()
    except (ValueError, OSError):
        print(json.dumps(dict(status='rejected', mode=mode)))
        raise SystemExit(0)
    raise AssertionError('missing or substituted kit was accepted')

installed_provider()
import pr320_installed_dispatch as dispatch
import pr320_campaign_capture as capture
import composed_budget_campaign_admission as admission
from cryptad_certification import cross_version_evidence as evidence
from cryptad_certification import composed_budget_journal_member as journal
from cryptad_certification import composed_budget_privacy_evidence as privacy
import cross_version_runtime as runtime

owner_names = {
    'pr320_route_runtime_evidence', 'pr320_storage_runtime_evidence',
    'pr320_owner_runtime_evidence', 'pr320_restart_runtime_evidence',
    'pr320_privacy_runtime_evidence'}
selection_names = {
    'pr320_route_selection', 'pr320_storage_selection', 'pr320_owner_selection',
    'pr320_restart_selection', 'pr320_privacy_selection'}
for name in owner_names | selection_names | {'pr320_campaign_capture', 'pr320_installed_dispatch'}:
    assert not (product / ('tools/release-certification/restricted/' + name + '.py')).exists()

rows = json.loads((root / 'originals.json').read_bytes())
loaded_owners, loaded_selections, measured_profiles, finished_members = set(), set(), set(), []

# Temporary export paths replace the installed-prefix identity provider only. The
# actual installed owner dispatchers, native decoders and original validators run.
with patch.object(admission, '__file__', '/opt/cryptad-cross-version/current/tools/release-certification/protected/composed_budget_campaign_admission.py'), \
     patch.object(privacy, '__file__', '/opt/cryptad-cross-version/current/tools/release-certification/cryptad_certification/composed_budget_privacy_evidence.py'), \
     patch.object(runtime, 'installed_snapshot_identity', return_value=identity), \
     patch.object(acquisition.os, 'geteuid', return_value=0):
    resolver = acquisition.InstalledFixtureSource(acquisition._SEAL, identity,
        Path('/root/cryptad/build/offline-source-test/verifier'), 'sha256:' + '0' * 64)
    for row in rows:
        originals = row['originals']
        selected = originals['selected']
        execution = selected['authorization']['executionClass']
        factory, fixed_fixture = dispatch.fixture(execution, product)
        assert Path(factory.__spec__.origin).parent == kit / 'tools/release-certification/restricted'
        assert fixed_fixture.is_relative_to(product / 'build')
        loaded_selections.add(factory.__name__)
        assert factory.contract.verify_selection_contract(**selected)
        if execution not in measured_profiles:
            profile = dispatch.common.prospective_profile(execution)
            import pr320_storage_selection as source_reader
            measured = source_reader.tool_identities(product, profile['toolPaths'], installed_source=resolver)
            assert set(measured) == set(profile['toolPaths'])
            for key, relative in profile['toolPaths'].items():
                actual = resolver.tool_path(relative)
                expected_root = product if installation.production_member(relative) else kit
                assert actual == expected_root / relative
                assert measured[key] == 'sha256:' + hashlib.sha256(actual.read_bytes()).hexdigest()
            measured_profiles.add(execution)

        owner = acquisition.verified_owner(originals['owner'])
        assert Path(owner.__spec__.origin) == kit / ('tools/release-certification/restricted/' + owner.__name__ + '.py')
        loaded_owners.add(owner.__name__)
        if originals['owner'] == 'pr320_privacy_runtime_evidence':
            # The actor verifies local artifacts without root custody. Only the
            # public installed identity provider is substituted; real kit/leaf
            # verification and the installed privacy dispatch branch still run.
            with patch.object(acquisition.os, 'geteuid', return_value=62002):
                assert privacy._installed_privacy_owner() is owner
                private = owner.decode_private(base64.b64decode(originals['private'], validate=True))
                assert privacy.verify_installed(private['component'])['status'] == 'verified'
                try:
                    acquisition.OwnedAcquisitionCapture(acquisition._SEAL, {}, 'activation', 'plan', {})
                except acquisition.AcquisitionError:
                    pass
                else:
                    raise AssertionError('read-only observer gained root custody')
        precursor = dict(schemaVersion=1, kind='pr320-root-original-input-capture',
            planDigest=evidence.digest(selected['plan']), originals=dict(originals, report=None))
        raw_precursor = json.dumps(precursor, sort_keys=True, separators=(',', ':')).encode()
        assert capture.decode_root_capsule(raw_precursor) == precursor

        raw = base64.b64decode(row['rawBase64'], validate=True)
        # This is the real per-member function used by terminal acquisition and
        # original campaign retention, including all five independent owners.
        assert admission.verify_original_member(row['kind'], raw, originals) == selected
        finished_members.append(row['member'])

assert loaded_owners == owner_names
assert loaded_selections == selection_names
assert len(measured_profiles) == 17
assert sorted(finished_members) == ['member-%02d.json' % i for i in range(19)]
assert Path(capture.__spec__.origin).parent == kit / 'tools/release-certification/restricted'
assert Path(dispatch.__spec__.origin).parent == kit / 'tools/release-certification/restricted'

repo_modules = []
for name, module in list(sys.modules.items()):
    spec = getattr(module, '__spec__', None)
    origin = getattr(spec, 'origin', None)
    if not origin or origin in {'built-in', 'frozen'}: continue
    path = Path(origin)
    if path.is_relative_to(root):
        assert path.is_relative_to(product) or path.is_relative_to(kit), (name, origin)
        if path.is_relative_to(kit):
            assert not installation.production_member(path.relative_to(kit).as_posix())
        repo_modules.append(name)
    else:
        # A fresh -I -S process may load its standard library, never the checkout.
        assert path.is_relative_to(Path(sys.base_prefix)) or path.is_relative_to(Path(sys.prefix)), (name, origin)
assert not any(name.startswith('test_pr320_') for name in repo_modules)
assert not any(name.startswith('cryptad_certification.tests') for name in repo_modules)
print(json.dumps(dict(status='offline-physical-export-passed', owners=len(loaded_owners),
    selectionFactories=len(loaded_selections), profiles=len(measured_profiles),
    originalMembers=len(finished_members), exportedModules=len(repo_modules))))
'''


class PhysicalExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='pr320-exported-source-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve()
        cls.product, cls.kit = cls.root / 'product', cls.root / 'kit'
        cls.product.mkdir(mode=0o700)
        cls.kit.mkdir(mode=0o700)
        names = subprocess.check_output(['git', '-C', str(SOURCE), 'ls-files', '--cached',
            '--others', '--exclude-standard', '-z'], timeout=30).split(b'\0')
        # Actual reviewed tool sources, workflow identities and each class's exact
        # additional source pins. No generated product or full-checkout symlink.
        import pr320_budget_contract as common
        required = {relative for execution in common.PROSPECTIVE_EXECUTION_CLASSES
            for relative in common.prospective_profile(execution)['toolPaths'].values()}
        roster = sorted({os.fsdecode(name) for name in names if name and
            (Path(os.fsdecode(name)).parts[0] in {'tools', '.github'} or os.fsdecode(name) in required)})
        production, kit_files = {}, {}
        for relative in roster:
            source = SOURCE / relative
            if not source.is_file() or source.is_symlink():
                raise AssertionError('export fixture requires actual regular reviewed sources: ' + relative)
            is_production = installation.production_member(relative)
            destination = (cls.product if is_production else cls.kit) / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)
            raw = destination.read_bytes()
            checksum = hashlib.sha256(raw).hexdigest()
            if is_production:
                production[relative] = dict(sha256=checksum, size=len(raw), executable=bool(source.stat().st_mode & 0o111))
            else:
                kit_files[relative] = checksum
        commit = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'],
                                         text=True, timeout=10).strip()
        cls._write(cls.product / '.restricted-manifest.json', dict(schemaVersion=2,
            kind='cryptad-restricted-installation', exportPolicy=installation.EXPORT_POLICY,
            sourceCommit=commit, files=production))
        cls._write(cls.kit / '.test-kit.json', dict(schemaVersion=1, kind='synthetic-disposable-test-kit',
            sourceCommit=commit, productionEligible=False, files=kit_files))
        for base in (cls.product, cls.kit):
            for directory, _directories, _files in os.walk(base): Path(directory).chmod(0o700)
        from test_composed_budget_campaign_admission import full_originals
        _selection, _bundles, _reports, retained, _facts = full_originals(provenance='source-build-comparison')
        rows = []
        for receipt in retained.values():
            for member, entry in receipt['entries'].items():
                selected = entry['originals']['selected']
                descriptor = next(row for row in selected['plan']['budgetCampaignInputs']['members'] if row['member'] == member)
                rows.append(dict(member=member, kind=descriptor['kind'], rawBase64=entry['rawBase64'], originals=entry['originals']))
        cls._write(cls.root / 'originals.json', sorted(rows, key=lambda row: row['member']))
        cls.child = cls.root / 'export-smoke.py'
        cls.child.write_text(CHILD)
        cls.child.chmod(0o600)

    @staticmethod
    def _write(path, value):
        path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False))
        path.chmod(0o600)

    def _run(self, mode):
        result = subprocess.run([sys.executable, '-I', '-S', '-B', str(self.child), str(self.root), mode],
            cwd=self.root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_physical_export_loads_all_fixed_factories_and_original_owners_from_measured_kit(self):
        result = self._run('positive')
        self.assertEqual('offline-physical-export-passed', result['status'])
        self.assertEqual((5, 5, 17, 19), (result['owners'], result['selectionFactories'],
                                        result['profiles'], result['originalMembers']))
        self.assertGreater(result['exportedModules'], 40)

    def test_fresh_isolated_browser_helper_loads_product_dependencies_and_kit_helpers(self):
        child = self.root / 'browser-import-child.py'
        child.write_text(r'''
import builtins
import json
import pathlib
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace

root = Path(sys.argv[1])
product, kit = root / 'product', root / 'kit'
helper = kit / 'tools/release-certification/restricted/pr320_privacy_browser_admin.py'
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
assert not any(name.startswith(('pr320_', 'cryptad_certification')) for name in sys.modules)

# Replace only the fixed installed directory provider with the physical export.
# The helper's exact source and its startup imports execute in this fresh child.
def installed_path(*arguments, **kwargs):
    if len(arguments) == 1:
        mapped = {'/opt/cryptad-cross-version/current': product,
                  '/opt/cryptad-restricted-test-kit': kit}.get(str(arguments[0]))
        if mapped is not None:
            arguments = (mapped,)
    return Path(*arguments, **kwargs)

def helper_import(name, globals=None, locals=None, fromlist=(), level=0):
    if (name == 'pathlib' and level == 0 and fromlist == ('Path',)
            and globals is not None and globals.get('__file__') == str(helper)):
        return SimpleNamespace(Path=installed_path)
    return builtins.__import__(name, globals, locals, fromlist, level)

# Only this helper receives the mapping. Imported modules and pathlib internals
# use their normal builtins and concrete path constructors.
namespace = runpy.run_path(str(helper), run_name='browser_import_probe',
    init_globals={'__builtins__': dict(vars(builtins), __import__=helper_import)})
assert pathlib.Path is Path
assert namespace['PRODUCT'] == product and namespace['ROOT'] == kit
assert namespace['COLLECTOR'] == product / 'tools/interop/pr320_installed_privacy_browser.cjs'
assert namespace['COLLECTOR'].is_file()
for name in ('pr320_privacy_contract', 'bounded_process', 'cryptad_certification.io'):
    assert Path(sys.modules[name].__file__).is_relative_to(product), name
assert Path(sys.modules['pr319_restart_admin'].__file__).is_relative_to(kit)
print(json.dumps({'freshBrowserImports': 'passed'}))
''')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', str(child), str(self.root)],
            cwd=self.root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual({'freshBrowserImports': 'passed'}, json.loads(result.stdout))

    def test_missing_kit_helper_rejects_before_any_original_owner_admission(self):
        path = self.kit / 'tools/release-certification/restricted/pr320_owner_selection.py'
        raw = path.read_bytes()
        path.unlink()
        try:
            self.assertEqual({'status': 'rejected', 'mode': 'missing-kit'}, self._run('missing-kit'))
        finally:
            path.write_bytes(raw); path.chmod(0o600)

    def test_substituted_kit_helper_rejects_against_original_measured_manifest(self):
        path = self.kit / 'tools/release-certification/restricted/pr320_privacy_runtime_evidence.py'
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n# substituted after kit measurement\n')
        try:
            self.assertEqual({'status': 'rejected', 'mode': 'substituted-kit'}, self._run('substituted-kit'))
        finally:
            path.write_bytes(raw); path.chmod(0o600)


@unittest.skipUnless(os.name == 'posix', 'requires POSIX temporary-directory aliases')
class AliasedTemporaryRootTests(unittest.TestCase):
    def test_canonical_fixture_roots_work_without_linux_boot_file(self):
        with tempfile.TemporaryDirectory(prefix='pr320-aliased-temp-') as temporary:
            root = Path(temporary).resolve()
            physical, alias = root / 'physical', root / 'alias'
            physical.mkdir()
            alias.symlink_to(physical, target_is_directory=True)
            script = r'''
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

source = Path(sys.argv[1])
sys.path[:0] = [str(source / relative) for relative in (
    'tools/release-certification/protected', 'tools/release-certification/restricted',
    'tools/release-certification', 'tools/interop')]
assert Path(tempfile.gettempdir()).is_symlink()
from cryptad_certification import certification_public_export as exports
from cryptad_certification import cross_version_evidence as evidence
from cryptad_certification.tests.test_cross_version_evidence import fixture_plan
checks = unittest.TestCase()
with tempfile.TemporaryDirectory() as temporary:
    with checks.assertRaises(OSError):
        os.close(exports._open_directory(Path(temporary)))
    with checks.assertRaisesRegex(evidence.EvidenceError, 'journal-root-symlink'):
        with evidence.Journal(Path(temporary), fixture_plan()):
            pass
names = (
    'test_pr320_original_acquisition.FixedServiceTests.test_actual_partial_journal_verifier_rejects_lineage_and_checkpoint_replacement',
    'test_pr320_original_acquisition.FixedServiceTests.test_root_capability_returns_only_actual_committed_owner_originals',
    'test_pr320_budget_original_chain.BudgetOriginalChainTest.test_actual_partial_original_chain_and_native_owner_accept_without_upstream_validator_mocks',
    'test_composed_budget_campaign_admission.OriginalCampaignAdmissionTest.test_authenticated_budget_capability_preserves_all_49_phase_requirements_and_other_blockers',
    'test_pr320_exported_source.PhysicalExportTests.test_physical_export_loads_all_fixed_factories_and_original_owners_from_measured_kit',
)
read_text = Path.read_text
def no_linux_boot_file(path, *args, **kwargs):
    if path == Path('/proc/sys/kernel/random/boot_id'):
        raise FileNotFoundError('synthetic host without Linux boot identity')
    return read_text(path, *args, **kwargs)

with patch.object(Path, 'read_text', no_linux_boot_file):
    with checks.assertRaisesRegex(evidence.EvidenceError, 'boot-identity-unavailable'):
        evidence.boot_identity()
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromNames(names))
raise SystemExit(0 if result.wasSuccessful() else 1)
'''
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script, str(SOURCE)],
                cwd=root, env={**os.environ, 'TMPDIR': str(alias), 'TMP': str(alias), 'TEMP': str(alias)},
                capture_output=True, text=True, timeout=120)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == '__main__': unittest.main()
