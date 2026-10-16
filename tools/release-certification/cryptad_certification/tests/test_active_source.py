"""Selected-source tests never weaken the separate input/archive member policy."""
import hashlib
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from cryptad_certification import active_source as owner
from cryptad_certification import transparency_bundle as bundle


@contextmanager
def windows_source_metadata(mutation=None):
    """Model CPython's Windows path creation time/mode and handle change time/mode."""
    original_lstat, original_fstat = Path.lstat, os.fstat

    def metadata(info, *, handle=False):
        values = {key: getattr(info, key) for key in dir(info) if key.startswith('st_')}
        values['st_birthtime_ns'] = 123
        values['st_ctime_ns'] = 456 if handle else 123
        values['st_mode'] = info.st_mode & ~0o111 if handle else info.st_mode | 0o111
        return SimpleNamespace(**values)

    def lstat(path, *args, **kwargs):
        return metadata(original_lstat(path, *args, **kwargs))

    calls = 0

    def fstat(descriptor):
        nonlocal calls
        calls += 1
        info = metadata(original_fstat(descriptor), handle=True)
        if calls == 2 and mutation:
            setattr(info, mutation, getattr(info, mutation, 0) +
                    (0x400 if mutation == 'st_file_attributes' else 1))
        return info

    windows = SimpleNamespace(**vars(os))
    windows.name, windows.fstat, windows.supports_dir_fd = 'nt', fstat, set()
    with patch.object(owner, 'os', windows), patch.object(Path, 'lstat', lstat):
        yield


class ActiveSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)

    def git(self, *args):
        return subprocess.run(['git', '-c', 'user.name=Source Roster Fixture',
                               '-c', 'user.email=source-roster@example.invalid',
                               '-c', 'commit.gpgsign=false', *args], cwd=self.root,
                              check=True, capture_output=True, timeout=15)

    def repository(self):
        self.git('init', '--quiet')
        self.source = self.root / 'tools/release-certification/cryptad_certification/owner.py'
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'VALUE = 1\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: selected source')

    def clear_hidden_flags(self, name):
        self.git('update-index', '--no-assume-unchanged', '--', name)
        self.git('update-index', '--no-skip-worktree', '--', name)

    def manifest(self):
        source = self.root / 'tools/release-certification/cryptad_certification/owner.py'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b'VALUE = 1\n')
        value = {'schemaVersion': 2, 'kind': 'cryptad-restricted-installation',
                 'exportPolicy': 'production-without-test-seams-v1', 'sourceCommit': 'a' * 40,
                 'files': {source.relative_to(self.root).as_posix(): {
                     'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                     'size': source.stat().st_size, 'executable': False}}}
        (self.root / '.restricted-manifest.json').write_text(json.dumps(value))
        return source

    def full_source_manifest(self):
        source = self.manifest()
        test = self.root / 'platform-api/src/test/java/DeclaredTest.java'
        test.parent.mkdir(parents=True)
        test.write_bytes(b'class DeclaredTest {}\n')
        value = {'schemaVersion': 1, 'kind': 'cryptad-source-export',
                 'sourceCommit': 'a' * 40, 'sourceTree': 'b' * 40,
                 'sourceClass': 'committed-source', 'files': {}}
        for path in (source, test):
            value['files'][path.relative_to(self.root).as_posix()] = {
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'size': path.stat().st_size, 'executable': False}
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(value))
        return value, source, test

    def test_windows_export_metadata_does_not_compare_synthetic_host_execute_bits(self):
        manifest, source, _ = self.full_source_manifest()
        # Only the OS metadata interpretation is substituted; roster, bytes and links stay real.
        name = source.relative_to(self.root).as_posix()
        for executable in (False, True):
            manifest['files'][name]['executable'] = executable
            (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(manifest))
            with windows_source_metadata():
                selected = owner.source_roster(self.root)
                self.assertIn(name, selected.paths)
                self.assertEqual('manifest-source-export', selected.source_class)
                source.write_bytes(b'TAMPERED')
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
            source.write_bytes(b'VALUE = 1\n')
        manifest['files'][name]['executable'] = 1
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(manifest))
        with windows_source_metadata(), self.assertRaises(owner.SourceRosterError):
            owner.source_roster(self.root)

    @unittest.skipUnless(os.name == 'posix', 'requires actual POSIX permission bits')
    def test_posix_export_execute_bit_drift_remains_invalid(self):
        _, source, _ = self.full_source_manifest()
        source.chmod(0o744)
        with self.assertRaises(owner.SourceRosterError):
            owner.source_roster(self.root)

    def test_history_pollution_preserves_roster_and_current_working_bytes_are_bound(self):
        self.repository()
        clean = owner.source_roster(self.root)
        self.assertEqual('committed-source', clean.source_class)
        history = self.source.parent / '.stversions' / 'archived.py'
        history.parent.mkdir()
        history.write_bytes(b'PRIVATE HISTORY MUST NOT BECOME ACTIVE\n')
        polluted = owner.source_roster(self.root)
        self.assertEqual(clean.paths, polluted.paths)
        self.assertEqual('committed-source', polluted.source_class)
        active = self.source.with_name('new_owner.py')
        active.write_bytes(b'VALUE = 2\n')
        self.assertIn(active.relative_to(self.root).as_posix(), owner.active_files(self.root))
        self.assertEqual(b'VALUE = 2\n', owner.read_source(self.root, active.relative_to(self.root).as_posix()))

    def test_tracked_history_member_is_visible_instead_of_silently_excluded(self):
        self.repository()
        history = self.source.parent / '.stversions' / 'tracked.py'
        history.parent.mkdir()
        history.write_bytes(b'EXPLICITLY SELECTED\n')
        self.git('add', '.')
        self.assertIn(history.relative_to(self.root).as_posix(), owner.active_files(self.root))

    def test_hidden_index_flags_cannot_declare_even_unchanged_source_committed(self):
        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.clear_hidden_flags(name)
                self.git('update-index', flag, '--', name)
                self.assertEqual(b'', self.git('status', '--porcelain').stdout)
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
                self.clear_hidden_flags(name)
                self.assertEqual('committed-source', owner.source_roster(self.root).source_class)

    def test_hidden_index_byte_edits_cannot_pass_certification_source_clean(self):
        from cryptad_certification import phase_12_ci as ci

        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        source = {'commit': self.git('rev-parse', 'HEAD').stdout.decode().strip(),
                  'tree': self.git('rev-parse', 'HEAD^{tree}').stdout.decode().strip()}
        for flags in (('--assume-unchanged',), ('--skip-worktree',),
                      ('--assume-unchanged', '--skip-worktree')):
            with self.subTest(flags=flags):
                self.clear_hidden_flags(name)
                self.source.write_bytes(b'VALUE = 1\n')
                for flag in flags:
                    self.git('update-index', flag, '--', name)
                self.source.write_bytes(b'VALUE = 2\n')
                self.assertEqual(b'', self.git('status', '--porcelain').stdout)
                with patch.object(ci, 'ROOT', self.root), self.assertRaises(owner.SourceRosterError):
                    ci._source_clean(source)
                self.clear_hidden_flags(name)
                with patch.object(ci, 'ROOT', self.root):
                    self.assertFalse(ci._source_clean(source))
                self.source.write_bytes(b'VALUE = 1\n')
                with patch.object(ci, 'ROOT', self.root):
                    self.assertTrue(ci._source_clean(source))

    def test_hidden_index_deletions_cannot_declare_committed_source(self):
        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.clear_hidden_flags(name)
                self.source.write_bytes(b'VALUE = 1\n')
                self.git('update-index', flag, '--', name)
                self.source.unlink()
                self.assertEqual(b'', self.git('status', '--porcelain').stdout)
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
                self.clear_hidden_flags(name)
                self.assertEqual('working-source', owner.source_roster(self.root).source_class)
                self.source.write_bytes(b'VALUE = 1\n')

    @unittest.skipUnless(os.name == 'posix', 'requires actual POSIX permission bits')
    def test_hidden_index_execute_edits_cannot_declare_committed_source(self):
        self.repository()
        self.git('config', 'core.filemode', 'true')
        name = self.source.relative_to(self.root).as_posix()
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.clear_hidden_flags(name)
                self.source.chmod(0o644)
                self.git('update-index', flag, '--', name)
                self.source.chmod(0o755)
                self.assertEqual(b'', self.git('status', '--porcelain').stdout)
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
                self.clear_hidden_flags(name)
                self.assertEqual('working-source', owner.source_roster(self.root).source_class)
                self.source.chmod(0o644)

    @unittest.skipUnless(os.name == 'posix', 'requires actual POSIX permission bits')
    def test_ignored_mode_changes_cannot_pass_certification_source_clean(self):
        from cryptad_certification import phase_12_ci as ci

        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        for indexed in (False, True):
            self.source.chmod(0o755 if indexed else 0o644)
            self.git('update-index', '--chmod=+x' if indexed else '--chmod=-x', '--', name)
            self.git('commit', '--quiet', '--allow-empty', '-m', 'fixture: indexed mode')
            self.git('config', 'core.filemode', 'false')
            source = {'commit': self.git('rev-parse', 'HEAD').stdout.decode().strip(),
                      'tree': self.git('rev-parse', 'HEAD^{tree}').stdout.decode().strip()}
            for mode in ((0o644,) if indexed else (0o755, 0o654, 0o645)):
                with self.subTest(indexed=indexed, mode=oct(mode)):
                    self.source.chmod(mode)
                    self.assertEqual(b'', self.git('status', '--porcelain').stdout)
                    index = (self.root / '.git/index').read_bytes()
                    with patch.object(ci, 'ROOT', self.root):
                        self.assertFalse(ci._source_clean(source))
                    self.assertEqual('working-source', owner.source_roster(self.root).source_class)
                    self.assertEqual(index, (self.root / '.git/index').read_bytes())
            self.source.chmod(0o755 if indexed else 0o644)
            self.assertEqual('committed-source', owner.source_roster(self.root).source_class)

    def test_cached_stat_cannot_hide_same_size_working_byte_edits(self):
        self.repository()
        self.git('config', 'core.trustctime', 'false')
        stamp = self.source.stat().st_mtime_ns - 10_000_000_000
        os.utime(self.source, ns=(stamp, stamp))
        self.git('update-index', '--refresh')
        self.source.write_bytes(b'VALUE = 2\n')
        os.utime(self.source, ns=(stamp, stamp))
        self.assertEqual(b'', self.git('status', '--porcelain').stdout)
        index = (self.root / '.git/index').read_bytes()

        self.assertEqual('working-source', owner.source_roster(self.root).source_class)
        self.assertEqual(index, (self.root / '.git/index').read_bytes())

    def test_custom_clean_filter_cannot_mask_changed_source_bytes(self):
        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        for driver in ('mask', 'unset', 'unspecified'):
            with self.subTest(driver=driver):
                (self.root / '.git/info/attributes').write_text(name + ' filter=' + driver + '\n')
                self.git('config', 'filter.' + driver + '.clean', 'git show HEAD:' + name)
                self.source.write_bytes(b'VALUE = 2\n')
                index = (self.root / '.git/index').read_bytes()

                self.assertEqual('working-source', owner.source_roster(self.root).source_class)
                self.assertEqual(index, (self.root / '.git/index').read_bytes())
                # Matching bytes do not authenticate a repository-local executable filter.
                self.source.write_bytes(b'VALUE = 1\n')
                self.assertEqual('working-source', owner.source_roster(self.root).source_class)
        (self.root / '.git/info/attributes').write_text('')
        self.assertEqual('committed-source', owner.source_roster(self.root).source_class)

    def test_local_ident_expansion_cannot_hide_substituted_working_bytes(self):
        self.repository()
        self.source.write_bytes(b'VALUE = "$Id$"\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: ident source')
        name = self.source.relative_to(self.root).as_posix()
        (self.root / '.git/info/attributes').write_text(name + ' ident\n')
        self.source.write_bytes(b'VALUE = "$Id: substituted bytes $"\n')

        self.assertEqual('working-source', owner.source_roster(self.root).source_class)

    def test_replacement_commit_cannot_supply_original_source_identity(self):
        self.repository()
        original = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        tree = self.git('rev-parse', 'HEAD^{tree}').stdout.decode().strip()
        self.source.write_bytes(b'VALUE = 2\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: replacement source')
        replacement = self.git('rev-parse', 'HEAD').stdout.decode().strip()
        self.git('update-ref', 'HEAD', original)
        self.git('replace', original, replacement)

        roster = owner.source_roster(self.root)

        self.assertEqual(original, roster.source_commit)
        self.assertEqual(tree, roster.source_tree)
        self.assertEqual('working-source', roster.source_class)

    def test_crlf_checkout_is_working_until_raw_bytes_match_committed_blob(self):
        from cryptad_certification import phase_12_ci as ci

        self.repository()
        (self.root / '.gitattributes').write_bytes(b'*.bat text eol=crlf\n')
        script = self.root / 'native space é.bat'
        script.write_bytes(b'echo one\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: native checkout line endings')
        script.unlink()
        self.git('checkout-index', '--force', '--all')
        self.assertEqual(b'echo one\r\n', script.read_bytes())
        self.assertEqual(b'', self.git('diff', '--raw').stdout)
        index = (self.root / '.git/index').read_bytes()
        original = owner.source_roster(self.root)
        source = {'commit': original.source_commit, 'tree': original.source_tree}
        self.assertEqual('working-source', original.source_class)
        self.assertEqual(b'echo one\n', self.git('show', 'HEAD:' + script.name).stdout)
        self.assertEqual(b'echo one\r\n', owner.read_source(self.root, script.name))
        with patch.object(ci, 'ROOT', self.root):
            self.assertFalse(ci._source_clean(source))
        with windows_source_metadata():
            self.assertEqual('working-source', owner.source_roster(self.root).source_class)

        script.write_bytes(b'echo one\n')
        self.assertEqual('committed-source', owner.source_roster(self.root).source_class)
        with patch.object(ci, 'ROOT', self.root):
            self.assertTrue(ci._source_clean(source))
        self.assertEqual(index, (self.root / '.git/index').read_bytes())

        script.write_bytes(b'echo two\r\n')

        self.assertEqual('working-source', owner.source_roster(self.root).source_class)

    def test_autocrlf_normalization_cannot_hide_raw_bytes_without_attributes(self):
        self.repository()
        self.git('config', 'core.autocrlf', 'true')
        name = self.source.relative_to(self.root).as_posix()
        self.source.write_bytes(b'VALUE = 1\r\n')
        self.assertEqual(b'', self.git('diff', '--raw').stdout)
        self.assertEqual('working-source', owner.source_roster(self.root).source_class)
        self.assertEqual(b'VALUE = 1\n', self.git('show', 'HEAD:' + name).stdout)

    def test_binary_crlf_blob_can_match_its_raw_checkout(self):
        self.repository()
        (self.root / '.gitattributes').write_bytes(b'*.bin -text\n')
        binary = self.root / 'exact.bin'
        binary.write_bytes(b'\x00exact\r\nbytes\xff')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: exact binary bytes')
        self.assertEqual(binary.read_bytes(), self.git('show', 'HEAD:exact.bin').stdout)
        self.assertEqual('committed-source', owner.source_roster(self.root).source_class)

    def test_intent_to_add_members_are_working_source_even_when_empty(self):
        from cryptad_certification import phase_12_ci as ci

        self.repository()
        original = owner.source_roster(self.root)
        for name, raw in (('new space é.py', b'NEW SOURCE\n'), ('empty.py', b''),
                          ('.stversions/selected.py', b'TRACKED HISTORY\n')):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                self.git('add', '--intent-to-add', '--', name)
                selected = owner.source_roster(self.root)
                self.assertIn(name, selected.paths)
                self.assertEqual('working-source', selected.source_class)
                with patch.object(ci, 'ROOT', self.root):
                    self.assertFalse(ci._source_clean({'commit': original.source_commit,
                                                       'tree': original.source_tree}))
                self.git('reset', '--quiet', '--', name)
                path.unlink()

    def test_git_selections_reject_the_reserved_source_export_roster(self):
        self.repository()
        path = self.root / owner.SOURCE_EXPORT_ROSTER
        path.write_bytes(b'{}\n')
        for tracked in (False, True):
            with self.subTest(tracked=tracked):
                if tracked:
                    self.git('add', '--', path.name)
                    self.git('commit', '--quiet', '-m', 'fixture: reserved member')
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)

    def test_tracked_deletions_select_current_files_before_and_after_staging(self):
        self.repository()
        history = self.source.parent / '.stversions'
        history.mkdir()
        kept = history / 'kept.py'
        kept.write_bytes(b'EXPLICITLY SELECTED\n')
        deleted = [self.source.with_name('deleted space é.py'), history / 'deleted.py']
        for path in deleted:
            path.write_bytes(b'DELETED\n')
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', 'fixture: tracked deletion candidates')
        for path in deleted:
            path.unlink()
        current = self.source.with_name('new source.py')
        current.write_bytes(b'NEW SOURCE\n')
        (history / 'untracked.py').write_bytes(b'UNSELECTED HISTORY\n')
        expected = tuple(sorted(path.relative_to(self.root).as_posix()
                                for path in (self.source, kept, current)))

        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    self.git('add', '--update')
                roster = owner.source_roster(self.root)
                self.assertEqual(expected, roster.paths)
                self.assertEqual('working-source', roster.source_class)
                self.assertEqual(b'NEW SOURCE\n', owner.read_source(
                    self.root, current.relative_to(self.root).as_posix()))

    def test_unstaged_rename_selects_destination_and_remains_working_source(self):
        self.repository()
        destination = self.source.with_name('renamed source é.py')
        self.source.rename(destination)

        roster = owner.source_roster(self.root)

        self.assertEqual((destination.relative_to(self.root).as_posix(),), roster.paths)
        self.assertEqual('working-source', roster.source_class)

    def test_untracked_history_never_consumes_the_active_source_count_budget(self):
        self.repository()
        clean = owner.active_files(self.root)
        for location in (self.root / '.stversions', self.source.parent / '.stversions'):
            location.mkdir()
            for number in range(3):
                (location / f'archive-{number}.py').write_bytes(b'archived')
        with patch.object(owner, 'MAX_PATHS', 1):
            self.assertEqual(clean, owner.active_files(self.root))

    def test_source_export_requires_exact_manifest_and_selected_bytes(self):
        with self.assertRaises(owner.SourceRosterError):
            owner.active_files(self.root)
        source = self.manifest()
        roster = owner.source_roster(self.root)
        self.assertEqual('manifest-source-export', roster.source_class)
        self.assertIsNone(roster.source_tree)
        self.assertEqual((source.relative_to(self.root).as_posix(),), roster.paths)
        source.write_bytes(b'changed\n')
        with self.assertRaises(owner.SourceRosterError):
            owner.active_files(self.root)

    def test_full_source_export_preserves_declared_tests_and_ignores_local_history(self):
        manifest, source, test = self.full_source_manifest()
        (self.root / '.restricted-manifest.json').unlink()
        clean = owner.source_roster(self.root)
        self.assertEqual(tuple(sorted(manifest['files'])), clean.paths)
        self.assertIn(test.relative_to(self.root).as_posix(), clean.paths)
        self.assertEqual('b' * 40, clean.source_tree)
        self.assertEqual('manifest-source-export', clean.source_class)
        history = source.parent / '.stversions'
        history.mkdir()
        (history / 'archived.py').write_bytes(b'local history')
        self.assertEqual(clean, owner.source_roster(self.root))
        manifest['sourceClass'] = 'working-source'
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(manifest))
        self.assertEqual('manifest-source-export', owner.source_roster(self.root).source_class)

    def test_full_source_export_keeps_explicitly_declared_history_visible(self):
        manifest, source, _ = self.full_source_manifest()
        history = source.parent / '.stversions'
        history.mkdir()
        declared = history / 'declared.py'
        declared.write_bytes(b'explicitly selected')
        name = declared.relative_to(self.root).as_posix()
        manifest['files'][name] = {'sha256': hashlib.sha256(declared.read_bytes()).hexdigest(),
                                   'size': declared.stat().st_size, 'executable': False}
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(manifest))
        self.assertIn(name, owner.active_files(self.root))

    def test_full_source_export_can_select_restricted_manifest_as_ordinary_source_data(self):
        manifest, _, _ = self.full_source_manifest()
        selected = self.root / '.restricted-manifest.json'
        manifest['files'][selected.name] = {
            'sha256': hashlib.sha256(selected.read_bytes()).hexdigest(),
            'size': selected.stat().st_size, 'executable': False}
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(manifest))
        roster = owner.source_roster(self.root)
        self.assertIn(selected.name, roster.paths)
        self.assertEqual('b' * 40, roster.source_tree)
        self.assertEqual('manifest-source-export', roster.source_class)

    def test_full_source_export_tampering_cannot_fall_back_to_restricted_manifest(self):
        _, _, test = self.full_source_manifest()
        test.write_bytes(b'substituted test bytes')
        with self.assertRaises(owner.SourceRosterError):
            owner.source_roster(self.root)
        test.unlink()
        with self.assertRaises(owner.SourceRosterError):
            owner.source_roster(self.root)

    def test_full_source_export_links_cannot_fall_back_to_restricted_manifest(self):
        self.full_source_manifest()
        roster = self.root / owner.SOURCE_EXPORT_ROSTER
        original = self.root / 'original-roster.json'
        roster.rename(original)
        for target in (original, self.root / 'missing-roster.json'):
            with self.subTest(target=target):
                roster.symlink_to(target)
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
                roster.unlink()

    def test_full_source_export_keeps_prospective_count_and_byte_limits(self):
        self.full_source_manifest()
        for name in ('MAX_PATHS', 'MAX_ROSTER', 'MAX_EXPORT_SOURCE_BYTES'):
            with self.subTest(limit=name), patch.object(owner, name, 1):
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
    def test_full_source_export_rejects_malformed_and_boolean_integer_fields(self):
        baseline, source, _ = self.full_source_manifest()
        member = source.relative_to(self.root).as_posix()
        source.write_bytes(b'x')
        baseline['files'][member].update(size=1, sha256=hashlib.sha256(b'x').hexdigest())
        (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(json.dumps(baseline))
        self.assertIn(member, owner.source_roster(self.root).paths)
        changes = [
            ('schemaVersion', True), ('schemaVersion', 1.0), ('kind', 'other'),
            ('sourceCommit', True), ('sourceCommit', 'a' * 64),
            ('sourceTree', None), ('sourceTree', 'b' * 64),
            ('sourceClass', 'manifest-source-export'), ('sourceClass', []),
            ('files', []), ('files', {}), ('unexpected', 'field')]
        variants = []
        for field, value in changes:
            selected = copy.deepcopy(baseline)
            selected[field] = value
            variants.append(selected)
        for field, value in (('size', True), ('size', 1.0), ('size', -1),
                             ('executable', 0), ('executable', True),
                             ('sha256', True), ('sha256', 'f' * 64), ('extra', 1)):
            selected = copy.deepcopy(baseline)
            selected['files'][member][field] = value
            variants.append(selected)
        for name in ('../outside.py', '/outside.py', 'C:/outside.py', r'\\server\share\outside.py'):
            selected = copy.deepcopy(baseline)
            selected['files'][name] = selected['files'].pop(member)
            variants.append(selected)
        roster = self.root / owner.SOURCE_EXPORT_ROSTER
        for index, selected in enumerate(variants):
            with self.subTest(index=index):
                roster.write_text(json.dumps(selected))
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)

    def test_full_source_export_rejects_duplicate_json_members(self):
        manifest, source, _ = self.full_source_manifest()
        member = source.relative_to(self.root).as_posix()
        raw = json.dumps(manifest, separators=(',', ':'))
        record = json.dumps(manifest['files'][member], separators=(',', ':'))
        member_row = json.dumps(member) + ':' + record
        variants = (
            raw.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1', 1),
            raw.replace(member_row, member_row + ',' + member_row, 1),
            '{malformed-json', 'null', '[1]')
        for selected in variants:
            with self.subTest(selected=selected):
                (self.root / owner.SOURCE_EXPORT_ROSTER).write_text(selected)
                with self.assertRaises(owner.SourceRosterError):
                    owner.source_roster(self.root)
    def test_selected_final_and_ancestor_links_cannot_supply_source_bytes(self):
        self.repository()
        target = self.root / 'target.py'
        target.write_bytes(b'out of selection')
        self.source.unlink()
        self.source.symlink_to(target)
        name = self.source.relative_to(self.root).as_posix()
        with self.assertRaises(owner.SourceRosterError):
            owner.read_source(self.root, name)
        self.source.unlink()
        self.source.parent.rename(self.source.parent.with_name('real-owner'))
        self.source.parent.symlink_to(self.source.parent.with_name('real-owner'), target_is_directory=True)
        with self.assertRaises(owner.SourceRosterError):
            owner.read_source(self.root, name)

    def test_hardlink_and_size_bound_cannot_supply_source_bytes(self):
        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        with self.assertRaises(owner.SourceRosterError):
            owner.read_source(self.root, name, maximum=1)
        os.link(self.source, self.source.with_suffix('.alias'))
        with self.assertRaises(owner.SourceRosterError):
            owner.read_source(self.root, name)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO refusal requires mkfifo')
    def test_special_source_file_is_rejected_before_opening_it(self):
        fifo = self.root / 'special.py'
        os.mkfifo(fifo)
        with patch.object(owner.os, 'open') as opened:
            with self.assertRaises(owner.SourceRosterError):
                owner.read_source(self.root, fifo.name)
            opened.assert_not_called()

    def test_source_growth_and_truncation_during_read_are_rejected(self):
        self.repository()
        original = owner._source_handle
        for replacement in (b'', b'GROWTH' * 10):
            self.source.write_bytes(b'original')

            @contextmanager
            def changing(path):
                with original(path) as source:
                    class MutatingReader:
                        def fileno(self):
                            return source.fileno()

                        def read(self, size):
                            raw = source.read(size)
                            path.write_bytes(replacement)
                            return raw
                    yield MutatingReader()

            with self.subTest(replacement=replacement), patch.object(owner, '_source_handle', changing):
                with self.assertRaises(owner.SourceRosterError):
                    owner.read_source(self.root, self.source.relative_to(self.root).as_posix())

    def test_windows_path_and_handle_metadata_preserve_read_and_mutation_checks(self):
        self.repository()
        name = self.source.relative_to(self.root).as_posix()
        for mutation in (None, 'st_ctime_ns', 'st_ino', 'st_nlink', 'st_size', 'st_mtime_ns',
                         'st_mode', 'st_birthtime_ns', 'st_file_attributes'):
            with self.subTest(mutation=mutation), windows_source_metadata(mutation):
                if mutation:
                    with self.assertRaises(owner.SourceRosterError):
                        owner.read_source(self.root, name)
                else:
                    self.assertEqual(b'VALUE = 1\n', owner.read_source(self.root, name))

    def test_directory_replacement_after_handle_open_cannot_supply_source(self):
        self.repository()
        original = owner._source_handle

        @contextmanager
        def replacing(path):
            with original(path) as source:
                previous = path.parent.with_name('previous-owner')
                path.parent.rename(previous)
                path.parent.mkdir()
                (previous / path.name).rename(path)
                yield source

        with patch.object(owner, '_source_handle', replacing):
            with self.assertRaises(owner.SourceRosterError):
                owner.read_source(self.root, self.source.relative_to(self.root).as_posix())

    def test_windows_and_parent_lexical_escapes_cannot_select_source(self):
        for name in ('../outside', '/outside', 'C:/outside', r'C:\outside', r'\\server\share\outside'):
            with self.subTest(name=name), self.assertRaises(owner.SourceRosterError):
                owner.read_source(self.root, name)

    def test_tool_identity_ignores_untracked_history_and_binds_new_working_sources(self):
        self.repository()
        with patch.object(bundle, '__file__', str(self.source.with_name('transparency_bundle.py'))):
            clean = bundle.tool_identity()
            history = self.source.parent / '.stversions' / 'archived.py'
            history.parent.mkdir()
            history.write_bytes(b'archived')
            self.assertEqual(clean, bundle.tool_identity())
            self.source.with_name('new_owner.py').write_bytes(b'current source')
            self.assertNotEqual(clean, bundle.tool_identity())

    def test_source_exclusions_do_not_remove_unexpected_external_artifact_members(self):
        artifact = self.root / 'artifact'
        artifact.mkdir()
        history = artifact / '.stversions'
        history.mkdir()
        (history / 'sidecar.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'member-name-invalid'):
            bundle.inventory(artifact)


if __name__ == '__main__':
    unittest.main()
