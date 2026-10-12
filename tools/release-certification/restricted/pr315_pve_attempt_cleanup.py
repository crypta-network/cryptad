#!/usr/bin/env python3
"""PVE-only release of exact successful guest duplicates after Mac verification.

The separate inventory program has no deletion code. Apply binds its read-only
inventory to the Mac-selected digest, then rechecks dependencies under the PVE
configuration lock and every local image storage's actual PVE lock before unlink.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pr315_pve_attempt_inventory as inventory

STORAGE_LOCK_ROOT = Path('/var/lock/pve-manager')
WORKER = '--storage-exclusion-worker'
MAX_PAYLOAD = 32768

# PVE's configuration lock excludes adding/changing storage while the child
# holds the same local lock files used by Storage::Plugin::cluster_lock_storage.
# Shared stores require a distributed lifetime/renewal protocol; retain copies
# rather than silently substituting a local lock for that protocol.
PVE_GUARD = r'''
use strict;
use warnings;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use PVE::Storage;
use PVE::Tools qw(run_command file_get_contents);
die "invalid release command\n" unless @ARGV == 3 && $ARGV[0] eq '/usr/bin/python3';
my ($python, $script, $lease) = @ARGV;
my $input = do { local $/; <STDIN> };
die "release payload too large\n" if length($input) > 32768;
my $request = decode_json($input);
my $output = '';
PVE::Storage::lock_storage_config(sub {
    my $cfg = PVE::Storage::config();
    my @stores;
    for my $id (sort keys %{$cfg->{ids}}) {
        my $entry = $cfg->{ids}->{$id};
        next unless $entry->{content}->{images};
        die "shared image storage is not supported for release\n" if $entry->{shared};
        die "nonlocal image storage is not supported for release\n"
            unless $entry->{type} =~ /\A(?:dir|btrfs|lvm|lvmthin|zfspool)\z/;
        push @stores, $id;
    }
    $request->{guard} = {
        stores => \@stores,
        configDigest => sha256_hex(file_get_contents('/etc/pve/storage.cfg')),
        taskLeaseFd => 0 + $lease,
    };
    # cfs configuration leases expire after 120 seconds. PVE's own command
    # window is 60 seconds; kill/reap the child within 50 before unlocking.
    run_command([$python, $script, '--storage-exclusion-worker'],
        input => encode_json($request), timeout => 50,
        outfunc => sub {
            $output .= shift;
            die "release output too large\n" if length($output) > 32768;
        });
});
print $output, "\n";
'''


def _epochs(plan):
    base = inventory.TASK / plan['suite'] / 'attempt-01'
    values = {}
    for name in (*inventory.FILES, *inventory.DIRECTORIES):
        info = (inventory._regular(base / name, inventory.OWNER_UID)
            if name in inventory.FILES else
            inventory._directory(base / name, inventory.OWNER_UID))
        values[name] = [info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]
    return {'objects': values,
        'configDigest': inventory._hash(inventory.PVE_STORAGE_CONFIG)}


@contextmanager
def _storage_locks(stores):
    if (not isinstance(stores, list) or len(stores) > 64
            or any(not isinstance(name, str) or
                   re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) is None
                   for name in stores)
            or stores != sorted(set(stores))):
        raise ValueError('pr315-cleanup-storage-lock-selection-invalid')
    info = inventory._directory(STORAGE_LOCK_ROOT, 0)
    if info.st_mode & 0o022:
        raise ValueError('pr315-cleanup-storage-lock-root-writable')
    with ExitStack() as stack:
        for name in stores:
            path = STORAGE_LOCK_ROOT / ('pve-storage-' + name)
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stack.callback(os.close, descriptor)
            before = inventory._regular(path, 0)
            actual = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino):
                raise ValueError('pr315-cleanup-storage-lock-replaced')
            if before.st_mode & 0o022:
                raise ValueError('pr315-cleanup-storage-lock-writable')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def _require_storage_parent(guard):
    if os.geteuid() != 0 or not sys.platform.startswith('linux'):
        raise ValueError('pr315-cleanup-storage-exclusion-required')
    parent = os.getppid()
    # If the lock holder dies, this worker cannot continue after its locks unwind.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        raise ValueError('pr315-cleanup-storage-parent-unavailable')
    script = Path(__file__).resolve()
    source = inventory._regular(script, 0, 16384)
    if source.st_mode & 0o022:
        raise ValueError('pr315-cleanup-storage-worker-writable')
    command = (Path('/proc') / str(parent) / 'cmdline').read_bytes().split(b'\0')
    expected = [os.fsencode(value) for value in ('/usr/bin/perl', '-e', PVE_GUARD,
        '--', '/usr/bin/python3', str(script), str(guard['taskLeaseFd']))] + [b'']
    if (command != expected or
            (Path('/proc') / str(parent)).stat().st_uid != 0):
        raise ValueError('pr315-cleanup-storage-exclusion-required')
    environment = (Path('/proc') / str(parent) / 'environ').read_bytes().split(b'\0')
    unsafe = (b'PERL5LIB=', b'PERL5OPT=', b'PERLLIB=', b'PYTHONPATH=',
              b'PYTHONHOME=', b'LD_PRELOAD=', b'LD_LIBRARY_PATH=')
    if any(value.startswith(unsafe) for value in environment):
        raise ValueError('pr315-cleanup-storage-parent-environment-invalid')
    lease = inventory.TASK / 'workload-suite.lock'
    selected = inventory._regular(lease, inventory.OWNER_UID)
    inherited = (Path('/proc') / str(parent) / 'fd' / str(guard['taskLeaseFd'])).stat()
    if (selected.st_dev, selected.st_ino) != (inherited.st_dev, inherited.st_ino):
        raise ValueError('pr315-cleanup-task-lease-changed')


def _guarded_release(plan, checked, expected_check_digest, epochs, guard):
    if (not isinstance(guard, dict)
            or set(guard) != {'stores', 'configDigest', 'taskLeaseFd'}
            or type(guard['taskLeaseFd']) is not int or guard['taskLeaseFd'] < 0
            or guard['configDigest'] != epochs['configDigest']):
        raise ValueError('pr315-cleanup-storage-configuration-changed')
    _require_storage_parent(guard)
    with _storage_locks(guard['stores']):
        return _release_copies(plan, checked, expected_check_digest, epochs)


def _release_copies(plan, checked, expected_check_digest, epochs):
    """Run only in the verified PVE guard worker, with every storage lock held."""
    if _epochs(plan) != epochs:
        raise ValueError('pr315-cleanup-copy-epoch-changed')
    base = inventory.TASK / plan['suite'] / 'attempt-01'
    files = {name: base / name for name in inventory.FILES}
    directories = {base / name: None for name in inventory.DIRECTORIES}
    dependents, scanned = inventory._external_backing_users({
        base / 'guest.qcow2', base / 'prepared.qcow2'})
    if (inventory._qemu_processes(base) or inventory._open_users(files, directories)
            or dependents or scanned != checked['qcowMetadataScanned']):
        raise ValueError('pr315-cleanup-copy-still-in-use')
    if _epochs(plan) != epochs:
        raise ValueError('pr315-cleanup-copy-epoch-changed')
    return _unlink_checked_copies(plan, checked, expected_check_digest)


def apply(plan, expected_check_digest):
    """Refuse changes before the first unlink if any identity changed."""
    if (inventory.HEX64.fullmatch(str(expected_check_digest)) is None
            or not shutil.rmtree.avoids_symlink_attacks):
        raise ValueError('pr315-cleanup-check-digest-or-platform-invalid')
    plan = inventory._plan(plan)
    lease = inventory.TASK / 'workload-suite.lock'
    inventory._regular(lease, inventory.OWNER_UID)
    descriptor = os.open(lease, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        epochs = _epochs(plan)
        checked = inventory.inspect(plan)
        if _epochs(plan) != epochs:
            raise ValueError('pr315-cleanup-copy-epoch-changed')
        if (hashlib.sha256(inventory._canonical(checked)).hexdigest()
                != expected_check_digest):
            raise ValueError('pr315-cleanup-check-changed')
        payload = inventory._canonical({'plan': plan, 'checked': checked,
            'checkDigest': expected_check_digest, 'epochs': epochs})
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('pr315-cleanup-storage-payload-too-large')
        result = subprocess.run(['/usr/bin/perl', '-e', PVE_GUARD, '--',
            '/usr/bin/python3', str(Path(__file__).resolve()), str(descriptor)],
            input=payload, capture_output=True, check=True, timeout=1200,
            pass_fds=(descriptor,), env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                        'LC_ALL': 'C.UTF-8'})
        if len(result.stdout) > MAX_PAYLOAD:
            raise ValueError('pr315-cleanup-storage-output-too-large')
        completed = json.loads(result.stdout)
        if completed != _completion(plan, checked, expected_check_digest):
            raise ValueError('pr315-cleanup-storage-completion-invalid')
        return completed
    finally:
        os.close(descriptor)


def _unlink_checked_copies(plan, checked, expected_check_digest):
    if (hashlib.sha256(inventory._canonical(checked)).hexdigest()
            != expected_check_digest):
        raise ValueError('pr315-cleanup-check-changed')
    base = inventory.TASK / plan['suite'] / 'attempt-01'
    for name in inventory.FILES:
        info = (base / name).lstat()
        selected = checked['files'][name]
        if (info.st_dev, info.st_ino) != (selected['device'],
                                          selected['inode']):
            raise ValueError('pr315-cleanup-file-replaced')
    for name in inventory.DIRECTORIES:
        info = (base / name).lstat()
        selected = checked['directories'][name]
        if (info.st_dev, info.st_ino) != (selected['device'],
                                          selected['inode']):
            raise ValueError('pr315-cleanup-directory-replaced')
    for name in inventory.FILES:
        (base / name).unlink()
    for name in inventory.DIRECTORIES:
        shutil.rmtree(base / name)
    descriptor = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _completion(plan, checked, expected_check_digest)


def _completion(plan, checked, expected_check_digest):
    return {**checked, 'checkDigest': expected_check_digest,
            'release': ('completed-remote-preparation-duplicates-only'
                if plan['kind'] == 'pr315-host-preparation-copy-release-plan-v1'
                else 'completed-remote-success-duplicates-only')}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == [WORKER]:
        raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
        if len(raw) > MAX_PAYLOAD:
            raise SystemExit('pr315-cleanup-storage-payload-too-large')
        request = json.loads(raw)
        if set(request) != {'plan', 'checked', 'checkDigest', 'epochs', 'guard'}:
            raise SystemExit('pr315-cleanup-storage-payload-invalid')
        plan = inventory._plan(request['plan'])
        completed = _guarded_release(plan, request['checked'], request['checkDigest'],
            request['epochs'], request['guard'])
        print(json.dumps(completed, sort_keys=True))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--check-digest', required=True)
    args = parser.parse_args(argv)
    if (inventory.SUITE.fullmatch(args.suite) is None
            or inventory.HEX40.fullmatch(args.source_commit) is None):
        raise SystemExit('pr315-cleanup-selection-invalid')
    root = inventory.TASK / 'host-release'
    info = inventory._directory(root, 0)
    if info.st_mode & 0o077:
        raise SystemExit('pr315-cleanup-plan-root-not-private')
    plan_path = root / (args.suite + '.plan.private.json')
    inventory._regular(plan_path, 0, 16384)
    plan = inventory._plan(json.loads(plan_path.read_bytes()))
    if (plan['suite'] != args.suite
            or plan['sourceCommit'] != args.source_commit):
        raise SystemExit('pr315-cleanup-selection-invalid')
    print(json.dumps(apply(plan, args.check_digest), sort_keys=True))


if __name__ == '__main__':
    main()
