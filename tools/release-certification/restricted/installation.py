#!/usr/bin/python3
"""Administrator-only immutable installation; plan and verify never provision a host.

The approved dependency inventory is a host/image identity, not a sandbox proof. Administrators
must provision the dedicated image outside evaluated jobs and review its complete package closure.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

PREFIX = Path('/opt/cryptad-cross-version')
STATE = Path('/var/lib/cryptad-restricted')
APPROVAL = Path('/etc/cryptad-certification/restricted-installation.json')
EXECUTION = Path('/etc/cryptad-certification/restricted-execution.json')
MANIFEST = '.restricted-manifest.json'
MAX_FILE = 512 * 1024 * 1024
DEPENDENCY_ROOTS = ('/usr/lib/python3.13', '/usr/lib/x86_64-linux-gnu', '/usr/lib64')
DEPENDENCY_FILES = ('/usr/bin/python3', '/usr/bin/python3.13', '/usr/bin/openssl',
                    '/usr/bin/bwrap', '/usr/bin/prlimit', '/usr/bin/gh', '/usr/bin/git',
                    '/usr/bin/systemd-sysusers', '/usr/bin/systemd-tmpfiles',
                    '/usr/bin/systemctl', '/usr/bin/sudo', '/usr/bin/setpriv', '/usr/bin/true', '/usr/lib/systemd/systemd',
                    '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ssl/certs/ca-certificates.crt',
                    '/usr/lib/ssl/openssl.cnf', '/etc/ssl/openssl.cnf')
# Go crypto/x509 Linux system roots: first available file plus all certificate directories.
TLS_ROOT_PATHS = ('/etc/ssl/certs', '/etc/pki/tls/certs',
    '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/ca-bundle.pem', '/etc/pki/tls/cacert.pem',
    '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', '/etc/ssl/cert.pem')


class InstallationError(ValueError):
    """Closed installation diagnostic."""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    if path.stat().st_size > 32 * 1024 * 1024:
        raise InstallationError('restricted-manifest-too-large')
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise InstallationError('restricted-duplicate-field')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(InstallationError('restricted-json-invalid')))


def secured(path, *, private=False):
    """Reject writable or linked installation components, including ancestors."""
    path = Path(path)
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallationError('restricted-installation-not-root-owned')
    if private and path.stat().st_mode & 0o077:
        raise InstallationError('restricted-approval-not-private')
    return path


def file_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise InstallationError('restricted-bundle-file-invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallationError('restricted-bundle-file-changed')
        return {'sha256': value, 'size': before.st_size, 'executable': bool(before.st_mode & 0o111)}
    finally:
        os.close(fd)


def inventory(root, *, protected=False):
    root = Path(root)
    result = {}
    if root.is_symlink() or not root.is_dir():
        raise InstallationError('restricted-bundle-root-invalid')
    for directory, names, files in os.walk(root, followlinks=False):
        current = Path(directory)
        if protected:
            secured(current)
        for name in names:
            if (current / name).is_symlink():
                raise InstallationError('restricted-bundle-link')
        for name in sorted(files):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            if protected:
                secured(path)
            result[relative] = file_record(path)
            if len(result) > 100000:
                raise InstallationError('restricted-bundle-too-many-files')
    return result


def plan(source, output):
    """Export a pinned committed Git tree for subsequent separate approval."""
    source, output = Path(source).resolve(), Path(output).absolute()
    if output.exists() or output.is_relative_to(source):
        raise InstallationError('restricted-plan-output-must-be-new-external-directory')
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'GIT_NO_REPLACE_OBJECTS': '1'}
    status = subprocess.run(['/usr/bin/git', 'status', '--porcelain', '--untracked-files=normal'],
                            cwd=source, env=environment, check=True, capture_output=True)
    if status.stdout:
        raise InstallationError('restricted-plan-exact-committed-source-required')
    revision = subprocess.run(['/usr/bin/git', 'rev-parse', '--verify', 'HEAD^{commit}'], cwd=source,
                              env=environment, check=True, capture_output=True).stdout.decode().strip()
    if re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', revision) is None:
        raise InstallationError('restricted-source-revision-invalid')
    files = subprocess.run(['/usr/bin/git', 'ls-tree', '-r', '-z', '-l', '--full-tree', revision],
                           cwd=source, env=environment, check=True, capture_output=True).stdout.split(b'\0')
    output.mkdir(mode=0o700)
    try:
        export_blobs(source, output, files, environment)
        manifest = {'schemaVersion': 1, 'kind': 'cryptad-restricted-installation',
                    'sourceCommit': revision, 'files': inventory(output)}
        (output / MANIFEST).write_bytes(encode(manifest))
        return {'bundleIdentity': digest(encode(manifest)), 'sourceCommit': revision,
                'fileCount': len(manifest['files']), 'status': 'prepared-not-approved'}
    except BaseException:
        shutil.rmtree(output)
        raise


def export_blobs(source, output, files, environment):
    """Read raw blobs without checkout filters, attributes, index flags or replacement objects."""
    with subprocess.Popen(['/usr/bin/git', 'cat-file', '--batch'], cwd=source, env=environment,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            count = 0
            for item in files:
                if not item:
                    continue
                count += 1
                metadata, name = item.split(b'\t', 1)
                mode, kind, oid, size_bytes = metadata.split()
                size = int(size_bytes) if size_bytes.isdigit() else -1
                relative = Path(os.fsdecode(name))
                if (count > 100000 or mode not in (b'100644', b'100755') or kind != b'blob'
                        or not 0 <= size <= MAX_FILE or relative.is_absolute()
                        or '..' in relative.parts or relative.as_posix() == MANIFEST
                        or re.fullmatch(b'[0-9a-f]{40}|[0-9a-f]{64}', oid) is None):
                    raise InstallationError('restricted-source-entry-invalid')
                process.stdin.write(oid + b'\n')
                process.stdin.flush()
                header = process.stdout.readline(256)
                if header != oid + b' blob ' + str(size).encode() + b'\n':
                    raise InstallationError('restricted-source-object-invalid')
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                checksum = hashlib.new('sha1' if len(oid) == 40 else 'sha256')
                checksum.update(b'blob ' + str(size).encode() + b'\0')
                remaining = size
                with target.open('xb') as stream:
                    while remaining:
                        block = process.stdout.read(min(remaining, 1024 * 1024))
                        if not block:
                            raise InstallationError('restricted-source-object-truncated')
                        stream.write(block)
                        checksum.update(block)
                        remaining -= len(block)
                if process.stdout.read(1) != b'\n' or checksum.hexdigest().encode() != oid:
                    raise InstallationError('restricted-source-object-substituted')
                target.chmod(0o555 if mode == b'100755' else 0o444)
            process.stdin.close()
            if process.wait(timeout=30) != 0:
                raise InstallationError('restricted-source-export-failed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)


def verify_bundle(bundle, expected, *, protected=True):
    if protected:
        secured(bundle / MANIFEST)
    raw = (bundle / MANIFEST).read_bytes()
    if digest(raw) != expected:
        raise InstallationError('restricted-bundle-identity-mismatch')
    manifest = read_json(bundle / MANIFEST)
    if (set(manifest) != {'schemaVersion', 'kind', 'sourceCommit', 'files'}
            or manifest['schemaVersion'] != 1 or manifest['kind'] != 'cryptad-restricted-installation'
            or inventory(bundle, protected=protected) != manifest['files']):
        raise InstallationError('restricted-bundle-content-mismatch')
    return manifest


def dependencies(config):
    """Check every administrator-approved image dependency before sensitive imports.

    Distro symlinks bind both link bytes and their resolved file/target. Python user/site startup
    is disabled by -I -S; link targets remain part of the administrator-approved dependency map.
    """
    records = config['dependencies']
    if not isinstance(records, dict) or not records:
        raise InstallationError('restricted-dependencies-missing')
    if not set(DEPENDENCY_FILES) <= records.keys():
        raise InstallationError('restricted-dependency-closure-incomplete')
    if not any(name.startswith('/usr/lib/python3.13/') for name in records):
        raise InstallationError('restricted-python-closure-missing')
    if not any('/ld-linux-' in name for name in records):
        raise InstallationError('restricted-loader-closure-missing')
    if dependency_inventory() != records:
        raise InstallationError('restricted-dependency-closure-changed')


def dependency_inventory():
    """Read-only full reference runtime closure, including additions and fixed distro links."""
    records = {}
    def add(path):
        name = str(path)
        if name in records:
            return
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode):
            raise InstallationError('restricted-image-dependency-writable')
        secured(path.parent)
        if stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            secured(target)
            records[name] = {'link': os.readlink(path), 'target': str(target)}
            add(target)
        elif path.is_dir():
            records[name] = {'directory': True}
            for entry in sorted(path.iterdir()):
                add(entry)
        else:
            records[name] = file_record(path)
    for name in (*DEPENDENCY_ROOTS, *DEPENDENCY_FILES):
        add(Path(name))
    for name in TLS_ROOT_PATHS:
        path = Path(name)
        try:
            path.lstat()
        except FileNotFoundError:
            records[name] = {'absent': True}
        else:
            add(path)
    # A loader hook is privileged code. The supported reference has none.
    if Path('/etc/ld.so.preload').exists():
        raise InstallationError('restricted-loader-preload-unsupported')
    return records


def host_plan(bundle_identity):
    """Draft the exact image inventory; only out-of-band root installation confers approval."""
    return {'schemaVersion': 1, 'bundleIdentity': bundle_identity,
            'dependencies': dependency_inventory(), 'profile': 'debian13-systemd257-dedicated-v1',
            'runnerUid': 62001, 'runnerGroups': [62001, 62005], 'revokedVersions': []}


def configuration():
    config = read_json(secured(APPROVAL, private=True))
    if (set(config) != {'schemaVersion', 'bundleIdentity', 'dependencies', 'profile', 'runnerUid',
                       'runnerGroups', 'revokedVersions'}
            or config['schemaVersion'] != 1 or config['profile'] != 'debian13-systemd257-dedicated-v1'
            or type(config['runnerUid']) is not int or config['runnerUid'] <= 0
            or not isinstance(config['runnerGroups'], list)
            or not isinstance(config['revokedVersions'], list)):
        raise InstallationError('restricted-approval-invalid')
    if config['bundleIdentity'] in config['revokedVersions']:
        raise InstallationError('restricted-helper-revoked')
    history = STATE / 'revocations.json'
    if history.exists():
        retained = read_json(secured(history, private=True))
        if (not isinstance(retained, list) or not set(retained) <= set(config['revokedVersions'])
                or config['bundleIdentity'] in retained):
            raise InstallationError('restricted-security-history-rollback')
    return config


def verify_role_groups(roles, config):
    """Accept only the provisioned primary group, plus socket access for the runner."""
    import grp
    allowed = {}
    primary = set()
    control = grp.getgrnam('cryptad-control').gr_gid
    if control == 0 or any(role.pw_gid == control for role in roles):
        raise InstallationError('restricted-role-groups-unreviewed')
    for role in roles:
        own = grp.getgrnam(role.pw_name).gr_gid
        expected = {own}
        if role.pw_name == 'cryptad-runner':
            expected.add(control)
        actual = set(os.getgrouplist(role.pw_name, role.pw_gid))
        if own == 0 or role.pw_gid != own or own in primary or actual != expected or 0 in actual:
            raise InstallationError('restricted-role-groups-unreviewed')
        primary.add(own)
        if role.pw_name == 'cryptad-runner' and (
                role.pw_uid != config['runnerUid'] or sorted(actual) != sorted(config['runnerGroups'])):
            raise InstallationError('restricted-runner-identity-mismatch')
        allowed[role.pw_uid] = expected
    return allowed


def verify_role_processes(roles, allowed):
    """Reject stale group memberships and capabilities in already running role processes."""
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            status = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
        except FileNotFoundError:
            continue
        uids = [int(item) for item in status.get('Uid', '').split()]
        for role in roles:
            if role.pw_uid not in uids:
                continue
            gids = [int(item) for item in status.get('Gid', '').split()]
            groups = {int(item) for item in status.get('Groups', '').split()}
            if (len(uids) != 4 or set(uids) != {role.pw_uid} or len(gids) != 4
                    or set(gids) != {role.pw_gid} or 'Groups' not in status
                    or not groups <= allowed[role.pw_uid]):
                raise InstallationError('restricted-role-process-groups-unreviewed')
            if any(int(status.get(field, '0').strip(), 16)
                   for field in ('CapEff', 'CapPrm', 'CapAmb', 'CapInh')):
                raise InstallationError('restricted-role-process-capabilities')


def verify_profile(config):
    import pwd
    if 'VERSION_ID="13"' not in Path('/etc/os-release').read_text():
        raise InstallationError('restricted-host-profile-unsupported')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise InstallationError('restricted-systemd-required')
    version = subprocess.run(['/usr/lib/systemd/systemd', '--version'], capture_output=True,
                             env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=10, check=True)
    if not version.stdout.startswith(b'systemd 257 '):
        raise InstallationError('restricted-systemd-version-unsupported')
    runner = pwd.getpwnam('cryptad-runner')
    roles = [pwd.getpwnam(name) for name in ('cryptad-runner', 'cryptad-native', 'cryptad-workload', 'cryptad-soak')]
    if len({row.pw_uid for row in roles}) != 4 or any(row.pw_uid == 0 for row in roles):
        raise InstallationError('restricted-role-uids-not-separated')
    allowed = verify_role_groups(roles, config)
    verify_role_processes(roles, allowed)
    # sudo policy is evaluated by its actual policy engine, not by grepping one drop-in.
    probe = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', runner.pw_name],
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, capture_output=True, timeout=15)
    diagnostic = (probe.stdout + probe.stderr).decode('utf-8', errors='strict').strip()
    if (probe.returncode != 1 or re.fullmatch(
            r'User cryptad-runner is not allowed to run sudo on [A-Za-z0-9_.-]+\.', diagnostic) is None):
        raise InstallationError('restricted-runner-sudo-or-policy-unknown')
    # The reviewed reference admits no local Polkit policy extending system-service control.
    for directory in ('/etc/polkit-1/rules.d', '/etc/polkit-1/localauthority'):
        root = Path(directory)
        if root.exists() and any(path.is_file() for path in root.rglob('*')):
            raise InstallationError('restricted-local-polkit-policy-unreviewed')
    native = pwd.getpwnam('cryptad-native')
    # Exercise the mandatory kernel user/mount/PID/network namespaces after a real host UID
    # drop. The only executable is the image-pinned true binary, and no private path is mounted.
    probe = subprocess.run(['/usr/bin/setpriv', '--reuid=' + str(native.pw_uid),
        '--regid=' + str(native.pw_gid), '--clear-groups', '--no-new-privs', '--bounding-set=-all',
        '--inh-caps=-all', '--ambient-caps=-all', '--', '/usr/bin/bwrap', '--unshare-all',
        '--die-with-parent', '--new-session', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/usr/lib', '/lib', '--ro-bind', '/usr/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--chdir', '/tmp', '--', '/usr/bin/true'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=15)
    if probe.returncode != 0:
        raise InstallationError('restricted-keyless-kernel-boundary-unavailable')
    return runner


CONTROLLER_CAPABILITIES = frozenset({'cap_setuid', 'cap_setgid', 'cap_setpcap', 'cap_chown',
                                    'cap_dac_override', 'cap_fowner', 'cap_kill'})


def verify_controller_capabilities(value):
    """Require cleanup authority in the controller without admitting unrelated capabilities."""
    if not isinstance(value, str) or set(value.split()) != CONTROLLER_CAPABILITIES:
        raise InstallationError('restricted-effective-controller-capabilities-mismatch')


HOST_ASSETS = (
    ('cryptad-restricted.conf', '/usr/lib/sysusers.d/cryptad-restricted.conf'),
    ('cryptad-restricted-tmpfiles.conf', '/usr/lib/tmpfiles.d/cryptad-restricted.conf'),
    ('cryptad-restricted.service', '/etc/systemd/system/cryptad-restricted.service'),
    ('cryptad-restricted.socket', '/etc/systemd/system/cryptad-restricted.socket'),
    ('cryptad-cross-version-soak.service', '/etc/systemd/system/cryptad-cross-version-soak.service'),
)


def host_assets(bundle):
    for name, target in HOST_ASSETS:
        directory = ('tools/interop/systemd' if name == 'cryptad-cross-version-soak.service'
                     else 'tools/release-certification/restricted/systemd')
        yield bundle / directory / name, Path(target)


def verify_host_assets(bundle, *, upgrading=False):
    for source, target in host_assets(bundle):
        if secured(target).read_bytes() != source.read_bytes():
            raise InstallationError('restricted-upgrade-host-asset-replacement-required' if upgrading
                                    else 'restricted-host-asset-content-mismatch')


def verify_units():
    verify_host_assets(PREFIX / 'current')
    for name in ('cryptad-restricted.service', 'cryptad-restricted.socket', 'cryptad-cross-version-soak.service'):
        for root in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system',
                     '/etc/systemd/system.control', '/run/systemd/system.control'):
            if (Path(root) / (name + '.d')).exists():
                raise InstallationError('restricted-unit-dropin-unreviewed')
        loaded = subprocess.run(['/usr/bin/systemctl', 'show', name,
            '--property=FragmentPath,DropInPaths', '--no-pager'], check=True, capture_output=True,
            timeout=15, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        paths = dict(line.split('=', 1) for line in loaded.stdout.decode().splitlines() if '=' in line)
        if paths != {'FragmentPath': '/etc/systemd/system/' + name, 'DropInPaths': ''}:
            raise InstallationError('restricted-unit-load-path-unreviewed')
    result = subprocess.run(['/usr/bin/systemctl', 'show', 'cryptad-restricted.service',
        '--property=User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,LimitCORE,FragmentPath,CapabilityBoundingSet',
        '--no-pager'], check=True, capture_output=True, timeout=15,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    properties = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
    verify_controller_capabilities(properties.pop('CapabilityBoundingSet', None))
    expected = {'User': 'root', 'Group': 'root', 'NoNewPrivileges': 'yes', 'ProtectSystem': 'strict',
                'ProtectHome': 'yes', 'PrivateTmp': 'yes', 'PrivateDevices': 'yes', 'LimitCORE': '0',
                'FragmentPath': '/etc/systemd/system/cryptad-restricted.service'}
    if properties != expected:
        raise InstallationError('restricted-effective-unit-mismatch')


def verify():
    config = configuration()
    manifest = verify_bundle(PREFIX / 'current', config['bundleIdentity'])
    required_entrypoints(manifest)
    verify_bundle(PREFIX / 'versions' / config['bundleIdentity'], config['bundleIdentity'])
    dependencies(config)
    verify_profile(config)
    verify_units()
    return {'bundleIdentity': config['bundleIdentity'], 'sourceCommit': manifest['sourceCommit'],
            'executionClosureDigest': 'sha256:' + digest(encode(config['dependencies'])),
            'status': 'installation-verified-no-operation-authority'}


def verify_execution(root=None):
    """Read-only public installed-source verification for the tokenless observer.

    This record contains only reviewed code/dependency identities. It grants no operation,
    selection or private credential authority; activation and original checks remain separate.
    """
    if root is not None and Path(root) != PREFIX / 'current':
        raise InstallationError('restricted-execution-root-not-fixed')
    record = read_json(secured(EXECUTION))
    if (set(record) != {'schemaVersion', 'bundleIdentity', 'sourceCommit', 'dependencies'}
            or record['schemaVersion'] != 1):
        raise InstallationError('restricted-execution-identity-invalid')
    manifest = verify_bundle(PREFIX / 'current', record['bundleIdentity'])
    if manifest['sourceCommit'] != record['sourceCommit']:
        raise InstallationError('restricted-execution-source-mismatch')
    dependencies(record)
    return {'bundleIdentity': record['bundleIdentity'], 'sourceCommit': record['sourceCommit'],
            'executionClosureDigest': 'sha256:' + digest(encode(record['dependencies']))}


def publish_execution_identity(result, config):
    """Publish only after administrator installation verification; never called by a job."""
    temporary = EXECUTION.with_name('.restricted-execution-stage')
    with temporary.open('xb') as stream:
        stream.write(encode({'schemaVersion': 1, 'bundleIdentity': result['bundleIdentity'],
                             'sourceCommit': result['sourceCommit'], 'dependencies': config['dependencies']}))
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o444)
    os.replace(temporary, EXECUTION)
    descriptor = os.open(EXECUTION.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install(bundle):
    """Explicit initial install only. Existing current/authority/history is never replaced."""
    if os.geteuid() != 0:
        raise InstallationError('restricted-administrator-required')
    config = configuration()
    bundle = Path(bundle).resolve()
    required_entrypoints(verify_bundle(bundle, config['bundleIdentity'], protected=False))
    dependencies(config)
    if (PREFIX / 'current').exists() or (PREFIX / 'current').is_symlink():
        raise InstallationError('restricted-existing-installation-requires-reviewed-upgrade')
    PREFIX.mkdir(parents=True, exist_ok=True, mode=0o755)
    secured(PREFIX)
    with (PREFIX / '.install.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (PREFIX / 'current').exists():
            raise InstallationError('restricted-installation-already-active')
        versions = PREFIX / 'versions'
        versions.mkdir(exist_ok=True, mode=0o755)
        secured(versions)
        destination = versions / config['bundleIdentity']
        if destination.exists():
            verify_bundle(destination, config['bundleIdentity'])
        else:
            staged = Path(tempfile.mkdtemp(prefix='.stage-', dir=versions))
            shutil.copytree(bundle, staged, dirs_exist_ok=True)
            for directory, _, files in os.walk(staged):
                Path(directory).chmod(0o755)
                for name in files:
                    path = Path(directory) / name
                    path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
            verify_bundle(staged, config['bundleIdentity'])
            os.rename(staged, destination)
        for source, path in host_assets(destination):
            if path.exists():
                raise InstallationError('restricted-existing-host-asset-requires-review')
            secured(path.parent)
            with path.open('xb') as stream:
                stream.write(source.read_bytes())
            path.chmod(0o644)
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        for command in (['/usr/bin/systemd-sysusers', '/usr/lib/sysusers.d/cryptad-restricted.conf'],
                        ['/usr/bin/systemd-tmpfiles', '--create', '/usr/lib/tmpfiles.d/cryptad-restricted.conf']):
            subprocess.run(command, check=True, env=environment, timeout=30)
        revocations = STATE / 'revocations.json'
        if not revocations.exists():
            with revocations.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(encode(config['revokedVersions']))
                stream.flush()
                os.fsync(stream.fileno())
        verify_profile(config)
        staged_current = PREFIX / '.current-stage'
        shutil.copytree(destination, staged_current)
        verify_bundle(staged_current, config['bundleIdentity'])
        os.rename(staged_current, PREFIX / 'current')
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, env=environment, timeout=30)
        result = verify()
        publish_execution_identity(result, config)
        return result


def require_stopped_units(environment):
    """Socket state has no MainPID; services must additionally have no remaining main process."""
    for unit in ('cryptad-restricted.socket', 'cryptad-restricted.service', 'cryptad-cross-version-soak.service'):
        expected = {'ActiveState': 'inactive', 'SubState': 'dead'}
        if unit.endswith('.service'):
            expected['MainPID'] = '0'
        observed = subprocess.run(['/usr/bin/systemctl', 'show', unit,
            '--property=' + ','.join(expected), '--no-pager'], check=True,
            capture_output=True, env=environment, timeout=15)
        fields = dict(line.split('=', 1) for line in observed.stdout.decode().splitlines() if '=' in line)
        if fields != expected:
            raise InstallationError('restricted-upgrade-services-not-stopped')


def upgrade(bundle):
    """Activate a separately approved version only after all fixed services are stopped.

    This is a security upgrade: the previous helper is durably revoked before activation. It
    cannot resume old operations. Old version trees, journals, approval and public records remain.
    """
    if os.geteuid() != 0:
        raise InstallationError('restricted-administrator-required')
    config = configuration()
    dependencies(config)
    verify_profile(config)
    bundle = Path(bundle).resolve()
    required_entrypoints(verify_bundle(bundle, config['bundleIdentity'], protected=False))
    old_raw = secured(PREFIX / 'current' / MANIFEST).read_bytes()
    previous = digest(old_raw)
    verify_bundle(PREFIX / 'current', previous)
    if previous == config['bundleIdentity'] or previous not in config['revokedVersions']:
        raise InstallationError('restricted-upgrade-must-revoke-previous-version')
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C'}
    with secured(PREFIX / '.install.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_stopped_units(environment)
        if digest((PREFIX / 'current' / MANIFEST).read_bytes()) != previous:
            raise InstallationError('restricted-upgrade-current-changed')
        versions = secured(PREFIX / 'versions')
        destination = versions / config['bundleIdentity']
        if destination.exists():
            verify_bundle(destination, config['bundleIdentity'])
        else:
            stage = Path(tempfile.mkdtemp(prefix='.upgrade-', dir=versions))
            shutil.copytree(bundle, stage, dirs_exist_ok=True)
            for directory, _, files in os.walk(stage):
                Path(directory).chmod(0o755)
                for name in files:
                    path = Path(directory) / name
                    path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
            verify_bundle(stage, config['bundleIdentity'])
            os.rename(stage, destination)
        # Account, directory and unit changes require reviewed replacement while stopped.
        verify_host_assets(destination, upgrading=True)
        secured(STATE)
        history = STATE / 'revocations.json'
        temporary = STATE / '.revocations-stage'
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encode(sorted(set(config['revokedVersions']))))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, history)
        directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        stage = PREFIX / '.current-stage'
        shutil.copytree(destination, stage)
        verify_bundle(stage, config['bundleIdentity'])
        # A real current directory is retained. No service is running across this two-rename
        # administrator transaction; a crash in its gap is fail-closed and keeps both trees.
        retained = PREFIX / ('retired-current-' + previous)
        if retained.exists():
            raise InstallationError('restricted-upgrade-recovery-required')
        os.rename(PREFIX / 'current', retained)
        os.rename(stage, PREFIX / 'current')
        directory = os.open(PREFIX, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, env=environment, timeout=30)
        result = verify()
        publish_execution_identity(result, config)
        return result


def required_entrypoints(manifest):
    required = {'tools/release-certification/restricted/' + name for name in
                ('installation.py', 'bootstrap.py', 'runtime_bootstrap.py')}
    required |= {'tools/release-certification/protected/' + name for name in
                 ('restricted_worker.py', 'restricted_client.py', 'restricted_protocol.py',
                  'restricted_native.py', 'restricted_maintenance.py', 'restricted_registration.py')}
    if not required <= manifest['files'].keys():
        raise InstallationError('restricted-bundle-entrypoints-incomplete')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    prepare = sub.add_parser('plan')
    prepare.add_argument('--source', required=True, type=Path)
    prepare.add_argument('--output', required=True, type=Path)
    provision = sub.add_parser('install')
    provision.add_argument('--bundle', required=True, type=Path)
    replacement = sub.add_parser('upgrade')
    replacement.add_argument('--bundle', required=True, type=Path)
    profile = sub.add_parser('host-plan')
    profile.add_argument('--bundle-identity', required=True)
    sub.add_parser('verify')
    args = parser.parse_args()
    try:
        if args.operation == 'plan':
            result = plan(args.source, args.output)
        elif args.operation == 'host-plan':
            result = host_plan(args.bundle_identity)
        else:
            result = install(args.bundle) if args.operation == 'install' else (
                upgrade(args.bundle) if args.operation == 'upgrade' else verify())
        print(encode(result).decode())
    except (InstallationError, OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('restricted-installation-rejected') from None


if __name__ == '__main__':
    main()
