"""One source-pinned browser collector in the selected daemon network namespace.

Only the root test kit invokes this helper. Provider paths, role, collector and
protocol are fixed; the observer supplies only a bound existing app credential.
Provider qualification is a private original input, not a new approval authority.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[3]
PRODUCT = Path('/opt/cryptad-cross-version/current') if ROOT == Path('/opt/cryptad-restricted-test-kit') else ROOT
sys.path[:0] = [str(path) for path in (
    PRODUCT / 'tools/release-certification/protected',
    ROOT / 'tools/release-certification/restricted',
    PRODUCT / 'tools/release-certification/restricted',
    PRODUCT / 'tools/release-certification',
    PRODUCT / 'tools/interop')]
import pr320_privacy_contract as contract
import pr319_restart_admin as historical
from bounded_process import run
from cryptad_certification.io import read_json_bytes
from cryptad_certification.certification_public_export import _open_directory

PROVIDER_ROOT = Path('/opt/cryptad-privacy-browser')
NODE = PROVIDER_ROOT / 'bin/node'
CHROMIUM = PROVIDER_ROOT / 'bin/chromium'
PACKAGE = PROVIDER_ROOT / 'lib/node_modules'
COLLECTOR = PRODUCT / 'tools/interop/pr320_installed_privacy_browser.cjs'
ROLE = 'candidate-sender'
BROWSER_FILE = 'pr320-privacy-browser.private.json'


def _need(condition):
    if not condition:
        raise ValueError('pr320-privacy-browser-invalid')


def _private_file(path, maximum, *, owner=None, allow_empty=False):
    parent = _open_directory(Path(path).absolute().parent)
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                  and (owner is None or info.st_uid == owner) and not info.st_mode & 0o022
                  and (0 if allow_empty else 1) <= info.st_size <= maximum)
            raw = bytearray()
            while len(raw) <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(fd)
            _need(len(raw) == info.st_size and len(raw) <= maximum and all(getattr(info, key) == getattr(after, key)
                for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
            return bytes(raw)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _file_digest(path):
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                  and not info.st_mode & 0o022 and 0 < info.st_size <= 512 * 1024 * 1024)
            digest, total = hashlib.sha256(), 0
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                total += len(block)
                _need(total <= 512 * 1024 * 1024)
                digest.update(block)
            after = os.fstat(fd)
            _need(total == info.st_size and all(getattr(info, key) == getattr(after, key)
                for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
            return 'sha256:' + digest.hexdigest(), total
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _package_digest():
    _need(PACKAGE.is_dir() and not PACKAGE.is_symlink())
    rows, total = [], 0
    for visited, path in enumerate(PACKAGE.rglob('*')):
        _need(visited < 10000 and len(path.relative_to(PACKAGE).parts) <= 16)
        info = path.lstat()
        _need(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
        if stat.S_ISDIR(info.st_mode):
            continue
        _need(stat.S_ISREG(info.st_mode) and len(rows) < 10000)
        digest, size = _file_digest(path)
        total += size
        _need(total <= 512 * 1024 * 1024)
        rows.append({'path': path.relative_to(PACKAGE).as_posix(), 'digest': digest, 'size': size})
    _need(rows and (PACKAGE / 'playwright/package.json').is_file()
          and (PACKAGE / 'playwright-core/package.json').is_file())
    return contract.canonical_digest(sorted(rows, key=lambda row: row['path']))


def verify_provider(selected):
    _need(contract.valid_browser_provider(selected))
    declaration = read_json_bytes(_private_file(PROVIDER_ROOT / 'provider.private.json', 65536, owner=0),
                                  'privacy-browser-provider')
    _need(declaration == selected and _file_digest(NODE)[0] == selected['nodeDigest']
          and _file_digest(CHROMIUM)[0] == selected['chromiumDigest']
          and _package_digest() == selected['packageDigest'])
    return declaration


def _packaged_script_digest(workload):
    path = workload.ROOT / 'roles' / ROLE / 'package/lib/cryptad.jar'
    parent = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            _need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                  and not before.st_mode & 0o022 and 0 < before.st_size <= 512 * 1024 * 1024)
            try:
                with zipfile.ZipFile(stream) as archive:
                    member = 'network/crypta/platform/webshell/static/web-shell.js'
                    names = archive.namelist()
                    _need(len(names) <= 100000 and names.count(member) == 1)
                    info = archive.getinfo(member)
                    _need(0 < info.file_size <= 512 * 1024 and info.compress_size <= 512 * 1024)
                    raw = archive.read(member)
            except (zipfile.BadZipFile, KeyError):
                raise ValueError('pr320-privacy-browser-product-invalid') from None
            after = os.fstat(stream.fileno())
            _need(all(getattr(before, key) == getattr(after, key) for key in
                      ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
            return 'sha256:' + hashlib.sha256(raw).hexdigest()
    finally:
        os.close(parent)


def _selected(workload):
    selected = workload.read(workload.ROOT / 'selection.json')
    _need(contract.verify_selection_contract(selected['plan'], selected['private'], selected['authorization']))
    return selected


def _validate_context(workload, record, supplied):
    _need(isinstance(supplied, dict) and set(supplied) == {'appOrigin', 'appSession'}
          and isinstance(supplied['appSession'], str) and 16 <= len(supplied['appSession']) <= 4096)
    original = workload.read(workload.ROOT / 'authority' /
        ('candidate-sender-budget-bootstrap-' + record['generation'] + '.json'))
    app = original['apps']['feed-reader']
    _need(contract.canonical_digest(supplied['appOrigin']) == app['originDigest']
          and contract.canonical_digest(supplied['appSession']) == app['sessionDigest'])
    return supplied


def collect_browser(workload, campaign, record, user, context):
    selected = _selected(workload)
    context = _validate_context(workload, record, context)
    provider = verify_provider(selected['authorization']['browserProvider'])
    daemon, pidfd = historical._daemon(workload, record)
    os.close(pidfd)
    started = time.monotonic_ns()
    diagnostics = []

    def sink(stdout, stderr):
        # Bounded original bytes remain private even when the collector fails.
        diagnostics.append({'stdout': stdout.decode('utf-8', errors='strict'),
                            'stderr': stderr.decode('utf-8', errors='strict')})

    def bind(pid):
        # The trusted helper's PID comes directly from Popen; no observer PID selector exists.
        with (workload.group(ROLE) / 'cgroup.procs').open('w') as stream:
            stream.write(str(pid))

    try:
        from pr320_privacy_admin import FixedPrivacyCollector
        proof = FixedPrivacyCollector(workload, record['handle'])
        app_binding, _runtime = proof._worker('feed-reader', context)
        bootstrap = workload.read(workload.ROOT / 'authority' /
            ('candidate-sender-budget-bootstrap-' + record['generation'] + '.json'))
        _need(contract.canonical_digest(app_binding['worker']) == bootstrap['apps']['feed-reader']['workerEpochDigest']
              and contract.canonical_digest(app_binding['daemon']) == bootstrap['apps']['feed-reader']['daemonEpochDigest'])
        raw = run(['/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), '--child'],
            environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            payload=json.dumps({'browserContext': context, 'daemon': daemon}, separators=(',', ':')).encode(),
            timeout=min(60, campaign['deadlineMonotonicNs'] / 1e9 - time.monotonic()),
            output_limit=2 * 1024 * 1024, start_observer=bind, diagnostic_sink=sink)
        component = read_json_bytes(raw, 'privacy-browser-original')
        current_binding, _runtime = proof._worker('feed-reader', context)
        _need(current_binding == app_binding)
        script_digest = _packaged_script_digest(workload)
        _need(component.get('kind') == 'composed-budget-installed-browser-component'
              and component.get('scriptDigest') == script_digest)
    except BaseException:
        # Keep bounded original output on parse/source failure as well as process failure.
        from pr320_privacy_admin import _write_root
        _write_root(workload, 'pr320-privacy-browser-failure.json',
                    {'status': 'collector-failed', 'diagnostics': diagnostics})
        raise
    receipt = {'schemaVersion': 1, 'kind': 'pr320-original-browser-observation',
        'selectionDigest': campaign['budgetSelectionDigest'], 'generation': record['generation'],
        'managerInvocation': record['managerInvocation'], 'bootId': record['bootId'],
        'daemon': daemon, 'provider': provider, 'component': component, 'appBinding': app_binding,
        'appOrigin': context['appOrigin'],
        'packagedScriptDigest': script_digest,
        'collectorOutput': diagnostics,
        'startedMonotonicNs': started, 'finishedMonotonicNs': time.monotonic_ns(),
        'collectorDigest': 'sha256:' + hashlib.sha256(_private_file(COLLECTOR, 65536)).hexdigest()}
    from pr320_privacy_admin import _write_root
    _write_root(workload, 'pr320-privacy-browser-original.json', receipt)
    return receipt


def child():
    """Join the fixed selected role and drop privilege before replacing this process with Node."""
    _need(os.geteuid() == 0 and hasattr(os, 'setns'))
    import restricted_workload as workload
    request = read_json_bytes(sys.stdin.buffer.read(8193), 'privacy-browser-command')
    _need(isinstance(request, dict) and set(request) == {'browserContext', 'daemon'})
    selected = _selected(workload)
    campaign = workload.read(workload.ROOT / 'campaign.json')
    _need(campaign.get('executionClass') == contract.EXECUTION_CLASS)
    record = workload.read(workload.ROOT / 'authority/candidate-sender.json')
    workload.admit(campaign)
    workload.exact(ROLE, record, workload.manager(ROLE, 'show'))
    context = _validate_context(workload, record, request['browserContext'])
    verify_provider(selected['authorization']['browserProvider'])
    # The parent derived this identity before binding our root helper to the role
    # cgroup. Revalidate that exact daemon rather than enumerating the helper itself.
    daemon = request['daemon']
    user = workload.account(ROLE)
    current = workload._process(daemon['hostPid'], ROLE, user.pw_uid)
    _need(all(current[key] == daemon[key] for key in
              ('hostPid', 'startTicks', 'executableDigest', 'networkNamespaceIdentity')))
    launch = workload.read(workload.ROOT / 'roles' / ROLE / 'launch.json')
    _need(current['executableDigest'] == launch['javaDigest'])
    pidfd = os.pidfd_open(daemon['hostPid'])
    namespace = os.open('/proc/' + str(daemon['hostPid']) + '/ns/net', os.O_RDONLY)
    try:
        info = os.fstat(namespace)
        _need((info.st_dev, info.st_ino) == tuple(daemon['networkNamespaceIdentity']))
        os.setns(namespace, os.CLONE_NEWNET)
    finally:
        os.close(namespace)
        os.close(pidfd)
    private_root = Path(selected['private']['root'])
    _need(private_root == Path('/var/lib/cryptad-cross-version/experiments') / contract.EXPERIMENT)
    native_raw = _private_file(private_root / contract.PRIVATE_FILE, 4 * 1024 * 1024)
    from pr320_privacy_runtime_evidence import decode_private
    native = decode_private(native_raw)
    payload = {'base': 'http://127.0.0.1:19402', **context,
        'nativeMemberDigest': 'sha256:' + hashlib.sha256(native_raw).hexdigest(),
        'stimuli': [row['marker'] for row in native['component']['stimuli']]}
    temporary = workload.ROOT / 'state' / ROLE / 'tmp'
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    # Stdin is a newly owned bounded pipe. No credential enters argv or ordinary logs.
    read_end, write_end = os.pipe()
    encoded = json.dumps(payload, separators=(',', ':')).encode()
    _need(len(encoded) <= 8192)
    os.write(write_end, encoded)
    os.close(write_end)
    os.dup2(read_end, 0)
    os.close(read_end)
    os.execve(str(NODE), [str(NODE), str(COLLECTOR)], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
        'TMPDIR': str(temporary)})


def main():
    try:
        _need(sys.argv[1:] == ['--child'])
        child()
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt):
        sys.stderr.write('installed-privacy-browser-failed\n')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
