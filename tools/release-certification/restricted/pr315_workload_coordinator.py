#!/usr/bin/env python3
"""Mac-owned fixed CT102/PVE transport and per-attempt admission for PR-315.

Only a sealed host campaign may call these primitives.  The module performs no
implicit allocation when imported; its caller selects a single declared group,
checks the pinned source and capacity, then verifies and seals the archive.
"""
from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

import pr315_campaign_seal as seal
import pr315_workload_campaign as campaign

CT = 'codex@192.168.1.180'
PVE = 'root@192.168.1.200'
CT_TASK = '/work/pr315-task'
CT_LIVE_SOURCE = '/work/cryptad'
PVE_TASK = '/mnt/tank1/files/pr315-workload-acceptance'
PVE_SCRIPT = '/root/pr315-workload/source-0fa'
CAP_BYTES = 224 * 1024**3
PVE_RESERVE = 16 * 1024**3
MAC_RESERVE = 64 * 1024**3
MAC_ADDITIONAL_BUDGET = 160 * 1024**3
THIN_POOL_RESERVE = 2 * 1024**3
_SUITE = re.compile(r'suite-[1-9][0-9]*\Z')


class Remote:
    def __init__(self, known_hosts: Path):
        self.known_hosts = known_hosts
        value = known_hosts.read_bytes()
        if len(value) > 16384 or not value.strip():
            raise ValueError('pr315-fixed-host-key-pin-invalid')
        self.ssh = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(known_hosts),
            '-o', 'ConnectTimeout=5']

    def call(self, host, arguments, *, timeout=30, check=True):
        if (host not in (CT, PVE) or not isinstance(arguments, list)
                or not arguments or any(not isinstance(arg, str)
                                        for arg in arguments)):
            raise ValueError('pr315-remote-command-invalid')
        result = subprocess.run([*self.ssh, host, shlex.join(arguments)],
            stdin=subprocess.DEVNULL, capture_output=True,
            timeout=timeout)
        if len(result.stdout) > 65536 or len(result.stderr) > 4096:
            raise ValueError('pr315-remote-output-limit')
        if check and result.returncode:
            raise ValueError('pr315-remote-command-failed')
        return result


def fixed_config(value):
    fields = {'sourceCommit', 'sourceTree', 'trackedByteDigest',
        'productSelectionDigest', 'sourceSnapshot', 'campaignPlanPath',
        'fixtureManifestDigest', 'preparedImageDigest',
        'productSourceCommit', 'campaignPlanDigest', 'hostKeyFingerprint',
        'fixturePath', 'qemuRoot', 'preparedImage', 'seed', 'sshKey',
        'knownHosts', 'port'}
    if (not isinstance(value, dict) or set(value) != fields
            or any(re.fullmatch('[0-9a-f]{64}',
                str(value[name])) is None for name in (
                    'fixtureManifestDigest', 'preparedImageDigest',
                    'campaignPlanDigest', 'hostKeyFingerprint'))
            or re.fullmatch('[0-9a-f]{40}',
                str(value['sourceCommit'])) is None
            or re.fullmatch('[0-9a-f]{40}',
                str(value['sourceTree'])) is None
            or any(re.fullmatch('[0-9a-f]{64}',
                str(value[name])) is None for name in (
                    'trackedByteDigest', 'productSelectionDigest'))
            or re.fullmatch('[0-9a-f]{40}',
                str(value['productSourceCommit'])) is None
            or value['port'] != 23113
            or not value['sourceSnapshot'].startswith(
                CT_TASK + '/campaign-frozen/source-')
            or not value['campaignPlanPath'].startswith(
                CT_TASK + '/campaign-frozen/')
            or any('..' in Path(value[name]).parts for name in
                   ('sourceSnapshot', 'campaignPlanPath'))
            or any(not isinstance(value[name], str)
                or not value[name].startswith(CT_TASK + '/')
                or '..' in Path(value[name]).parts for name in (
                    'fixturePath', 'qemuRoot', 'preparedImage',
                    'seed', 'sshKey', 'knownHosts'))):
        raise ValueError('pr315-coordinator-frozen-input-invalid')
    return value


def _json_command(remote, host, argv, *, timeout=30):
    raw = remote.call(host, argv, timeout=timeout).stdout
    return json.loads(raw)


def source_preflight(remote, config):
    head = remote.call(CT, ['git', '-C', config['sourceSnapshot'],
        'rev-parse', 'HEAD']).stdout.decode().strip()
    tree = remote.call(CT, ['git', '-C', config['sourceSnapshot'],
        'rev-parse', 'HEAD^{tree}']).stdout.decode().strip()
    status = remote.call(CT, ['git', '-C', config['sourceSnapshot'],
        'status', '--porcelain', '--untracked-files=normal']).stdout
    if (head != config['sourceCommit']
            or tree != config['sourceTree'] or status):
        raise ValueError('pr315-ct-source-not-frozen')
    code = ('import sys;sys.path.insert(0,sys.argv[1]+'
        '"/tools/release-certification/restricted");'
        'import pr315_campaign_owner as o;'
        'print(o.tracked_byte_digest(sys.argv[1]))')
    raw = remote.call(CT, ['python3', '-c', code,
        config['sourceSnapshot']], timeout=60).stdout.decode().strip()
    if raw != config['trackedByteDigest']:
        raise ValueError('pr315-ct-tracked-source-bytes-changed')
    product = remote.call(CT, ['sha256sum',
        config['sourceSnapshot'] + '/build/cryptad-dist/lib/cryptad.jar'],
        timeout=30).stdout.decode().split()
    if (len(product) != 2 or product[0] !=
            config['productSelectionDigest']):
        raise ValueError('pr315-ct-product-byte-identity-changed')
    return head, tree, raw


def prepare_source_snapshot(remote, config):
    """Clone committed bytes outside Syncthing and copy only fixed product outputs."""
    snapshot = config['sourceSnapshot']
    remote.call(CT, ['git', 'clone', '--no-hardlinks', '--no-checkout',
                     CT_LIVE_SOURCE, snapshot], timeout=180)
    remote.call(CT, ['git', '-C', snapshot, 'checkout', '--detach',
                     config['sourceCommit']], timeout=60)
    for relative in ('build/cryptad-dist',
                     'platform-devtools/build/install/crypta-app',
                     'platform-api/build/libs'):
        remote.call(CT, ['mkdir', '-p', str(Path(snapshot, relative).parent)],
                    timeout=10)
        remote.call(CT, ['rsync', '-a', '--checksum',
            CT_LIVE_SOURCE + '/' + relative + '/',
            snapshot + '/' + relative + '/'], timeout=120)
    return source_preflight(remote, config)


def capacity_preflight(remote, config, mac_root, required_bytes,
                       mac_initial_available_bytes):
    if (type(required_bytes) is not int or required_bytes <= 0
            or required_bytes > 40 * 1024**3):
        raise ValueError('pr315-vm-reservation-invalid')
    raw = remote.call(PVE, ['zfs', 'list', '-Hp', '-o', 'used,avail',
        'tank1/files/pr315-workload-acceptance']).stdout.decode().split()
    if len(raw) != 2 or any(not part.isdecimal() for part in raw):
        raise ValueError('pr315-pve-storage-unavailable')
    used, free = map(int, raw)
    pools = _json_command(remote, PVE,
        ['lvs', '--reportformat', 'json', '--units', 'b', '-o',
         'vg_name,lv_name,lv_attr,lv_size,data_percent'], timeout=15)
    selected = [row for report in pools.get('report', [])
                for row in report.get('lv', [])
                if row.get('vg_name') == 'pve'
                and row.get('lv_name') == 'data'
                and str(row.get('lv_attr', '')).startswith('t')]
    if len(selected) != 1:
        raise ValueError('pr315-pve-thin-pool-unavailable')
    try:
        size = int(selected[0]['lv_size'].removesuffix('B'))
        percent = Decimal(selected[0]['data_percent'])
        thin_free = int(Decimal(size) * (Decimal(100) - percent) / 100)
    except (ValueError, TypeError, KeyError, InvalidOperation):
        raise ValueError('pr315-pve-thin-pool-invalid') from None
    if not 0 <= percent <= 100 or thin_free < THIN_POOL_RESERVE:
        raise ValueError('pr315-pve-thin-pool-reserve-unavailable')
    mac_free = os.statvfs(mac_root).f_bavail * os.statvfs(mac_root).f_frsize
    if (used + required_bytes > CAP_BYTES
            or free - required_bytes < PVE_RESERVE
            or mac_initial_available_bytes <
                MAC_RESERVE + MAC_ADDITIONAL_BUDGET
            or mac_free < MAC_RESERVE
            or mac_initial_available_bytes - mac_free >
                MAC_ADDITIONAL_BUDGET):
        raise ValueError('pr315-task-capacity-unavailable')
    return {'pveUsedBytes': used, 'pveAvailableBytes': free,
            'requiredAttemptBytes': required_bytes,
            'macAvailableBytes': mac_free,
            'thinPoolFreeBytes': thin_free}


def admit_and_watch(remote, suite, source_commit, source_snapshot):
    if _SUITE.fullmatch(suite) is None:
        raise ValueError('pr315-suite-invalid')
    if not source_snapshot.startswith(CT_TASK + '/campaign-frozen/source-'):
        raise ValueError('pr315-source-snapshot-invalid')
    published = _json_command(remote, PVE,
        ['python3', PVE_SCRIPT + '/pr315_pve_host_admission.py',
         '--suite', suite, '--source-commit', source_commit])
    if published != {'policy': 'pve-tcg-swap-admission-v1',
                     'admitted': True, 'reason': None}:
        raise ValueError('pr315-pve-admission-rejected')
    # The PVE watcher publishes its ready receipt before this returns.
    command = ('nohup /usr/bin/python3 '
        + shlex.quote(PVE_SCRIPT + '/pr315_pve_pressure_watch.py')
        + ' --suite ' + shlex.quote(suite)
        + ' --source-commit ' + shlex.quote(source_commit)
        + ' > ' + shlex.quote('/root/pr315-workload/' + suite + '-watch.private.log')
        + ' 2>&1 < /dev/null &')
    remote.call(PVE, ['sh', '-c', command], timeout=10)
    ready = _json_command(remote, CT,
        ['python3', '-c',
         'import sys,json;sys.path.insert(0,sys.argv[3]+"/tools/release-certification/restricted");'
         'import pr315_pve_pressure_watch as w;print(json.dumps(w.wait_ready(sys.argv[1],sys.argv[2])))',
         suite, source_commit, source_snapshot], timeout=15)
    if ready.get('suite') != suite or ready.get('sourceCommit') != source_commit:
        raise ValueError('pr315-pve-watcher-not-ready')
    return ready


def runner_arguments(config, suite, group_id, *, retired_prep=False,
                     retired_files=None):
    if (_SUITE.fullmatch(suite) is None
            or group_id not in dict(campaign.GROUPS)):
        raise ValueError('pr315-selected-group-invalid')
    path = CT_TASK + '/' + suite
    base = ['python3', config['sourceSnapshot'] + '/tools/release-certification/restricted/'
            'pr315_workload_runner.py',
        '--source', config['sourceSnapshot'], '--output', path,
        '--storage-root', CT_TASK,
        '--prepared-fixtures', config['fixturePath'],
        '--prepared-image', config['preparedImage'],
        '--qemu-root', config['qemuRoot'], '--seed', config['seed'],
        '--ssh-key', config['sshKey'], '--known-hosts', config['knownHosts'],
        '--product-source-commit', config['productSourceCommit'],
        '--prepared-image-digest', config['preparedImageDigest'],
        '--fixture-manifest-digest', config['fixtureManifestDigest'],
        '--storage-budget-bytes', str(CAP_BYTES),
        '--min-free-bytes', str(PVE_RESERVE),
        '--memory-budget-bytes', str(7 * 1024**3),
        '--min-host-memory-bytes', str(1024**3),
        '--profile', 'tcg-multi',
        '--host-memory-policy', 'pve-tcg-swap-admission-v1',
        '--port', str(config['port']), '--timeout', '4200',
        '--host-key-pin-origin', 'preselected-host-key',
        '--campaign-plan', config['campaignPlanPath'],
        '--campaign-key-fingerprint', config['hostKeyFingerprint']]
    if retired_prep:
        if group_id != 'authority':
            raise ValueError('pr315-retired-prep-group-invalid')
        base.extend(('--role-readiness-measurement',
                     '--retired-authority-preparation'))
    else:
        base.extend(('--case-group', group_id))
    if retired_files is not None:
        if group_id != 'authority' or len(retired_files) != 3:
            raise ValueError('pr315-retired-input-invalid')
        for option, path in zip(('--retired-authority-input',
                '--retired-authority-handoff', '--campaign-public-key'),
                retired_files):
            if not path.startswith(CT_TASK + '/campaign-frozen/'):
                raise ValueError('pr315-retired-path-unpinned')
            base.extend((option, path))
    return base


_REQUIRED_CODE = (
    'import sys;from pathlib import Path;from types import SimpleNamespace;'
    'source=Path(sys.argv[1]);sys.path.insert(0,str(source/"tools/release-certification/restricted"));'
    'import pr313_acceptance_runner as a;'
    'x=SimpleNamespace(source=source,prepared_image=Path(sys.argv[2]),'
    'prepared_fixtures=Path(sys.argv[3]),qemu_root=Path(sys.argv[4]),'
    'seed=Path(sys.argv[5]),ssh_key=Path(sys.argv[6]),'
    'known_hosts=Path(sys.argv[7]));print(a.required_attempt_bytes(x))')


def required_attempt_bytes(remote, config):
    raw = remote.call(CT, ['python3', '-c', _REQUIRED_CODE,
        config['sourceSnapshot'], config['preparedImage'],
        config['fixturePath'], config['qemuRoot'], config['seed'],
        config['sshKey'], config['knownHosts']], timeout=60).stdout.decode().strip()
    if not raw.isdecimal():
        raise ValueError('pr315-attempt-reservation-unavailable')
    return int(raw)


def run_selected_attempt(remote, config, suite, group_id, *,
                         retired_prep=False, retired_files=None):
    """One CT runner only; the caller separately verifies, archives and seals."""
    command = runner_arguments(config, suite, group_id,
        retired_prep=retired_prep, retired_files=retired_files)
    completed = remote.call(CT, command, timeout=4500, check=False)
    if completed.returncode not in (0, 2, 78):
        raise ValueError('pr315-ct-runner-unexpected-exit')
    assessment_path = CT_TASK + '/' + suite + '/assessment.json'
    observed = remote.call(CT, ['cat', assessment_path], timeout=10,
                           check=False)
    if observed.returncode != 0 or len(observed.stdout) > 65536:
        raise ValueError('pr315-ct-assessment-unavailable')
    assessment = json.loads(observed.stdout)
    if (assessment.get('schemaVersion') != 2
            or assessment.get('campaignPlanDigest') !=
                config['campaignPlanDigest']
            or assessment.get('installedWorkloadAcceptanceSatisfied') is not False):
        raise ValueError('pr315-ct-partial-assessment-invalid')
    return {'runnerExitCode': completed.returncode,
            'assessment': assessment}


_FINISHED_CODE = (
    'import sys,json;sys.path.insert(0,sys.argv[4]+"/tools/release-certification/restricted");'
    'import pr315_pve_pressure_watch as w;'
    'ready=json.loads(sys.argv[3]);'
    'print(json.dumps(w.verify_finished(sys.argv[1],sys.argv[2],ready)))')


def finished_watcher(remote, config, suite, ready):
    """Recheck the root-owned watcher receipt through CT102 after QEMU stops."""
    until = time.monotonic() + 30
    while True:
        result = remote.call(CT, ['python3', '-c', _FINISHED_CODE,
            suite, config['sourceCommit'],
            json.dumps(ready, sort_keys=True, separators=(',', ':')),
            config['sourceSnapshot']], timeout=10, check=False)
        if result.returncode == 0:
            record = json.loads(result.stdout)
            if (record.get('suite') == suite
                    and record.get('sourceCommit') == config['sourceCommit']
                    and record.get('action') == 'completed'
                    and record.get('seenTaskQemu') is True):
                return record
        if time.monotonic() >= until:
            raise ValueError('pr315-pve-watcher-incomplete')
        time.sleep(.25)


_PVE_STOP_CODE = '''import json,sys,time
from pathlib import Path
task=Path("/mnt/tank1/files/pr315-workload-acceptance")
suite,source=sys.argv[1:3]
finished=json.loads((task/"host-monitor"/(suite+".finished.json")).read_text())
if finished.get("suite")!=suite or finished.get("sourceCommit")!=source or finished.get("action")!="completed" or finished.get("seenTaskQemu") is not True:
 raise RuntimeError("watcher-not-completed")
root=str(task/suite/"attempt-01").encode(); processes=[]
for entry in Path("/proc").iterdir():
 if entry.name.isdecimal():
  try:
   argv=(entry/"cmdline").read_bytes().split(b"\\0")
   if any(arg.startswith(root) and arg.endswith(b"/tools/qemu-system-x86_64") for arg in argv):processes.append(int(entry.name))
  except (FileNotFoundError,PermissionError,ProcessLookupError):pass
observed=time.monotonic_ns()
if processes or observed<=finished["finishedMonotonicNs"]:raise RuntimeError("task-qemu-not-stopped")
print(json.dumps({"schemaVersion":1,"kind":"pr315-pve-task-qemu-stopped-v1","attemptId":suite,"sourceCommit":source,"pveBootId":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"watcherFinishedMonotonicNs":finished["finishedMonotonicNs"],"observedMonotonicNs":observed,"taskQemuProcesses":processes},sort_keys=True))'''


def stopped_observation(remote, suite, source_commit):
    if _SUITE.fullmatch(suite) is None:
        raise ValueError('pr315-stop-suite-invalid')
    value = _json_command(remote, PVE,
        ['python3', '-c', _PVE_STOP_CODE, suite, source_commit], timeout=20)
    if (value.get('kind') != 'pr315-pve-task-qemu-stopped-v1'
            or value.get('attemptId') != suite
            or value.get('sourceCommit') != source_commit
            or value.get('taskQemuProcesses') != []):
        raise ValueError('pr315-pve-stopped-observation-invalid')
    return value


def _exclusive_json(path: Path, value):
    raw = seal._canonical(value)
    descriptor = os.open(path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('pr315-owner-short-write')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scp(remote, host, source: str, target: Path):
    if (host not in (CT, PVE) or not source.startswith(
            CT_TASK + '/' if host == CT else PVE_TASK + '/')
            or not target.is_absolute()):
        raise ValueError('pr315-copy-path-unpinned')
    command = ['scp', '-F', '/dev/null', '-o', 'BatchMode=yes',
        '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=' + str(remote.known_hosts),
        '-o', 'ConnectTimeout=5', host + ':' + source, str(target)]
    checked = subprocess.run(command, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=120)
    if checked.returncode or checked.stdout or checked.stderr:
        raise ValueError('pr315-private-scp-failed')
    target.chmod(0o600)


def archive_selected_attempt(remote, config, suite, group_id, mac_root,
                             archive_builder, *, retain_disks=False):
    """Copy all nonreconstructible files, then prove the exact remote copy."""
    if (_SUITE.fullmatch(suite) is None
            or group_id not in dict(campaign.GROUPS)):
        raise ValueError('pr315-archive-selection-invalid')
    destination = Path(mac_root) / 'attempts' / suite
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    excluded = ('attempt-01/cryptad/***',
        'attempt-01/expected-bundle/***',
        'attempt-01/boot-runtime/***', 'attempt-01/tools/***')
    if not retain_disks:
        excluded += ('attempt-01/guest.qcow2',
                     'attempt-01/prepared.qcow2')
    base = ['rsync', '-a', '--checksum',
        *('--exclude=' + item for item in excluded),
        '-e', shlex.join(remote.ssh),
        CT + ':' + CT_TASK + '/' + suite + '/', str(destination) + '/']
    copied = subprocess.run(base, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=900)
    if copied.returncode or copied.stdout or copied.stderr:
        raise ValueError('pr315-private-archive-copy-failed')
    verified = subprocess.run([*base[:3], '--dry-run', '--delete',
        '--itemize-changes', *base[3:]], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=900)
    if verified.returncode or verified.stdout or verified.stderr:
        raise ValueError('pr315-private-archive-copy-changed')
    receipts = destination / 'host-receipts'
    receipts.mkdir(mode=0o700)
    for host, source, name in (
            (CT, CT_TASK + '/host-admission/' + suite + '.json',
             'host-admission.private.json'),
            (CT, CT_TASK + '/host-monitor/' + suite + '.ready.json',
             'host-monitor-ready.private.json'),
            (CT, CT_TASK + '/host-monitor/' + suite + '.finished.json',
             'host-monitor-finished.private.json'),
            (PVE, PVE_TASK + '/host-monitor/' + suite + '.private.jsonl',
             'host-monitor-samples.private.jsonl')):
        _scp(remote, host, source, receipts / name)
    _exclusive_json(destination / 'host-stop.private.json',
        stopped_observation(remote, suite, config['sourceCommit']))
    manifest_digest = archive_builder(destination, group_id, suite, verified)
    return destination, manifest_digest


def next_campaign_selection(verified_history):
    """Consume one of at most three preparation slots, with no post-probe retry."""
    if not isinstance(verified_history, list):
        raise ValueError('pr315-verified-history-required')
    by_group = {group: [] for group, _ in campaign.GROUPS}
    for receipt in verified_history:
        if (not isinstance(receipt, dict)
                or receipt.get('groupId') not in by_group):
            raise ValueError('pr315-verified-receipt-invalid')
        by_group[receipt['groupId']].append(receipt)
    for group_id, _cases in campaign.GROUPS:
        rows = by_group[group_id]
        if sum(row['status'] == 'preparation-completed' for row in rows) > 1:
            return {'status': 'failed', 'groupId': group_id,
                    'reason': 'duplicate-retired-authority'}
        if rows and rows[-1]['status'] == 'completed':
            continue
        if len(rows) >= 3 or any(row['status'] == 'failed' for row in rows):
            return {'status': 'failed', 'groupId': group_id,
                    'reason': 'retry-budget-or-probe-failure'}
        if any(row['status'] not in ('setup-failed',
                                    'preparation-completed') for row in rows):
            return {'status': 'failed', 'groupId': group_id,
                    'reason': 'unclassified-attempt'}
        if group_id == 'authority' and not any(
                row['status'] == 'preparation-completed' for row in rows):
            action = 'retired-authority-preparation'
        else:
            action = 'selected-group'
        return {'status': 'ready', 'groupId': group_id,
                'attemptOrdinal': len(rows) + 1, 'action': action}
    return {'status': 'complete', 'groupId': None,
            'attemptOrdinal': None, 'action': None}
