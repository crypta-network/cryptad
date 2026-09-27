#!/usr/bin/env python3
"""Mac-owned fixed CT102/PVE transport and per-attempt admission for PR-315.

Only a sealed host campaign may call these primitives.  The module performs no
implicit allocation when imported; its caller selects a single declared group,
checks the pinned source and capacity, then verifies and seals the archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal, InvalidOperation
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import time

import pr315_campaign_seal as seal
import pr315_campaign_owner as owner
import pr315_workload_fixtures as fixtures
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
MAC_FULL_ATTEMPT_RESERVATION = 8 * 1024**3
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
        'localFixtureManifest', 'probeDigest',
        'fixturePath', 'qemuRoot', 'preparedImage', 'seed', 'sshKey',
        'knownHosts', 'port'}
    if (not isinstance(value, dict) or set(value) != fields
            or any(re.fullmatch('[0-9a-f]{64}',
                str(value[name])) is None for name in (
                    'fixtureManifestDigest', 'preparedImageDigest',
                    'campaignPlanDigest', 'hostKeyFingerprint',
                    'probeDigest'))
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
            or not Path(value['localFixtureManifest']).is_absolute()
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
    check = ('import os,stat,sys;from pathlib import Path;'
        'p=Path(sys.argv[1]);a=p.lstat();d=p.parent.lstat();g=(p/".git").lstat();'
        'assert p.parent==Path("/work/pr315-task/campaign-frozen");'
        'assert stat.S_ISDIR(a.st_mode) and a.st_uid==os.geteuid() and a.st_mode&0o077==0;'
        'assert stat.S_ISDIR(d.st_mode) and d.st_uid==os.geteuid() and d.st_mode&0o077==0;'
        'assert stat.S_ISDIR(g.st_mode) and g.st_uid==os.geteuid();'
        'assert not (p/".git/objects/info/alternates").exists()')
    remote.call(CT, ['python3', '-c', check, config['sourceSnapshot']])
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


def prepare_source_snapshot(remote, config, *, capacity_checked=False):
    """Clone committed bytes outside Syncthing and copy only fixed product outputs."""
    snapshot = config['sourceSnapshot']
    parent = str(Path(snapshot).parent)
    if parent != CT_TASK + '/campaign-frozen':
        raise ValueError('pr315-source-snapshot-parent-invalid')
    remote.call(CT, ['mkdir', '-p', '-m', '700', parent])
    exists = remote.call(CT, ['test', '-e', snapshot], check=False)
    if exists.returncode == 0:
        return source_preflight(remote, config)
    if exists.returncode != 1:
        raise ValueError('pr315-source-snapshot-existence-unavailable')
    if capacity_checked is not True:
        raise ValueError('pr315-source-snapshot-capacity-preflight-required')
    remote.call(CT, ['git', 'clone', '--no-hardlinks', '--no-checkout',
                     CT_LIVE_SOURCE, snapshot], timeout=180)
    remote.call(CT, ['chmod', '700', snapshot])
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
            or mac_free - MAC_FULL_ATTEMPT_RESERVATION < MAC_RESERVE
            or mac_initial_available_bytes - mac_free +
                MAC_FULL_ATTEMPT_RESERVATION >
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


def required_attempt_bytes(remote, config, *, source_override=None):
    selected_source = (config['sourceSnapshot'] if source_override is None
                       else source_override)
    if selected_source not in (config['sourceSnapshot'], CT_LIVE_SOURCE):
        raise ValueError('pr315-reservation-source-invalid')
    raw = remote.call(CT, ['python3', '-c', _REQUIRED_CODE,
        selected_source, config['preparedImage'],
        config['fixturePath'], config['qemuRoot'], config['seed'],
        config['sshKey'], config['knownHosts']], timeout=60).stdout.decode().strip()
    if not raw.isdecimal():
        raise ValueError('pr315-attempt-reservation-unavailable')
    return int(raw)


_SNAPSHOT_SIZE_CODE = '''import os,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]); tracked=subprocess.check_output(['git','-C',str(root),'ls-files','-z']).split(b'\\0')
if not tracked or len(tracked)>100000: raise RuntimeError('tracked-roster-invalid')
total=0
for raw in tracked:
 if raw:
  path=root/os.fsdecode(raw);total+=path.lstat().st_blocks*512
for relative in ('.git','build/cryptad-dist','platform-devtools/build/install/crypta-app','platform-api/build/libs'):
 path=root/relative
 for directory,dirs,files in os.walk(path):
  for name in files:total+=(Path(directory)/name).lstat().st_blocks*512
print(total+max(1024**3,total//4))'''


def source_snapshot_reservation_bytes(remote):
    """Reserve the independent Git clone and three copied product outputs."""
    raw = remote.call(CT, ['python3', '-c', _SNAPSHOT_SIZE_CODE,
        CT_LIVE_SOURCE], timeout=90).stdout.decode().strip()
    if not raw.isdecimal():
        raise ValueError('pr315-source-snapshot-reservation-unavailable')
    size = int(raw)
    if not 0 < size <= 16 * 1024**3:
        raise ValueError('pr315-source-snapshot-reservation-invalid')
    return size


_QEMU_INVENTORY_CODE = '''import json,os
from pathlib import Path
if os.geteuid()!=0: raise RuntimeError('root-required')
roots=('/work/pr315-task/','/mnt/tank1/files/pr315-workload-acceptance/')
found=[]
for entry in Path('/proc').iterdir():
 if not entry.name.isdecimal(): continue
 try:
  args=(entry/'cmdline').read_bytes().split(b'\\0')
  selected=[arg.decode('utf-8','strict') for arg in args if arg.endswith(b'/tools/qemu-system-x86_64')]
  if any(path.startswith(roots) for path in selected):
   ticks=int((entry/'stat').read_text().rsplit(')',1)[1].split()[19])
   found.append({'pid':int(entry.name),'startTicks':ticks})
 except (FileNotFoundError,PermissionError,ProcessLookupError,UnicodeDecodeError,ValueError): pass
print(json.dumps(found,sort_keys=True))'''


def task_qemu_inventory(remote):
    """Require zero task-owned QEMU instances before every guest allocation."""
    found = _json_command(remote, PVE,
        ['python3', '-c', _QEMU_INVENTORY_CODE], timeout=15)
    if not isinstance(found, list) or found:
        raise ValueError('pr315-existing-task-qemu-active')
    return found


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


def _write_or_verify_json(path: Path, value):
    raw = seal._canonical(value)
    try:
        info = path.lstat()
    except FileNotFoundError:
        _exclusive_json(path, value)
        return
    if (not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077
            or info.st_size != len(raw) or path.read_bytes() != raw):
        raise ValueError('pr315-host-private-receipt-changed')


def _exclusive_bytes(path: Path, raw: bytes):
    if not isinstance(raw, bytes) or len(raw) > 16384:
        raise ValueError('pr315-owner-small-file-invalid')
    descriptor = os.open(path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(descriptor, raw) != len(raw):
            raise ValueError('pr315-owner-small-file-short-write')
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


def _put_frozen_input(remote, source: Path, destination: str, *, private=True):
    """Publish one fixed campaign input once; verify bytes on every resume."""
    source = Path(source)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_size > 16384
            or (private and info.st_mode & 0o077)
            or not re.fullmatch(r'/work/pr315-task/campaign-frozen/[a-zA-Z0-9_.-]+',
                                destination)):
        raise ValueError('pr315-frozen-input-path-or-mode-invalid')
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    exists = remote.call(CT, ['test', '-e', destination], check=False)
    if exists.returncode not in (0, 1):
        raise ValueError('pr315-frozen-input-existence-unavailable')
    if exists.returncode == 1:
        command = ['scp', '-p', '-F', '/dev/null', '-o', 'BatchMode=yes',
            '-o', 'IdentitiesOnly=yes', '-o', 'ForwardAgent=no',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(remote.known_hosts),
            str(source), CT + ':' + destination]
        completed = subprocess.run(command, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=120)
        if completed.returncode or completed.stdout or completed.stderr:
            raise ValueError('pr315-frozen-input-copy-failed')
    observed = remote.call(CT, ['sha256sum', destination]).stdout.decode().split()
    if len(observed) != 2 or observed[0] != expected or observed[1] != destination:
        raise ValueError('pr315-frozen-input-byte-identity-changed')
    check = ('import os,stat,sys;from pathlib import Path;'
        'p=Path(sys.argv[1]);a=p.lstat();d=p.parent.lstat();'
        'assert stat.S_ISREG(a.st_mode) and a.st_uid==os.geteuid() and a.st_nlink==1;'
        'assert stat.S_ISDIR(d.st_mode) and d.st_uid==os.geteuid() and d.st_mode&0o077==0;'
        'assert sys.argv[2]=="0" or a.st_mode&0o077==0')
    remote.call(CT, ['python3', '-c', check, destination,
                     '1' if private else '0'])
    return expected


def publish_frozen_campaign(remote, root, config):
    """Copy only the public plan and key after the isolated CT source passes."""
    root = seal._private_directory(Path(root).resolve(strict=True))
    fixed_config(config)
    source_preflight(remote, config)
    parent = str(Path(config['campaignPlanPath']).parent)
    if parent != CT_TASK + '/campaign-frozen':
        raise ValueError('pr315-campaign-plan-parent-invalid')
    remote.call(CT, ['mkdir', '-p', '-m', '700', parent])
    plan = _put_frozen_input(remote, root / 'campaign-plan.private.json',
                             config['campaignPlanPath'])
    public = _put_frozen_input(remote, root / (seal.KEY_NAME + '.pub'),
                               parent + '/campaign-ed25519.pub', private=False)
    return {'planFileDigest': plan, 'publicKeyFileDigest': public}


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


def stage_full_attempt(remote, config, suite, campaign_root):
    """Keep a complete attempt copy until case and remote cleanup are verified.

    A public `passed` field does not authorize omitting failure disks. This
    staging copy remains immutable if any later case, seal, stop or cleanup
    check fails.
    """
    if _SUITE.fullmatch(suite) is None:
        raise ValueError('pr315-full-stage-suite-invalid')
    root = seal._private_directory(Path(campaign_root).resolve(strict=True))
    startup = owner._json(root, 'start.private.json', 8192)
    measured = remote.call(CT, ['du', '-sb',
        CT_TASK + '/' + suite], timeout=90).stdout.decode().split()
    if (len(measured) != 2 or not measured[0].isdecimal()
            or measured[1] != CT_TASK + '/' + suite):
        raise ValueError('pr315-full-stage-remote-size-unavailable')
    needed = int(measured[0]) + 1024**3
    volume = os.statvfs(root)
    mac_free = volume.f_bavail * volume.f_frsize
    baseline = startup.get('macAvailableAtStartBytes')
    if (type(baseline) is not int
            or needed > 40 * 1024**3
            or mac_free - needed < MAC_RESERVE
            or baseline - mac_free + needed > MAC_ADDITIONAL_BUDGET):
        raise ValueError('pr315-full-stage-mac-capacity-unavailable')
    stage_root = root / 'full-attempt-staging'
    stage_root.mkdir(mode=0o700, exist_ok=True)
    destination = stage_root / suite
    destination.mkdir(mode=0o700, exist_ok=False)
    command = ['rsync', '-a', '--checksum',
        '-e', shlex.join(remote.ssh),
        CT + ':' + CT_TASK + '/' + suite + '/', str(destination) + '/']
    copied = subprocess.run(command, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=1800)
    if copied.returncode or copied.stdout or copied.stderr:
        raise ValueError('pr315-full-stage-copy-failed')
    verified = subprocess.run([*command[:3], '--dry-run', '--delete',
        '--itemize-changes', *command[3:]], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=1800)
    if verified.returncode or verified.stdout or verified.stderr:
        raise ValueError('pr315-full-stage-copy-changed')
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
    rows = {}
    for path in destination.rglob('*'):
        if path.is_symlink():
            raise ValueError('pr315-full-stage-link-invalid')
        if not path.is_file():
            continue
        relative = path.relative_to(destination).as_posix()
        checksum = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                checksum.update(block)
        rows[relative] = {'sha256': checksum.hexdigest(),
                          'sizeBytes': path.stat().st_size}
        if len(rows) > 100000:
            raise ValueError('pr315-full-stage-file-limit')
    if not {'attempt-01/guest.qcow2', 'attempt-01/prepared.qcow2',
            'host-stop.private.json'} <= set(rows):
        raise ValueError('pr315-full-stage-disk-or-stop-unavailable')
    manifest = {'schemaVersion': 1,
        'kind': 'pr315-mac-full-attempt-preservation-v1',
        'attemptId': suite, 'sourceCommit': config['sourceCommit'],
        'files': rows, 'copyVerified': True,
        'excludedReconstructible': []}
    _exclusive_json(destination / 'full-stage-manifest.private.json', manifest)
    return destination, seal._digest(manifest)


def verify_full_staging_copy(root, suite, source_commit):
    """Rehash all retained guest bytes before authorizing remote release."""
    root = seal._private_directory(Path(root).resolve(strict=True))
    if _SUITE.fullmatch(suite) is None:
        raise ValueError('pr315-full-stage-suite-invalid')
    stage = seal._private_directory(root / 'full-attempt-staging' / suite)
    manifest = owner._json(stage,
        'full-stage-manifest.private.json', 8 * 1024 * 1024)
    if (not isinstance(manifest, dict)
            or manifest.get('schemaVersion') != 1
            or manifest.get('kind') != 'pr315-mac-full-attempt-preservation-v1'
            or manifest.get('attemptId') != suite
            or manifest.get('sourceCommit') != source_commit
            or manifest.get('copyVerified') is not True
            or manifest.get('excludedReconstructible') != []
            or not isinstance(manifest.get('files'), dict)
            or not {'attempt-01/guest.qcow2',
                    'attempt-01/prepared.qcow2',
                    'attempt-01/source.tar.gz',
                    'host-stop.private.json'} <= set(manifest['files'])):
        raise ValueError('pr315-full-stage-manifest-invalid')
    actual = set()
    for directory, directories, names in os.walk(stage, followlinks=False):
        base = Path(directory)
        if any((base / name).is_symlink()
               for name in (*directories, *names)):
            raise ValueError('pr315-full-stage-link-invalid')
        for name in names:
            path = base / name
            relative = path.relative_to(stage).as_posix()
            if relative != 'full-stage-manifest.private.json':
                actual.add(relative)
    if actual != set(manifest['files']) or len(actual) > 100000:
        raise ValueError('pr315-full-stage-file-set-changed')
    for relative, expected in manifest['files'].items():
        path = stage / relative
        if (not isinstance(expected, dict)
                or set(expected) != {'sha256', 'sizeBytes'}
                or not isinstance(expected['sizeBytes'], int)
                or not 0 <= expected['sizeBytes'] <= 32 * 1024**3
                or re.fullmatch(r'[0-9a-f]{64}',
                    str(expected['sha256'])) is None):
            raise ValueError('pr315-full-stage-file-metadata-invalid')
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_size != expected['sizeBytes']):
            raise ValueError('pr315-full-stage-file-identity-changed')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                digest.update(block)
        if (digest.hexdigest() != expected['sha256']
                or path.lstat().st_size != info.st_size):
            raise ValueError('pr315-full-stage-file-digest-changed')
    return stage, manifest, seal._digest(manifest)


def _pve_release_root(source_commit):
    if re.fullmatch(r'[0-9a-f]{40}', source_commit) is None:
        raise ValueError('pr315-pve-release-source-invalid')
    return '/root/pr315-workload/campaign-' + source_commit[:12]


def _publish_pve_release_file(remote, source, destination, *, mode):
    source = Path(source)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_size > 1024 * 1024
            or mode not in (0o400, 0o600)
            or not (destination.startswith('/root/pr315-workload/campaign-')
                    or destination.startswith(PVE_TASK + '/host-release/'))
            or '..' in Path(destination).parts):
        raise ValueError('pr315-pve-release-file-selection-invalid')
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    exists = remote.call(PVE, ['test', '-e', destination], check=False)
    if exists.returncode not in (0, 1):
        raise ValueError('pr315-pve-release-file-existence-unavailable')
    if exists.returncode == 1:
        command = ['scp', '-p', '-F', '/dev/null',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'ForwardAgent=no', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(remote.known_hosts),
            str(source), PVE + ':' + destination]
        completed = subprocess.run(command, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=120)
        if completed.returncode or completed.stdout or completed.stderr:
            raise ValueError('pr315-pve-release-file-transfer-failed')
        remote.call(PVE, ['chmod', format(mode, 'o'), destination])
    actual = remote.call(PVE, ['sha256sum', destination]).stdout.decode().split()
    if len(actual) != 2 or actual != [expected, destination]:
        raise ValueError('pr315-pve-release-file-byte-mismatch')
    check = ('import os,stat,sys;from pathlib import Path;'
        'p=Path(sys.argv[1]);a=p.lstat();d=p.parent.lstat();'
        'assert stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1;'
        'assert stat.S_ISDIR(d.st_mode) and d.st_uid==0 and d.st_mode&0o077==0;'
        'assert a.st_mode&0o777==int(sys.argv[2],8)')
    remote.call(PVE, ['python3', '-c', check, destination,
                      format(mode, 'o')])
    return expected


def _publish_pve_release_tools(remote, source, source_commit):
    root = _pve_release_root(source_commit)
    remote.call(PVE, ['mkdir', '-p', '-m', '700', root])
    relative = Path('tools/release-certification/restricted')
    result = {}
    for name in ('pr315_pve_attempt_inventory.py',
                 'pr315_pve_attempt_cleanup.py'):
        result[name] = _publish_pve_release_file(remote,
            Path(source) / relative / name, root + '/' + name,
            mode=0o400)
    return root, result


def _release_plan(root, plan, receipt, staging, staging_digest):
    files = staging['files']
    selected = {name: files['attempt-01/' + name]['sha256']
                for name in ('guest.qcow2', 'prepared.qcow2',
                             'source.tar.gz')}
    value = {'schemaVersion': 1,
        'kind': 'pr315-host-success-copy-release-plan-v1',
        'suite': receipt['attemptId'],
        'sourceCommit': receipt['sourceCommit'],
        'campaignPlanDigest': plan['planDigest'],
        'sealedReceiptDigest': seal._digest(receipt),
        'macFullArchiveDigest': staging_digest,
        'fileDigests': selected}
    directory = root / 'host-release'
    directory.mkdir(mode=0o700, exist_ok=True)
    _write_or_verify_json(directory / (receipt['attemptId'] +
                         '.plan.private.json'), value)
    return value


_PVE_RELEASE_ABSENCE_CODE = '''import json,re,sys
from pathlib import Path
suite=sys.argv[1]
if re.fullmatch(r'suite-[1-9][0-9]*',suite) is None: raise RuntimeError('suite-invalid')
base=Path('/mnt/tank1/files/pr315-workload-acceptance')/suite/'attempt-01'
names=('guest.qcow2','prepared.qcow2','source.tar.gz','cryptad','expected-bundle','boot-runtime','tools')
if any((base/name).exists() or (base/name).is_symlink() for name in names): raise RuntimeError('released-copy-present')
if not (base/'attempt.private.json').is_file():raise RuntimeError('original-observation-missing')
print(json.dumps({'suite':suite,'removed':list(names),'originalObservationRetained':True},sort_keys=True))'''


def _postrelease_absence(remote, suite):
    absent = _json_command(remote, PVE, ['python3', '-c',
        _PVE_RELEASE_ABSENCE_CODE, suite], timeout=20)
    if (absent != {'suite': suite,
            'removed': ['guest.qcow2', 'prepared.qcow2', 'source.tar.gz',
                        'cryptad', 'expected-bundle', 'boot-runtime', 'tools'],
            'originalObservationRetained': True}):
        raise ValueError('pr315-release-postcheck-invalid')
    task_qemu_inventory(remote)


def _recover_postdelete_cleanup(remote, root, source, plan, receipt,
                                staging_digest, selected):
    """Seal only a fully observed prior deletion if the last write crashed."""
    suite = receipt['attemptId']
    directory = root / 'host-release'
    complete_path = directory / (suite + '.complete.private.json')
    if not complete_path.exists():
        return None
    check = owner._json(root, 'host-release/' + suite +
                        '.check.private.json', 16384)
    complete = owner._json(root, 'host-release/' + suite +
                           '.complete.private.json', 16384)
    core = {key: value for key, value in check.items()
            if key != 'checkDigest'}
    check_digest = check.get('checkDigest')
    if (check_digest != seal._digest(core)
            or core.get('sealedReceiptDigest') !=
                selected['sealedReceiptDigest']
            or core.get('macFullArchiveDigest') != staging_digest
            or any(core.get('files', {}).get(name, {}).get('sha256') != digest
                   for name, digest in selected['fileDigests'].items())
            or any(core.get(key) != [] for key in (
                'taskQemuPids', 'openUserPids',
                'externalBackingDependents'))
            or complete != {**core, 'checkDigest': check_digest,
                'release': 'completed-remote-success-duplicates-only'}):
        raise ValueError('pr315-release-postdelete-record-changed')
    _postrelease_absence(remote, suite)
    relative = Path('tools/release-certification/restricted')
    inventory_digest = hashlib.sha256((source / relative /
        'pr315_pve_attempt_inventory.py').read_bytes()).hexdigest()
    cleanup_digest = hashlib.sha256((source / relative /
        'pr315_pve_attempt_cleanup.py').read_bytes()).hexdigest()
    cleanup = seal.cleanup_receipt(plan, receipt, staging_digest,
        check_digest, seal._digest(complete), seal._digest(selected),
        inventory_digest, cleanup_digest)
    _write_or_verify_json(directory / (suite + '.seal.private.json'),
        seal.sign_cleanup(root, plan, receipt, cleanup))
    return complete


def release_completed_attempt(remote, root, source, plan, receipt,
                              history):
    """Release only a sealed success after both Mac archives reverify."""
    root = seal._private_directory(Path(root).resolve(strict=True))
    source = Path(source).resolve(strict=True)
    if (receipt not in history
            or receipt.get('status') not in
                ('completed', 'preparation-completed')
            or receipt.get('sourceCommit') !=
                plan['identity']['helperSourceCommit']):
        raise ValueError('pr315-release-unsealed-attempt')
    archive = root / 'attempts' / receipt['attemptId']
    if receipt['status'] == 'completed':
        owner.verify_completed_archive(plan, receipt, archive, source,
            history=history, campaign_root=root)
    else:
        verify_retired_preparation_for_resume(root, plan, history)
        owner._archive_manifest(archive, plan, receipt)
    _stage, staging, staging_digest = verify_full_staging_copy(
        root, receipt['attemptId'], receipt['sourceCommit'])
    selected = _release_plan(root, plan, receipt, staging,
                             staging_digest)
    recovered = _recover_postdelete_cleanup(remote, root, source, plan,
        receipt, staging_digest, selected)
    if recovered is not None:
        return recovered
    pve_root, _tool_digests = _publish_pve_release_tools(
        remote, source, receipt['sourceCommit'])
    remote.call(PVE, ['mkdir', '-p', '-m', '700',
        PVE_TASK + '/host-release'])
    local_plan = root / 'host-release' / (receipt['attemptId'] +
                                         '.plan.private.json')
    remote_plan = PVE_TASK + '/host-release/' + (
        receipt['attemptId'] + '.plan.private.json')
    _publish_pve_release_file(remote, local_plan, remote_plan, mode=0o400)
    common = ['--suite', receipt['attemptId'], '--source-commit',
              receipt['sourceCommit']]
    checked = _json_command(remote, PVE, ['python3', pve_root +
        '/pr315_pve_attempt_inventory.py', *common], timeout=180)
    check_digest = checked.pop('checkDigest', None)
    if (checked.get('suite') != receipt['attemptId']
            or checked.get('sourceCommit') != receipt['sourceCommit']
            or checked.get('campaignPlanDigest') != plan['planDigest']
            or checked.get('sealedReceiptDigest') !=
                selected['sealedReceiptDigest']
            or checked.get('macFullArchiveDigest') != staging_digest
            or any(checked.get('files', {}).get(name, {}).get('sha256') != digest
                   for name, digest in selected['fileDigests'].items())
            or any(checked.get(key) != [] for key in (
                'taskQemuPids', 'openUserPids',
                'externalBackingDependents'))
            or check_digest != seal._digest(checked)):
        raise ValueError('pr315-release-pve-readonly-check-invalid')
    _write_or_verify_json(root / 'host-release' /
        (receipt['attemptId'] + '.check.private.json'),
        {**checked, 'checkDigest': check_digest})
    completed = _json_command(remote, PVE, ['python3', pve_root +
        '/pr315_pve_attempt_cleanup.py', *common,
        '--check-digest', check_digest], timeout=180)
    if (completed.get('release') !=
            'completed-remote-success-duplicates-only'
            or completed.get('checkDigest') != check_digest
            or any(completed.get(key) != checked[key] for key in checked)):
        raise ValueError('pr315-release-pve-completion-invalid')
    _write_or_verify_json(root / 'host-release' /
        (receipt['attemptId'] + '.complete.private.json'), completed)
    _postrelease_absence(remote, receipt['attemptId'])
    cleanup = seal.cleanup_receipt(plan, receipt, staging_digest,
        check_digest, seal._digest(completed), seal._digest(selected),
        _tool_digests['pr315_pve_attempt_inventory.py'],
        _tool_digests['pr315_pve_attempt_cleanup.py'])
    signed_cleanup = seal.sign_cleanup(root, plan, receipt, cleanup)
    _write_or_verify_json(root / 'host-release' /
        (receipt['attemptId'] + '.seal.private.json'), signed_cleanup)
    return completed


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


def selected_group_complete(campaign_plan, group_id, assessment):
    """Use public case statuses only to decide which private archive to verify."""
    owned = set(dict(campaign.GROUPS)[group_id])
    if (not isinstance(assessment, dict)
            or assessment.get('schemaVersion') != 2
            or assessment.get('contract') != seal.CONTRACT
            or assessment.get('campaignPlanDigest') !=
                campaign_plan['planDigest']
            or assessment.get('campaignNonce') !=
                campaign_plan['campaignNonce']
            or assessment.get('hostKeyFingerprint') !=
                campaign_plan['hostKeyFingerprint']
            or assessment.get('status') != 'partial-execution'
            or assessment.get('reasons') != []
            or assessment.get('installedPositiveExecuted') is not
                (group_id == 'positive')
            or assessment.get('installedWorkloadAcceptanceSatisfied') is not False):
        return False
    cases = assessment.get('cases')
    if (not isinstance(cases, list) or len(cases) != 45
            or any(not isinstance(row, dict) or 'caseId' not in row
                   or 'status' not in row for row in cases)):
        return False
    statuses = {row['caseId']: row['status'] for row in cases}
    if len(statuses) != 45 or not owned <= set(statuses):
        return False
    return (all(statuses[case] == 'passed' for case in owned)
            and all(status != 'passed' for case, status in statuses.items()
                    if case not in owned))


def explicit_probe_phase(group_id, diagnostic):
    """A missing or malformed start record is unknown, never setup-failed."""
    if not isinstance(diagnostic, dict):
        return None
    marker = diagnostic.get('probeStart')
    if marker is None:
        return None
    if (not isinstance(marker, dict)
            or set(marker) != {'schemaVersion', 'kind', 'caseId',
                               'startedMonotonicNs'}
            or marker['schemaVersion'] != 1
            or marker['kind'] != 'pr315-workload-probe-start'
            or marker['caseId'] != group_id
            or type(marker['startedMonotonicNs']) is not int
            or marker['startedMonotonicNs'] <= 0):
        return None
    return True


def initialize_campaign(root, source, config, identity, remote_known_hosts,
                        first_suite_number):
    """Freeze the Mac key, measured source and fixed 21-group plan before VM use."""
    root, source = Path(root), Path(source)
    if not isinstance(config, dict):
        raise ValueError('pr315-campaign-config-invalid')
    fixed_config({**config, 'campaignPlanDigest': '0' * 64,
                  'hostKeyFingerprint': '0' * 64})
    if root.exists() or root.is_symlink():
        raise ValueError('pr315-campaign-root-already-exists')
    remote_pin = Path(remote_known_hosts)
    raw_pin = remote_pin.read_bytes()
    if not 0 < len(raw_pin) <= 16384 or b'ssh-ed25519 ' not in raw_pin:
        raise ValueError('pr315-campaign-remote-host-pin-invalid')
    head = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        capture_output=True, check=True, text=True, timeout=10).stdout.strip()
    tree = subprocess.run(['git', '-C', str(source), 'rev-parse',
        'HEAD^{tree}'], capture_output=True, check=True,
        text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(source), 'status',
        '--porcelain', '--untracked-files=normal'],
        capture_output=True, check=True, timeout=10).stdout
    if (dirty or head != config['sourceCommit']
            or tree != config['sourceTree']
            or identity.get('helperSourceCommit') != head
            or identity.get('helperSourceTree') != tree
            or identity.get('fixtureManifestDigest') !=
                config['fixtureManifestDigest']
            or identity.get('preparedImageDigest') !=
                config['preparedImageDigest']
            or identity.get('productSelectionDigest') !=
                config['productSelectionDigest']
            or owner.tracked_byte_digest(source) !=
                config['trackedByteDigest']):
        raise ValueError('pr315-campaign-local-frozen-identity-invalid')
    fixture_path = Path(config['localFixtureManifest'])
    fixture_info = fixture_path.lstat()
    if (not stat.S_ISREG(fixture_info.st_mode)
            or fixture_info.st_uid != os.geteuid()
            or fixture_info.st_nlink != 1
            or fixture_info.st_size > 8 * 1024 * 1024):
        raise ValueError('pr315-campaign-local-fixture-invalid')
    fixture_raw = fixture_path.read_bytes()
    fixture_manifest = json.loads(fixture_raw)
    if (fixture_manifest.get('sourceCommit') != head
            or fixture_manifest.get('probeDigest') !=
                'sha256:' + config['probeDigest']
            or hashlib.sha256(fixture_raw).hexdigest() !=
                config['fixtureManifestDigest']):
        raise ValueError('pr315-campaign-fixture-input-invalid')
    volume = os.statvfs(root.parent)
    mac_available = volume.f_bavail * volume.f_frsize
    if mac_available < MAC_RESERVE + MAC_ADDITIONAL_BUDGET:
        raise ValueError('pr315-campaign-mac-baseline-capacity-unavailable')
    root.mkdir(mode=0o700)
    fingerprint = seal.prepare_key(root)
    policy_digest = seal._digest(fixtures.preparation.launcher_policy())
    planned = seal.plan(identity, policy_digest,
        'pve-tcg-swap-admission-v1', config['probeDigest'],
        secrets.token_hex(32), fingerprint)
    frozen_config = {**config,
        'campaignPlanDigest': planned['planDigest'],
        'hostKeyFingerprint': fingerprint}
    fixed_config(frozen_config)
    _exclusive_json(root / 'campaign-plan.private.json', planned)
    pin = root / 'remote-known-hosts.private'
    descriptor = os.open(pin, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw_pin)
        stream.flush()
        os.fsync(stream.fileno())
    start = seal.frozen_start(planned, tree, config['trackedByteDigest'],
        hashlib.sha256(raw_pin).hexdigest(), first_suite_number,
        mac_available)
    _exclusive_json(root / 'start.private.json', start)
    _exclusive_json(root / 'start-seal.private.json',
        seal.sign_start(root, planned, start))
    _exclusive_json(root / 'coordinator-config.private.json', frozen_config)
    (root / 'attempts').mkdir(mode=0o700)
    (root / 'full-attempt-staging').mkdir(mode=0o700)
    return planned


def frozen_campaign_context(root, source):
    """Authenticate the Mac start seal and exact source before any remote work."""
    root = seal._private_directory(Path(root).resolve(strict=True))
    source = Path(source).resolve(strict=True)
    plan = owner._json(root, 'campaign-plan.private.json', 16384)
    start = owner._json(root, 'start.private.json', 8192)
    signed = owner._json(root, 'start-seal.private.json', 8192)
    config = fixed_config(owner._json(root,
        'coordinator-config.private.json', 16384))
    if seal.verify_start(root, plan, signed) != start:
        raise ValueError('pr315-coordinator-start-seal-changed')
    head = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'],
        capture_output=True, check=True, text=True, timeout=10).stdout.strip()
    tree = subprocess.run(['git', '-C', str(source), 'rev-parse',
        'HEAD^{tree}'], capture_output=True, check=True,
        text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(source), 'status',
        '--porcelain', '--untracked-files=normal'],
        capture_output=True, check=True, timeout=10).stdout
    pin = owner._read(root, 'remote-known-hosts.private', 16384)
    fixture_path = Path(config['localFixtureManifest'])
    fixture_info = fixture_path.lstat()
    if (not stat.S_ISREG(fixture_info.st_mode)
            or fixture_info.st_uid != os.geteuid()
            or fixture_info.st_nlink != 1
            or fixture_info.st_size > 8 * 1024 * 1024):
        raise ValueError('pr315-coordinator-local-fixture-invalid')
    fixture_raw = fixture_path.read_bytes()
    fixture = json.loads(fixture_raw)
    if (dirty or start['sourceCommit'] != head
            or start['sourceTree'] != tree
            or start['trackedByteDigest'] != owner.tracked_byte_digest(source)
            or start['remoteKnownHostsDigest'] != hashlib.sha256(pin).hexdigest()
            or config['sourceCommit'] != head
            or config['sourceTree'] != tree
            or config['trackedByteDigest'] != start['trackedByteDigest']
            or config['campaignPlanDigest'] != plan['planDigest']
            or config['hostKeyFingerprint'] != plan['hostKeyFingerprint']
            or config['fixtureManifestDigest'] !=
                plan['identity']['fixtureManifestDigest']
            or hashlib.sha256(fixture_raw).hexdigest() !=
                config['fixtureManifestDigest']
            or fixture.get('sourceCommit') != head
            or fixture.get('probeDigest') !=
                'sha256:' + config['probeDigest']
            or config['productSelectionDigest'] !=
                plan['identity']['productSelectionDigest']):
        raise ValueError('pr315-coordinator-frozen-source-changed')
    return root, source, plan, start, config


def _archive_case_group(remote, root, source, config, plan, suite,
                        group_id, history):
    def build(destination, selected_group, selected_suite, verified):
        if selected_group == 'authority':
            _exclusive_bytes(destination /
                'retired-authority-handoff.private.json',
                owner._read(root, 'retired-authority-handoff.private.json', 8192))
            _exclusive_bytes(destination / 'campaign-public-key.pub',
                (root / (seal.KEY_NAME + '.pub')).read_bytes())
        return owner.create_archive_manifest(destination, plan,
            selected_group, selected_suite, verified)

    archive, _digest = archive_selected_attempt(remote, config, suite,
        group_id, root, build)
    receipt = owner.prepared_completed_receipt(plan, group_id, suite,
        archive, source, history=history, campaign_root=root,
        sequence=len(history) + 1,
        previous_digest=seal._digest(history[-1]) if history else '0' * 64)
    signed = seal.append_verified_attempt(root, plan,
        pinned_source_commit=config['sourceCommit'],
        pinned_fingerprint=config['hostKeyFingerprint'],
        group_id=group_id, attempt_id=suite, status='completed',
        probe_started=True, case_digests=receipt['caseDigests'],
        evidence_digest=receipt['evidenceDigest'],
        stop_digest=receipt['stopDigest'],
        monitor_digest=receipt['monitorDigest'],
        archive_digest=receipt['archiveDigest'])
    if signed != receipt:
        raise ValueError('pr315-completed-receipt-changed')
    return signed


def _archive_retired_preparation(remote, root, config, plan, suite):
    """Verify the stopped old guest, then seal its handle source for authority."""
    import pr315_workload_runner as runner

    archive, manifest_digest = archive_selected_attempt(remote, config,
        suite, 'authority', root,
        lambda destination, group, attempt, verified:
            owner.create_archive_manifest(destination, plan,
                                          group, attempt, verified))
    manifest = owner._json(archive, 'archive.private.json')
    proof = owner._json(archive,
        'retired-authority-v2-provenance.private.json', 8192)
    retained = owner._json(archive,
        'attempt-01/pr315-retired-authority.private.json', 8192)
    report = owner._json(archive, 'attempt-01/attempt.private.json')
    result = owner._json(archive,
        'attempt-01/pr314-workload-observation.private.json')
    terminal = owner._json(archive,
        'attempt-01/pr315-workload-volatile.private.json')
    if (report.get('guestStopped') is not True
            or report.get('guestExitCode') != 0
            or runner.retired_authority_provenance(report, result,
                terminal, retained) != proof
            or manifest_digest != seal._digest(manifest)):
        raise ValueError('pr315-retired-preparation-proof-invalid')
    files = manifest['files']
    handoff = seal.authority_handoff(plan, suite, proof,
        files['host-stop.private.json']['sha256'], manifest_digest)
    signed_handoff = seal.sign_authority_handoff(root, plan, handoff)
    runner.verified_retired_authority_input(plan, signed_handoff,
        (root / (seal.KEY_NAME + '.pub')).read_bytes(), retained)
    receipt = seal.append_verified_attempt(root, plan,
        pinned_source_commit=config['sourceCommit'],
        pinned_fingerprint=config['hostKeyFingerprint'],
        group_id='authority', attempt_id=suite,
        status='preparation-completed', probe_started=False,
        case_digests={}, evidence_digest=proof['inputDigest'],
        stop_digest=files['host-stop.private.json']['sha256'],
        monitor_digest=files['host-monitor.private.json']['sha256'],
        archive_digest=manifest_digest)
    _exclusive_json(root / 'retired-authority-handoff.private.json',
                    signed_handoff)
    _exclusive_json(root / 'retired-authority-input.private.json', retained)
    return receipt


def _seal_failed_attempt(root, config, plan, suite, group_id,
                         staging, stage_digest):
    """Preserve unknown probe phase as failure, never as a setup retry."""
    manifest = owner._json(staging,
        'full-stage-manifest.private.json', 8 * 1024 * 1024)
    assessment = owner._json(staging, 'assessment.json')
    report = owner._json(staging, 'attempt-01/attempt.private.json')
    if (seal._digest(manifest) != stage_digest
            or report.get('guestStopped') is not True
            or report.get('helperSourceCommit') != config['sourceCommit']
            or assessment.get('campaignPlanDigest') != plan['planDigest']):
        raise ValueError('pr315-failed-attempt-host-premise-invalid')
    try:
        diagnostic = owner._json(staging,
            'attempt-01/pr315-workload-memory.private.json')
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        diagnostic = None
    phase = explicit_probe_phase(group_id, diagnostic)
    files = manifest['files']
    assessment_digest = hashlib.sha256(owner._read(
        staging, 'assessment.json')).hexdigest()
    return seal.append_verified_attempt(root, plan,
        pinned_source_commit=config['sourceCommit'],
        pinned_fingerprint=config['hostKeyFingerprint'],
        group_id=group_id, attempt_id=suite, status='failed',
        probe_started=phase, case_digests={},
        evidence_digest=seal._digest({
            'fullStageDigest': stage_digest,
            'assessmentDigest': assessment_digest}),
        stop_digest=files['host-stop.private.json']['sha256'],
        monitor_digest=files[
            'host-receipts/host-monitor-finished.private.json']['sha256'],
        archive_digest=stage_digest)


def verify_retired_preparation_for_resume(root, plan, history):
    """Rebuild the old stopped authority before sending its handle to CT102."""
    import pr315_workload_runner as runner

    rows = [row for row in history if row['groupId'] == 'authority'
            and row['status'] == 'preparation-completed']
    if len(rows) != 1:
        raise ValueError('pr315-retired-preparation-history-invalid')
    receipt = rows[0]
    archive = root / 'attempts' / receipt['attemptId']
    manifest = owner._archive_manifest(archive, plan, receipt)
    proof = owner._json(archive,
        'retired-authority-v2-provenance.private.json', 8192)
    retained = owner._json(root, 'retired-authority-input.private.json', 8192)
    signed = owner._json(root, 'retired-authority-handoff.private.json', 8192)
    public = (root / (seal.KEY_NAME + '.pub')).read_bytes()
    handoff = runner.verified_retired_authority_input(
        plan, signed, public, retained)
    report = owner._json(archive, 'attempt-01/attempt.private.json')
    result = owner._json(archive,
        'attempt-01/pr314-workload-observation.private.json')
    terminal = owner._json(archive,
        'attempt-01/pr315-workload-volatile.private.json')
    if (runner.retired_authority_provenance(report, result, terminal,
            retained) != proof
            or handoff['preparationAttemptId'] != receipt['attemptId']
            or handoff['privateInputDigest'] != receipt['evidenceDigest']
            or handoff['stopDigest'] != receipt['stopDigest']
            or handoff['archiveDigest'] != receipt['archiveDigest']
            or seal._digest(manifest) != receipt['archiveDigest']):
        raise ValueError('pr315-retired-preparation-recovery-invalid')
    return handoff


def run_campaign(root, source, *, case_group=None):
    """Run the 21 groups serially from host-sealed, byte-reverified state.

    A selected development group is still a partial campaign. Any failed or
    uncertain operation stops this invocation after preserving its full guest
    copy and sealing a failed receipt. A later source fix starts a new campaign.
    """
    import pr315_case_registry as registry

    root, source, plan, start, config = frozen_campaign_context(root, source)
    if case_group is not None and case_group not in dict(campaign.GROUPS):
        raise ValueError('pr315-coordinator-case-group-invalid')
    if (case_group is None
            and registry.implementation_coverage(source) != 'complete'):
        raise ValueError('pr315-coordinator-emitter-coverage-incomplete')
    remote = Remote(root / 'remote-known-hosts.private')
    source_preflight(remote, config)
    publish_frozen_campaign(remote, root, config)
    pin = {'expected_plan_digest': plan['planDigest'],
           'expected_key_fingerprint': plan['hostKeyFingerprint']}
    # This rebuilds every already-completed case from the private archives.
    owner.recovered_campaign_verdict(root, source, **pin)
    while True:
        history = seal.load_verified_history(root, plan,
            pinned_source_commit=config['sourceCommit'],
            pinned_fingerprint=config['hostKeyFingerprint'])
        for prior in history:
            if (prior['status'] in ('completed', 'preparation-completed')
                    and not owner.verify_completed_cleanup_receipts(
                        root, source, plan, prior)):
                release_completed_attempt(remote, root, source, plan,
                                          prior, history)
        selected = next_campaign_selection(history)
        if selected['status'] == 'complete':
            return owner.recovered_campaign_verdict(root, source, **pin)
        if selected['status'] != 'ready':
            return owner.recovered_campaign_verdict(root, source, **pin)
        group_id = selected['groupId']
        if case_group is not None and group_id != case_group:
            return owner.recovered_campaign_verdict(root, source, **pin)
        suite = 'suite-' + str(start['firstSuiteNumber'] + len(history))
        if _SUITE.fullmatch(suite) is None:
            raise ValueError('pr315-coordinator-suite-id-invalid')
        absent = remote.call(CT,
            ['test', '!', '-e', CT_TASK + '/' + suite], check=False)
        if absent.returncode != 0:
            raise ValueError('pr315-coordinator-unsealed-attempt-reconciliation-required')
        task_qemu_inventory(remote)
        required = required_attempt_bytes(remote, config)
        capacity = capacity_preflight(remote, config, root, required,
            start['macAvailableAtStartBytes'])
        _exclusive_json(root / ('capacity-' + suite + '.private.json'),
                        capacity)
        ready = admit_and_watch(remote, suite, config['sourceCommit'],
                                config['sourceSnapshot'])
        retired_files = None
        if group_id == 'authority' and selected['action'] == 'selected-group':
            verify_retired_preparation_for_resume(root, plan, history)
            parent = CT_TASK + '/campaign-frozen/'
            retired_files = tuple(parent + name for name in (
                'retired-authority-input.private.json',
                'retired-authority-handoff.private.json',
                'campaign-ed25519.pub'))
            for local, target, private in zip((
                    root / 'retired-authority-input.private.json',
                    root / 'retired-authority-handoff.private.json',
                    root / (seal.KEY_NAME + '.pub')),
                    retired_files, (True, True, False)):
                _put_frozen_input(remote, local, target, private=private)
        execution = run_selected_attempt(remote, config, suite, group_id,
            retired_prep=(selected['action'] ==
                          'retired-authority-preparation'),
            retired_files=retired_files)
        finished_watcher(remote, config, suite, ready)
        staging, stage_digest = stage_full_attempt(remote, config, suite,
                                                     root)
        if selected['action'] == 'retired-authority-preparation':
            if (execution['runnerExitCode'] != 0
                    or execution['assessment'].get('status') !=
                        'retired-authority-preparation-executed'):
                _seal_failed_attempt(root, config, plan, suite,
                    group_id, staging, stage_digest)
                return owner.recovered_campaign_verdict(root, source, **pin)
            completed_receipt = _archive_retired_preparation(
                remote, root, config, plan, suite)
        elif selected_group_complete(plan, group_id,
                                     execution['assessment']):
            completed_receipt = _archive_case_group(remote, root, source,
                config, plan, suite, group_id, history)
        else:
            _seal_failed_attempt(root, config, plan, suite,
                group_id, staging, stage_digest)
            return owner.recovered_campaign_verdict(root, source, **pin)
        sealed_history = seal.load_verified_history(root, plan,
            pinned_source_commit=config['sourceCommit'],
            pinned_fingerprint=config['hostKeyFingerprint'])
        release_completed_attempt(remote, root, source, plan,
                                  completed_receipt, sealed_history)
        # Refuse to continue if any sealed case/archive changed during the run.
        owner.recovered_campaign_verdict(root, source, **pin)
        if case_group == group_id:
            return owner.recovered_campaign_verdict(root, source, **pin)


def main(argv=None):
    """Default to all 21 groups; probe and preparation never allocate a VM."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    purposes = parser.add_mutually_exclusive_group()
    purposes.add_argument('--probe', action='store_true')
    purposes.add_argument('--initialize-config', type=Path)
    purposes.add_argument('--prepare-remote', action='store_true')
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--remote-known-hosts', type=Path)
    parser.add_argument('--first-suite-number', type=int)
    parser.add_argument('--case-group', choices=tuple(dict(campaign.GROUPS)))
    args = parser.parse_args(argv)
    try:
        if args.initialize_config is not None:
            if (args.identity is None or args.remote_known_hosts is None
                    or args.first_suite_number is None
                    or args.case_group is not None):
                raise ValueError('pr315-coordinator-initialization-input-required')
            config = json.loads(args.initialize_config.read_bytes())
            identity = json.loads(args.identity.read_bytes())
            planned = initialize_campaign(args.campaign_root, args.source,
                config, identity, args.remote_known_hosts,
                args.first_suite_number)
            print(json.dumps({'schemaVersion': 2,
                'status': 'frozen-campaign-prepared-not-executed',
                'campaignPlanDigest': planned['planDigest'],
                'installedWorkloadAcceptanceSatisfied': False},
                sort_keys=True))
            return 78
        root, source, plan, start, config = frozen_campaign_context(
            args.campaign_root, args.source)
        remote = Remote(root / 'remote-known-hosts.private')
        if args.prepare_remote:
            if args.case_group is not None:
                raise ValueError('pr315-coordinator-preparation-group-invalid')
            task_qemu_inventory(remote)
            exists = remote.call(CT,
                ['test', '-e', config['sourceSnapshot']], check=False)
            if exists.returncode not in (0, 1):
                raise ValueError('pr315-source-snapshot-existence-unavailable')
            required = required_attempt_bytes(remote, config,
                source_override=CT_LIVE_SOURCE if exists.returncode == 1
                else None)
            if exists.returncode == 1:
                required += source_snapshot_reservation_bytes(remote)
            capacity_preflight(remote, config, root, required,
                start['macAvailableAtStartBytes'])
            prepare_source_snapshot(remote, config, capacity_checked=True)
            published = publish_frozen_campaign(remote, root, config)
            print(json.dumps({'schemaVersion': 2,
                'status': 'frozen-remote-inputs-prepared-not-executed',
                'campaignPlanDigest': plan['planDigest'],
                'inputDigests': published,
                'installedWorkloadAcceptanceSatisfied': False},
                sort_keys=True))
            return 78
        if args.probe:
            source_preflight(remote, config)
            task_qemu_inventory(remote)
            required = required_attempt_bytes(remote, config)
            capacity_preflight(remote, config, root, required,
                start['macAvailableAtStartBytes'])
            print(json.dumps({'schemaVersion': 2,
                'status': 'prerequisites-present-not-executed',
                'campaignPlanDigest': plan['planDigest'],
                'installedWorkloadAcceptanceSatisfied': False},
                sort_keys=True))
            return 78
        result = run_campaign(root, source, case_group=args.case_group)
        print(json.dumps(result, sort_keys=True))
        return 0 if result['installedWorkloadAcceptanceSatisfied'] is True else 78
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        detail = str(error)
        reason = (detail if re.fullmatch(r'pr315-[a-z0-9-]{1,126}', detail)
                  else type(error).__name__)
        print(json.dumps({'schemaVersion': 2, 'status': 'incomplete',
            'reason': reason,
            'installedWorkloadAcceptanceSatisfied': False},
            sort_keys=True))
        return 78 if args.probe else 2


if __name__ == '__main__':
    raise SystemExit(main())
