"""Fixed private volatile diagnostics for the disposable workload administrator kit.

These observations are not acceptance records or a runtime restore format. The caller owns
cleanup verification; a missing cgroup is never interpreted here as proof of quiescence.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

import runtime_snapshot as snapshot

ROOT = Path('/var/lib/cryptad-restricted-workload')
ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
SENTINEL = 'pr315-retention-sentinel'
MAX_RECORD = 32768
MAX_OUTPUT = 64 * 1024
MAX_WRAPPER_LOG = 2 * 1024 * 1024
WRAPPER_TAIL = 4096
OBSERVER_EXPERIMENTS = Path('/var/lib/cryptad-cross-version/experiments')
MAX_OBSERVER_FCP_LOG = 16 * 1024 * 1024
OBSERVER_FCP_TAIL = 2048
CAMPAIGN_FIELDS = ('generation', 'bootId', 'state', 'deadlineMonotonicNs', 'usedOperations')
ROLE_FIELDS = ('generation', 'bootId', 'state', 'managerInvocation', 'cgroupIdentity', 'stopReason',
               'previousStopGeneration')
STOP_FIELDS = ('schemaVersion', 'role', 'campaign', 'generation', 'bootId', 'managerInvocation',
               'cgroupIdentity', 'helperPid', 'helperStartTimeTicks', 'startedMonotonicNs',
               'observedMonotonicNs', 'membership', 'descendantCgroups')
EXCHANGE_CASES = ('own-management', 'dynamic-app-bootstrap')
EXCHANGE_FIELDS = ('schemaVersion', 'kind', 'caseId', 'method', 'role', 'managerInvocation',
                   'bootId', 'cgroupIdentity', 'requestDigest', 'responseDigest',
                   'startedMonotonicNs', 'finishedMonotonicNs', 'serverRequests')
ROLE_PROBE_ACTOR_FIELDS = frozenset(('hostPid', 'hostParentPid', 'pidNamespace',
    'networkNamespaceIdentity', 'mountNamespaceIdentity', 'userNamespaceIdentity',
    'namespacePids', 'startTicks', 'executableDigest', 'rssBytes', 'processThreads',
    'noNewPrivileges', 'effectiveCapabilities'))
FNP_COUNTER_NAMES = frozenset({*(f'fnp_role{index}_to_relay' for index in range(3)),
                               *(f'fnp_relay_to_role{index}' for index in range(3))})


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _installed(workload):
    if os.geteuid() != 0 or workload.ROOT != ROOT or tuple(workload.ROLES) != ROLES:
        raise ValueError('workload-evidence-fixed-administrator-required')


def _wait(pid, deadline):
    while True:
        child, status = os.waitpid(pid, os.WNOHANG)
        if child == pid:
            return status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('workload-sentinel-child-timeout')
        time.sleep(min(.02, remaining))


def _create(parent, raw):
    """The caller has already selected and pinned the one fixed state directory."""
    fd = os.open(SENTINEL, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    try:
        if os.write(fd, raw) != len(raw):
            raise ValueError('workload-sentinel-short-write')
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare_sentinel(workload):
    """After prepare(), before role start: create only a new synthetic 32-byte subject."""
    _installed(workload)
    user = workload.account('candidate-sender')
    if user.pw_uid <= 0 or user.pw_gid <= 0:
        raise ValueError('workload-sentinel-role-owner-invalid')
    if any(workload.read(ROOT / 'authority' / (role + '.json')).get('state') != 'prepared'
           for role in ROLES):
        raise ValueError('workload-sentinel-before-launch-required')
    raw = os.urandom(32)
    root = ROOT / 'state/candidate-sender'
    # No candidate process has run yet. Pin all ancestors and the selected tmpfs before
    # dropping privileges, then create the exclusive leaf as its actual selected owner.
    with snapshot._directory(root) as parent:
        info = os.fstat(parent)
        if (info.st_uid != user.pw_uid or info.st_gid != user.pw_gid
                or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077):
            raise ValueError('workload-sentinel-state-owner-invalid')
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(user.pw_gid)
                os.setuid(user.pw_uid)
                os.umask(0o077)
                _create(parent, raw)
                os._exit(0)
            except BaseException:
                os._exit(1)
        try:
            status = _wait(pid, time.monotonic() + 5)
        except TimeoutError:
            os.kill(pid, signal.SIGKILL)
            _wait(pid, time.monotonic() + 5)
            raise
        if status != 0:
            raise ValueError('workload-sentinel-creation-failed')
    actual = snapshot.read_file(root, SENTINEL, maximum=32, timeout=2)
    if actual != raw:
        raise ValueError('workload-sentinel-initial-observation-mismatch')
    return _digest(raw)


def _record(root, name, fields, deadline):
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {'status': 'capture-deadline'}
        raw = snapshot.read_file(root, name, maximum=MAX_RECORD, timeout=min(2, remaining))
        value = json.loads(raw)
        if not isinstance(value, dict):
            return {'status': 'invalid-record'}
        # No candidate values, tokens, handles, selections or arbitrary role-tree entries.
        projection = {key: value[key] for key in fields if key in value}
        if any(type(item) not in (str, int, type(None)) for key, item in projection.items()
               if key != 'cgroupIdentity'):
            return {'status': 'invalid-record'}
        if 'cgroupIdentity' in projection and not (
                projection['cgroupIdentity'] is None or
                isinstance(projection['cgroupIdentity'], list)
                and len(projection['cgroupIdentity']) == 2
                and all(type(part) is int and part >= 0 for part in projection['cgroupIdentity'])):
            return {'status': 'invalid-record'}
        return {'status': 'captured', 'record': projection}
    except (OSError, ValueError, UnicodeError):
        return {'status': 'unavailable-or-unsafe'}


def _wrapper_excerpt(raw, deadline):
    """Select bounded private diagnostic lines; candidate text does not authenticate severity."""
    chunks = []
    size = 0
    offset = 0
    truncated = False
    status = 'captured'
    while offset < len(raw):
        if time.monotonic() >= deadline:
            status = 'capture-deadline'
            truncated = True
            break
        end = raw.find(b'\n', offset)
        end = len(raw) if end < 0 else end + 1
        line = raw[offset:end]
        offset = end
        selected = (re.match(rb' *(?:ERROR|FATAL|WARN) *\| *wrapper *\|', line)
                    or re.match(rb' *[A-Z]{1,16} *\| *jvm [0-9]{1,10} *\|', line))
        if not selected or re.search(rb'\b(?:Command|JavaCommandLine)\b', line):
            continue
        available = 8192 - size
        chunks.append(line[:available])
        size += min(len(line), available)
        if len(line) > available or size == 8192:
            truncated = len(line) > available or offset < len(raw)
            break
    return {'status': status, 'classification': 'candidate-origin-private-diagnostic-not-acceptance',
            'sizeBytes': size, 'truncated': truncated,
            'contentBase64': base64.b64encode(b''.join(chunks)).decode('ascii')}


def _wrapper_log(root, role, deadline):
    """Snapshot one fixed candidate-origin log safely; retain only its bounded private tail."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'state' / role / 'logs', 'wrapper.log',
                                 maximum=MAX_WRAPPER_LOG, timeout=min(2, remaining))
        tail = raw[-WRAPPER_TAIL:]
        return {'status': 'captured', 'classification': 'candidate-origin-private-diagnostic-not-acceptance',
            'sizeBytes': len(raw), 'tailBytes': len(tail), 'truncated': len(tail) < len(raw),
            'tailBase64': base64.b64encode(tail).decode('ascii'),
            'excerpt': _wrapper_excerpt(raw, deadline)}
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}


def _fatal_sections(raw, deadline):
    """Select instruction hex rows and explicitly labelled CPU lines, never adjacent sections."""
    selected = {'instructions': bytearray(), 'cpu': bytearray()}
    limits = {'instructions': 2048, 'cpu': 1024}
    truncated = {key: False for key in selected}
    expired = False
    in_instructions = False
    instruction_header = b''
    offset = 0
    while offset < len(raw):
        if time.monotonic() >= deadline:
            expired = True
            break
        end = raw.find(b'\n', offset)
        end = len(raw) if end < 0 else end + 1
        line = raw[offset:end]
        offset = end
        key = None
        if line.startswith(b'Instructions:'):
            header = re.fullmatch(rb'Instructions:(?: \(pc=(0x[0-9a-fA-F]{1,16})\))?\r?\n?', line)
            in_instructions = header is not None
            instruction_header = (b'Instructions:' + (b' (pc=' + header[1].lower() + b')'
                                  if header is not None and header[1] else b'') + b'\n')
        elif in_instructions:
            # HotSpot's highlighted dump prefixes rows with two spaces or =>. The
            # optional ASCII column follows three spaces; retain only parsed hex.
            row = re.fullmatch(rb'(?:  |=>)?(0x[0-9a-fA-F]{1,16}):[ \t]*(.*?)\r?\n?', line)
            hex_part = row[2].split(b'   ', 1)[0].rstrip(b' \t') if row else b''
            if re.fullmatch(rb'[0-9a-fA-F]{2}(?:[ \t][0-9a-fA-F]{2}){0,63}', hex_part):
                normalized = row[1].lower() + b': ' + b' '.join(hex_part.lower().split()) + b'\n'
                line = instruction_header + normalized
                instruction_header = b''
                key = 'instructions'
            else:
                in_instructions = False
        if key is None and line.startswith((b'CPU:', b'CPU Description:', b'CPU Features:')):
            key = 'cpu'
        if key is not None:
            available = limits[key] - len(selected[key])
            selected[key].extend(line[:available])
            truncated[key] |= len(line) > available
    return {key: {'status': 'capture-deadline' if expired else 'captured' if value else 'not-found',
                  'sizeBytes': len(value), 'truncated': truncated[key] or expired,
                  'contentBase64': base64.b64encode(value).decode('ascii')}
            for key, value in selected.items()}


def _fatal_logs(root, role, deadline):
    """Inspect only the fixed possible JVM fallback directory, not an asserted crash location."""
    if time.monotonic() >= deadline:
        return {'status': 'capture-deadline'}
    directory = root / 'state' / role / 'tmp'
    try:
        with snapshot._directory(directory) as descriptor:
            names = []
            with os.scandir(descriptor) as entries:
                for count, entry in enumerate(entries, 1):
                    if time.monotonic() >= deadline:
                        return {'status': 'capture-deadline'}
                    if count > 64:
                        return {'status': 'too-many-directory-entries'}
                    if re.fullmatch(r'hs_err_pid[0-9]{1,10}\.log', entry.name):
                        names.append(entry.name)
            result = {'status': 'none' if not names else
                      'too-many-matching-files' if len(names) > 2 else 'captured',
                      'classification': 'candidate-origin-private-diagnostic-not-acceptance',
                      'locationProven': False, 'matchedFiles': len(names), 'files': []}
            for name in sorted(names)[:2]:
                row = {'name': name}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    row['status'] = 'capture-deadline'
                else:
                    try:
                        raw = snapshot.read_file(directory, name, maximum=MAX_WRAPPER_LOG,
                                                 timeout=min(2, remaining))
                        header = raw[:4096]
                        row.update(status='captured', sizeBytes=len(raw), headBytes=len(header),
                                   truncated=len(header) < len(raw),
                                   headBase64=base64.b64encode(header).decode('ascii'),
                                   sections=_fatal_sections(raw, deadline))
                    except (OSError, ValueError):
                        row['status'] = 'unavailable-or-unsafe'
                result['files'].append(row)
        return result
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}


def _observer_fcp_log(root, role, deadline):
    """Read only one fixed observer transcript; its content is never acceptance authority."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root, 'fcp-' + role + '.log', maximum=MAX_OBSERVER_FCP_LOG,
                                 timeout=min(2, remaining))
        tail = raw[-OBSERVER_FCP_TAIL:]
        return {'status': 'captured', 'classification': 'observer-origin-private-diagnostic-not-acceptance',
                'sizeBytes': len(raw), 'tailBytes': len(tail), 'truncated': len(tail) < len(raw),
                'tailBase64': base64.b64encode(tail).decode('ascii')}
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}


def _fnp_counter_pair(root, deadline):
    """Project only the fixed, root-owned six-link counter pair after cleanup."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'fnp-content-probe.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'caseId', 'role',
                                  'managerInvocation', 'before', 'after'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-fnp-counter-pair'
                or value['caseId'] != 'fnp-content-retrieval'
                or value['role'] != 'candidate-recipient'
                or re.fullmatch('[0-9a-f]{32}', str(value['managerInvocation'])) is None):
            raise ValueError('fnp-counter-pair-invalid')
        before, after = value['before'], value['after']
        for sample in (before, after):
            if (not isinstance(sample, dict)
                    or set(sample) != {'schemaVersion', 'kind', 'policyDigest', 'bootId',
                                      'switchNamespaceIdentity', 'observedMonotonicNs', 'counters'}
                    or sample['schemaVersion'] != 1 or sample['kind'] != 'pr315-fixed-fnp-counters'
                    or re.fullmatch('[0-9a-f]{64}', str(sample['policyDigest'])) is None
                    or not isinstance(sample['bootId'], str)
                    or not isinstance(sample['switchNamespaceIdentity'], list)
                    or len(sample['switchNamespaceIdentity']) != 2
                    or any(type(part) is not int or part < 1 for part in sample['switchNamespaceIdentity'])
                    or type(sample['observedMonotonicNs']) is not int or sample['observedMonotonicNs'] <= 0
                    or not isinstance(sample['counters'], dict)
                    or set(sample['counters']) != FNP_COUNTER_NAMES):
                raise ValueError('fnp-counter-sample-invalid')
            for counter in sample['counters'].values():
                if (not isinstance(counter, dict) or set(counter) != {'packets', 'bytes'}
                        or any(type(counter[key]) is not int or counter[key] < 0
                               for key in ('packets', 'bytes'))):
                    raise ValueError('fnp-counter-value-invalid')
        if (any(before[key] != after[key] for key in
                ('policyDigest', 'bootId', 'switchNamespaceIdentity'))
                or before['observedMonotonicNs'] >= after['observedMonotonicNs']):
            raise ValueError('fnp-counter-epoch-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _probe_app_result(root, deadline, name='pr315-probe-result.json'):
    """Project only the signed app's fixed candidate-origin syscall result."""
    if name not in ('pr315-probe-result.json', 'pr315-probe-result-first.json',
                    'pr315-probe-result-second.json'):
        raise ValueError('probe-app-result-selection-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'state/candidate-sender/data/node/apps/data/pr315-probe',
                                 name, maximum=2048, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'pid', 'uid', 'gid',
                                  'startedMonotonicNs', 'namespaceInodes', 'mountEscape'}
                or value['schemaVersion'] != 1 or value['kind'] != 'pr315-signed-apphost-probe'
                or any(type(value[key]) is not int or value[key] <= 0 for key in
                       ('pid', 'uid', 'gid', 'startedMonotonicNs'))
                or not isinstance(value['namespaceInodes'], dict)
                or set(value['namespaceInodes']) != {'mnt', 'pid', 'net', 'user'}
                or any(type(part) is not int or part <= 0 for part in
                       value['namespaceInodes'].values())):
            raise ValueError('probe-app-result-invalid')
        probe = value['mountEscape']
        if (not isinstance(probe, dict)
                or set(probe) != {'operation', 'startedMonotonicNs', 'finishedMonotonicNs',
                                  'returnCode', 'errno'}
                or probe['operation'] != 'unshare-mount'
                or any(type(probe[key]) is not int or probe[key] <= 0 for key in
                       ('startedMonotonicNs', 'finishedMonotonicNs'))
                or probe['startedMonotonicNs'] >= probe['finishedMonotonicNs']
                or type(probe['returnCode']) is not int or probe['returnCode'] not in (-1, 0)
                or probe['errno'] not in (None, 'EPERM', 'EACCES', 'UNKNOWN')):
            raise ValueError('probe-app-syscall-result-invalid')
        return {'status': 'captured',
                'classification': 'signed-app-candidate-origin-not-acceptance', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _probe_app_log(root, deadline):
    """Keep only a bounded private AppHost log tail after owned cleanup."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'state/candidate-sender/run/node/apps/pr315-probe',
                                 'process.log', maximum=2 * 1024 * 1024,
                                 timeout=min(2, remaining))
        tail = raw[-2048:]
        return {'status': 'captured',
                'classification': 'apphost-process-private-diagnostic-not-acceptance',
                'sizeBytes': len(raw), 'tailBytes': len(tail),
                'truncated': len(tail) < len(raw),
                'tailBase64': base64.b64encode(tail).decode('ascii')}
    except (OSError, ValueError):
        return {'status': 'unavailable-or-unsafe'}


def _probe_kernel_checkpoint(observer_root, deadline):
    """Retain only the fixed observer/controller app epoch before later faults."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(observer_root, 'pr315-probe-kernel.private.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'appId', 'bundleDigest',
                                  'roleKernelRoster', 'roleKernelRosterWindow',
                                  'senderStateBefore', 'probeWorker',
                                  'administratorRecordDigest'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-observer-probe-kernel-checkpoint'
                or value['appId'] != 'pr315-probe'
                or re.fullmatch('sha256:[0-9a-f]{64}', str(value['bundleDigest'])) is None
                or re.fullmatch('[0-9a-f]{64}', str(value['senderStateBefore'])) is None
                or re.fullmatch('[0-9a-f]{64}', str(value['administratorRecordDigest'])) is None
                or not isinstance(value['roleKernelRoster'], dict)
                or not isinstance(value['roleKernelRosterWindow'], dict)
                or not isinstance(value['probeWorker'], dict)):
            raise ValueError('probe-kernel-checkpoint-invalid')
        return {'status': 'captured',
                'classification': 'observer-origin-private-checkpoint-not-acceptance',
                'record': value}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-or-unsafe'}


def _probe_administrator_record(root, deadline):
    """Retain one fixed root-owned live-process record with a closed field set."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'pr315-probe-process.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'caseId', 'role', 'bundleDigest',
                                  'verifiedTree', 'firstResultDigest', 'senderUid', 'senderGid',
                                  'managerInvocation', 'bootId', 'cgroupIdentity',
                                  'stateBefore', 'stateAfter', 'activeBeforeNs', 'activeAfterNs',
                                  'worker', 'sandboxLeader', 'outer'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-probe-process'
                or value['caseId'] != 'namespace-mount-escape'
                or value['role'] != 'candidate-sender'
                or not isinstance(value['worker'], dict)
                or not isinstance(value['sandboxLeader'], dict)
                or not isinstance(value['outer'], dict)
                or any(key not in value['worker'] or key not in value['sandboxLeader']
                       or key not in value['outer'] for key in
                       ('hostPid', 'namespacePids', 'mountNamespaceIdentity',
                        'networkNamespaceIdentity'))):
            raise ValueError('probe-administrator-record-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-or-unsafe'}


def _observer_control_checkpoint(root, deadline):
    """Retain one fixed observer-origin denial transcript without the role handle."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root, 'pr315-observer-control.private.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'caseId', 'actorPid',
                                  'actorStartTicks', 'roleKernelRoster',
                                  'roleKernelRosterWindow', 'senderStateBefore',
                                  'requestDigest', 'responseDigest'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-observer-control-denial-checkpoint'
                or value['caseId'] != 'observer-control'
                or any(type(value[key]) is not int or value[key] <= 1
                       for key in ('actorPid', 'actorStartTicks'))
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('senderStateBefore', 'requestDigest', 'responseDigest'))
                or not isinstance(value['roleKernelRoster'], dict)
                or not isinstance(value['roleKernelRosterWindow'], dict)):
            raise ValueError('observer-control-checkpoint-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-or-unsafe'}


def _observer_control_audit(root, deadline):
    """Retain only the fixed root controller denial and live target projection."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'observer-control-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'caseId', 'actor',
                                  'targetBefore', 'targetAfter', 'senderManagerInvocation',
                                  'senderCgroupIdentity', 'senderStateBefore',
                                  'senderStateAfter', 'requestObservedNs',
                                  'responseSentNs', 'requestDigest', 'responseDigest'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-observer-control-denial'
                or value['caseId'] != 'observer-control'
                or not isinstance(value['actor'], dict)
                or set(value['actor']) != {'pid', 'uid', 'startTicks'}
                or any(not isinstance(value[key], dict) or
                       set(value[key]) != {'invocationId', 'cgroupIdentity', 'bootId',
                                           'observedMonotonicNs'}
                       for key in ('targetBefore', 'targetAfter'))):
            raise ValueError('observer-control-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-or-unsafe'}


def _runner_control_audit(root, deadline):
    """Read one fixed root-observed vmadmin denial of active systemd unit control."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'runner-control-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'actor', 'roleKernelRoster',
                  'roleKernelRosterWindow', 'targetBefore', 'targetAfter',
                  'senderManagerInvocation', 'senderCgroupIdentity',
                  'senderStateBefore', 'senderStateAfter', 'requestStartedNs',
                  'responseObservedNs', 'requestDigest', 'responseDigest',
                  'responseBase64', 'exitCode', 'stdoutBytes'}
        target_fields = {'invocationId', 'cgroupIdentity', 'bootId', 'mainPid',
                         'mainStartTicks', 'observedMonotonicNs'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-runner-control-denial'
                or value['caseId'] != 'runner-control'
                or not isinstance(value['actor'], dict)
                or set(value['actor']) != {'pid', 'uid', 'startTicks'}
                or not isinstance(value['roleKernelRoster'], dict)
                or not isinstance(value['roleKernelRosterWindow'], dict)
                or any(not isinstance(value[key], dict) or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or type(value['exitCode']) is not int or not 1 <= value['exitCode'] <= 255
                or value['stdoutBytes'] != 0
                or any(type(value['actor'][key]) is not int or value['actor'][key] <= 0
                       for key in ('pid', 'uid', 'startTicks'))):
            raise ValueError('runner-control-audit-invalid')
        response = base64.b64decode(value['responseBase64'], validate=True)
        if (not 1 <= len(response) <= 2048
                or value['responseDigest'] != hashlib.sha256(response).hexdigest()
                or not any(marker in response for marker in
                           (b'Interactive authentication required', b'Access denied'))):
            raise ValueError('runner-control-response-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError, binascii.Error):
        return {'status': 'unavailable-or-unsafe'}


def _observer_private_read_audit(root, deadline):
    """Retain the fixed administrator actor and live-target probe, privately."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'observer-private-read-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                  'actorUid',
                  'actorBefore', 'actorAfter', 'roleInvocationBefore',
                  'roleInvocationAfter', 'targetDigestBefore', 'targetDigestAfter',
                  'triggerMonotonicNs', 'attackStartedNs', 'attackFinishedNs',
                  'kernelOpenResult', 'controllerObservedBeforeNs',
                  'controllerObservedAfterNs'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-observer-private-read'
                or value['caseId'] != 'observer-private-read'
                or value['kernelOpenResult'] != {'opened': False, 'errno': 'ENOENT'}
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None for key in
                       ('sourceDigest', 'nonceDigest', 'targetDigestBefore', 'targetDigestAfter'))
                or value['targetDigestBefore'] != value['targetDigestAfter']
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or not isinstance(value['actorBefore'], dict)
                or not isinstance(value['actorAfter'], dict)
                or set(value['actorBefore']) != ROLE_PROBE_ACTOR_FIELDS
                or set(value['actorAfter']) != ROLE_PROBE_ACTOR_FIELDS
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key])) is None for key in
                       ('roleInvocationBefore', 'roleInvocationAfter'))
                or any(type(value[key]) is not int or value[key] <= 0 for key in
                       ('triggerMonotonicNs', 'attackStartedNs', 'attackFinishedNs',
                        'controllerObservedBeforeNs', 'controllerObservedAfterNs'))
                or not value['controllerObservedBeforeNs'] < value['triggerMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['controllerObservedAfterNs']):
            raise ValueError('observer-private-read-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _capture(root, expected, cleanup_complete, *, observer_root=None):
    """Internal acquisition over the fixed selection; tests use synthetic temporary roots."""
    if expected is not None and (not isinstance(expected, str)
            or re.fullmatch('sha256:[0-9a-f]{64}', expected) is None):
        raise ValueError('workload-sentinel-expected-digest-invalid')
    started = time.monotonic_ns()
    result = {'schemaVersion': 1, 'kind': 'pr315-private-volatile-diagnostics',
        'classification': 'synthetic-private-diagnostic-not-acceptance-or-restore',
        'observedWallTimeNs': time.time_ns(), 'startedMonotonicNs': started,
        'cleanupReportedByCaller': cleanup_complete is True,
        'quiescenceIndependentlyEstablished': False,
        'snapshotLimitations': 'fixed-files-not-atomic-not-runtime-continuation',
        'sentinel': {'status': 'not-captured-cleanup-unverified'}, 'controllerRecords': {},
        'exchangeAudits': {case: {'status': 'not-captured-cleanup-unverified'}
                           for case in EXCHANGE_CASES},
        'fnpCounterPair': {'status': 'not-captured-cleanup-unverified'},
        'probeAppResult': {'status': 'not-captured-cleanup-unverified'},
        'probeAppFirstResult': {'status': 'not-captured-cleanup-unverified'},
        'probeAppSecondResult': {'status': 'not-captured-cleanup-unverified'},
        'probeAppLog': {'status': 'not-captured-cleanup-unverified'},
        'probeKernelCheckpoint': {'status': 'not-captured-cleanup-unverified'},
        'probeAdministratorRecord': {'status': 'not-captured-cleanup-unverified'},
        'observerControlCheckpoint': {'status': 'not-captured-cleanup-unverified'},
        'observerControlAudit': {'status': 'not-captured-cleanup-unverified'},
        'runnerControlAudit': {'status': 'not-captured-cleanup-unverified'},
        'observerPrivateReadAudit': {'status': 'not-captured-cleanup-unverified'},
        'observerFcpLogs': ({} if observer_root is None else
                            {role: {'status': 'not-captured-cleanup-unverified'} for role in ROLES}),
        'wrapperLogs': {role: {'status': 'not-captured-cleanup-unverified'} for role in ROLES},
        'fatalLogs': {role: {'status': 'not-captured-cleanup-unverified'} for role in ROLES}}
    if cleanup_complete is True:
        deadline = time.monotonic() + 15
        result['controllerRecords']['campaign'] = _record(root, 'campaign.json', CAMPAIGN_FIELDS, deadline)
        result['controllerRecords']['network'] = _record(root / 'authority', 'network.json',
            ('version', 'bootId', 'phase', 'pending'), deadline)
        for role in ROLES:
            result['controllerRecords'][role] = _record(root / 'authority', role + '.json', ROLE_FIELDS, deadline)
        result['stopReceipts'] = {}
        for role in ROLES:
            receipts = {'current': _record(root / 'authority', role + '-stop.json', STOP_FIELDS, deadline)}
            previous = result['controllerRecords'][role].get('record', {}).get('previousStopGeneration')
            if isinstance(previous, str) and re.fullmatch('[0-9a-f]{64}', previous):
                receipts['previous'] = _record(root / 'authority', role + '-stop-' + previous + '.json',
                                               STOP_FIELDS, deadline)
            result['stopReceipts'][role] = receipts
        for case in EXCHANGE_CASES:
            result['exchangeAudits'][case] = _record(root / 'authority',
                                                     case + '-exchange.json', EXCHANGE_FIELDS, deadline)
        result['fnpCounterPair'] = _fnp_counter_pair(root, deadline)
        result['probeAppResult'] = _probe_app_result(root, deadline)
        result['probeAppFirstResult'] = _probe_app_result(root, deadline,
                                                        'pr315-probe-result-first.json')
        result['probeAppSecondResult'] = _probe_app_result(root, deadline,
                                                         'pr315-probe-result-second.json')
        if observer_root is not None:
            result['probeKernelCheckpoint'] = _probe_kernel_checkpoint(observer_root, deadline)
            result['observerControlCheckpoint'] = _observer_control_checkpoint(observer_root, deadline)
        result['probeAdministratorRecord'] = _probe_administrator_record(root, deadline)
        result['observerControlAudit'] = _observer_control_audit(root, deadline)
        result['runnerControlAudit'] = _runner_control_audit(root, deadline)
        result['observerPrivateReadAudit'] = _observer_private_read_audit(root, deadline)
        if expected is None:
            result['sentinel'] = {'status': 'not-prepared'}
        else:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('workload-evidence-deadline')
                raw = snapshot.read_file(root / 'state/candidate-sender', SENTINEL,
                                         maximum=32, timeout=min(2, remaining))
                actual = _digest(raw)
                result['sentinel'] = {'status': 'matched' if len(raw) == 32 and actual == expected else 'changed',
                                      'expectedDigest': expected, 'observedDigest': actual, 'sizeBytes': len(raw)}
            except (OSError, ValueError):
                result['sentinel'] = {'status': 'unavailable-or-unsafe', 'expectedDigest': expected}
        # Crash headers and instruction sections precede routine transcript volume. They
        # remain untrusted private diagnostics and share the same deadline/output ceiling.
        for role in ROLES:
            result['fatalLogs'][role] = _fatal_logs(root, role, deadline)
            if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT - 256:
                result['fatalLogs'][role] = {'status': 'not-captured-output-budget'}
        # The fixed observer transcripts precede lower-priority routine wrapper logs.
        if observer_root is not None:
            for role in ROLES:
                result['observerFcpLogs'][role] = _observer_fcp_log(observer_root, role, deadline)
                if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT - 256:
                    result['observerFcpLogs'][role] = {'status': 'not-captured-output-budget'}
        result['probeAppLog'] = _probe_app_log(root, deadline)
        if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT - 256:
            result['probeAppLog'] = {'status': 'not-captured-output-budget'}
        # Controller projections and the selected sentinel take precedence. The same absolute
        # capture deadline covers logs; reserve the final timestamp and per-role status space.
        for role in ROLES:
            result['wrapperLogs'][role] = _wrapper_log(root, role, deadline)
            if (len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT - 256
                    and 'excerpt' in result['wrapperLogs'][role]):
                result['wrapperLogs'][role]['excerpt'] = {'status': 'not-captured-output-budget'}
            if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT - 256:
                result['wrapperLogs'][role] = {'status': 'not-captured-output-budget'}
    else:
        # Root authority may explain a failed reconciliation. Its fixed files can be
        # sampled safely without claiming role quiescence or reading candidate state.
        deadline = time.monotonic() + 8
        result['snapshotLimitations'] = 'failed-cleanup-root-authority-only-not-quiescent'
        result['controllerRecords']['campaign'] = _record(root, 'campaign.json', CAMPAIGN_FIELDS, deadline)
        result['controllerRecords']['network'] = _record(root / 'authority', 'network.json',
            ('version', 'bootId', 'phase', 'pending'), deadline)
        result['stopReceipts'] = {}
        for role in ROLES:
            result['controllerRecords'][role] = _record(root / 'authority', role + '.json',
                                                       ROLE_FIELDS, deadline)
            result['stopReceipts'][role] = {'current': _record(
                root / 'authority', role + '-stop.json', STOP_FIELDS, deadline)}
        result['observerPrivateReadAudit'] = _observer_private_read_audit(root, deadline)
    result['finishedMonotonicNs'] = time.monotonic_ns()
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > MAX_OUTPUT:
        raise ValueError('workload-evidence-output-limit')
    return result


def capture(workload, expected, cleanup_complete, *, observer_root=None):
    """After trusted cleanup: return private bounded observations, never infer acceptance."""
    _installed(workload)
    if observer_root is not None:
        observer_root = Path(observer_root)
        if (not observer_root.is_absolute() or observer_root.parent != OBSERVER_EXPERIMENTS
                or observer_root.name in {'', '.', '..'}):
            raise ValueError('workload-evidence-observer-root-invalid')
    return _capture(ROOT, expected, cleanup_complete, observer_root=observer_root)
