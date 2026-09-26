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
MAX_OUTPUT = 128 * 1024
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


def _provider_app_result(root, deadline):
    """Read only the signed child candidate-origin provider syscall result."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(
            root / 'state/candidate-sender/data/node/apps/data/pr315-probe',
            'pr315-provider-result.json', maximum=2048,
            timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
                'startedMonotonicNs', 'finishedMonotonicNs',
                'targetPathDigest', 'outcome'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-signed-provider-authority-probe'
                or value['caseId'] != 'provider-authority'
                or re.fullmatch('[0-9a-f]{64}', str(value['nonce'])) is None
                or re.fullmatch('[0-9a-f]{64}', str(value['targetPathDigest'])) is None
                or any(type(value[key]) is not int or value[key] <= 0
                       for key in ('pid', 'uid', 'gid', 'startedMonotonicNs',
                                   'finishedMonotonicNs'))
                or value['startedMonotonicNs'] >= value['finishedMonotonicNs']
                or value['outcome'] not in (
                    {'opened': False, 'errno': 'ENOENT'},
                    {'opened': False, 'errno': 'EACCES'},
                    {'opened': False, 'errno': 'EPERM'})):
            raise ValueError('provider-app-result-invalid')
        return {'status': 'captured',
                'classification': 'signed-app-candidate-origin-not-acceptance',
                'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _sibling_app_result(root, deadline):
    """Read only one fixed signed-AppHost network probe from managed app data."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(
            root / 'state/candidate-sender/data/node/apps/data/pr315-probe',
            'pr315-sibling-app-result.json', maximum=2048,
            timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {
                'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid', 'gid',
                'startedMonotonicNs', 'finishedMonotonicNs', 'sourcePort',
                'targetEndpointDigest', 'outcome'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-signed-sibling-app-probe'
                or value['caseId'] != 'sibling-app'
                or re.fullmatch('[0-9a-f]{64}', str(value['nonce'])) is None
                or value['sourcePort'] != 19404
                or value['targetEndpointDigest'] != hashlib.sha256(
                    b'10.231.0.2:19402').hexdigest()
                or any(type(value[key]) is not int or value[key] <= 0
                       for key in ('pid', 'uid', 'gid', 'startedMonotonicNs',
                                   'finishedMonotonicNs'))
                or value['startedMonotonicNs'] >= value['finishedMonotonicNs']
                or value['outcome'] not in (
                    {'connected': False, 'phase': 'connect', 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'ENETUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EACCES'})):
            raise ValueError('sibling-app-result-invalid')
        return {'status': 'captured',
                'classification': 'signed-app-candidate-origin-not-acceptance',
                'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _resource_app_record(root, deadline, kind):
    """Read only one fixed signed-app pressure barrier or terminal receipt."""
    names = {'ready': 'pr315-resource-ready.json',
             'result': 'pr315-resource-result.json'}
    if kind not in names:
        raise ValueError('resource-app-record-selection-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(
            root / 'state/candidate-sender/data/node/apps/data/pr315-probe',
            names[kind], maximum=2048, timeout=min(2, remaining))
        value = json.loads(raw)
        common = {'schemaVersion', 'kind', 'caseId', 'nonce', 'pid', 'uid',
                  'startedMonotonicNs', 'spawnedCount', 'forkErrno'}
        fields = (common | {'limitReachedNs'} if kind == 'ready' else
                  common | {'gid', 'finishedMonotonicNs', 'cleanupFinishedNs',
                            'forkLimit', 'reapedCount', 'forcedKillCount',
                            'abnormalExitCount', 'barrierReadyNs',
                            'releaseObservedNs'})
        expected_kind = ('pr315-signed-resource-ready' if kind == 'ready'
                         else 'pr315-signed-resource-exhaustion-probe')
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != expected_kind):
            raise ValueError('resource-app-record-invalid')
        if (value['caseId'] != 'resource-exhaustion'
                or re.fullmatch('[0-9a-f]{64}', str(value['nonce'])) is None
                or any(type(value[key]) is not int or value[key] <= 0
                       for key in ('pid', 'uid', 'startedMonotonicNs',
                                   'spawnedCount'))
                or value['forkErrno'] != 'EAGAIN'):
            raise ValueError('resource-app-record-invalid')
        if kind == 'ready':
            if (type(value['limitReachedNs']) is not int
                    or value['limitReachedNs'] <= value['startedMonotonicNs']):
                raise ValueError('resource-app-ready-invalid')
        elif (value['kind'] != 'pr315-signed-resource-exhaustion-probe'
              or value['forkLimit'] != 600
              or any(type(value[key]) is not int or value[key] < 0
                     for key in ('gid', 'reapedCount', 'forcedKillCount',
                                 'abnormalExitCount'))
              or value['reapedCount'] != value['spawnedCount']
              or value['forcedKillCount'] != 0
              or value['abnormalExitCount'] != 0
              or not value['startedMonotonicNs']
                  < value['finishedMonotonicNs']
                  == value['barrierReadyNs']
                  < value['releaseObservedNs']
                  < value['cleanupFinishedNs']):
            raise ValueError('resource-app-result-invalid')
        return {'status': 'captured',
                'classification': 'signed-app-candidate-origin-not-acceptance',
                'record': value}
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


def _arbitrary_endpoint_checkpoint(root, deadline):
    """Retain the observer's fixed denied selector without its role handle."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root, 'pr315-arbitrary-endpoint.private.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict)
                or set(value) != {'schemaVersion', 'kind', 'caseId', 'actorPid',
                                  'actorStartTicks', 'roleKernelRoster',
                                  'roleKernelRosterWindow',
                                  'requestDigest', 'responseDigest'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-arbitrary-endpoint-denial-checkpoint'
                or value['caseId'] != 'arbitrary-endpoint'
                or any(type(value[key]) is not int or value[key] <= 1
                       for key in ('actorPid', 'actorStartTicks'))
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('requestDigest', 'responseDigest'))
                or not isinstance(value['roleKernelRoster'], dict)
                or not isinstance(value['roleKernelRosterWindow'], dict)):
            raise ValueError('arbitrary-endpoint-checkpoint-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-or-unsafe'}


def _arbitrary_endpoint_audit(root, deadline):
    """Retain root's denied network selector and active recipient FCP controls."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'arbitrary-endpoint-denial.json',
                                 maximum=12288, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'actor', 'targetBefore',
                  'targetAfter', 'senderBefore', 'senderAfter', 'recipientBefore',
                  'recipientAfter', 'recipientControlBeforeNs',
                  'recipientControlAfterNs', 'recipientControlBeforeDigest',
                  'recipientControlAfterDigest', 'endpointSelection', 'denial',
                  'requestObservedNs', 'attackStartedNs', 'attackFinishedNs',
                  'responseSentNs', 'requestDigest', 'responseDigest'}
        role_fields = {'managerInvocation', 'cgroupIdentity', 'bootId',
                       'stateDigest', 'observedMonotonicNs'}
        controller_fields = {'invocationId', 'cgroupIdentity', 'bootId',
                             'observedMonotonicNs'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-arbitrary-endpoint-denial'
                or value['caseId'] != 'arbitrary-endpoint'
                or value['endpointSelection'] != 'sibling-fcp'
                or value['denial'] != 'restricted-workload-network-rejected'
                or not isinstance(value['actor'], dict)
                or set(value['actor']) != {'pid', 'uid', 'startTicks'}
                or any(not isinstance(value[key], dict) or set(value[key]) != role_fields
                       for key in ('senderBefore', 'senderAfter',
                                   'recipientBefore', 'recipientAfter'))
                or any(not isinstance(value[key], dict) or set(value[key]) != controller_fields
                       for key in ('targetBefore', 'targetAfter'))
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('requestDigest', 'responseDigest',
                                   'recipientControlBeforeDigest',
                                   'recipientControlAfterDigest'))):
            raise ValueError('arbitrary-endpoint-audit-invalid')
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


def _observer_private_audit(root, deadline, case_id):
    """Retain one of the two fixed administrator actor and target probes."""
    if case_id not in ('observer-private-read', 'observer-private-write'):
        raise ValueError('observer-private-case-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', case_id + '-denial.json',
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
                or value['kind'] != 'pr315-administrator-' + case_id
                or value['caseId'] != case_id
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


def _fixed_claim_audit(root, deadline, case_id):
    """Capture one root-measured false identity or counter comparison."""
    if case_id not in ('forged-runtime-identity', 'forged-counters'):
        raise ValueError('fixed-claim-case-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', case_id + '-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        common = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                  'actorUid', 'actorBefore', 'actorAfter', 'roleInvocationBefore',
                  'roleInvocationAfter', 'cgroupIdentityBefore', 'cgroupIdentityAfter',
                  'targetActiveBeforeNs', 'targetActiveAfterNs', 'denial',
                  'attackStartedNs', 'attackFinishedNs'}
        extra = ({'claimedHostPid', 'claimedHostUid', 'actualHostPid', 'actualHostUid'}
                 if case_id == 'forged-runtime-identity' else
                 {'claimedMemoryCurrentBytes', 'claimedTasksCurrent',
                  'actualMemoryBefore', 'actualTasksBefore',
                  'actualMemoryAfter', 'actualTasksAfter'})
        if (not isinstance(value, dict) or set(value) != common | extra
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-' + case_id
                or value['caseId'] != case_id
                or value['denial'] != 'kernel-mismatch-observed'
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest'))
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key])) is None
                       for key in ('roleInvocationBefore', 'roleInvocationAfter'))
                or value['roleInvocationBefore'] != value['roleInvocationAfter']
                or not isinstance(value['actorBefore'], dict)
                or not isinstance(value['actorAfter'], dict)
                or set(value['actorBefore']) != ROLE_PROBE_ACTOR_FIELDS
                or set(value['actorAfter']) != ROLE_PROBE_ACTOR_FIELDS
                or value['cgroupIdentityBefore'] != value['cgroupIdentityAfter']
                or any(not isinstance(value[key], list) or len(value[key]) != 2
                       or any(type(part) is not int or part <= 0 for part in value[key])
                       for key in ('cgroupIdentityBefore', 'cgroupIdentityAfter'))
                or any(type(value[key]) is not int or value[key] <= 0 for key in
                       ('actorUid', 'targetActiveBeforeNs', 'targetActiveAfterNs',
                        'attackStartedNs', 'attackFinishedNs'))
                or not value['targetActiveBeforeNs'] < value['attackStartedNs']
                    < value['attackFinishedNs'] < value['targetActiveAfterNs']):
            raise ValueError('fixed-claim-audit-invalid')
        if case_id == 'forged-runtime-identity':
            if (type(value['claimedHostPid']) is not int or value['claimedHostPid'] != 1
                    or type(value['claimedHostUid']) is not int or value['claimedHostUid'] != 0
                    or value['actualHostPid'] != value['actorBefore']['hostPid']
                    or value['actualHostUid'] != value['actorUid']):
                raise ValueError('fixed-identity-claim-invalid')
        elif (type(value['claimedMemoryCurrentBytes']) is not int
                or value['claimedMemoryCurrentBytes'] != 0
                or type(value['claimedTasksCurrent']) is not int
                or value['claimedTasksCurrent'] != 0
                or any(type(value[key]) is not int or value[key] <= 0 for key in
                       ('actualMemoryBefore', 'actualTasksBefore',
                        'actualMemoryAfter', 'actualTasksAfter'))):
            raise ValueError('fixed-counter-claim-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _fixed_role_access_audit(root, deadline, case_id):
    """Capture one fixed candidate syscall against an active role-owned target."""
    roles = {'sibling-data': 'candidate-recipient',
             'package-expectation': 'candidate-sender',
             'cgroup-migration': 'candidate-recipient'}
    if case_id not in roles:
        raise ValueError('fixed-role-access-case-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', case_id + '-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                  'actorUid', 'actorBefore', 'actorAfter',
                  'actorInvocationBefore', 'actorInvocationAfter',
                  'actorCgroupBefore', 'actorCgroupAfter',
                  'targetBefore', 'targetAfter', 'attackStartedNs',
                  'attackFinishedNs', 'kernelOpenResult', 'writtenBytes'}
        target_fields = {'role', 'managerInvocation', 'cgroupIdentity',
                         'observedMonotonicNs', 'controlDigest'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-fixed-role-access-denial'
                or value['caseId'] != case_id
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest'))
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != ROLE_PROBE_ACTOR_FIELDS
                       for key in ('actorBefore', 'actorAfter'))
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key])) is None
                       for key in ('actorInvocationBefore', 'actorInvocationAfter'))
                or value['actorInvocationBefore'] != value['actorInvocationAfter']
                or value['actorCgroupBefore'] != value['actorCgroupAfter']
                or any(not isinstance(value[key], list) or len(value[key]) != 2
                       or any(type(part) is not int or part <= 0 for part in value[key])
                       for key in ('actorCgroupBefore', 'actorCgroupAfter'))
                or any(not isinstance(value[key], dict) or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or value['targetBefore']['role'] != roles[case_id]
                or value['targetAfter']['role'] != roles[case_id]
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key]['managerInvocation'])) is None
                       or re.fullmatch('[0-9a-f]{64}', str(value[key]['controlDigest'])) is None
                       or type(value[key]['observedMonotonicNs']) is not int
                       or value[key]['observedMonotonicNs'] <= 0
                       for key in ('targetBefore', 'targetAfter'))
                or value['targetBefore']['managerInvocation'] !=
                    value['targetAfter']['managerInvocation']
                or value['targetBefore']['cgroupIdentity'] !=
                    value['targetAfter']['cgroupIdentity']
                or value['targetBefore']['controlDigest'] !=
                    value['targetAfter']['controlDigest']
                or any(not isinstance(value[key]['cgroupIdentity'], list)
                       or len(value[key]['cgroupIdentity']) != 2
                       or any(type(part) is not int or part <= 0
                              for part in value[key]['cgroupIdentity'])
                       for key in ('targetBefore', 'targetAfter'))
                or type(value['attackStartedNs']) is not int
                or type(value['attackFinishedNs']) is not int
                or not value['targetBefore']['observedMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['targetAfter']['observedMonotonicNs']
                or type(value['writtenBytes']) is not int or value['writtenBytes'] != 0
                or not isinstance(value['kernelOpenResult'], dict)
                or set(value['kernelOpenResult']) != {'opened', 'errno'}
                or value['kernelOpenResult']['opened'] is not False):
            raise ValueError('fixed-role-access-audit-invalid')
        if (case_id == 'package-expectation' and
                value['kernelOpenResult']['errno'] not in ('EACCES', 'EPERM', 'EROFS')):
            raise ValueError('fixed-package-denial-code-invalid')
        if (case_id != 'package-expectation'
                and value['kernelOpenResult']['errno'] != 'ENOENT'):
            raise ValueError('fixed-role-denial-code-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _resolver_authority_audit(root, deadline):
    """Capture only the fixed root audit of a live resolver canary denial."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', 'resolver-authority-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                  'actorUid', 'actorBefore', 'actorAfter',
                  'actorInvocationBefore', 'actorInvocationAfter',
                  'actorCgroupBefore', 'actorCgroupAfter',
                  'actorStateBefore', 'actorStateAfter',
                  'targetBefore', 'targetAfter', 'targetPathDigest',
                  'attackStartedNs', 'attackFinishedNs', 'kernelOpenResult'}
        target_fields = {'role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                         'mainPid', 'mainStartTicks', 'canaryIdentity',
                         'observedMonotonicNs', 'controlDigest'}
        stable = target_fields - {'observedMonotonicNs'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-resolver-authority-denial'
                or value['caseId'] != 'resolver-authority'
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != ROLE_PROBE_ACTOR_FIELDS
                       for key in ('actorBefore', 'actorAfter'))
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest', 'actorStateBefore',
                                   'actorStateAfter', 'targetPathDigest'))
                or value['actorStateBefore'] != value['actorStateAfter']
                or value['actorInvocationBefore'] != value['actorInvocationAfter']
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key])) is None
                       for key in ('actorInvocationBefore', 'actorInvocationAfter'))
                or value['actorCgroupBefore'] != value['actorCgroupAfter']
                or any(not isinstance(value[key], list) or len(value[key]) != 2
                       or any(type(part) is not int or part <= 0 for part in value[key])
                       for key in ('actorCgroupBefore', 'actorCgroupAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or any(value['targetBefore'][key] != value['targetAfter'][key]
                       for key in stable)
                or any(value[key]['role'] is not None
                       or re.fullmatch('[0-9a-f]{32}', str(value[key]['managerInvocation'])) is None
                       or re.fullmatch('[0-9a-f]{64}', str(value[key]['controlDigest'])) is None
                       or any(type(value[key][name]) is not int or value[key][name] <= 0
                              for name in ('mainPid', 'mainStartTicks', 'observedMonotonicNs'))
                       or any(not isinstance(value[key][name], list)
                              or len(value[key][name]) != 2
                              or any(type(part) is not int or part <= 0
                                     for part in value[key][name])
                              for name in ('cgroupIdentity', 'canaryIdentity'))
                       for key in ('targetBefore', 'targetAfter'))
                or any(type(value[key]) is not int or value[key] <= 0
                       for key in ('attackStartedNs', 'attackFinishedNs'))
                or not value['targetBefore']['observedMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['targetAfter']['observedMonotonicNs']
                or value['kernelOpenResult'] not in (
                    {'opened': False, 'errno': 'ENOENT'},
                    {'opened': False, 'errno': 'EACCES'},
                    {'opened': False, 'errno': 'EPERM'})):
            raise ValueError('resolver-authority-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _provider_authority_audit(root, deadline):
    """Retain only the fixed AppHost actor and live synthetic provider audit."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'provider-authority-denial.json', maximum=16384,
            timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'bundleDigest',
            'nonceDigest', 'actorUid', 'actorBefore', 'actorAfter',
            'senderStateBefore', 'senderStateAfter', 'targetBefore',
            'targetAfter', 'targetPathDigest', 'attackStartedNs',
            'attackFinishedNs', 'kernelOpenResult', 'appResultDigest'}
        actor_fields = {'role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'observedMonotonicNs',
            'sandboxLeader', 'provenance'}
        leader_fields = {'hostPid', 'namespacePids', 'startTicks',
            'executableDigest', 'mountNamespaceIdentity',
            'userNamespaceIdentity', 'networkNamespaceIdentity',
            'pidNamespaceIdentity'}
        target_fields = {'role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'mainPid', 'mainStartTicks',
            'resolverCanaryIdentity', 'resolverControlDigest',
            'providerCanaryIdentity', 'observedMonotonicNs', 'controlDigest'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-provider-authority-denial'
                or value['caseId'] != 'provider-authority'
                or not isinstance(value['bundleDigest'], str)
                or re.fullmatch('sha256:[0-9a-f]{64}', value['bundleDigest']) is None
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('nonceDigest', 'senderStateBefore',
                                   'senderStateAfter', 'targetPathDigest',
                                   'appResultDigest'))
                or value['senderStateBefore'] != value['senderStateAfter']
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != actor_fields
                       or not isinstance(value[key].get('sandboxLeader'), dict)
                       or set(value[key]['sandboxLeader']) != leader_fields
                       or value[key].get('provenance') != 'controller-kernel-sample'
                       for key in ('actorBefore', 'actorAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or any(value['targetBefore'][key] != value['targetAfter'][key]
                       for key in target_fields - {'observedMonotonicNs'})
                or value['targetBefore']['role'] is not None
                or value['targetBefore']['mainPid'] <= 1
                or value['targetBefore']['mainStartTicks'] <= 0
                or value['kernelOpenResult'] not in (
                    {'opened': False, 'errno': 'ENOENT'},
                    {'opened': False, 'errno': 'EACCES'},
                    {'opened': False, 'errno': 'EPERM'})
                or not value['targetBefore']['observedMonotonicNs']
                    < value['actorBefore']['observedMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['actorAfter']['observedMonotonicNs']
                    < value['targetAfter']['observedMonotonicNs']):
            raise ValueError('provider-authority-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _sibling_app_audit(root, deadline):
    """Retain one signed-AppHost SYN with its own kernel DROP counter."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'sibling-app-denial.json', maximum=16384,
            timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'bundleDigest',
            'nonceDigest', 'actorUid', 'actorBefore', 'actorAfter',
            'senderStateBefore', 'senderStateAfter', 'targetBefore',
            'targetAfter', 'counterBefore', 'counterAfter', 'counterName',
            'sourcePort', 'targetEndpointDigest', 'triggerMonotonicNs',
            'attackStartedNs', 'attackFinishedNs', 'kernelConnectResult',
            'appResultDigest'}
        actor_fields = {'role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'observedMonotonicNs',
            'sandboxLeader', 'provenance'}
        leader_fields = {'hostPid', 'namespacePids', 'startTicks',
            'executableDigest', 'mountNamespaceIdentity',
            'userNamespaceIdentity', 'networkNamespaceIdentity',
            'pidNamespaceIdentity'}
        target_fields = {'role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'workerHostPid', 'workerStartTicks',
            'javaHostPid', 'javaStartTicks', 'observedMonotonicNs',
            'controlObservedNs', 'controlDigest', 'appUiOriginDigest'}
        counter_fields = {'schemaVersion', 'kind', 'policyDigest', 'bootId',
            'roleNamespaceIdentity', 'observedMonotonicNs', 'counters'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-sibling-app-denial'
                or value['caseId'] != 'sibling-app'
                or value['bundleDigest'] is None
                or re.fullmatch('sha256:[0-9a-f]{64}', str(value['bundleDigest'])) is None
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('nonceDigest', 'senderStateBefore',
                                   'senderStateAfter', 'targetEndpointDigest',
                                   'appResultDigest'))
                or value['senderStateBefore'] != value['senderStateAfter']
                or value['counterName'] != 'pr315_sibling_app_drop'
                or value['sourcePort'] != 19404
                or value['targetEndpointDigest'] != hashlib.sha256(
                    b'10.231.0.2:19402').hexdigest()
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != actor_fields
                       or not isinstance(value[key]['sandboxLeader'], dict)
                       or set(value[key]['sandboxLeader']) != leader_fields
                       for key in ('actorBefore', 'actorAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != counter_fields
                       for key in ('counterBefore', 'counterAfter'))
                or value['targetBefore']['role'] != 'candidate-recipient'
                or re.fullmatch('[0-9a-f]{64}', str(
                    value['targetBefore']['appUiOriginDigest'])) is None
                or value['kernelConnectResult'] not in (
                    {'connected': False, 'phase': 'connect', 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'ENETUNREACH'},
                    {'connected': False, 'phase': 'connect', 'errno': 'EACCES'})
                or not value['actorBefore']['observedMonotonicNs']
                    < value['targetBefore']['observedMonotonicNs']
                    < value['counterBefore']['observedMonotonicNs']
                    < value['triggerMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['counterAfter']['observedMonotonicNs']
                    < value['actorAfter']['observedMonotonicNs']
                    < value['targetAfter']['observedMonotonicNs']):
            raise ValueError('sibling-app-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _resource_audit(root, deadline):
    """Retain bounded root cgroup-limit and live sibling FCP controls."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'resource-exhaustion-denial.json', maximum=32768,
            timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'bundleDigest',
            'nonceDigest', 'actorUid', 'actorBefore', 'actorAfter',
            'senderStateBefore', 'senderStateAfter',
            'roleBefore', 'roleDuring', 'roleAfter',
            'siblingsBefore', 'siblingsDuring', 'siblingsAfter',
            'ready', 'releasePublishedNs', 'triggerMonotonicNs',
            'attackStartedNs', 'attackFinishedNs',
            'childCleanupFinishedNs', 'childEpochCount',
            'childEpochDigest', 'childEpochsObservedNs',
            'childExitObservedNs', 'kernelLimit', 'limitEventDelta',
            'appResultDigest'}
        actor_fields = {'role', 'hostPid', 'namespacePid', 'namespacePids',
            'startTicks', 'executableDigest', 'mountNamespaceIdentity',
            'outerMountNamespaceIdentity', 'userNamespaceIdentity',
            'pidNamespaceIdentity', 'managerInvocation', 'cgroupIdentity',
            'networkNamespaceIdentity', 'stateDigest', 'observedMonotonicNs',
            'sandboxLeader', 'provenance'}
        role_fields = {'role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'pidsMax', 'pidsCurrent', 'pidsMaxEvents',
            'memoryMaxBytes', 'memoryOomKills', 'observedMonotonicNs'}
        sibling_fields = {'role', 'managerInvocation', 'bootId',
            'cgroupIdentity', 'stateDigest', 'observedMonotonicNs',
            'controlObservedNs', 'controlDigest'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-resource-exhaustion-denial'
                or value['caseId'] != 'resource-exhaustion'
                or value['kernelLimit'] != 'pids.max'
                or re.fullmatch('sha256:[0-9a-f]{64}',
                                str(value['bundleDigest'])) is None
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('nonceDigest', 'senderStateBefore',
                                   'senderStateAfter', 'appResultDigest'))
                or value['senderStateBefore'] != value['senderStateAfter']
                or type(value['limitEventDelta']) is not int
                or value['limitEventDelta'] < 1
                or type(value['childEpochCount']) is not int
                or not 1 <= value['childEpochCount'] <= 600
                or re.fullmatch('[0-9a-f]{64}',
                    str(value['childEpochDigest'])) is None
                or not 0 < value['childEpochsObservedNs']
                    < value['releasePublishedNs']
                    < value['childCleanupFinishedNs']
                    < value['childExitObservedNs']
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != actor_fields
                       or value[key].get('provenance') != 'controller-kernel-sample'
                       for key in ('actorBefore', 'actorAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != role_fields
                       or value[key]['role'] != 'candidate-sender'
                       or value[key]['pidsMax'] != 512
                       or value[key]['memoryMaxBytes'] != 1024**3
                       for key in ('roleBefore', 'roleDuring', 'roleAfter'))
                or value['roleDuring']['pidsMaxEvents'] -
                    value['roleBefore']['pidsMaxEvents'] != value['limitEventDelta']
                or not isinstance(value['ready'], dict)
                or value['ready'].get('kind') != 'pr315-signed-resource-ready'
                or any(not isinstance(value[key], list)
                       or len(value[key]) != 3
                       or any(not isinstance(row, dict)
                              or set(row) != sibling_fields for row in value[key])
                       or {row['role'] for row in value[key]} != {
                            'candidate-recipient', 'previous', 'relay-no-apps'}
                       for key in ('siblingsBefore', 'siblingsDuring', 'siblingsAfter'))
                or not value['actorBefore']['observedMonotonicNs']
                    < value['roleBefore']['observedMonotonicNs']
                    < value['triggerMonotonicNs']
                    < value['attackStartedNs']
                    < value['attackFinishedNs']
                    < value['roleDuring']['observedMonotonicNs']
                    < value['siblingsDuring'][-1]['controlObservedNs']
                    < value['releasePublishedNs']
                    < value['childCleanupFinishedNs']
                    < value['roleAfter']['observedMonotonicNs']
                    < value['actorAfter']['observedMonotonicNs']):
            raise ValueError('resource-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _partial_launch_audit(root, deadline):
    """Retain a real two-role startup, failed previous launch and absent relay."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'partial-launch.json', maximum=32768,
            timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'nonceDigest',
            'administratorBefore', 'administratorAfter',
            'observerUid', 'observerActor', 'senderBefore', 'senderAfter',
            'recipientBefore', 'recipientAfter', 'previousBefore',
            'previousStartMarker', 'previousFault', 'previousActor',
            'previousStopReceipt', 'relayBefore', 'relayAfter',
            'controllerResponse', 'probeStartedNs', 'releasePublishedNs',
            'terminalObservedNs', 'launcherSourceDigest'}
        prepared = {'state': 'prepared', 'generation': None,
                    'managerInvocation': None, 'cgroupIdentity': None}
        before = value['previousBefore']
        relay = value['relayBefore']
        fault = value['previousFault']
        actor = value['previousActor']
        marker = value['previousStartMarker']
        receipt = value['previousStopReceipt']
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-partial-launch'
                or value['caseId'] != 'partial-launch'
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('nonceDigest', 'launcherSourceDigest'))
                or type(value['observerUid']) is not int
                or value['observerUid'] <= 0
                or any(not isinstance(value[key], dict) for key in (
                    'administratorBefore', 'administratorAfter',
                    'observerActor', 'senderBefore', 'senderAfter',
                    'recipientBefore', 'recipientAfter', 'previousBefore',
                    'previousStartMarker', 'previousFault', 'previousActor',
                    'previousStopReceipt', 'relayBefore', 'relayAfter'))
                or any(before.get(key) != expected for key, expected in prepared.items())
                or any(relay.get(key) != expected for key, expected in prepared.items())
                or value['relayAfter'] != relay
                or value['controllerResponse'] not in (
                    'controller-rejected-launch', 'transient-start-response')
                or fault.get('kind') != 'pr315-previous-launch-fault'
                or fault.get('caseId') != 'partial-launch'
                or hashlib.sha256(str(fault.get('nonce')).encode()).hexdigest()
                    != value['nonceDigest']
                or fault.get('sourceDigest') != value['launcherSourceDigest']
                or actor.get('hostPid') != fault.get('pid')
                or actor.get('startTicks') != fault.get('startTicks')
                or marker.get('generation') != receipt.get('generation')
                or marker.get('managerInvocation') != receipt.get('managerInvocation')
                or marker.get('cgroupIdentity') != receipt.get('cgroupIdentity')
                or receipt.get('membership') != 'only-stop-helper'
                or receipt.get('descendantCgroups') != 0
                or not 0 < value['probeStartedNs']
                    < fault['observedMonotonicNs']
                    <= actor['observedMonotonicNs']
                    < value['releasePublishedNs']
                    < receipt['observedMonotonicNs']
                    < value['terminalObservedNs']):
            raise ValueError('partial-launch-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'status': 'unavailable-or-unsafe'}


def _stale_handle_audit(root, deadline):
    """Retain the root-checked three-request observer sequence without raw handles."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'stale-handle-denial.json', maximum=8192,
            timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {
                'schemaVersion', 'kind', 'caseId', 'sourceCommit',
                'retiredInputDigest', 'retiredBootId',
                'retiredHandleDigest', 'successorBootId',
                'observerActor', 'controllerBefore', 'controllerAfter',
                'targetBefore', 'targetAfter',
                'replies', 'finishedMonotonicNs'}
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-stale-handle-denial'
                or value['caseId'] != 'stale-handle'
                or any(re.fullmatch('[0-9a-f]{64}',
                    str(value[key])) is None for key in (
                        'retiredInputDigest', 'retiredHandleDigest'))
                or not isinstance(value['observerActor'], dict)
                or not isinstance(value['controllerBefore'], dict)
                or not isinstance(value['controllerAfter'], dict)
                or not isinstance(value['targetBefore'], dict)
                or not isinstance(value['targetAfter'], dict)
                or not isinstance(value['replies'], list)
                or len(value['replies']) != 3
                or [row.get('label') for row in value['replies']] != [
                    'current-before', 'retired-denied', 'current-after']):
            raise ValueError('stale-handle-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'status': 'unavailable-or-unsafe'}


def _stuck_output_audit(root, deadline):
    """Retain the real role writer, bounded collector timeout and stop receipt."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'stuck-output.json', maximum=32768, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest',
            'administratorBefore', 'administratorAfter',
            'nonceDigest', 'roleBefore', 'actor', 'writer', 'fifoIdentity',
            'collector', 'collectorOutputDigest', 'collectorStartedNs',
            'collectorFinishedNs', 'collectorDenial', 'observerStopActor',
            'observerStopResponse', 'senderStopReceipt',
            'siblingsBefore', 'siblingsAfter', 'terminalObservedNs'}
        actor = value['actor']
        writer = value['writer']
        collector = value['collector']
        receipt = value['senderStopReceipt']
        administrator = value['administratorBefore']
        administrator_after = value['administratorAfter']
        stop_actor = value['observerStopActor']
        stop_response = value['observerStopResponse']
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-stuck-output'
                or value['caseId'] != 'stuck-output'
                or value['collectorDenial'] != 'bounded_process_deadline_exceeded'
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest',
                                   'collectorOutputDigest'))
                or value['collectorOutputDigest'] != hashlib.sha256(
                    b'pr315-stuck-output\n').hexdigest()
                or not isinstance(actor, dict) or not isinstance(writer, dict)
                or not isinstance(collector, dict) or not isinstance(receipt, dict)
                or not isinstance(administrator, dict)
                or not isinstance(administrator_after, dict)
                or not isinstance(stop_actor, dict)
                or stop_actor.get('kind') != 'installed-observer-process'
                or not isinstance(stop_response, dict)
                or stop_response.get('state') != 'quiescent'
                or stop_response.get('managerInvocation') !=
                    receipt.get('managerInvocation')
                or any(administrator.get(key) != administrator_after.get(key)
                       for key in ('pid', 'uid', 'startTicks', 'bootId',
                                   'cgroupIdentity', 'cgroupDigest',
                                   'invocationId', 'sourceDigest'))
                or writer.get('hostParentPid') != actor.get('hostPid')
                or collector.get('uid') != 0
                or collector.get('pid') != collector.get('session')
                or not isinstance(value['fifoIdentity'], list)
                or len(value['fifoIdentity']) != 2
                or receipt.get('membership') != 'only-stop-helper'
                or receipt.get('descendantCgroups') != 0
                or any(not isinstance(value[key], list)
                       or len(value[key]) != 3 for key in
                       ('siblingsBefore', 'siblingsAfter'))
                or not 0 < value['collectorStartedNs']
                    < collector['observedMonotonicNs']
                    < value['collectorFinishedNs']
                    < receipt['startedMonotonicNs']
                    < value['terminalObservedNs']):
            raise ValueError('stuck-output-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'status': 'unavailable-or-unsafe'}


def _late_child_audit(root, deadline):
    """Retain the root stop phase, live owned child and exact terminal receipt."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'late-child.json', maximum=32768, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest',
            'barrierSourceDigest', 'nonceDigest', 'administratorBefore',
            'administratorAfter', 'observerStopActor', 'roleBefore',
            'actor', 'phase', 'childRecord', 'childActor',
            'childExitObservedNs', 'triggerPublishedNs', 'releasePublishedNs',
            'stopReceipt', 'siblingsBefore', 'siblingsAfter',
            'terminalObservedNs'}
        child = value['childRecord']
        actor = value['childActor']
        phase = value['phase']
        receipt = value['stopReceipt']
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-late-child'
                or value['caseId'] != 'late-child'
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'barrierSourceDigest',
                                   'nonceDigest'))
                or not isinstance(child, dict) or not isinstance(actor, dict)
                or not isinstance(phase, dict) or not isinstance(receipt, dict)
                or child.get('kind') != 'pr315-candidate-late-child-created'
                or child.get('caseId') != 'late-child'
                or hashlib.sha256(str(child.get('nonce')).encode()).hexdigest()
                    != value['nonceDigest']
                or actor.get('hostParentPid') != value['actor'].get('hostPid')
                or actor.get('namespacePids', [])[-1:] != [child.get('childPid')]
                or phase.get('kind') != 'pr315-fixed-stop-phase'
                or phase.get('caseId') != 'late-child'
                or phase.get('nonceDigest') != value['nonceDigest']
                or receipt.get('managerInvocation') != phase.get('managerInvocation')
                or receipt.get('cgroupIdentity') != phase.get('cgroupIdentity')
                or receipt.get('membership') != 'only-stop-helper'
                or receipt.get('descendantCgroups') != 0
                or any(not isinstance(value[key], list)
                       or len(value[key]) != 3 for key in
                       ('siblingsBefore', 'siblingsAfter'))
                or not 0 < phase['observedMonotonicNs']
                    < value['triggerPublishedNs']
                    < child['startedMonotonicNs']
                    < actor['observedMonotonicNs']
                    < value['releasePublishedNs']
                    < receipt['observedMonotonicNs']
                    <= value['childExitObservedNs']
                    < value['terminalObservedNs']):
            raise ValueError('late-child-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {'status': 'unavailable-or-unsafe'}


def _hostile_origin_audit(root, deadline):
    """Retain the fixed browser-session origin denial without its raw credential."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority',
            'hostile-app-origin-denial.json', maximum=16384,
            timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest',
            'nonceDigest', 'actorUid', 'actorBefore', 'actorAfter',
            'actorInvocationBefore', 'actorInvocationAfter',
            'actorCgroupBefore', 'actorCgroupAfter',
            'actorStateBefore', 'actorStateAfter', 'targetBefore',
            'targetAfter', 'inputDigest', 'sessionDigest',
            'expectedOriginDigest', 'hostileOriginDigest',
            'targetEndpointDigest', 'controlBefore', 'controlAfter',
            'attackStartedNs', 'attackFinishedNs',
            'attackResponseDigest', 'denialStatus', 'denialCode'}
        targets = {'role', 'managerInvocation', 'bootId', 'cgroupIdentity',
            'workerHostPid', 'workerStartTicks', 'javaHostPid',
            'javaStartTicks', 'observedMonotonicNs',
            'controlResponseDigest'}
        controls = {'status', 'errorCode', 'responseDigest',
            'startedMonotonicNs', 'finishedMonotonicNs'}
        stable = targets - {'observedMonotonicNs', 'controlResponseDigest'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-hostile-app-origin-denial'
                or value['caseId'] != 'hostile-app-origin'
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != ROLE_PROBE_ACTOR_FIELDS
                       for key in ('actorBefore', 'actorAfter'))
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest',
                           'actorStateBefore', 'actorStateAfter', 'inputDigest',
                           'sessionDigest', 'expectedOriginDigest',
                           'hostileOriginDigest', 'targetEndpointDigest',
                           'attackResponseDigest'))
                or value['actorStateBefore'] != value['actorStateAfter']
                or value['actorInvocationBefore'] != value['actorInvocationAfter']
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != targets
                       for key in ('targetBefore', 'targetAfter'))
                or any(value['targetBefore'][key] != value['targetAfter'][key]
                       for key in stable)
                or any(value[key]['role'] != 'candidate-sender'
                       or any(type(value[key][field]) is not int
                              or value[key][field] <= 0 for field in
                              ('workerHostPid', 'workerStartTicks',
                               'javaHostPid', 'javaStartTicks',
                               'observedMonotonicNs'))
                       or re.fullmatch('[0-9a-f]{64}',
                           str(value[key]['controlResponseDigest'])) is None
                       for key in ('targetBefore', 'targetAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != controls
                       or value[key]['status'] != 200
                       or value[key]['errorCode'] is not None
                       for key in ('controlBefore', 'controlAfter'))
                or value['denialStatus'] != 403
                or value['denialCode'] != 'origin_mismatch'
                or not value['targetBefore']['observedMonotonicNs']
                    < value['controlBefore']['startedMonotonicNs']
                    < value['controlBefore']['finishedMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['controlAfter']['startedMonotonicNs']
                    < value['controlAfter']['finishedMonotonicNs']
                    < value['targetAfter']['observedMonotonicNs']):
            raise ValueError('hostile-origin-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _output_artifact_audit(root, deadline, case_id):
    """Retain only one fixed role artifact and actual safe-reader rejection."""
    if case_id not in ('output-symlink', 'output-fifo',
                       'output-hardlink', 'output-flood', 'output-replacement'):
        raise ValueError('output-artifact-case-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', case_id + '-denial.json',
                                 maximum=8192, timeout=min(2, remaining))
        value = json.loads(raw)
        fields = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                  'actorUid', 'actorBefore', 'actorAfter',
                  'actorInvocationBefore', 'actorInvocationAfter',
                  'actorCgroupBefore', 'actorCgroupAfter',
                  'senderStateBefore', 'senderStateAfter',
                  'collectorBefore', 'collectorAfter', 'collectorStartedNs',
                  'collectorFinishedNs', 'collectorDenial',
                  'targetBefore', 'targetAfter', 'artifactIdentity',
                  'artifactOwnerUid', 'triggerMonotonicNs',
                  'attackStartedNs', 'attackFinishedNs'}
        fields |= ({'linkTargetDigest'} if case_id == 'output-symlink' else
                   {'artifactType', 'artifactMode'} if case_id == 'output-fifo' else
                   {'artifactType', 'artifactMode', 'artifactLinkCount'}
                   if case_id == 'output-hardlink' else
                   {'artifactType', 'artifactMode', 'artifactSize', 'artifactDigest'}
                   if case_id == 'output-flood' else
                   {'artifactType', 'artifactMode', 'replacementIdentity',
                    'initialDigest', 'replacementDigest', 'swapTriggerNs',
                    'swapStartedNs', 'swapFinishedNs'})
        collector_fields = {'pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
                            'cgroupDigest', 'invocationId', 'sourceDigest',
                            'observedMonotonicNs'}
        target_fields = {'controlDigest', 'fileIdentity', 'observedMonotonicNs'}
        if case_id == 'output-hardlink':
            target_fields.add('linkCount')
        if (not isinstance(value, dict) or set(value) != fields
                or value['schemaVersion'] != 1
                or value['kind'] != 'pr315-administrator-' + case_id + '-denial'
                or value['caseId'] != case_id
                or value['collectorDenial'] != ('workload-snapshot-changed'
                    if case_id == 'output-replacement'
                    else 'workload-snapshot-file-invalid')
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest'))
                or (case_id == 'output-symlink' and
                    re.fullmatch('[0-9a-f]{64}', str(value['linkTargetDigest'])) is None)
                or (case_id == 'output-fifo' and
                    (value['artifactType'] != 'fifo' or value['artifactMode'] != 0o600))
                or (case_id == 'output-hardlink' and
                    (value['artifactType'] != 'hardlink'
                     or value['artifactMode'] != 0o600
                     or value['artifactLinkCount'] != 2))
                or (case_id == 'output-flood' and
                    (value['artifactType'] != 'regular'
                     or value['artifactMode'] != 0o600
                     or type(value['artifactSize']) is not int
                     or value['artifactSize'] != 65537
                     or value['artifactDigest'] != hashlib.sha256(
                         b'F' * 65537).hexdigest()))
                or (case_id == 'output-replacement' and
                    (value['artifactType'] != 'replacement'
                     or value['artifactMode'] != 0o600
                     or not isinstance(value['replacementIdentity'], list)
                     or len(value['replacementIdentity']) != 2
                     or any(type(part) is not int or part <= 0
                            for part in value['replacementIdentity'])
                     or not isinstance(value['artifactIdentity'], list)
                     or len(value['artifactIdentity']) != 2
                     or value['replacementIdentity'][0] != value['artifactIdentity'][0]
                     or value['replacementIdentity'][1] == value['artifactIdentity'][1]
                     or value['initialDigest'] != hashlib.sha256(b'A' * 32).hexdigest()
                     or value['replacementDigest'] != hashlib.sha256(b'B' * 32).hexdigest()
                     or any(type(value[key]) is not int or value[key] <= 0
                            for key in ('swapTriggerNs', 'swapStartedNs',
                                        'swapFinishedNs'))))
                or type(value['actorUid']) is not int or value['actorUid'] <= 0
                or value['artifactOwnerUid'] != value['actorUid']
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != ROLE_PROBE_ACTOR_FIELDS
                       for key in ('actorBefore', 'actorAfter'))
                or any(not isinstance(value[key], list) or len(value[key]) != 2
                       or any(type(part) is not int or part <= 0 for part in value[key])
                       for key in ('actorCgroupBefore', 'actorCgroupAfter',
                                   'artifactIdentity'))
                or value['actorCgroupBefore'] != value['actorCgroupAfter']
                or value['senderStateBefore'] != value['senderStateAfter']
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('senderStateBefore', 'senderStateAfter'))
                or value['actorInvocationBefore'] != value['actorInvocationAfter']
                or any(re.fullmatch('[0-9a-f]{32}', str(value[key])) is None
                       for key in ('actorInvocationBefore', 'actorInvocationAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != collector_fields
                       or value[key]['uid'] != 0
                       or any(type(value[key][name]) is not int or value[key][name] <= 0
                              for name in ('pid', 'startTicks', 'observedMonotonicNs'))
                       or not isinstance(value[key]['cgroupIdentity'], list)
                       or len(value[key]['cgroupIdentity']) != 2
                       or any(type(part) is not int or part <= 0
                              for part in value[key]['cgroupIdentity'])
                       for key in ('collectorBefore', 'collectorAfter'))
                or any(value['collectorBefore'][key] != value['collectorAfter'][key]
                       for key in collector_fields - {'observedMonotonicNs'})
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != target_fields
                       or re.fullmatch('[0-9a-f]{64}', str(value[key]['controlDigest'])) is None
                       or not isinstance(value[key]['fileIdentity'], list)
                       or len(value[key]['fileIdentity']) != 5
                       or any(type(part) is not int or part < 0
                              for part in value[key]['fileIdentity'])
                       for key in ('targetBefore', 'targetAfter'))
                or value['targetBefore']['controlDigest'] != value['targetAfter']['controlDigest']
                or (case_id != 'output-hardlink' and
                    value['targetBefore']['fileIdentity'] != value['targetAfter']['fileIdentity'])
                or (case_id == 'output-hardlink' and
                    (value['targetBefore']['fileIdentity'][:4] !=
                     value['targetAfter']['fileIdentity'][:4]
                     or value['targetAfter']['fileIdentity'][4] <
                     value['targetBefore']['fileIdentity'][4]
                     or type(value['targetBefore']['linkCount']) is not int
                     or type(value['targetAfter']['linkCount']) is not int
                     or value['targetBefore']['linkCount'] != 1
                     or value['targetAfter']['linkCount'] != 2
                     or value['artifactIdentity'] !=
                     value['targetAfter']['fileIdentity'][:2]))
                or any(type(value[key]) is not int or value[key] <= 0
                       for key in ('collectorStartedNs', 'collectorFinishedNs',
                                   'triggerMonotonicNs', 'attackStartedNs',
                                   'attackFinishedNs'))
                or (case_id == 'output-replacement' and
                    not value['attackFinishedNs'] < value['collectorStartedNs']
                        < value['swapTriggerNs'] < value['swapStartedNs']
                        < value['swapFinishedNs'] < value['collectorFinishedNs'])
                or not value['targetBefore']['observedMonotonicNs']
                    < value['collectorBefore']['observedMonotonicNs']
                    < value['triggerMonotonicNs']
                    < value['attackStartedNs'] < value['attackFinishedNs']
                    < value['collectorStartedNs'] < value['collectorFinishedNs']
                    < value['targetAfter']['observedMonotonicNs']
                    < value['collectorAfter']['observedMonotonicNs']):
            raise ValueError('output-artifact-audit-invalid')
        return {'status': 'captured', 'record': value}
    except (OSError, ValueError, TypeError, KeyError):
        return {'status': 'unavailable-or-unsafe'}


def _output_symlink_audit(root, deadline):
    return _output_artifact_audit(root, deadline, 'output-symlink')


def _output_fifo_audit(root, deadline):
    return _output_artifact_audit(root, deadline, 'output-fifo')


def _output_hardlink_audit(root, deadline):
    return _output_artifact_audit(root, deadline, 'output-hardlink')


def _output_flood_audit(root, deadline):
    return _output_artifact_audit(root, deadline, 'output-flood')


def _output_replacement_audit(root, deadline):
    return _output_artifact_audit(root, deadline, 'output-replacement')


def _sibling_network_audit(root, deadline, case_id):
    """Retain one fixed root audit of role SYN and named kernel DROP counters."""
    if case_id not in ('sibling-fcp', 'sibling-http', 'host-network'):
        raise ValueError('sibling-network-audit-case-invalid')
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'capture-deadline'}
    try:
        raw = snapshot.read_file(root / 'authority', case_id + '-denial.json',
                                 maximum=12288, timeout=min(2, remaining))
        value = json.loads(raw)
        expected = {'schemaVersion', 'kind', 'caseId', 'sourceDigest', 'nonceDigest',
                    'actorUid', 'actorBefore', 'actorAfter',
                    'senderInvocationBefore', 'senderInvocationAfter',
                    'senderCgroupBefore', 'senderCgroupAfter',
                    'senderStateBefore', 'senderStateAfter',
                    'targetBefore', 'targetAfter', 'counterBefore', 'counterAfter',
                    'triggerMonotonicNs', 'attackStartedNs', 'attackFinishedNs',
                    'targetEndpointDigest', 'kernelConnectResult', 'counterName'}
        target_fields = ({'role', 'managerInvocation', 'bootId', 'cgroupIdentity',
                          'observedMonotonicNs', 'controlObservedNs', 'controlDigest'}
                         if case_id != 'host-network' else
                         {'pid', 'uid', 'startTicks', 'bootId', 'cgroupIdentity',
                          'networkNamespace', 'initNetworkNamespace',
                          'addressBinding', 'sourceDigest', 'invocationId',
                          'controlDigest', 'observedMonotonicNs'})
        counter_fields = {'schemaVersion', 'kind', 'policyDigest', 'bootId',
                          'roleNamespaceIdentity', 'observedMonotonicNs', 'counters'}
        if (not isinstance(value, dict) or set(value) != expected
                or value['schemaVersion'] != 1
                or value['kind'] != ('pr315-administrator-host-network-denial'
                    if case_id == 'host-network' else
                    'pr315-administrator-sibling-network-denial')
                or value['caseId'] != case_id
                or value['counterName'] != 'pr315_' + case_id.replace('-', '_') + '_drop'
                or any(re.fullmatch('[0-9a-f]{64}', str(value[key])) is None
                       for key in ('sourceDigest', 'nonceDigest', 'targetEndpointDigest',
                                   'senderStateBefore', 'senderStateAfter'))
                or any(not isinstance(value[key], dict)
                       or set(value[key]) != ROLE_PROBE_ACTOR_FIELDS
                       for key in ('actorBefore', 'actorAfter'))
                or any(not isinstance(value[key], dict) or set(value[key]) != target_fields
                       for key in ('targetBefore', 'targetAfter'))
                or any(not isinstance(value[key], dict) or set(value[key]) != counter_fields
                       for key in ('counterBefore', 'counterAfter'))
                or value['kernelConnectResult'] not in (
                    {'connected': False, 'errno': 'ETIMEDOUT'},
                    {'connected': False, 'errno': 'EHOSTUNREACH'},
                    {'connected': False, 'errno': 'ENETUNREACH'},
                    {'connected': False, 'errno': 'EACCES'})):
            raise ValueError('sibling-network-audit-invalid')
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
        'arbitraryEndpointCheckpoint': {'status': 'not-captured-cleanup-unverified'},
        'arbitraryEndpointAudit': {'status': 'not-captured-cleanup-unverified'},
        'runnerControlAudit': {'status': 'not-captured-cleanup-unverified'},
        'observerPrivateReadAudit': {'status': 'not-captured-cleanup-unverified'},
        'observerPrivateWriteAudit': {'status': 'not-captured-cleanup-unverified'},
        'forgedRuntimeIdentityAudit': {'status': 'not-captured-cleanup-unverified'},
        'forgedCountersAudit': {'status': 'not-captured-cleanup-unverified'},
        'resolverAuthorityAudit': {'status': 'not-captured-cleanup-unverified'},
        'outputSymlinkAudit': {'status': 'not-captured-cleanup-unverified'},
        'outputFifoAudit': {'status': 'not-captured-cleanup-unverified'},
        'outputHardlinkAudit': {'status': 'not-captured-cleanup-unverified'},
        'outputFloodAudit': {'status': 'not-captured-cleanup-unverified'},
        'outputReplacementAudit': {'status': 'not-captured-cleanup-unverified'},
        'siblingDataAudit': {'status': 'not-captured-cleanup-unverified'},
        'siblingFcpAudit': {'status': 'not-captured-cleanup-unverified'},
        'siblingHttpAudit': {'status': 'not-captured-cleanup-unverified'},
        'packageExpectationAudit': {'status': 'not-captured-cleanup-unverified'},
        'cgroupMigrationAudit': {'status': 'not-captured-cleanup-unverified'},
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
        if os.path.lexists(root /
                'state/candidate-sender/data/node/apps/data/pr315-probe/pr315-provider-result.json'):
            result['providerAppResult'] = _provider_app_result(root, deadline)
        if os.path.lexists(root /
                'state/candidate-sender/data/node/apps/data/pr315-probe/pr315-sibling-app-result.json'):
            result['siblingAppResult'] = _sibling_app_result(root, deadline)
        app_data = root / 'state/candidate-sender/data/node/apps/data/pr315-probe'
        if os.path.lexists(app_data / 'pr315-resource-ready.json'):
            result['resourceAppReady'] = _resource_app_record(root, deadline, 'ready')
        if os.path.lexists(app_data / 'pr315-resource-result.json'):
            result['resourceAppResult'] = _resource_app_record(root, deadline, 'result')
        if observer_root is not None:
            result['probeKernelCheckpoint'] = _probe_kernel_checkpoint(observer_root, deadline)
            result['observerControlCheckpoint'] = _observer_control_checkpoint(observer_root, deadline)
            result['arbitraryEndpointCheckpoint'] = _arbitrary_endpoint_checkpoint(
                observer_root, deadline)
        result['probeAdministratorRecord'] = _probe_administrator_record(root, deadline)
        result['observerControlAudit'] = _observer_control_audit(root, deadline)
        result['arbitraryEndpointAudit'] = _arbitrary_endpoint_audit(root, deadline)
        result['runnerControlAudit'] = _runner_control_audit(root, deadline)
        result['observerPrivateReadAudit'] = _observer_private_audit(
            root, deadline, 'observer-private-read')
        result['observerPrivateWriteAudit'] = _observer_private_audit(
            root, deadline, 'observer-private-write')
        result['forgedRuntimeIdentityAudit'] = _fixed_claim_audit(
            root, deadline, 'forged-runtime-identity')
        result['forgedCountersAudit'] = _fixed_claim_audit(root, deadline, 'forged-counters')
        result['resolverAuthorityAudit'] = _resolver_authority_audit(root, deadline)
        if os.path.lexists(root / 'authority/stale-handle-denial.json'):
            result['staleHandleAudit'] = _stale_handle_audit(root, deadline)
        if os.path.lexists(root / 'authority/provider-authority-denial.json'):
            result['providerAuthorityAudit'] = _provider_authority_audit(root, deadline)
        if os.path.lexists(root / 'authority/sibling-app-denial.json'):
            result['siblingAppAudit'] = _sibling_app_audit(root, deadline)
        if os.path.lexists(root / 'authority/resource-exhaustion-denial.json'):
            result['resourceAudit'] = _resource_audit(root, deadline)
        if os.path.lexists(root / 'authority/partial-launch.json'):
            result['partialLaunchAudit'] = _partial_launch_audit(root, deadline)
        if os.path.lexists(root / 'authority/stuck-output.json'):
            result['stuckOutputAudit'] = _stuck_output_audit(root, deadline)
        if os.path.lexists(root / 'authority/late-child.json'):
            result['lateChildAudit'] = _late_child_audit(root, deadline)
        if os.path.lexists(root / 'authority/hostile-app-origin-denial.json'):
            result['hostileAppOriginAudit'] = _hostile_origin_audit(root, deadline)
        result['outputSymlinkAudit'] = _output_symlink_audit(root, deadline)
        result['outputFifoAudit'] = _output_fifo_audit(root, deadline)
        result['outputHardlinkAudit'] = _output_hardlink_audit(root, deadline)
        result['outputFloodAudit'] = _output_flood_audit(root, deadline)
        result['outputReplacementAudit'] = _output_replacement_audit(root, deadline)
        for case_id, field in (('sibling-data', 'siblingDataAudit'),
                               ('package-expectation', 'packageExpectationAudit'),
                               ('cgroup-migration', 'cgroupMigrationAudit')):
            result[field] = _fixed_role_access_audit(root, deadline, case_id)
        result['siblingFcpAudit'] = _sibling_network_audit(root, deadline, 'sibling-fcp')
        result['siblingHttpAudit'] = _sibling_network_audit(root, deadline, 'sibling-http')
        if os.path.lexists(root / 'authority/host-network-denial.json'):
            result['hostNetworkAudit'] = _sibling_network_audit(
                root, deadline, 'host-network')
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
        result['arbitraryEndpointAudit'] = _arbitrary_endpoint_audit(root, deadline)
        result['observerPrivateReadAudit'] = _observer_private_audit(
            root, deadline, 'observer-private-read')
        result['observerPrivateWriteAudit'] = _observer_private_audit(
            root, deadline, 'observer-private-write')
        result['forgedRuntimeIdentityAudit'] = _fixed_claim_audit(
            root, deadline, 'forged-runtime-identity')
        result['forgedCountersAudit'] = _fixed_claim_audit(root, deadline, 'forged-counters')
        result['resolverAuthorityAudit'] = _resolver_authority_audit(root, deadline)
        if os.path.lexists(root / 'authority/stale-handle-denial.json'):
            result['staleHandleAudit'] = _stale_handle_audit(root, deadline)
        if os.path.lexists(root / 'authority/provider-authority-denial.json'):
            result['providerAuthorityAudit'] = _provider_authority_audit(root, deadline)
        if os.path.lexists(root / 'authority/sibling-app-denial.json'):
            result['siblingAppAudit'] = _sibling_app_audit(root, deadline)
        if os.path.lexists(root / 'authority/resource-exhaustion-denial.json'):
            result['resourceAudit'] = _resource_audit(root, deadline)
        if os.path.lexists(root / 'authority/partial-launch.json'):
            result['partialLaunchAudit'] = _partial_launch_audit(root, deadline)
        if os.path.lexists(root / 'authority/stuck-output.json'):
            result['stuckOutputAudit'] = _stuck_output_audit(root, deadline)
        if os.path.lexists(root / 'authority/late-child.json'):
            result['lateChildAudit'] = _late_child_audit(root, deadline)
        if os.path.lexists(root / 'authority/hostile-app-origin-denial.json'):
            result['hostileAppOriginAudit'] = _hostile_origin_audit(root, deadline)
        result['outputSymlinkAudit'] = _output_symlink_audit(root, deadline)
        result['outputFifoAudit'] = _output_fifo_audit(root, deadline)
        result['outputHardlinkAudit'] = _output_hardlink_audit(root, deadline)
        result['outputFloodAudit'] = _output_flood_audit(root, deadline)
        result['outputReplacementAudit'] = _output_replacement_audit(root, deadline)
        for case_id, field in (('sibling-data', 'siblingDataAudit'),
                               ('package-expectation', 'packageExpectationAudit'),
                               ('cgroup-migration', 'cgroupMigrationAudit')):
            result[field] = _fixed_role_access_audit(root, deadline, case_id)
        result['siblingFcpAudit'] = _sibling_network_audit(root, deadline, 'sibling-fcp')
        result['siblingHttpAudit'] = _sibling_network_audit(root, deadline, 'sibling-http')
        if os.path.lexists(root / 'authority/host-network-denial.json'):
            result['hostNetworkAudit'] = _sibling_network_audit(
                root, deadline, 'host-network')
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
