"""Fixed administrator preparation witnesses; these records grant no case pass.

The host consumes them only from its stopped, source-bound private VM archive.
An absent probe marker or an imported JSON document is not a preparation proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import stat
import time

ROLES = ('candidate-sender', 'candidate-recipient', 'previous', 'relay-no-apps')
ELIGIBLE = frozenset((
    'role-boundary', 'authority', 'network-app', 'output-symlink', 'output-fifo',
    'output-hardlink', 'output-replacement', 'output-flood', 'resource-exhaustion',
    'observer-death', 'controller-restart', 'late-child', 'setsid-double-fork',
    'deadline', 'revocation-running', 'cancellation', 'stuck-output', 'cleanup-race'))
KIND = 'pr315-installed-pre-probe-readiness-failure-v1'
ARCHIVE_KIND = 'pr315-launched-preparation-archive-v1'


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _requests(root):
    """Observe the fixed root-owned release directory, without accepting a path."""
    path = root / 'probe-requests'
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or list(path.iterdir())):
        raise ValueError('pr315-preparation-probe-release-not-empty')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': 0,
            'mode': stat.S_IMODE(info.st_mode), 'entries': []}


def _termination(workload):
    """Measure actual manager/kernel absence; never invent unstarted instances."""
    from pr315_workload_evidence import CAMPAIGN_FIELDS, ROLE_FIELDS, STOP_FIELDS
    rows = {}
    uids = set()
    for role in ROLES:
        user = workload.account(role)
        uids.add(user.pw_uid)
        record = workload.read(workload.ROOT / 'authority' / (role + '.json'))
        state = workload.manager(role, 'show')
        group = workload.group(role)
        if (state['ActiveState'] not in ('inactive', 'failed') or state['MainPID'] != '0'
                or not workload.quiescent(role)):
            raise ValueError('pr315-preparation-role-not-terminated')
        present = group.exists()
        events = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines()) if present else None
        if present and events.get('populated') != '0':
            raise ValueError('pr315-preparation-cgroup-populated')
        receipt_path = workload.ROOT / 'authority' / (role + '-stop.json')
        receipt = workload.read(receipt_path) if receipt_path.exists() else None
        launched = record['state'] == 'quiescent'
        if not launched and (record['state'] != 'prepared'
                or any(record.get(key) is not None for key in
                       ('generation', 'managerInvocation', 'cgroupIdentity'))
                or receipt is not None
                or os.path.lexists(workload.ROOT / 'authority' / (role + '-start.json'))):
            raise ValueError('pr315-preparation-unstarted-role-ambiguous')
        rows[role] = {'uid': user.pw_uid, 'launched': launched,
            'campaignGeneration': record['campaign'],
            'authority': {k: record[k] for k in ROLE_FIELDS if k in record},
            'stopReceipt': ({k: receipt[k] for k in STOP_FIELDS if k in receipt}
                            if receipt is not None else None),
            'manager': {key: state[key] for key in ('ActiveState', 'SubState', 'MainPID')},
            'cgroupPresent': present, 'cgroupPopulated': False}
    live = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
            if set(map(int, status['Uid'].split())) & uids:
                live.append(int(proc.name))
        except FileNotFoundError:
            continue
    if live:
        raise ValueError('pr315-preparation-role-process-remains')
    campaign = workload.read(workload.ROOT / 'campaign.json')
    if campaign['state'] != 'terminalizing':
        raise ValueError('pr315-preparation-campaign-not-fenced')
    return {'roles': rows, 'roleUidProcesses': [],
            'campaign': {k: campaign[k] for k in CAMPAIGN_FIELDS if k in campaign},
            'observedMonotonicNs': time.monotonic_ns()}


class PreparationGate:
    """Parent-private latch for the fixed initial four-role preparation only.

    Positive, lost-response and partial-launch operations are deliberately excluded.
    A successful observer return closes the preparation window irreversibly, before
    any selected probe can run. Later readiness failures cannot reopen it.
    """
    def __init__(self, group, workload, epoch, deadline_ns, *, retired=False):
        if group not in ELIGIBLE or os.geteuid() != 0:
            raise ValueError('pr315-preparation-selection-invalid')
        self.group, self.workload, self.epoch = group, workload, epoch
        self.deadline = deadline_ns
        self.phase = 'preparing'
        self.fd = os.pidfd_open(os.getpid())
        try:
            self.before = epoch()
            self.requests = _requests(workload.ROOT)
        except BaseException:
            os.close(self.fd)
            raise
        self.mode = 'retired-authority' if retired else 'group'
        self.nonce = secrets.token_hex(32)
        self.failure = None

    def prepared(self):
        if self.phase != 'preparing':
            raise ValueError('pr315-preparation-transition-invalid')
        self.phase = 'prepared'

    def readiness_failed(self, diagnostics, observer):
        if (self.phase != 'preparing' or 'probeStart' in diagnostics
                or self.failure is not None or select.select([self.fd], [], [], 0)[0]):
            raise ValueError('pr315-preparation-probe-phase-not-established')
        failure = json.loads(diagnostics['observerFailure']['privateTranscript'])
        readiness = failure['readinessDiagnostic']
        independent = diagnostics['readinessAtFailure']
        if (failure.get('observerFailure') != 'RuntimeFailure'
                or failure.get('privateDetail') != 'workload-daemon-readiness-timeout'
                or readiness['stage'] != 'fcp-get-node'
                or readiness['role'] not in ROLES
                or independent['stage'] != readiness['stage']
                or independent['role'] != readiness['role']
                or readiness['failedAtNs'] >= self.deadline):
            raise ValueError('pr315-preparation-not-initial-readiness-failure')
        current = _requests(self.workload.ROOT)
        if current != self.requests:
            raise ValueError('pr315-preparation-probe-release-changed')
        self.failure = {'schemaVersion': 1, 'kind': KIND, 'groupId': self.group,
            'phase': 'pre-probe-readiness-failure', 'probeStarted': False,
            'preparationMode': self.mode,
            'nonce': self.nonce, 'campaignDeadlineMonotonicNs': self.deadline,
            'producerDigest': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'administratorBefore': self.before, 'administratorAtFailure': self.epoch(),
            'observer': copy.deepcopy(observer), 'readiness': copy.deepcopy(readiness),
            'requestsBefore': self.requests, 'requestsAtFailure': current}
        self.phase = 'readiness-failed'

    def after_cleanup(self):
        if self.phase != 'readiness-failed' or self.failure is None:
            return None
        if select.select([self.fd], [], [], 0)[0]:
            raise ValueError('pr315-preparation-administrator-exited')
        requests_after = _requests(self.workload.ROOT)
        if requests_after != self.requests:
            raise ValueError('pr315-preparation-probe-release-changed')
        result = dict(self.failure, administratorAfterCleanup=self.epoch(),
                      requestsAfterCleanup=requests_after,
                      termination=_termination(self.workload))
        self.phase = 'closed'
        return result

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def verify_failure(proof, diagnostics, terminal, group, driver_digest, producer_digest,
                   *, retired=False):
    """Check a host-received witness; this never grants installed acceptance."""
    try:
        fields = {'schemaVersion', 'kind', 'groupId', 'phase', 'probeStarted',
            'nonce', 'campaignDeadlineMonotonicNs', 'producerDigest', 'preparationMode',
            'administratorBefore', 'administratorAtFailure', 'administratorAfterCleanup',
            'observer', 'readiness', 'requestsBefore', 'requestsAtFailure',
            'requestsAfterCleanup', 'termination'}
        if (group not in ELIGIBLE or not isinstance(proof, dict) or set(proof) != fields
                or type(proof['schemaVersion']) is not int
                or proof['schemaVersion'] != 1 or proof['kind'] != KIND
                or proof['groupId'] != group or proof['phase'] != 'pre-probe-readiness-failure'
                or proof['preparationMode'] != ('retired-authority' if retired else 'group')
                or proof['probeStarted'] is not False or 'probeStart' in diagnostics
                or diagnostics.get('cleanup') != 'completed'
                or terminal.get('cleanupReportedByCaller') is not True
                or terminal.get('sentinel', {}).get('status') != 'matched'
                or proof['producerDigest'] != producer_digest
                or type(proof['nonce']) is not str or len(proof['nonce']) != 64
                or any(x not in '0123456789abcdef' for x in proof['nonce'])):
            return False
        epochs = [proof[name] for name in (
            'administratorBefore', 'administratorAtFailure', 'administratorAfterCleanup')]
        stable = {key: value for key, value in epochs[0].items() if key != 'observedMonotonicNs'}
        for actor in epochs:
            if ({key: value for key, value in actor.items() if key != 'observedMonotonicNs'} != stable
                    or type(actor['uid']) is not int or actor['uid'] != 0
                    or type(actor['gid']) is not int or actor['gid'] != 0 or type(actor['pid']) is not int
                    or actor['pid'] < 1 or type(actor['startTicks']) is not int or actor['startTicks'] <= 0
                    or actor['sourceDigest'] != driver_digest
                    or type(actor['observedMonotonicNs']) is not int
                    or actor['observedMonotonicNs'] <= 0
                    or set(actor['namespaces']) != {'pid', 'net', 'mnt', 'user'}
                    or any(type(x) is not int or x <= 0 for x in actor['namespaces'].values())
                    or not isinstance(actor['cgroupIdentity'], list)
                    or len(actor['cgroupIdentity']) != 2
                    or any(type(x) is not int or x <= 0 for x in actor['cgroupIdentity'])
                    or any(type(x) is not int or x < 1 for x in actor['namespacePids'])
                    or actor['namespacePids'][0] != actor['pid']
                    or actor['cgroupDigest'] != _digest({'role': 'preparation-administrator',
                                                       'identity': actor['cgroupIdentity']})):
                return False
        readiness = proof['readiness']
        failure = json.loads(diagnostics['observerFailure']['privateTranscript'])
        observer = proof['observer']
        if (failure.get('readinessDiagnostic') != readiness
                or failure.get('privateDetail') != 'workload-daemon-readiness-timeout'
                or failure.get('observerFailure') != 'RuntimeFailure'
                or diagnostics['readinessAtFailure']['role'] != readiness['role']
                or diagnostics['readinessAtFailure']['stage'] != 'fcp-get-node'
                or readiness['role'] not in ROLES or readiness['stage'] != 'fcp-get-node'
                or any(type(readiness[key]) is not int for key in (
                    'startRequestNs', 'startResponseNs', 'readinessDeadlineNs', 'failedAtNs'))
                or type(observer['uid']) is not int or type(observer['pid']) is not int
                or observer['kind'] != 'installed-observer-process' or observer['uid'] <= 0
                or observer['pid'] == epochs[0]['pid'] or observer['sourceDigest'] != driver_digest
                or observer['bootId'] != epochs[0]['bootId']
                or not epochs[0]['observedMonotonicNs'] <= observer['observedMonotonicNs']
                    <= readiness['startRequestNs'] <= readiness['startResponseNs']
                    < readiness['readinessDeadlineNs'] <= readiness['failedAtNs']
                    <= epochs[1]['observedMonotonicNs'] <= epochs[2]['observedMonotonicNs']
                or readiness['failedAtNs'] >= proof['campaignDeadlineMonotonicNs']):
            return False
        request = proof['requestsBefore']
        if (request != proof['requestsAtFailure'] or request != proof['requestsAfterCleanup']
                or set(request) != {'device', 'inode', 'uid', 'mode', 'entries'}
                or type(request['uid']) is not int or request['uid'] != 0
                or type(request['mode']) is not int or request['mode'] & 0o022
                or request['entries'] != []
                or type(request['device']) is not int or request['device'] < 1
                or type(request['inode']) is not int or request['inode'] < 1):
            return False
        ended = proof['termination']
        campaign = terminal['controllerRecords']['campaign']
        if (set(ended['roles']) != set(ROLES) or ended['roleUidProcesses'] != []
                or campaign['status'] != 'captured' or ended['campaign'] != campaign['record']
                or ended['campaign']['state'] != 'terminalizing'
                or ended['campaign']['bootId'] != epochs[0]['bootId']
                or ended['campaign']['deadlineMonotonicNs'] != proof['campaignDeadlineMonotonicNs']
                or ended['observedMonotonicNs'] < epochs[2]['observedMonotonicNs']):
            return False
        launched = []
        for role in ROLES:
            row = ended['roles'][role]
            retained = terminal['controllerRecords'][role]
            authority = row['authority']
            stop = terminal['stopReceipts'][role]['current']
            if (retained['status'] != 'captured' or retained['record'] != authority
                    or authority['bootId'] != epochs[0]['bootId']
                    or row['campaignGeneration'] != ended['campaign']['generation']
                    or type(row['uid']) is not int or row['uid'] <= 0
                    or row['uid'] == observer['uid'] or type(row['launched']) is not bool
                    or row['manager']['ActiveState'] not in ('inactive', 'failed')
                    or row['manager']['MainPID'] != '0'
                    or row['cgroupPopulated'] is not False):
                return False
            if row['launched']:
                launched.append(role)
                receipt = row['stopReceipt']
                if (authority['state'] != 'quiescent' or stop['status'] != 'captured'
                        or stop['record'] != receipt or receipt['role'] != role
                        or receipt['campaign'] != row['campaignGeneration']
                        or any(receipt[k] != authority[k] for k in
                               ('generation', 'bootId', 'managerInvocation', 'cgroupIdentity'))
                        or receipt['membership'] != 'only-stop-helper' or receipt['descendantCgroups'] != 0):
                    return False
            elif (authority['state'] != 'prepared' or row['stopReceipt'] is not None
                    or stop['status'] == 'captured'
                    or any(authority.get(k) is not None for k in
                           ('generation', 'managerInvocation', 'cgroupIdentity'))):
                return False
        return (readiness['role'] in launched and len({r['uid'] for r in ended['roles'].values()}) == 4
                and launched == list(ROLES[:ROLES.index(readiness['role']) + 1]))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return False


def verify_received_stage(stage, campaign, group, *, retired=False):
    """Rebuild preparation proof from fixed-transport bytes after host stop.

    The coordinator must first rehash its full staging manifest. No record or
    status imported through this function is an installed case result.
    """
    import installation
    import pr312_reference_vm as reference

    try:
        stage = Path(stage)
        attempt = stage / 'attempt-01'
        def read(name, maximum=1024 * 1024):
            path = stage / name
            if not 0 < path.stat().st_size <= maximum:
                raise ValueError('pr315-preparation-record-size-invalid')
            return json.loads(path.read_bytes())
        report = read('attempt-01/attempt.private.json')
        diagnostics = read('attempt-01/pr315-workload-memory.private.json')
        terminal = read('attempt-01/pr315-workload-volatile.private.json')
        monitor = read('host-monitor.private.json')
        stopped = read('host-stop.private.json')
        kit = read('attempt-01/test-kit.private.json')
        identity = campaign['identity']
        actual = reference.verified_attempt_identity(report, attempt,
            identity['bundleIdentity'], identity['testKitDigest'])
        if (report.get('status') != 'guest-operation-failed' or report.get('guestExitCode') != 1
                or report.get('executed') is not True or report.get('guestStopped') is not True
                or report.get('mode') != 'workload-positive'
                or report.get('stage') != 'installed-workload-positive'
                or report.get('cpuModel') != 'qemu64'
                or report.get('accelerator') != 'tcg,thread=multi'
                or report.get('workloadPurpose') !=
                    ('role-readiness-measurement' if retired else 'selected-group')
                or report.get('developmentSnapshot') is not False
                or actual != report.get('hostVerifiedIdentity')
                or any(actual[key] != identity[key] for key in (
                    'helperSourceCommit', 'helperSourceTree', 'bundleIdentity',
                    'testKitDigest', 'profileDigest', 'bootClosureDigest',
                    'preparedImageDigest', 'fixtureManifestDigest'))
                or actual['productDigest'] != identity['productSelectionDigest']
                or monitor.get('kind') != 'pr315-pve-watch-finished'
                or monitor.get('action') != 'completed' or monitor.get('seenTaskQemu') is not True
                or monitor.get('suite') != stage.name
                or monitor.get('sourceCommit') != identity['helperSourceCommit']
                or stopped.get('kind') != 'pr315-pve-task-qemu-stopped-v1'
                or stopped.get('attemptId') != stage.name
                or stopped.get('sourceCommit') != identity['helperSourceCommit']
                or stopped.get('taskQemuProcesses') != []
                or stopped.get('watcherFinishedMonotonicNs') != monitor['finishedMonotonicNs']
                or stopped['observedMonotonicNs'] <= monitor['finishedMonotonicNs']
                or kit.get('sourceCommit') != identity['helperSourceCommit']
                or monitor.get('moduleDigest') != kit['files'][
                    'tools/release-certification/restricted/pr315_pve_pressure_watch.py']):
            return None
        proof = diagnostics.get('preparationFailure')
        if not verify_failure(proof, diagnostics, terminal, group,
                kit['files']['tools/release-certification/restricted/pr314_workload_driver.py'],
                kit['files']['tools/release-certification/restricted/pr315_preparation.py'],
                retired=retired):
            return None
        fixture_path = stage / 'attempt-01/cryptad/build/pr315-inputs/manifest.private.json'
        fixture = read('attempt-01/cryptad/build/pr315-inputs/manifest.private.json', 8 * 1024 * 1024)
        if reference.sha256(fixture_path) != identity['fixtureManifestDigest']:
            return None
        policy = fixture['runtimePolicy']
        if (policy.get('preparationFailureProof') != 'root-epoch-no-probe-release-and-termination-v1'
                or installation.digest(installation.encode(policy)) != campaign['runtimePolicyDigest']):
            return None
        return proof
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OSError):
        return None
