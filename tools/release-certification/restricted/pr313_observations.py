"""Source-owned installed observations for the separate finite synthetic test kit."""
import hashlib
import json
from pathlib import Path
import re
import time


def quiescent():
    import restricted_native as native
    state = native._manager('show')
    active_path = native.ROOT / 'active.json'
    active = active_path.exists() or active_path.is_symlink()
    events = Path('/sys/fs/cgroup' + native.CGROUP) / 'cgroup.events'
    populated = False
    if events.exists():
        fields = dict(line.split() for line in events.read_text().splitlines())
        if fields.get('populated') not in ('0', '1'):
            raise ValueError('pr313-quiescence-unobserved')
        populated = fields['populated'] == '1'
    if (state['ActiveState'] not in ('inactive', 'failed')
            or state['ControlGroup'] not in ('', native.CGROUP) or populated or active):
        raise ValueError('pr313-quiescence-unobserved')
    return {'activeState': state['ActiveState'], 'cgroupPopulated': populated,
            'activeRecordPresent': active}


class InvocationWindow:
    """Bind stages created by one measured call, never an unrelated latest record."""
    def __init__(self):
        import restricted_native as native
        self.native = native
        self.before = set(native.ROOT.iterdir())
        self.started = time.monotonic_ns()
        self.finished = None

    def _records(self, owner_operation=None):
        state = quiescent()
        self.finished = time.monotonic_ns()
        stages = sorted(path for path in set(self.native.ROOT.iterdir()) - self.before if path.is_dir())
        if not stages:
            raise ValueError('pr313-owner-native-invocation-unobserved')
        selected = []
        for stage in stages:
            record = json.loads((stage / 'invocation.json').read_bytes())
            manager = json.loads((stage / 'manager.json').read_bytes())
            if (record['invocation'] != stage.name or manager['controlGroup'] != self.native.CGROUP
                    or re.fullmatch('[0-9a-f]{32}', str(manager['invocationId'])) is None
                    or (owner_operation is not None and record['owner']['operationId'] != owner_operation)):
                raise ValueError('pr313-owner-native-invocation-substituted')
            raw = self.native._read_output(stage / 'diagnostics/stdout', 8 * 1024 * 1024, allow_empty=True)
            selected.append({'managerInvocationId': manager['invocationId'],
                'operationId': record['owner']['operationId'], 'operation': record['spec']['operation'],
                'stdoutDigest': hashlib.sha256(raw).hexdigest(),
                'appId': record['spec'].get('options', {}).get('--app-id')})
        return selected, state

    def finish(self, operation, *, owner_operation=None):
        records, _state = self._records(owner_operation)
        selected = [record for record in records if record['operation'] == operation]
        if len(selected) != 1 or (owner_operation is None and len(records) != 1):
            raise ValueError('pr313-owner-native-invocation-ambiguous')
        binding = {key: value for key, value in selected[0].items() if key != 'appId'}
        return {**binding, 'startedMonotonicNs': self.started, 'finishedMonotonicNs': self.finished}

    def consumer_phase(self, phase, owner_operation):
        records, state = self._records(owner_operation)
        expected = {'queue-manager', 'publisher', 'site-publisher', 'profile-publisher',
                    'social-inbox', 'feed-reader', 'trust-graph', 'mail-prototype', 'pr305-fixture'}
        package = [row for row in records if row['operation'] == 'package-api' and row['appId'] is None]
        apps = [row['appId'] for row in records if row['operation'] == 'app-projection']
        if (len(package) != 1 or len(records) != 10 or len(apps) != 9 or set(apps) != expected
                or len({row['managerInvocationId'] for row in records}) != len(records)):
            raise ValueError('pr313-consumer-native-roster-invalid')
        if self.finished - self.started > 900 * 1_000_000_000:
            raise ValueError('pr313-consumer-native-budget-expired')
        return {'phase': phase, 'operationId': owner_operation,
            'startedMonotonicNs': self.started, 'finishedMonotonicNs': self.finished,
            'invocations': [{key: value for key, value in row.items() if key != 'operationId'}
                            for row in records], 'quiescent': state}


def owner(row, binding):
    """Attach an explicitly measured native call, or the exact originating CMS context."""
    witness = row['attackWitness']
    operation = witness['operation']
    expected = 'probe' if operation == 'bootstrap-probe' else operation
    if operation != 'maintenance-prepare' and binding['operation'] != expected:
        raise ValueError('pr313-owner-native-operation-substituted')
    if (binding['finishedMonotonicNs'] <= binding['startedMonotonicNs']
            or binding['finishedMonotonicNs'] > witness['finishedMonotonicNs']):
        raise ValueError('pr313-owner-native-interval-invalid')
    if operation != 'maintenance-prepare' and binding['startedMonotonicNs'] != witness['startedMonotonicNs']:
        raise ValueError('pr313-owner-native-interval-substituted')
    return {**row, 'managerInvocationId': binding['managerInvocationId'], 'quiescent': quiescent(),
        'attackWitness': {**witness, 'stdoutDigest': binding['stdoutDigest']}}


def completed(case, operation, outcome, binding):
    return owner({'caseId': case, 'phase': 'native-complete', 'outcome': outcome,
        'attackWitness': {'operation': operation, 'operationMarker': case, 'ownerOutcome': outcome,
            'stdoutDigest': binding['stdoutDigest'], 'startedMonotonicNs': binding['startedMonotonicNs'],
            'finishedMonotonicNs': time.monotonic_ns()}}, binding)


def baseline(case, witness):
    from pr313_acceptance import CASES
    selected = CASES[case]
    return {'caseId': case, 'phase': selected.phase, 'outcome': selected.outcome,
            'managerInvocationId': None, 'attackWitness': witness, 'quiescent': quiescent()}
