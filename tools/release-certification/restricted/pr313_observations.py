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

    def finish(self, operation, *, owner_operation=None):
        quiescent()
        self.finished = time.monotonic_ns()
        created = set(self.native.ROOT.iterdir()) - self.before
        stages = sorted(path for path in created if path.is_dir())
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
            if record['spec']['operation'] == operation:
                selected.append((stage, record, manager))
        if len(selected) != 1 or (owner_operation is None and len(stages) != 1):
            raise ValueError('pr313-owner-native-invocation-ambiguous')
        stage, record, manager = selected[0]
        # The launcher retains this bounded real stdout on success and native rejection alike.
        raw = self.native._read_output(stage / 'diagnostics/stdout', 8 * 1024 * 1024, allow_empty=True)
        return {'managerInvocationId': manager['invocationId'],
            'operationId': record['owner']['operationId'], 'operation': operation,
            'stdoutDigest': hashlib.sha256(raw).hexdigest(),
            'startedMonotonicNs': self.started, 'finishedMonotonicNs': self.finished}


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
