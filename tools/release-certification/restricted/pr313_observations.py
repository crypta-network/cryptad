"""Source-owned installed observations for the separate finite synthetic test kit."""
import hashlib
import json
from pathlib import Path
import time


def quiescent():
    import restricted_native as native
    from pr312_app_projection import _quiescent
    _quiescent(native)
    state = native._manager('show')
    return {'activeState': state['ActiveState'], 'cgroupPopulated': False,
            'activeRecordPresent': False}


def owner(row):
    """Attach retained manager identity to an assertion emitted by the actual semantic owner."""
    import restricted_native as native
    stages = [p for p in native.ROOT.iterdir() if p.is_dir() and (p / 'manager.json').is_file()]
    operation = row['attackWitness']['operation']
    if operation in ('package-api', 'app-projection'):
        stages = [p for p in stages if json.loads((p / 'invocation.json').read_bytes())['spec']['operation'] == operation]
    if not stages:
        raise ValueError('pr313-owner-native-invocation-unobserved')
    selected = max(stages, key=lambda p: (p / 'manager.json').stat().st_mtime_ns)
    manager = json.loads((selected / 'manager.json').read_bytes())
    return {**row, 'managerInvocationId': manager['invocationId'], 'quiescent': quiescent()}


def completed(case, operation, outcome, started, raw):
    return owner({'caseId': case, 'phase': 'native-complete', 'outcome': outcome,
        'attackWitness': {'operation': operation, 'operationMarker': case, 'ownerOutcome': outcome,
            'stdoutDigest': hashlib.sha256(raw).hexdigest(), 'startedMonotonicNs': started,
            'finishedMonotonicNs': time.monotonic_ns()}})


def baseline(case, witness):
    from pr313_acceptance import CASES
    selected = CASES[case]
    return {'caseId': case, 'phase': selected.phase, 'outcome': selected.outcome,
            'managerInvocationId': None, 'attackWitness': witness, 'quiescent': quiescent()}
