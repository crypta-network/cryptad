#!/usr/bin/python3
"""Bounded private stuck-output failure observations, never case witnesses."""
import hashlib
import os
from pathlib import Path
import time

POLICY = 'pr315-stuck-output-diagnostic-v1'
NAME = 'stuck-output-diagnostic.json'
PHASES = frozenset(('preconditions', 'request-publication', 'role-ready',
    'child-ready', 'actor-binding', 'sibling-controls', 'collector-start',
    'collector-epoch', 'collector-proof', 'writer-recheck', 'observer-stop',
    'stop-receipt', 'sibling-recheck', 'audit-publication'))
CODES = frozenset('workload-stuck-output-' + suffix for suffix in (
    'preparation-invalid', 'role-ready-timeout', 'child-ready-timeout',
    'writer-invalid', 'writer-exited', 'collector-finished',
    'collector-proof-invalid', 'role-changed', 'observer-invalid',
    'collector-invalid', 'collector-namespace-invalid',
    'controller-stop-invalid', 'writer-not-stopped', 'sibling-changed')) | frozenset((
    'workload-role-probe-actor-unavailable', 'workload-role-probe-file-invalid',
    'workload-role-probe-file-changed', 'workload-resource-sibling-inactive',
    'workload-stuck-collector-executable-limit', 'workload-stuck-collector-epoch-invalid',
    'workload-stuck-collector-cgroup-invalid', 'workload-positive-observer-exited',
    'workload-positive-observer-uid-unavailable', 'workload-positive-observer-epoch-changed',
    'restricted-workload-process-scope-changed', 'restricted-workload-preparation-incomplete',
    'bounded_process_deadline_exceeded'))


class Trace:
    def __init__(self, workload, deadline_ns):
        self.workload = workload
        self.deadline_ns = deadline_ns
        self.phase = 'preconditions'
        self.failed_phase = None
        self.started_ns = time.monotonic_ns()
        self.events = []
        self.administrator = None

    def step(self, phase, *, wait_until_ns=None):
        if phase not in PHASES or len(self.events) >= 16:
            raise ValueError('workload-stuck-output-diagnostic-phase-invalid')
        self.phase = phase
        event = {'phase': phase, 'observedMonotonicNs': time.monotonic_ns()}
        if wait_until_ns is not None:
            if type(wait_until_ns) is not int or wait_until_ns <= 0:
                raise ValueError('workload-stuck-output-diagnostic-clock-invalid')
            event['waitUntilMonotonicNs'] = wait_until_ns
        self.events.append(event)

    def failed(self):
        if self.failed_phase is None:
            self.failed_phase = self.phase

    def capture(self, error):
        """Capture while role tmpfs remains mounted; a diagnostic cannot mask failure."""
        import runtime_snapshot as snapshot
        self.failed()
        files = {}
        selected = {
            'ready': 'state/candidate-sender/tmp/pr315-stuck-output-ready.json',
            'child': 'state/candidate-sender/tmp/pr315-stuck-output-child.json',
            'request': 'probe-requests/candidate-sender.json',
            'roleAuthority': 'authority/candidate-sender.json',
            'stopReceipt': 'authority/candidate-sender-stop.json',
            'controllerProgress': '/run/cryptad-workload/request-progress.private.json'}
        for key, name in selected.items():
            if time.monotonic_ns() >= self.deadline_ns:
                files[key] = {'status': 'original-deadline-expired'}
                continue
            path = self.workload.ROOT / name if not name.startswith('/') else Path(name)
            if not os.path.lexists(path):
                files[key] = {'status': 'absent-at-failure'}
                continue
            try:
                remaining = (self.deadline_ns - time.monotonic_ns()) / 1e9
                raw = snapshot.read_file(path.parent, path.name, maximum=8192,
                                         timeout=min(1, remaining))
                files[key] = {'status': 'captured-private-diagnostic',
                    'sha256': hashlib.sha256(raw).hexdigest(), 'sizeBytes': len(raw)}
                # Keep exact private bytes separately; they cannot supply a case witness.
                import base64
                files[key]['privateBytesBase64'] = base64.b64encode(raw).decode()
            except (OSError, ValueError, TimeoutError):
                files[key] = {'status': 'unavailable-at-failure'}
        value = {'schemaVersion': 1, 'policy': POLICY,
            'classification': 'private-diagnostic-not-acceptance',
            'caseId': 'stuck-output', 'status': 'unavailable-or-unsafe',
            'phase': self.failed_phase, 'exceptionType': type(error).__name__[:128],
            'privateErrorCode': str(error) if str(error) in CODES else None,
            'startedMonotonicNs': self.started_ns,
            'observedMonotonicNs': time.monotonic_ns(),
            'campaignDeadlineNs': self.deadline_ns, 'events': self.events,
            'administrator': self.administrator, 'files': files}
        try:
            self.workload.write(self.workload.ROOT / 'authority' / NAME, value, create=True)
        except (OSError, ValueError):
            pass
        return value


def summary(workload):
    """Return only fixed phase/code fields; retained bytes remain administrator-private."""
    try:
        path = workload.ROOT / 'authority' / NAME
        if path.stat().st_size > 65536:
            return {}
        value = workload.read(path)
        if (value.get('schemaVersion') != 1 or value.get('policy') != POLICY
                or value.get('classification') != 'private-diagnostic-not-acceptance'
                or value.get('caseId') != 'stuck-output'
                or value.get('phase') not in PHASES
                or value.get('privateErrorCode') not in CODES | {None}):
            return {}
        return {key: value[key] for key in ('phase', 'privateErrorCode', 'classification')}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def retained(root, deadline):
    """Copy the private diagnostic into volatile evidence after role tmpfs cleanup."""
    import json
    import runtime_snapshot as snapshot
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {'status': 'capture-deadline'}
        raw = snapshot.read_file(root / 'authority', NAME, maximum=65536,
                                 timeout=min(2, remaining))
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('schemaVersion') != 1
                or value.get('policy') != POLICY
                or value.get('classification') != 'private-diagnostic-not-acceptance'
                or value.get('caseId') != 'stuck-output'
                or value.get('status') != 'unavailable-or-unsafe'
                or value.get('phase') not in PHASES
                or value.get('privateErrorCode') not in CODES | {None}):
            return {'status': 'invalid-diagnostic'}
        return {'status': 'captured-private-diagnostic', 'record': value,
                'sha256': hashlib.sha256(raw).hexdigest()}
    except (OSError, ValueError, TypeError):
        return {'status': 'unavailable-diagnostic'}
