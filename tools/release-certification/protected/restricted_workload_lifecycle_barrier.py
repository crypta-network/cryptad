#!/usr/bin/python3
"""Fixed root-owned stop barrier for isolated PR-315 lifecycle faults."""
import hashlib
import os
from pathlib import Path
import re
import time

ROOT = Path('/var/lib/cryptad-restricted-workload')
REQUEST = ROOT / 'authority/pr315-stop-barrier.json'
PHASE = ROOT / 'authority/pr315-stop-phase.json'
RELEASE = ROOT / 'authority/pr315-stop-release.json'
CASES = frozenset(('late-child', 'cleanup-race'))


def await_release(role, record, campaign_deadline_ns):
    """Pause only an exact selected sender stop within its fixed case ceiling."""
    import restricted_workload as workload
    if (role != 'candidate-sender' or record.get('state') != 'stopping'
            or type(campaign_deadline_ns) is not int
            or campaign_deadline_ns <= time.monotonic_ns()):
        workload.reject('lifecycle-barrier-selection-invalid')
    selected = workload.read(REQUEST)
    if (not isinstance(selected, dict) or set(selected) != {
            'schemaVersion', 'kind', 'caseId', 'role', 'nonceDigest',
            'campaign', 'generation', 'managerInvocation',
            'bootId', 'cgroupIdentity', 'sourceDigest'}
            or selected['schemaVersion'] != 1
            or selected['kind'] != 'pr315-fixed-stop-barrier'
            or selected['caseId'] not in CASES
            or selected['role'] != role
            or re.fullmatch('[0-9a-f]{64}', str(selected['nonceDigest'])) is None
            or selected['sourceDigest'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or any(selected[key] != record[key] for key in
                   ('campaign', 'generation', 'managerInvocation',
                    'bootId', 'cgroupIdentity'))):
        workload.reject('lifecycle-barrier-request-invalid')
    started = time.monotonic_ns()
    workload.write(PHASE, {'schemaVersion': 1,
        'kind': 'pr315-fixed-stop-phase', 'caseId': selected['caseId'],
        'role': role, 'nonceDigest': selected['nonceDigest'],
        'campaign': record['campaign'], 'generation': record['generation'],
        'managerInvocation': record['managerInvocation'],
        'bootId': record['bootId'], 'cgroupIdentity': record['cgroupIdentity'],
        'observedMonotonicNs': started}, create=True)
    # A real manager restart may consume its fixed 20-second stop/start budgets.
    # The cleanup race still inherits the original campaign deadline.
    ceiling = 45 if selected['caseId'] == 'cleanup-race' else 10
    until = min(time.monotonic() + ceiling, campaign_deadline_ns / 1e9)
    while not os.path.lexists(RELEASE):
        if time.monotonic() >= until:
            workload.reject('lifecycle-barrier-release-timeout')
        time.sleep(.01)
    released = workload.read(RELEASE)
    nonce = released.get('nonce') if isinstance(released, dict) else None
    if (not isinstance(released, dict) or set(released) != {
            'schemaVersion', 'kind', 'caseId', 'nonce'}
            or released['schemaVersion'] != 1
            or released['kind'] != 'pr315-fixed-stop-release'
            or released['caseId'] != selected['caseId']
            or not isinstance(nonce, str)
            or re.fullmatch('[0-9a-f]{64}', nonce) is None
            or hashlib.sha256(nonce.encode()).hexdigest() != selected['nonceDigest']
            or workload.read(PHASE)['observedMonotonicNs'] != started
            or time.monotonic_ns() >= campaign_deadline_ns):
        workload.reject('lifecycle-barrier-release-invalid')
    return {'caseId': selected['caseId'],
            'stopIntentObservedNs': started,
            'releaseObservedNs': time.monotonic_ns()}
