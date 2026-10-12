"""Prospective fixed 45-case workload campaign plan and retry ledger.

This module has no report importer and grants no installed verdict.  The
installed runner must authenticate each selected attempt over its pinned
transport and verify the per-case process/operation context before supplying
any passed statuses.  Historical v8 attempts keep their original meaning.
"""
from __future__ import annotations

import hashlib
import json

import pr314_acceptance as acceptance

CONTRACT = 'pr314-workload-roles-v9'
CAMPAIGN = 'pr315-workload-campaign-v1'
GROUPS = (
    ('positive', tuple(name for name, case in acceptance.CASES.items()
                       if case.witness not in ('denial', 'lifecycle'))),
    ('role-boundary', ('observer-private-read', 'observer-private-write', 'sibling-data',
                       'package-expectation', 'cgroup-migration')),
    ('authority', ('resolver-authority', 'runner-control', 'observer-control',
                   'arbitrary-endpoint', 'hostile-app-origin', 'forged-runtime-identity',
                   'stale-handle', 'stale-pid-uid', 'forged-counters')),
    ('network-app', ('provider-authority', 'sibling-fcp', 'sibling-http', 'sibling-app',
                     'host-network', 'namespace-mount-escape')),
    *((name, (name,)) for name in ('output-symlink', 'output-fifo', 'output-hardlink',
                                    'output-replacement', 'output-flood')),
    ('resource-exhaustion', ('resource-exhaustion',)),
    *((name, (name,)) for name, case in acceptance.CASES.items()
      if case.witness == 'lifecycle'),
)
CASE_TO_GROUP = {case: group for group, cases in GROUPS for case in cases}
if (len(GROUPS) != 21 or len(CASE_TO_GROUP) != 45
        or set(CASE_TO_GROUP) != set(acceptance.CASES)
        or sum(len(cases) for _, cases in GROUPS) != 45):
    raise RuntimeError('pr315-campaign-inventory-invalid')


def plan(identity: dict, runtime_policy_digest: str, host_policy: str,
         probe_digest: str) -> dict:
    """Pin every group and the measured input identities before allocation."""
    if (not acceptance._identity(identity)
            or not all(acceptance._hex(value) for value in
                       (runtime_policy_digest, probe_digest))
            or host_policy != 'pve-tcg-swap-admission-v1'):
        raise ValueError('pr315-campaign-identity-invalid')
    value = {'schemaVersion': 1, 'kind': CAMPAIGN, 'contract': CONTRACT,
             'identity': identity, 'runtimePolicyDigest': runtime_policy_digest,
             'hostAdmissionPolicy': host_policy, 'probeDigest': probe_digest,
             'groups': [{'groupId': group, 'cases': list(cases)} for group, cases in GROUPS]}
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    value['planDigest'] = hashlib.sha256(encoded).hexdigest()
    return value


def reduce_attempts(campaign: dict, attempts: list, verified_case_statuses) -> dict:
    """Select the first complete attempt after at most two setup-only failures.

    ``verified_case_statuses`` is provided by the pinned-transport installed
    owner.  This reducer reports only campaign structure; it never turns
    caller-supplied JSON or a unit fixture into installed acceptance.
    """
    expected = plan(campaign['identity'], campaign['runtimePolicyDigest'],
                    campaign['hostAdmissionPolicy'], campaign['probeDigest'])
    if campaign != expected or not isinstance(attempts, list):
        raise ValueError('pr315-campaign-plan-changed')
    by_group = {group: [] for group, _ in GROUPS}
    for attempt in attempts:
        if (not isinstance(attempt, dict) or set(attempt) != {
                'groupId', 'declaredCases', 'status', 'attemptId'}
                or attempt['groupId'] not in by_group
                or attempt['declaredCases'] != list(dict(GROUPS)[attempt['groupId']])
                or not isinstance(attempt['attemptId'], str)
                or len(attempt['attemptId']) > 80 or not attempt['attemptId']
                or attempt['status'] not in ('setup-failed', 'completed', 'failed')):
            raise ValueError('pr315-campaign-attempt-invalid')
        by_group[attempt['groupId']].append(attempt)
    ids = [attempt['attemptId'] for attempt in attempts]
    if len(ids) != len(set(ids)):
        raise ValueError('pr315-campaign-attempt-duplicate')
    statuses = {}
    selected = {}
    for group, cases in GROUPS:
        history = by_group[group]
        if len(history) > 3:
            raise ValueError('pr315-campaign-retry-limit')
        final = None
        for index, attempt in enumerate(history):
            if attempt['status'] == 'setup-failed':
                if index == 2:
                    final = 'setup-failed'
                continue
            # A started probe has one terminal result.  Later attempts cannot
            # hide a functional or isolation failure in this campaign.
            if index != len(history) - 1:
                raise ValueError('pr315-campaign-post-probe-retry')
            final = attempt['status']
            if final == 'completed':
                checked = verified_case_statuses(attempt)
                if (not isinstance(checked, dict) or set(checked) != set(cases)
                        or any(value not in acceptance.STATUSES for value in checked.values())):
                    raise ValueError('pr315-campaign-unverified-cases')
                statuses.update(checked)
                selected[group] = attempt['attemptId']
            else:
                statuses.update({case: 'failed' for case in cases})
            break
        if final == 'setup-failed':
            statuses.update({case: 'setup-failed' for case in cases})
        if final is None and history:
            statuses.update({case: 'setup-failed' for case in cases})
    return {'schemaVersion': 1, 'kind': 'pr315-campaign-ledger',
            'contract': CONTRACT, 'planDigest': campaign['planDigest'],
            'selectedAttemptIds': selected, 'cases': acceptance.inventory(statuses),
            'allCasesStructurallyPassed': len(statuses) == 45
                and all(value == 'passed' for value in statuses.values()),
            'installedWorkloadAcceptanceSatisfied': False}
