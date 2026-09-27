#!/usr/bin/env python3
"""Closed PR-315 emitter, host verifier, and private evidence registry."""
from __future__ import annotations

import ast
from pathlib import Path

import pr314_acceptance as acceptance
import installation
import pr315_case_v10 as v10
import pr315_workload_campaign as campaign
import pr315_workload_fixtures as fixtures
import pr315_workload_runner as runner

DRIVER = 'tools/release-certification/restricted/pr314_workload_driver.py'
VERIFIER = 'tools/release-certification/restricted/pr315_workload_runner.py'
POSITIVE_DRIVER = 'tools/interop/cross_version_workload.py'
POSITIVE_VERIFIER = 'tools/release-certification/restricted/pr315_case_v10.py'
APP_PROBE = 'tools/release-certification/restricted/pr315-probe-app/bin/probe.py'


def spec(emitter, verifier, evidence, *, source=DRIVER, validator=VERIFIER):
    return {'emitter': (source, emitter), 'validator': (validator, verifier),
            'privateEvidence': evidence}


CASE_PATHS = {
    **{case: spec('InstalledWorkloadAdapter.run_positive', 'positive_records',
                  'positive-v8+v10', source=POSITIVE_DRIVER,
                  validator=POSITIVE_VERIFIER)
       for case in dict(campaign.GROUPS)['positive']},
    'observer-private-read': spec('probe_observer_private_read',
                                  'observer_private_read_attempt', 'root-role-denial-v9+v10'),
    'observer-private-write': spec('probe_observer_private_read',
                                   'observer_private_write_attempt', 'root-role-denial-v9+v10'),
    **{case: spec('probe_observer_private_read', '_fixed_role_access_attempt',
                  'root-role-boundary-v9+v10')
       for case in ('sibling-data', 'package-expectation', 'cgroup-migration')},
    'resolver-authority': spec('probe_authority_claims', '_resolver_authority_attempt',
                               'root-resolver-v8+v9+v10'),
    'runner-control': spec('probe_runner_control', 'runner_control_denial_attempt',
                           'root-runner-v8+v9+v10'),
    'observer-control': spec('observer_sequence', 'observer_control_denial_attempt',
                             'root-observer-v8+v9+v10'),
    'arbitrary-endpoint': spec('observer_sequence', 'arbitrary_endpoint_denial_attempt',
                               'root-endpoint-v8+v9+v10'),
    'hostile-app-origin': spec('probe_authority_claims', '_hostile_origin_attempt',
                               'signed-mail-origin-v8+v9+v10'),
    **{case: spec('probe_authority_claims', '_fixed_claim_attempt',
                  'root-fixed-claim-v9+v10')
       for case in ('forged-runtime-identity', 'forged-counters')},
    'stale-handle': spec('probe_stale_handle', 'stale_handle_attempt',
                         'sealed-retired-guest+root-observer-v9+v10'),
    'stale-pid-uid': spec('probe_stale_pid_uid', 'stale_pid_uid_attempt',
                          'two-installed-observers+dual-role-epoch-v9+v10'),
    'provider-authority': spec('probe_provider_authority',
                               '_provider_authority_attempt',
                               'signed-app+installed-worker-credential-v2+v10'),
    **{case: spec('probe_network_app_roles', '_sibling_network_attempt',
                  'role-syn-drop-v8+v9+v10')
       for case in ('sibling-fcp', 'sibling-http')},
    'sibling-app': spec('probe_sibling_app', '_sibling_app_attempt',
                        'signed-probe-sibling-drop-v8+v9+v10'),
    'host-network': spec('probe_host_network', '_host_network_attempt',
                         'host-namespace-listener-drop-v8+v9+v10'),
    'namespace-mount-escape': spec('mount_escape', 'probe_denial_attempt',
                                   'signed-probe-kernel-namespace-v8+v9+v10',
                                   source=APP_PROBE),
    **{case: spec('probe_' + case.replace('-', '_'),
                  '_output_artifact_attempt', 'role-descriptor-collector-v9+v10')
       for case in ('output-symlink', 'output-fifo', 'output-hardlink',
                    'output-replacement', 'output-flood')},
    'resource-exhaustion': spec('probe_resource_exhaustion',
                                '_resource_exhaustion_attempt',
                                'signed-app+root-child-epochs-v8+v9+v10'),
    'lost-start-response': spec('complete_lost_start_before_cleanup',
                                '_lifecycle_group_attempt',
                                'controller-intent+terminal-receipt-v9+v10'),
    'observer-death': spec('probe_observer_death', '_lifecycle_group_attempt',
                           '240-second-loss+terminal-receipt-v9+v10'),
    'controller-restart': spec('complete_controller_restart',
                               '_lifecycle_group_attempt',
                               'two-controller-epochs+terminal-receipt-v9+v10'),
    'late-child': spec('probe_late_child', '_late_child_record',
                       'root-barrier+pidfd+terminal-receipt-v10'),
    'setsid-double-fork': spec('probe_setsid_double_fork',
                               '_lifecycle_group_attempt',
                               'role-descendant+terminal-receipt-v9+v10'),
    'deadline': spec('complete_deadline', '_lifecycle_group_attempt',
                     'original-deadline+terminal-receipt-v9+v10'),
    'revocation-running': spec('complete_revocation_running',
                               '_lifecycle_group_attempt',
                               'revoked-running+terminal-receipt-v9+v10'),
    'cancellation': spec('complete_cancellation', '_lifecycle_group_attempt',
                         'controller-cancellation+terminal-receipt-v9+v10'),
    'partial-launch': spec('probe_partial_launch', '_partial_launch_record',
                           'failed-previous-marker+two-role-terminal-v10'),
    'stuck-output': spec('probe_stuck_output', '_stuck_output_record',
                         'role-fifo+bounded-collector+terminal-v10'),
    'cleanup-race': spec('probe_cleanup_race', 'cleanup_race_attempt',
                         'manager-replacement+reconciliation-v9+v10'),
}


def _functions(path):
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (OSError, SyntaxError):
        return set()
    found = {node.name for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            found.update(node.name + '.' + method.name
                         for method in node.body
                         if isinstance(method,
                                       (ast.FunctionDef, ast.AsyncFunctionDef)))
    return found


def implementation_coverage(source_root):
    """Require each closed case to have a measured emitter and host verifier."""
    source_root = Path(source_root)
    expected = set(acceptance.CASES)
    if (set(CASE_PATHS) != expected
            or len(campaign.GROUPS) != 21
            or fixtures.preparation.launcher_policy().get(
                'providerAuthorityProbe') !=
                'fixed-installed-worker-synthetic-provider-credential-v2'
            or not {'run_campaign', 'main', 'release_completed_attempt',
                    'frozen_campaign_context', 'task_qemu_inventory',
                    'stage_full_attempt', 'selected_group_complete'} <= _functions(source_root /
                'tools/release-certification/restricted/pr315_workload_coordinator.py')
            or 'verify_completed_cleanup_receipts' not in _functions(source_root /
                'tools/release-certification/restricted/pr315_campaign_owner.py')
            or 'verify_campaign_runtime_inputs' not in _functions(source_root /
                'tools/release-certification/restricted/pr315_workload_runner.py')
            or not {'inspect', 'main'} <= _functions(source_root /
                'tools/release-certification/restricted/pr315_pve_attempt_inventory.py')
            or not {'apply', 'main'} <= _functions(source_root /
                'tools/release-certification/restricted/pr315_pve_attempt_cleanup.py')
            or any(installation.production_member(
                'tools/release-certification/restricted/' + name)
                for name in ('pr315_workload_coordinator.py',
                             'pr315_pve_attempt_inventory.py',
                             'pr315_pve_attempt_cleanup.py'))
            or set(runner.SUPPORTED_GROUPS) !=
                {group for group, _ in campaign.GROUPS}
            or set(v10.POSITIVE) | {'output-symlink'} |
                set(v10.GENERIC) | set(v10.SPECIAL_LIFECYCLE) != expected):
        return 'incomplete'
    sources = {relative for row in CASE_PATHS.values()
               for relative, _name in (row['emitter'], row['validator'])}
    declared = {relative: _functions(source_root / relative)
                for relative in sources}
    for case_id, row in CASE_PATHS.items():
        if (campaign.CASE_TO_GROUP.get(case_id) is None
                or not isinstance(row['privateEvidence'], str)
                or not row['privateEvidence']
                or any(name not in declared[path]
                       for path, name in
                       (row['emitter'], row['validator']))):
            return 'incomplete'
    return 'complete'
