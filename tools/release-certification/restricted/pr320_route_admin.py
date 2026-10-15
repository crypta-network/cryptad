"""Fixed read-only root originals for selected prospective route profiles."""
from __future__ import annotations
import os
import json
import hashlib
import pr320_route_contract as contract

ROLE = 'candidate-sender'


def configure_sampler(sampler, execution_class, handoff):
    if execution_class in contract.EXECUTION_CLASSES:
        sampler.route_workload = sampler.workload
        sampler.route_handle = handoff['handles'][ROLE]


def cleanup_sampler(sampler, diagnostics):
    if sampler is None or not hasattr(sampler, 'route_workload'):
        return
    workload = sampler.route_workload
    try:
        from pr319_restart_admin import _store_capture
        from restricted_workload_controller import _prospective_budget_native
        with workload.locked():
            campaign, role, record = workload.retained(sampler.route_handle)
            if os.geteuid() != 0 or role != ROLE or campaign.get('executionClass') not in contract.EXECUTION_CLASSES:
                raise ValueError('pr320-route-original-unselected')
            workload.exact(role, record, workload.manager(role, 'show'))
            original = _store_capture(workload, workload.account(role).pw_uid)
            # The historical capture computes its baseline quota limit. Prospective
            # quotas are verified from the actual native configuration, so only file
            # values are retained here; no historical default is relabeled measured.
            for row in original['durableUsage']: row.pop('limit')
            for row in original['graphFacts']: row.pop('document')
            status, _headers, raw = _prospective_budget_native()
            if status != 200:
                raise ValueError('pr320-route-native-original-unavailable')
            native = json.loads(raw)
            if not isinstance(native, dict) or not isinstance(native.get('work'), dict) or not isinstance(native.get('budget'), dict) or not 1 <= len(raw) <= 4 * 1024 * 1024:
                raise ValueError('pr320-route-native-original-invalid')
            workload.secured(workload.ROOT / 'authority', directory=True)
            descriptor = os.open(workload.ROOT / 'authority/pr320-route-original-native.json',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            original['nativeDigest'] = 'sha256:' + hashlib.sha256(raw).hexdigest()
            diagnostics['routeBudgetOriginalRecord'] = original
            diagnostics['routeBudgetBootstrapContext'] = workload.read(workload.ROOT / 'authority' / (
                ROLE + '-budget-bootstrap-' + record['generation'] + '.json'))
            diagnostics['routeBudgetSelectionDigest'] = campaign['budgetSelectionDigest']
        diagnostics['routeBudgetCollectorCleanup'] = 'completed'
    except (OSError, ValueError, KeyError, TypeError):
        diagnostics['routeBudgetCollectorCleanup'] = 'incomplete'


def run_observer(adapter, _channel, _campaign_deadline, diagnostic):
    from cross_version_installed_route_budgets import run_route_lane
    return run_route_lane(adapter, leave_running_for_administrator=True, on_start_failure=diagnostic)
