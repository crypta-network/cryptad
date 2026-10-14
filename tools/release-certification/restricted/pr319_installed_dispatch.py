"""Finite installed dispatch separated from the capped PR-314 campaign driver."""
from __future__ import annotations
import time
from pr320_installed_dispatch import EXECUTION_CLASSES as COMPLETE_STORAGE_CLASSES

def observer_sequence(driver, selected, root, handoff, campaign_deadline, startup_begin, startup_measurement=False, *, admin_channel=None, workload_group=None, execution_class=None):
    """Observe controller readiness, then run the selected finite installed path."""
    driver.controller_ready(driver.readiness_deadline(campaign_deadline, startup_begin, startup_measurement))
    if startup_measurement:
        return {'classification': 'startup-measurement-not-workload-acceptance', 'controllerReadiness': 'observed-root-peer-response', 'startupElapsedSeconds': time.monotonic() - startup_begin, 'observationCeilingSeconds': driver.STARTUP_MEASUREMENT_SECONDS, 'installedPositiveExecuted': False}
    from cross_version_workload import InstalledWorkloadAdapter
    from cryptad_certification.cross_version_evidence import Journal
    with Journal(root, selected['plan']) as journal:
        journal.append('start')
        adapter = InstalledWorkloadAdapter(selected['plan'], selected['private'], selected['authorization'], journal, handoff, counter_sampler=(lambda phase: driver.request_administrator_fnp(admin_channel, phase, campaign_deadline)) if admin_channel is not None else None, lost_start_sampler=(lambda phase: driver.request_administrator_lost_start(admin_channel, phase, campaign_deadline)) if admin_channel is not None and workload_group == 'lost-start-response' else None, origin_handoff=(lambda session, origin: driver.request_administrator_hostile_origin(admin_channel, session, origin, campaign_deadline)) if admin_channel is not None and workload_group == 'authority' else None)
        diagnostic = (lambda role, stage: driver.request_administrator_readiness(admin_channel, role, stage)) if admin_channel is not None else None
        if execution_class in COMPLETE_STORAGE_CLASSES:
            from pr320_installed_dispatch import observe
            result = observe(adapter, execution_class, admin_channel, campaign_deadline, diagnostic)
        elif execution_class == 'pr319-composed-budget-restart-diagnostics-v1':
            from cross_version_installed_restart_budgets import run_observer
            result = run_observer(adapter, admin_channel, campaign_deadline, diagnostic)
        elif execution_class == driver.STORAGE_EXECUTION_CLASS:
            from pr318_storage_admin import run_observer
            result = run_observer(adapter, admin_channel, campaign_deadline, diagnostic)
        elif execution_class == driver.BUDGET_EXECUTION_CLASS:
            from cross_version_installed_budgets import run_budget_lane
            result = run_budget_lane(adapter, leave_running_for_administrator=True, on_start_failure=diagnostic)
        elif execution_class == driver.MAIL_EXECUTION_CLASS:
            result = adapter.run_mail_lane(leave_running_for_administrator=True, on_start_failure=diagnostic)
        elif workload_group in ('lost-start-response', 'partial-launch', 'stuck-output', 'late-child', 'cleanup-race', 'resource-exhaustion', 'output-symlink', 'output-fifo', 'output-hardlink', 'output-flood', 'output-replacement', 'role-readiness-diagnostic', 'role-boundary', 'authority', 'network-app', 'cancellation', 'controller-restart', 'deadline', 'revocation-running', 'setsid-double-fork', 'observer-death'):
            result = adapter.run_group_preparation(workload_group, leave_running_for_administrator=True, on_start_failure=diagnostic, on_prepared=(lambda: driver.request_administrator_prepared(admin_channel, campaign_deadline)) if admin_channel is not None and workload_group not in ('lost-start-response', 'partial-launch') else None)
        else:
            result = adapter.run_positive(leave_running_for_administrator=True, on_start_failure=diagnostic)
        journal.checkpoint('partial')
    return result
