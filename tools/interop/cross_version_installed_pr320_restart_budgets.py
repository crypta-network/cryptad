"""Same signed PR-320 cohort running the unchanged five-variant restart lane."""
import cross_version_installed_restart_budgets as historical
import pr320_restart_contract as contract


def run_observer(adapter, channel, deadline, diagnostic):
    return historical.run_restart_lane(adapter, historical._Administrator(channel, deadline),
        leave_running_for_administrator=True, on_start_failure=diagnostic, execution_class=contract.EXECUTION_CLASS)


def validate_guest_observation(value, expected_selection_digest=None):
    return historical.validate_guest_observation(value, expected_selection_digest, execution_class=contract.EXECUTION_CLASS)


def attach_guest_context(value, identity, runtime_policy, campaign_deadline):
    validate_guest_observation(value)
    return {**value, 'identity': identity, 'runtimePolicy': runtime_policy,
        'campaignDeadlineMonotonicNs': campaign_deadline,
        'workloadAcceptance': 'incomplete-pr320-restart-private-evidence-not-verified',
        'protectedExecutionEnabled': False}
