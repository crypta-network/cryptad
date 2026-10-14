"""Finite prospective selection around the existing root restart/fault controller."""
import pr319_restart_admin as historical
import pr320_restart_contract as contract


def configure_sampler(sampler, execution_class, handoff):
    if execution_class == contract.EXECUTION_CLASS:
        sampler.restart_faults = historical.FixedRestartFaults(sampler.workload,
            handoff['handles'][historical.ROLE], execution_class=contract.EXECUTION_CLASS)


cleanup_sampler = historical.cleanup_sampler


def run_observer(adapter, channel, deadline, diagnostic):
    from cross_version_installed_pr320_restart_budgets import run_observer as run
    return run(adapter, channel, deadline, diagnostic)
