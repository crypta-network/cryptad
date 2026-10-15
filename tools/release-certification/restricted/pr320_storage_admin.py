"""Reuse descriptor-owned PR-318 faults for finite prospective storage variants."""
from __future__ import annotations

import os
import socket
import json
import time

import pr318_storage_admin as legacy
import pr320_storage_contract as contract


class FixedStorageFaults(legacy.FixedStorageFaults):
    def _role(self, *, cleanup=False):
        workload = self.workload
        campaign, role, record = workload.retained(self.sender_handle)
        selected = contract.selected_profile(campaign.get("executionClass"))
        if (os.geteuid() != 0 or role != legacy.ROLE
                or campaign.get("budgetSelectionDigest") is None
                or selected["caseId"] not in legacy.TARGETS):
            raise ValueError("pr320-storage-admin-selection-invalid")
        if not cleanup:
            workload.admit(campaign)
            workload.exact(role, record, workload.manager(role, "show"))
        return campaign, record, workload.account(role)

    def request(self, command):
        campaign, _role, _record = self.workload.retained(self.sender_handle)
        selected = contract.selected_profile(campaign.get("executionClass"))
        allowed = tuple(selected["caseId"] + ":" + phase for phase in ("restrict", "restore"))
        if command not in allowed:
            raise ValueError("pr320-storage-admin-command-invalid")
        return super().request(command)


def configure_sampler(sampler, execution_class, handoff):
    if execution_class in contract.EXECUTION_CLASSES:
        selected = contract.selected_profile(execution_class)
        sampler.complete_storage_workload = sampler.workload
        sampler.complete_storage_handle = handoff["handles"][legacy.ROLE]
        if selected["caseId"] in legacy.TARGETS:
            sampler.storage_faults = FixedStorageFaults(
                sampler.workload, handoff["handles"][legacy.ROLE])


serve_storage = legacy.serve_storage


def cleanup_sampler(sampler, diagnostics):
    if sampler is None or not hasattr(sampler, 'complete_storage_workload'):
        return
    legacy.cleanup_sampler(sampler, diagnostics)
    workload = sampler.complete_storage_workload
    try:
        with workload.locked():
            campaign, role, record = workload.retained(sampler.complete_storage_handle)
            if role != legacy.ROLE or campaign.get('executionClass') not in contract.EXECUTION_CLASSES:
                raise ValueError('pr320-storage-original-unselected')
            diagnostics['storageBootstrapContext'] = workload.read(workload.ROOT / 'authority' / (
                'candidate-sender-budget-bootstrap-' + record['generation'] + '.json'))
            diagnostics['storageSelectionDigest'] = campaign['budgetSelectionDigest']
            if not hasattr(sampler, 'storage_faults'):
                diagnostics['storageFaultReceipts'] = []
                diagnostics['storageAccessCleanup'] = 'completed'
    except (OSError, ValueError, KeyError):
        diagnostics['storageAccessCleanup'] = 'restoration-required'


def run_observer(adapter, channel, campaign_deadline, diagnostic):
    from cross_version_installed_storage_budgets import run_complete_storage_variant

    def administrator(command):
        selected = contract.selected_profile(adapter.authorization["executionClass"])
        if command not in tuple(selected["caseId"] + ":" + phase
                                for phase in ("restrict", "restore")) or channel is None:
            raise ValueError("pr320-storage-command-invalid")
        remaining = min(5, campaign_deadline / 1e9 - time.monotonic())
        if remaining <= 0:
            raise ValueError("pr320-storage-command-expired")
        channel.settimeout(remaining)
        channel.sendall(b"K" + command.encode("ascii"))
        raw, _ancillary, flags, _address = channel.recvmsg(8193)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) > 8192:
            raise ValueError("pr320-storage-receipt-invalid")
        result = json.loads(raw)
        if not isinstance(result, dict) or "error" in result:
            raise ValueError("pr320-storage-admin-failed")
        return result

    return run_complete_storage_variant(adapter, administrator,
        leave_running_for_administrator=True, on_start_failure=diagnostic)
