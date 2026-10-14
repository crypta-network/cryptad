"""Finite prospective installed storage profiles; historical v4 is unchanged."""
from __future__ import annotations

import copy

import pr318_storage_contract as legacy
from pr320_budget_contract import APPROVED_PERMISSIONS, PROCESS_CLIENT_PATH

VARIANTS = (
    ("window-crossing", "available-capacity"),
    ("window-crossing", "contested-capacity"),
    ("partial-rate-write", "direct-readable-directory-denial"),
    ("partial-rate-write", "uri-child-write-denial"),
    ("partial-rate-write", "uri-import-commit-denial"),
    ("graph-store-unavailable", "direct-readable-directory-denial"),
    ("graph-store-unavailable", "uri-readable-directory-denial"),
)
ROLES, APP_IDS, PERMISSIONS = legacy.ROLES, legacy.APP_IDS, APPROVED_PERMISSIONS
FAILURE_POLICY = legacy.FAILURE_POLICY
canonical_digest = legacy.canonical_digest
TOOL_PATHS = {
    'campaignJournal': 'tools/release-certification/cryptad_certification/composed_budget_journal_member.py',
    'campaignCapture': 'tools/release-certification/restricted/pr320_campaign_capture.py',
    **legacy.TOOL_PATHS,
    "administrator": "tools/release-certification/restricted/pr320_storage_admin.py",
    "runtimeEvidence": "tools/release-certification/restricted/pr320_storage_runtime_evidence.py",
    "selection": "tools/release-certification/restricted/pr320_storage_selection.py",
    "selectionContract": "tools/release-certification/protected/pr320_storage_contract.py",
    "historicalSelection": "tools/release-certification/restricted/pr318_storage_selection.py",
    "processClient": PROCESS_CLIENT_PATH,
    "stdioCapture": "tools/release-certification/protected/pr320_stdio_capture.py",
    "prospectiveCohort": "tools/release-certification/protected/pr320_budget_contract.py",
    "historicalContract": "tools/release-certification/protected/pr318_storage_contract.py",
    "historicalAdministrator": "tools/release-certification/restricted/pr318_storage_admin.py",
    "hostRunner": "tools/release-certification/restricted/pr320_storage_runtime_runner.py",
    "historicalHostRunner": "tools/release-certification/restricted/pr318_storage_runtime_runner.py",
    "finiteDispatch": "tools/release-certification/restricted/pr320_installed_dispatch.py",
    "transitionDispatch": "tools/release-certification/restricted/pr319_installed_dispatch.py",
}


def profile(case, variant):
    """Return a fresh code-owned configuration, never a caller-specified quota map."""
    if (case, variant) not in VARIANTS:
        raise ValueError("pr320-storage-variant-invalid")
    name = case + "-" + variant
    environment = dict(legacy.ENVIRONMENT)
    normalized = copy.deepcopy(legacy.NORMALIZED_CONFIGURATION)
    if variant == "contested-capacity":
        environment.update({
            "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_CONCURRENT_PER_APP": "2",
            "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR": "1",
        })
        normalized["budgetConfiguration"].update(
            trustGraphImportConcurrentPerApp=2, trustGraphImportPerAppPerHour=1)
    return {"executionClass": "pr320-storage-" + name + "-v1",
            "experiment": "pr320-storage-" + name, "cases": (case,),
            "caseId": case, "variant": variant, "environment": environment,
            "permissions": dict(PERMISSIONS),
            "normalizedConfiguration": normalized, "toolPaths": dict(TOOL_PATHS)}


EXECUTION_CLASSES = tuple(profile(*pair)["executionClass"] for pair in VARIANTS)


def selected_profile(execution_class):
    for pair in VARIANTS:
        selected = profile(*pair)
        if selected["executionClass"] == execution_class:
            return selected
    raise ValueError("pr320-storage-class-invalid")


def verify_selection_contract(plan, private, authorization):
    try:
        selected = selected_profile(authorization.get("executionClass"))
        return (type(authorization.get("maxOperations")) is int
                and 1000 <= authorization["maxOperations"] <= 10000
                and type(authorization.get("maxSeconds")) is int
                and 60 <= authorization["maxSeconds"] <= 3600
                and authorization["maxSeconds"] == plan.get("requestedSeconds")
                and legacy.verify_profile_selection(plan, private, authorization, selected))
    except (KeyError, TypeError, ValueError):
        return False
