#!/usr/bin/python3
"""Run one bounded copied-VM PR-317 installed budget lifecycle attempt.

This host entry point grants no protected dispatch, release authority, historical acceptance, or
full-budget completion.  It reuses PR-316's VM/storage/PVE admission mechanics, but validates a
distinct fixed fixture, private causal record, terminal cleanup, and identifier-free projection.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/interop"))
sys.path.insert(0, str(ROOT / "tools/release-certification"))

import pr312_reference_vm as reference
import pr313_acceptance_runner as retained_runner
import pr315_pve_host_admission as host_admission
import pr315_pve_pressure_watch as pressure_watch
import pr316_mail_runtime_runner as shared
import pr317_budget_runtime_evidence as evidence
import pr317_budget_selection as fixtures
import cross_version_installed_budgets as installed
import cryptad_certification as certification_package
from cryptad_certification import composed_budget_evidence as composed
from cryptad_certification import composed_budget_storage_evidence as storage
from cryptad_certification import models as certification_models


PROFILE = shared.PROFILE
PORT = shared.PORT
TIMEOUT_SECONDS = shared.TIMEOUT_SECONDS
EXTRA_FIELDS = {"identity", "runtimePolicy", "campaignDeadlineMonotonicNs",
                "workloadAcceptance", "protectedExecutionEnabled"}


def _closed_public(value):
    expected = set(evidence.failed_projection("private-evidence-invalid"))
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("schemaVersion") != 1 or value.get("kind") != evidence.PUBLIC_KIND
            or value.get("executionClass") != evidence.EXECUTION_CLASS
            or value.get("topologyRoles") != 4
            or value.get("status") not in {"observed", "incomplete", "failed"}
            or value.get("fullAppBudgets") != "not-observed"
            or value.get("releaseEligible") is not False
            or value.get("phaseComplete") is not False
            or value.get("ownerCancelledInstalledDirection") is not False):
        raise ValueError("pr317-public-projection-invalid")
    return value


def _driver_observation(value):
    if not isinstance(value, dict) or not EXTRA_FIELDS <= set(value):
        raise ValueError("pr317-driver-observation-invalid")
    base = {key: selected for key, selected in value.items() if key not in EXTRA_FIELDS}
    installed.validate_guest_observation(base)
    if (set(value) != set(base) | EXTRA_FIELDS
            or value["cleanupState"] != "completed"
            or not isinstance(value["identity"], dict)
            or not isinstance(value["runtimePolicy"], dict)
            or type(value["campaignDeadlineMonotonicNs"]) is not int
            or value["campaignDeadlineMonotonicNs"] <= 0
            or value["workloadAcceptance"] !=
               "incomplete-pr317-private-evidence-not-verified"
            or value["protectedExecutionEnabled"] is not False):
        raise ValueError("pr317-driver-observation-invalid")
    return value


def _selection(value, fixture, fixture_root):
    if (not isinstance(value, dict) or set(value) != {"plan", "private", "authorization"}
            or not fixtures.verify_selection_contract(
                value["plan"], value["private"], value["authorization"])):
        raise ValueError("pr317-host-selection-invalid")
    authorization = value["authorization"]
    if (authorization["selectionDigest"] != fixtures.canonical_digest({
            "executionClass": evidence.EXECUTION_CLASS,
            "planDigest": authorization["planDigest"],
            "budgetSelection": authorization["budgetSelection"]})
            or authorization["budgetSelection"]["statementDigest"] !=
               fixture["statementDigest"]
            or authorization["budgetSelection"]["appBundleDigests"] != fixture["apps"]):
        raise ValueError("pr317-host-selection-invalid")
    return authorization["selectionDigest"]


def _private_evidence(path):
    raw = shared._private_bytes(path, evidence.MAX_PRIVATE_BYTES)
    value = evidence.decode_private(raw)
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def _candidate_identity(plan, fixture):
    nodes = [row for row in plan["nodes"] if row.get("role") == "candidate-sender"]
    expected_apps = [fixture["apps"][app_id] for app_id in fixtures.APP_IDS]
    if len(nodes) != 1 or nodes[0].get("appDigests") != expected_apps:
        raise ValueError("pr317-host-app-cohort-invalid")
    return nodes[0], fixtures.canonical_digest(expected_apps)


def _expected_node_epoch(private, terminal):
    expected = terminal["controllerRecords"]["candidate-sender"]["record"].get(
        "roleEpochDigest")
    context_digests = {private["contexts"][app_id]["roleEpochDigest"]
                       for app_id in evidence.APP_IDS}
    if (re.fullmatch("sha256:[0-9a-f]{64}", str(expected)) is None
            or context_digests != {expected}):
        raise ValueError("pr317-host-node-epoch-invalid")
    return expected[7:39]


def _attempt_projection(args, attempt, report, fixture, source_commit,
                        watcher_finished):
    if (not isinstance(report, dict) or report.get("schemaVersion") != 7
            or report.get("mode") != "workload-positive"
            or report.get("workloadPurpose") != "budget-lifecycle"
            or report.get("status") != "guest-report-retained"
            or report.get("guestExitCode") != 0 or report.get("guestStopped") is not True
            or report.get("helperSourceCommit") != source_commit
            or report.get("productSourceCommit") != args.product_source_commit
            or report.get("preparedImageDigest") != args.prepared_image_digest
            or report.get("fixtureManifestDigest") != args.fixture_manifest_digest):
        raise ValueError("pr317-reference-attempt-invalid")
    identity = shared._source_identity(report)
    observed = _driver_observation(shared._private_json(
        attempt / "pr314-workload-observation.private.json", 131072))
    private, private_digest = _private_evidence(
        attempt / "pr317-budget-lifecycle.private.json")
    selected = shared._private_json(attempt / "pr317-selection.private.json", 262144)
    selected_digest = _selection(selected, fixture, args.prepared_fixtures)
    if (observed["selectionDigest"] != private["selectionDigest"]
            or private["selectionDigest"] != selected_digest
            or observed["privateEvidenceDigest"] != private_digest
            or observed["identity"].get("sourceCommit") != identity["helperSourceCommit"]
            or observed["identity"].get("bundleIdentity") != identity["bundleIdentity"]):
        raise ValueError("pr317-private-evidence-binding-invalid")
    terminal = shared._private_json(
        attempt / "pr315-workload-volatile.private.json", 262144)
    if not shared._terminal_cleanup_verified(terminal):
        raise ValueError("pr317-terminal-cleanup-invalid")
    node_epoch = _expected_node_epoch(private, terminal)
    plan, attachment = selected["plan"], private["composedBudgetEvidence"]
    node, app_cohort_digest = _candidate_identity(plan, fixture)
    inputs = plan["composedBudgetInputs"]
    recomputed = composed.derive(attachment,
        workload_digest=plan["workloadInputs"]["scheduler"],
        product_digest=node["artifactDigest"], source_commit=node["sourceCommit"],
        app_cohort_digest=app_cohort_digest,
        node_epoch=node_epoch,
        collector_digest=inputs["collectorDigest"],
        configuration_digest=inputs["configurationDigest"])
    if recomputed != private["composedBudgetCoverage"]:
        raise ValueError("pr317-causal-coverage-substituted")
    source_digest = evidence.canonical_digest(identity)
    return _closed_public(evidence.public_projection(private,
        source_identity_digest=source_digest, selection_digest=selected_digest,
        cleanup_verified=True, guest_stopped=True,
        watcher_finished=watcher_finished, privacy_verified=True))


def _scan_budget_privacy(root):
    """Scan bounded retained text outside the copied source and binary fixture inputs."""
    root = Path(root).absolute()
    source = root / "attempt-01" / "cryptad"
    binaries = {".qcow2", ".img", ".iso", ".jar", ".zip", ".gz", ".class",
                ".so", ".dll", ".exe", ".bin", ".db"}
    count = total = 0
    for path in sorted(root.rglob("*")):
        if path.is_relative_to(source) or not path.is_file() or path.suffix.lower() in binaries:
            continue
        if path.is_symlink():
            raise ValueError("pr317-retained-surface-link-invalid")
        size = path.stat().st_size
        count, total = count + 1, total + size
        if count > 4096 or size > 8 * 1024 * 1024 or total > 64 * 1024 * 1024:
            raise ValueError("pr317-retained-surface-budget")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            raw = os.read(descriptor, size + 1)
            if len(raw) != size or evidence.payload_exposed(raw):
                raise ValueError("pr317-private-canary-exposure")
        finally:
            os.close(descriptor)
    return {"filesScanned": count, "bytesScanned": total, "sourceCloneExcluded": True}


def _host_evidence_modules():
    return {
        "installedRuntime": installed.runtime,
        "installedWorkload": installed.installed,
        "runtimePressureEvidence": installed.pressure,
        "runtimeBaseline": installed.pressure.baseline,
        "interopSmoke": installed.runtime.interop,
        "mailDemo": installed.runtime.mail_demo,
        "certificationPackage": certification_package,
        "certificationModels": certification_models,
    }


def _source_modules(args):
    modules = (reference, retained_runner, fixtures, evidence, shared,
               host_admission, pressure_watch)
    for module in modules:
        expected = args.source / "tools/release-certification/restricted" / Path(module.__file__).name
        if reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError("pr317-executing-source-mismatch")
    expected = args.source / "tools/release-certification/restricted" / Path(__file__).name
    if reference.sha256(__file__) != reference.sha256(expected):
        raise ValueError("pr317-executing-source-mismatch")
    for module, relative in ((installed, "tools/interop/cross_version_installed_budgets.py"),
                             (composed, "tools/release-certification/cryptad_certification/"
                              "composed_budget_evidence.py"),
                             (storage, "tools/release-certification/cryptad_certification/"
                              "composed_budget_storage_evidence.py"),
                             (fixtures.contract, "tools/release-certification/protected/"
                              "pr317_budget_contract.py")):
        expected = (args.source / relative).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected \
                or reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError("pr317-executing-source-mismatch")
    modules = _host_evidence_modules()
    if set(modules) != set(fixtures.contract.HOST_EVIDENCE_PATHS):
        raise ValueError("pr317-executing-source-mismatch")
    for name, module in modules.items():
        expected = (args.source / fixtures.contract.HOST_EVIDENCE_PATHS[name]).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected \
                or reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError("pr317-executing-source-mismatch")


def run(args):
    if os.geteuid() == 0:
        raise ValueError("reference-unprivileged-host-required")
    _source_modules(args)
    os.umask(0o077)
    output = args.output.absolute()
    root = retained_runner.storage_policy(args, output)
    for name in ("prepared_image", "prepared_fixtures", "qemu_root", "seed",
                 "ssh_key", "known_hosts"):
        if not getattr(args, name).resolve(strict=False).is_relative_to(root):
            raise ValueError("pr317-input-outside-task-storage-budget")
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("pr317-private-storage-root-required")
    lock = os.open(root / "pr317-budget-runtime.lock",
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 \
                or info.st_uid != os.geteuid():
            raise ValueError("pr317-suite-lock-invalid")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        initial = shared.task_vm_inventory(root)
        output.mkdir(mode=0o700, exist_ok=False)
        reasons = shared.prerequisites(args)
        try:
            measured = shared.memory_snapshot()
            reason = shared.memory_reason(args, measured)
            if reason:
                reasons.append(reason)
        except (OSError, ValueError):
            measured = {"status": "unavailable"}
            reasons.append("memory-observation-unavailable")
        source_commit = subprocess.run(["git", "-C", str(args.source), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        try:
            receipt = host_admission.verify_receipt(
                root / "host-admission" / (output.name + ".json"), output.name, source_commit)
            measured["pveHost"] = receipt["observation"]
            inventory = shared.pve_inventory.verify_receipt(
                root / "host-inventory" / (output.name + "-pre.json"),
                output.name, source_commit, "pre")
            measured["pveTaskInventory"] = inventory["observation"]
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            reasons.append("pve-host-admission-unavailable")
        capacity = {"allocatedBytes": retained_runner.allocated_bytes(root),
                    "taskInventory": initial, "memory": measured}
        if not reasons:
            required = retained_runner.required_attempt_bytes(args)
            capacity["requiredAttemptBytes"] = required
            reason = retained_runner.capacity_reason(args, root, required)
            if reason:
                reasons.append(reason)
        retained_runner._save(output / "capacity.private.json", capacity)
        retained_runner._save(output / "plan.private.json", {
            "schemaVersion": 1, "kind": "pr317-budget-runtime-host-plan",
            "executionClass": evidence.EXECUTION_CLASS, "sourceCommit": source_commit,
            "productSourceCommit": args.product_source_commit,
            "preparedImageDigest": args.prepared_image_digest,
            "fixtureManifestDigest": args.fixture_manifest_digest,
            "profile": PROFILE, "port": PORT, "timeoutSeconds": TIMEOUT_SECONDS,
            "storageBudgetBytes": args.storage_budget_bytes,
            "minimumFreeBytes": args.min_free_bytes,
            "memoryBudgetBytes": args.memory_budget_bytes,
            "minimumHostMemoryBytes": args.min_host_memory_bytes,
            "retention": "one-attempt-private-no-automatic-deletion"})
        if reasons:
            result, code = evidence.failed_projection(reasons[0]), 78
        elif args.probe:
            result, code = evidence.failed_projection("prerequisites-present-not-executed"), 78
        else:
            fixture = fixtures.verify(args.prepared_fixtures,
                args.fixture_manifest_digest, args.source, args.product_source_commit)
            selected = SimpleNamespace(**vars(args), attempt=output / "attempt-01",
                mode="workload-positive", profile=PROFILE, port=PORT,
                timeout=TIMEOUT_SECONDS, development_snapshot=False,
                host_key_pin_origin="preselected-host-key",
                execution_class=evidence.EXECUTION_CLASS, workload_group=None,
                lifecycle_scenario="none", startup_measurement=False,
                retired_authority_preparation=False, case_group=None, fault_case=None,
                retired_authority_input=None, retired_authority_input_digest=None)
            final = shared.wait_final_pve_inventory(root, output, output.name, source_commit)
            required = capacity["requiredAttemptBytes"]
            shared.validate_pve_capacity(args, final["observation"], required)
            watch_ready = None

            def start_watcher():
                nonlocal watch_ready
                prepared = retained_runner.allocated_bytes(selected.attempt)
                remaining = shared.launch_remaining_bytes(required, prepared)
                watch_ready = shared.wait_pressure_watcher(
                    args, root, output, output.name, source_commit, prepared, remaining)

            with (output / "transport.private.log").open("x") as log, redirect_stdout(log):
                reference.workload_guest_command(selected)
                reference.run(selected, before_guest_launch=start_watcher)
            deadline = time.monotonic() + 20
            while True:
                try:
                    monitor = pressure_watch.verify_finished(output.name, source_commit, watch_ready)
                    retained_runner._save(output / "host-monitor.private.json", monitor)
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise ValueError("pr317-pve-host-monitor-incomplete") from None
                    time.sleep(.25)
            report = shared._private_json(
                selected.attempt / "attempt.private.json", 1024 * 1024)
            privacy = shared._scan_retained_privacy(output, exclude_source_clone=True)
            privacy["budgetSurfaces"] = _scan_budget_privacy(output)
            retained_runner._save(output / "privacy-scan.private.json", privacy)
            result = _attempt_projection(args, selected.attempt, report,
                                         fixture, source_commit, True)
            code = 0
        result = _closed_public(result)
        retained_runner._save(output / "assessment.json", result)
        print(json.dumps(result, sort_keys=True))
        return code
    finally:
        os.close(lock)


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--probe", action="store_true")
    for name in ("source", "output", "prepared-image", "qemu-root", "seed",
                 "ssh-key", "known-hosts", "prepared-fixtures", "storage-root"):
        value.add_argument("--" + name, required=True, type=Path)
    for name in ("product-source-commit", "prepared-image-digest",
                 "fixture-manifest-digest"):
        value.add_argument("--" + name, required=True)
    for name in ("storage-budget-bytes", "min-free-bytes",
                 "memory-budget-bytes", "min-host-memory-bytes"):
        value.add_argument("--" + name, required=True, type=int)
    return value


def _retain_failure(args, error):
    """Best-effort watcher reconciliation and privacy scan after any launched-run failure."""
    output = args.output.absolute()
    if not output.is_dir() or output.is_symlink():
        return
    watcher = {"status": "not-ready-or-unavailable"}
    try:
        source_commit = subprocess.run(["git", "-C", str(args.source), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        ready = pressure_watch.verify_launch_ready(output.name, source_commit)
        watcher = shared.reconcile_failed_watcher(output.name, source_commit, ready)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    try:
        privacy = {"status": "passed", **_scan_budget_privacy(output)}
    except (OSError, ValueError):
        privacy = {"status": "failed"}
    detail = str(error)
    reason = detail if re.fullmatch(r"pr317-[a-z0-9-]{1,100}", detail) \
        else "execution-failed-private-reconciliation-required"
    retained_runner._save(output / "failure.private.json", {
        "schemaVersion": 1, "kind": "pr317-private-host-execution-failure",
        "executionClass": evidence.EXECUTION_CLASS,
        "exceptionType": type(error).__name__[:128], "reason": reason,
        "watcher": watcher, "privacy": privacy,
        "releaseEligible": False, "phaseComplete": False})


def main(argv=None):
    args = parser().parse_args(argv)
    if (re.fullmatch("[0-9a-f]{40}", args.product_source_commit) is None
            or any(re.fullmatch("[0-9a-f]{64}", value) is None for value in
                   (args.prepared_image_digest, args.fixture_manifest_digest))):
        parser().error("invalid fixed source or fixture identity")
    try:
        return run(args)
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        _retain_failure(args, error)
        raise


if __name__ == "__main__":
    try:
        exit_code = main()
    except (OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError, json.JSONDecodeError) as error:
        detail = str(error)
        reason = detail if re.fullmatch(r"pr317-[a-z0-9-]{1,126}", detail) \
            else "setup-or-execution-failed"
        print(json.dumps(evidence.failed_projection(reason), sort_keys=True))
        exit_code = 2
    raise SystemExit(exit_code)
