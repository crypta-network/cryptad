#!/usr/bin/python3
"""Run one bounded copied-VM PR-319 installed budget lifecycle attempt.

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
import pr319_restart_runtime_evidence as evidence
import pr319_restart_selection as fixtures
import cross_version_installed_restart_budgets as installed
import cryptad_certification as certification_package
from cryptad_certification import composed_budget_evidence as composed
from cryptad_certification import composed_budget_restart_evidence as restart_oracle
from cryptad_certification import models as certification_models


PROFILE = shared.PROFILE
PORT = shared.PORT
TIMEOUT_SECONDS = shared.TIMEOUT_SECONDS
EXTRA_FIELDS = {"identity", "runtimePolicy", "campaignDeadlineMonotonicNs",
                "workloadAcceptance", "protectedExecutionEnabled"}
CLOCK_TOLERANCE_NANOS = 1_000_000_000


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
        raise ValueError("pr319-public-projection-invalid")
    return value


def _driver_observation(value):
    if not isinstance(value, dict) or not EXTRA_FIELDS <= set(value):
        raise ValueError("pr319-driver-observation-invalid")
    base = {key: selected for key, selected in value.items() if key not in EXTRA_FIELDS}
    installed.validate_guest_observation(base)
    if (set(value) != set(base) | EXTRA_FIELDS
            or value["cleanupState"] != "completed"
            or not isinstance(value["identity"], dict)
            or not isinstance(value["runtimePolicy"], dict)
            or type(value["campaignDeadlineMonotonicNs"]) is not int
            or value["campaignDeadlineMonotonicNs"] <= 0
            or value["workloadAcceptance"] !=
               "incomplete-pr319-private-evidence-not-verified"
            or value["protectedExecutionEnabled"] is not False):
        raise ValueError("pr319-driver-observation-invalid")
    return value


def _selection(value, fixture, fixture_root):
    if (not isinstance(value, dict) or set(value) != {"plan", "private", "authorization"}
            or not fixtures.verify_selection_contract(
                value["plan"], value["private"], value["authorization"])):
        raise ValueError("pr319-host-selection-invalid")
    authorization = value["authorization"]
    plan = value["plan"]
    budget = authorization["budgetSelection"]
    if (authorization["selectionDigest"] != fixtures.canonical_digest({
            "executionClass": evidence.EXECUTION_CLASS,
            "planDigest": authorization["planDigest"],
            "budgetSelection": authorization["budgetSelection"]})
            or authorization["budgetSelection"]["statementDigest"] !=
               fixture["statementDigest"]
            or authorization["budgetSelection"]["appBundleDigests"] != fixture["apps"]):
        raise ValueError("pr319-host-selection-invalid")
    # Self-consistent hashes bind a document to itself, not to the independently
    # verified prospective fixture. Check every fixture identity used by this lane.
    bindings = {"timePlan": "timePlan", "toolIdentities": "toolIdentities",
                "trustedKeysDigest": "trustDigest", "permissions": "permissions",
                "caseIds": "caseIds", "environment": "environment",
                "normalizedConfiguration": "normalizedConfiguration",
                "failurePolicy": "failurePolicy",
                "statementFingerprint": "statementFingerprint"}
    if (any(budget.get(key) != fixture[name] for key, name in bindings.items())
            or plan.get("producer", {}).get("sourceCommit") != fixture["sourceCommit"]
            or plan.get("requestedSeconds") != fixture["maxSeconds"]
            or any(authorization.get(key) != fixture[key]
                   for key in ("maxSeconds", "maxOperations"))):
        raise ValueError("pr319-host-fixture-binding-invalid")
    for node in plan["nodes"]:
        product = fixture["products"]["previous" if node["role"] == "previous" else "candidate"]
        if (node.get("product") != "cryptad"
                or node.get("runtimeDigest") != fixture["runtimeDigest"]
                or any(node.get(key) != product[key] for key in
                       ("sourceCommit", "artifactDigest", "artifactSize",
                        "packageTarget", "contractVersion"))):
            raise ValueError("pr319-host-fixture-binding-invalid")
    return authorization["selectionDigest"]


def _selected_time_plan(attachment, authorization):
    """Preserve the prospectively selected real import hour for every continuity assertion."""
    selected = authorization['budgetSelection']['timePlan']
    for row in attachment['restartCases'] + attachment['diagnosticsCases']:
        for phase in (('before', 'during', 'after', 'recovery') if row['caseId'] == 'diagnostics-unavailable'
                      else ('before', 'after', 'recovery')):
            stamp = restart_oracle._time(row[phase]['diagnostics']['observedAt'])
            if not selected['boundaryEpochSecond'] - 3600 <= stamp < selected['boundaryEpochSecond']:
                raise ValueError('pr319-host-selected-hour-missed')


def _selected_statement(attachment, authorization):
    selected = authorization['budgetSelection']['statementFingerprint']
    if any(row['selectedFingerprint'] != selected for row in attachment['restartCases'] + attachment['diagnosticsCases']):
        raise ValueError('pr319-host-statement-substituted')


def _clock_sample(value):
    fields = {"hostEpochBeforeNanos", "hostMonotonicBeforeNanos", "guestEpochNanos",
              "hostMonotonicAfterNanos", "hostEpochAfterNanos"}
    if (not isinstance(value, dict) or set(value) != fields
            or any(type(value[name]) is not int or value[name] <= 0 for name in fields)):
        raise ValueError("pr319-host-guest-clock-invalid")
    wall_elapsed = value["hostEpochAfterNanos"] - value["hostEpochBeforeNanos"]
    monotonic_elapsed = (value["hostMonotonicAfterNanos"] -
                         value["hostMonotonicBeforeNanos"])
    if (not 0 <= monotonic_elapsed <= 10_000_000_000
            or abs(wall_elapsed - monotonic_elapsed) > CLOCK_TOLERANCE_NANOS
            or not value["hostEpochBeforeNanos"] - CLOCK_TOLERANCE_NANOS
                   <= value["guestEpochNanos"]
                   <= value["hostEpochAfterNanos"] + CLOCK_TOLERANCE_NANOS):
        raise ValueError("pr319-host-guest-clock-invalid")
    return value


def _clock_binding(report, attachment, authorization):
    """Require the guest UTC domain to agree with independently sampled host UTC."""
    clocks = report.get("storageClock")
    if not isinstance(clocks, dict) or set(clocks) != {"before", "after"}:
        raise ValueError("pr319-host-guest-clock-invalid")
    before, after = (_clock_sample(clocks[name]) for name in ("before", "after"))
    if (before["hostMonotonicAfterNanos"] >= after["hostMonotonicBeforeNanos"]
            or before["hostEpochAfterNanos"] >= after["hostEpochBeforeNanos"]):
        raise ValueError("pr319-host-guest-clock-invalid")
    for row in attachment['restartCases'] + attachment['diagnosticsCases']:
        for phase in (('before', 'during', 'after', 'recovery') if row['caseId'] == 'diagnostics-unavailable'
                      else ('before', 'after', 'recovery')):
            stamp = restart_oracle._time(row[phase]['diagnostics']['observedAt']) * 10**9
            if not before['hostEpochBeforeNanos'] - CLOCK_TOLERANCE_NANOS <= stamp <= after['hostEpochAfterNanos'] + CLOCK_TOLERANCE_NANOS:
                raise ValueError('pr319-host-observation-clock-substituted')


def _private_evidence(path):
    raw = shared._private_bytes(path, evidence.MAX_PRIVATE_BYTES)
    value = evidence.decode_private(raw)
    return value, "sha256:" + hashlib.sha256(raw).hexdigest()


def _candidate_identity(plan, fixture):
    nodes = [row for row in plan["nodes"] if row.get("role") == "candidate-sender"]
    expected_apps = [fixture["apps"][app_id] for app_id in fixtures.APP_IDS]
    if len(nodes) != 1 or nodes[0].get("appDigests") != expected_apps:
        raise ValueError("pr319-host-app-cohort-invalid")
    return nodes[0], fixtures.canonical_digest(expected_apps)


def _expected_node_epoch(private, terminal):
    expected = terminal["controllerRecords"]["candidate-sender"]["record"].get(
        "roleEpochDigest")
    context_digests = {private["contexts"][app_id]["roleEpochDigest"]
                       for app_id in evidence.APP_IDS}
    if (re.fullmatch("sha256:[0-9a-f]{64}", str(expected)) is None
            or context_digests != {expected}):
        raise ValueError("pr319-host-node-epoch-invalid")
    return expected[7:39]


def _original_admin_receipts(private, diagnostics, terminal, selection_digest):
    evidence.validate_originals(private, diagnostics, terminal, selection_digest)


def _attempt_projection(args, attempt, report, fixture, source_commit,
                        watcher_finished):
    if (not isinstance(report, dict) or report.get("schemaVersion") != 7
            or report.get("mode") != "workload-positive"
            or report.get("workloadPurpose") != "budget-restart"
            or report.get("status") != "guest-report-retained"
            or report.get("guestExitCode") != 0 or report.get("guestStopped") is not True
            or report.get("helperSourceCommit") != source_commit
            or report.get("productSourceCommit") != args.product_source_commit
            or report.get("preparedImageDigest") != args.prepared_image_digest
            or report.get("fixtureManifestDigest") != args.fixture_manifest_digest):
        raise ValueError("pr319-reference-attempt-invalid")
    identity = shared._source_identity(report)
    observed = _driver_observation(shared._private_json(
        attempt / "pr314-workload-observation.private.json", 131072))
    private, private_digest = _private_evidence(
        attempt / "pr319-restart-budget.private.json")
    selected = shared._private_json(attempt / "pr319-selection.private.json", 262144)
    selected_digest = _selection(selected, fixture, args.prepared_fixtures)
    if (observed["selectionDigest"] != private["selectionDigest"]
            or private["selectionDigest"] != selected_digest
            or observed["privateEvidenceDigest"] != private_digest
            or observed["identity"].get("sourceCommit") != identity["helperSourceCommit"]
            or observed["identity"].get("bundleIdentity") != identity["bundleIdentity"]):
        raise ValueError("pr319-private-evidence-binding-invalid")
    terminal = shared._private_json(
        attempt / "pr315-workload-volatile.private.json", 262144)
    if not shared._terminal_cleanup_verified(terminal):
        raise ValueError("pr319-terminal-cleanup-invalid")
    diagnostics = shared._private_json(attempt / "pr315-workload-memory.private.json", 262144)
    _original_admin_receipts(private, diagnostics, terminal, selected_digest)
    node_epoch = _expected_node_epoch(private, terminal)
    plan, attachment = selected["plan"], private["composedBudgetEvidence"]
    _selected_time_plan(attachment, selected["authorization"])
    _selected_statement(attachment, selected["authorization"])
    _clock_binding(report, attachment, selected["authorization"])
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
        raise ValueError("pr319-causal-coverage-substituted")
    source_digest = evidence.canonical_digest(identity)
    return _closed_public(evidence.public_projection(private,
        source_identity_digest=source_digest, selection_digest=selected_digest,
        cleanup_verified=True, guest_stopped=True,
        watcher_finished=watcher_finished, privacy_verified=True))


def _scan_budget_privacy(root):
    """Scan every bounded retained text/JSON surface collected for public assessment."""
    exclude_source_clone = True
    root = Path(root).absolute()
    source_clone = root / 'attempt-01' / 'cryptad'
    source_clone_present = source_clone.exists() or source_clone.is_symlink()
    if exclude_source_clone and source_clone_present:
        info = source_clone.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('pr319-retained-source-clone-invalid')
    binary_suffixes = {'.qcow2', '.img', '.iso', '.jar', '.zip', '.gz', '.class',
                       '.so', '.dll', '.exe', '.bin', '.db'}
    count = total = 0
    for path in sorted(root.rglob('*')):
        if exclude_source_clone and path.is_relative_to(source_clone):
            continue
        if path.is_symlink():
            raise ValueError('pr319-retained-surface-link-invalid')
        if path == root / 'attempt-01/pr315-workload-memory.private.json':
            evidence.decode_original_diagnostics(shared._private_bytes(path, 262144))
            continue
        if path in {root / 'attempt-01/pr319-restart-budget.private.json',
                    root / 'attempt-01/pr319-restart-attempts.private.jsonl'}:
            private_info = path.lstat()
            if (not stat.S_ISREG(private_info.st_mode) or private_info.st_nlink != 1
                    or private_info.st_uid != os.geteuid() or private_info.st_mode & 0o077):
                raise ValueError('pr319-private-graph-file-unsafe')
            if path.suffix == '.jsonl':
                raw_private = shared._private_bytes(path, evidence.MAX_PRIVATE_BYTES)
                evidence.decode_checkpoints(raw_private)
            else:
                _private_evidence(path)
            continue
        if not path.is_file() or path.suffix.lower() in binary_suffixes:
            continue
        info = path.stat()
        count += 1
        total += info.st_size
        if count > 4096 or info.st_size > 8 * 1024 * 1024 \
                or total > 64 * 1024 * 1024:
            raise ValueError('pr319-retained-surface-budget')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            raw = os.read(descriptor, info.st_size + 1)
            after = os.fstat(descriptor)
            if (len(raw) != info.st_size
                    or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns, before.st_ctime_ns) !=
                       (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns)
                    or evidence.payload_exposed(raw) or shared.evidence.payload_exposed(raw)):
                raise ValueError('pr319-private-canary-exposure')
        finally:
            os.close(descriptor)
    return {'filesScanned': count, 'bytesScanned': total,
            'sourceCloneExcluded': exclude_source_clone and source_clone_present}


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
            raise ValueError("pr319-executing-source-mismatch")
    expected = args.source / "tools/release-certification/restricted" / Path(__file__).name
    if reference.sha256(__file__) != reference.sha256(expected):
        raise ValueError("pr319-executing-source-mismatch")
    for module, relative in ((installed.transport, "tools/interop/cross_version_installed_budgets.py"),
                             (restart_oracle, "tools/release-certification/cryptad_certification/"
                              "composed_budget_restart_evidence.py"),
                             (installed, "tools/interop/cross_version_installed_restart_budgets.py"),
                             (composed, "tools/release-certification/cryptad_certification/"
                              "composed_budget_evidence.py"),
                             (fixtures.contract, "tools/release-certification/protected/"
                              "pr319_restart_contract.py")):
        expected = (args.source / relative).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected \
                or reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError("pr319-executing-source-mismatch")
    modules = _host_evidence_modules()
    if set(modules) != set(fixtures.contract.HOST_EVIDENCE_PATHS):
        raise ValueError("pr319-executing-source-mismatch")
    for name, module in modules.items():
        expected = (args.source / fixtures.contract.HOST_EVIDENCE_PATHS[name]).resolve(strict=True)
        if Path(module.__file__).resolve(strict=True) != expected \
                or reference.sha256(module.__file__) != reference.sha256(expected):
            raise ValueError("pr319-executing-source-mismatch")


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
            raise ValueError("pr319-input-outside-task-storage-budget")
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("pr319-private-storage-root-required")
    lock = os.open(root / "pr319-budget-runtime.lock",
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 \
                or info.st_uid != os.geteuid():
            raise ValueError("pr319-suite-lock-invalid")
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
            "schemaVersion": 1, "kind": "pr319-budget-runtime-host-plan",
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
                        raise ValueError("pr319-pve-host-monitor-incomplete") from None
                    time.sleep(.25)
            report = shared._private_json(
                selected.attempt / "attempt.private.json", 1024 * 1024)
            privacy = {"privateGraphEvidence": "retained-private-not-public"}
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
    reason = detail if re.fullmatch(r"pr319-[a-z0-9-]{1,100}", detail) \
        else "execution-failed-private-reconciliation-required"
    retained_runner._save(output / "failure.private.json", {
        "schemaVersion": 1, "kind": "pr319-private-host-execution-failure",
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
        reason = detail if re.fullmatch(r"pr319-[a-z0-9-]{1,126}", detail) \
            else "setup-or-execution-failed"
        print(json.dumps(evidence.failed_projection(reason), sort_keys=True))
        exit_code = 2
    raise SystemExit(exit_code)
