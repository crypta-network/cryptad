"""Offline structural checks for protected Stable maintenance producer workflows."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
RC_RELEASE = ROOT / ".github/workflows/stable-1.0-rc-release.yml"
GA_PROMOTION = ROOT / ".github/workflows/stable-1.0-ga-promotion.yml"
WINDOWS = ROOT / ".github/workflows/stable-1.0-maintenance-windows-package-producer.yml"
INPUTS = ROOT / ".github/workflows/stable-1.0-maintenance-input-producer.yml"
RELEASE = ROOT / ".github/workflows/stable-1.0-maintenance-release.yml"
LIFECYCLE_INPUTS = (
    ROOT / ".github/workflows/stable-1.0-support-lifecycle-input-producer.yml"
)
LIFECYCLE_RELEASE = ROOT / ".github/workflows/stable-1.0-support-lifecycle.yml"
EXAMPLE = (
    ROOT
    / "tools/release-certification/manifests/stable-1.0-maintenance.example.json"
)
POLICY = ROOT / "tools/release-certification/stable-1.0-maintenance-policy.json"
BACKEND_ACTION = (
    ROOT / ".github/actions/setup-stable-maintenance-publication-backend/action.yml"
)
BACKEND_PRODUCER = (
    ROOT
    / ".github/workflows/stable-1.0-maintenance-publication-backend-producer.yml"
)
BACKEND_ROOT = ROOT / "tools/release-certification/publication-backend"
MAINTENANCE_DOC = ROOT / "docs/stable-1.0-maintenance-release-and-hotfix-path.md"


def _input_producer_validation_script() -> str:
    workflow = INPUTS.read_text(encoding="utf-8")
    step_start = workflow.index(
        "      - name: Extract safely and validate the exact phase layout"
    )
    command = "          PYTHONPATH=tools/release-certification python3 - <<'PY'\n"
    script_start = workflow.index(command, step_start) + len(command)
    script_end = workflow.index("\n          PY\n", script_start)
    return textwrap.dedent(workflow[script_start:script_end])


def _input_producer_fetch_script() -> str:
    workflow = INPUTS.read_text(encoding="utf-8")
    step_start = workflow.index(
        "      - name: Fetch exact reviewed bundle without exposing its protected locator"
    )
    command = "          python3 - <<'PY'\n"
    script_start = workflow.index(command, step_start) + len(command)
    script_end = workflow.index("\n          PY\n", script_start)
    return textwrap.dedent(workflow[script_start:script_end])


def _release_lifecycle_handoff_script() -> str:
    workflow = RELEASE.read_text(encoding="utf-8")
    step_start = workflow.index("      - name: Stage exact redaction-safe candidate")
    command = (
        "              python3 - \\\n"
        "                build/prior-validated-candidate/authenticated-inputs \\\n"
        "                \"$root/authenticated-inputs\" <<'PY'\n"
    )
    script_start = workflow.index(command, step_start) + len(command)
    script_end = workflow.index("\n          PY\n", script_start)
    return textwrap.dedent(workflow[script_start:script_end])


def _release_lifecycle_authority_presence_script() -> str:
    workflow = RELEASE.read_text(encoding="utf-8")
    step_start = workflow.index(
        "      - name: Inspect exact lifecycle authority-chain presence"
    )
    command = "          python3 - <<'PY'\n"
    script_start = workflow.index(command, step_start) + len(command)
    script_end = workflow.index("\n          PY\n", script_start)
    return textwrap.dedent(workflow[script_start:script_end])


class StableMaintenanceProducerWorkflowTests(unittest.TestCase):
    def test_stable_release_workflows_enforce_runtime_release_id_bound(self) -> None:
        bash_workflows = (
            RC_RELEASE,
            GA_PROMOTION,
            INPUTS,
            RELEASE,
            LIFECYCLE_INPUTS,
            LIFECYCLE_RELEASE,
        )
        for workflow_path in bash_workflows:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")
                self.assertIn("${#INPUT_RELEASE_ID} -gt 128", workflow)
        self.assertIn(
            "$env:INPUT_RELEASE_ID.Length -gt 128",
            WINDOWS.read_text(encoding="utf-8"),
        )

    def test_ga_genesis_skips_lifecycle_observation_but_post_ga_remains_closed(
        self,
    ) -> None:
        script = _release_lifecycle_authority_presence_script()
        authority_files = {
            "previousStableLifecycleLedger": (
                "stable-1.0-support-lifecycle-ledger.json"
            ),
            "previousStableLifecycleDescriptor": (
                "stable-1.0-support-lifecycle-descriptor.json"
            ),
            "stableLifecycleAuthorization": (
                "stable-1.0-support-lifecycle-authorization-summary.json"
            ),
            "stableLifecyclePublicationPlan": (
                "stable-1.0-support-lifecycle-publication-plan.json"
            ),
            "stableLifecyclePublicationReceipt": (
                "stable-1.0-support-lifecycle-publication-receipt.json"
            ),
        }

        def run_presence_check(
            *,
            operation: str,
            predecessor_schema: int,
            configured_keys: tuple[str, ...] = (),
        ) -> tuple[subprocess.CompletedProcess[str], str]:
            with tempfile.TemporaryDirectory() as directory:
                checkout = Path(directory)
                protected = checkout / "build/protected-inputs"
                lifecycle = protected / "lifecycle"
                protected.mkdir(parents=True)
                predecessor = protected / "predecessor.json"
                predecessor.write_text(
                    json.dumps(
                        {
                            "schemaVersion": predecessor_schema,
                            "kind": (
                                "stable-1.0-maintenance-baseline"
                                if predecessor_schema == 1
                                else "stable-1.0-maintenance-successor-baseline"
                            ),
                        }
                    ),
                    encoding="utf-8",
                )
                inputs = {
                    "predecessorBaseline": "build/protected-inputs/predecessor.json"
                }
                for key in configured_keys:
                    lifecycle.mkdir(exist_ok=True)
                    name = authority_files[key]
                    path = lifecycle / name
                    path.write_text("{}\n", encoding="utf-8")
                    inputs[key] = f"build/protected-inputs/lifecycle/{name}"
                manifest = checkout / "build/stable-1.0-maintenance.json"
                manifest.write_text(
                    json.dumps({"inputs": inputs}), encoding="utf-8"
                )
                github_output = checkout / "github-output"
                completed = subprocess.run(
                    [sys.executable, "-c", script],
                    cwd=checkout,
                    env={
                        **os.environ,
                        "INPUT_OPERATION": operation,
                        "GITHUB_OUTPUT": str(github_output),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                output = (
                    github_output.read_text(encoding="utf-8")
                    if github_output.exists()
                    else ""
                )
                return completed, output

        genesis, genesis_output = run_presence_check(
            operation="prepare-authorization", predecessor_schema=1
        )
        self.assertEqual(0, genesis.returncode, genesis.stderr)
        self.assertEqual("present=false\n", genesis_output)

        complete, complete_output = run_presence_check(
            operation="prepare-authorization",
            predecessor_schema=2,
            configured_keys=tuple(authority_files),
        )
        self.assertEqual(0, complete.returncode, complete.stderr)
        self.assertEqual("present=true\n", complete_output)

        partial, _ = run_presence_check(
            operation="prepare-authorization",
            predecessor_schema=2,
            configured_keys=("previousStableLifecycleLedger",),
        )
        self.assertNotEqual(0, partial.returncode)
        self.assertIn("exact five-artifact authority chain", partial.stderr)

        post_ga, _ = run_presence_check(
            operation="prepare-authorization", predecessor_schema=2
        )
        self.assertNotEqual(0, post_ga.returncode)
        self.assertIn("only GA-genesis", post_ga.stderr)

        validate_genesis, _ = run_presence_check(
            operation="validate-authorization", predecessor_schema=1
        )
        self.assertNotEqual(0, validate_genesis.returncode)
        self.assertIn("only GA-genesis", validate_genesis.stderr)

        workflow = RELEASE.read_text(encoding="utf-8")
        observation_gate = "steps.lifecycle-authority.outputs.present == 'true'"
        self.assertGreaterEqual(workflow.count(observation_gate), 4)
        self.assertIn(
            "lifecycle_authority_present: "
            "${{ steps.lifecycle-authority.outputs.present }}",
            workflow,
        )
        self.assertIn(
            "needs.freeze-and-validate.outputs.lifecycle_authority_present == 'true'",
            workflow,
        )

    def test_lifecycle_observation_is_live_attested_and_shared_lock_bound(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")

        self.assertIn("group: stable-1-0-maintenance-publication", workflow)
        self.assertIn(
            "- name: Re-fetch exact public lifecycle edition under the shared publication lock",
            workflow,
        )
        observation = workflow.index(
            "- name: Re-fetch exact public lifecycle edition under the shared publication lock"
        )
        attestation = workflow.index(
            "- name: Attest the fresh exact public lifecycle observation", observation
        )
        verification = workflow.index(
            "- name: Verify fresh lifecycle observation provenance before certification",
            attestation,
        )
        certification = workflow.index(
            "- name: Validate exact frozen candidate without publication", verification
        )
        self.assertLess(observation, attestation)
        self.assertLess(attestation, verification)
        self.assertLess(verification, certification)
        validation_slice = workflow[observation:certification]
        self.assertIn("--mode observe-authorized-state", validation_slice)
        self.assertIn("actions/attest@", validation_slice)
        self.assertIn("gh attestation verify", validation_slice)
        self.assertIn(
            "stableLifecyclePublicObservationReceipt = $path", validation_slice
        )

        publication_observation = workflow.index(
            "- name: Re-observe exact lifecycle edition immediately before maintenance preflight"
        )
        preflight = workflow.index(
            "- name: Preflight predecessor, authorization, freeze, and public conflicts",
            publication_observation,
        )
        mutation = workflow.index(
            "- name: Publish or idempotently verify exact bytes", preflight
        )
        self.assertLess(publication_observation, preflight)
        self.assertLess(preflight, mutation)
        self.assertIn(
            "--mode observe-authorized-state",
            workflow[publication_observation:preflight],
        )

    def test_lifecycle_observation_provider_is_phase_scoped_and_exact(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        dispatch_inputs = workflow[
            workflow.index("    inputs:") : workflow.index("\nconcurrency:")
        ]
        input_names = [
            line.strip()[:-1]
            for line in dispatch_inputs.splitlines()
            if len(line) - len(line.lstrip()) == 6
            and line.strip().endswith(":")
        ]

        self.assertLessEqual(len(input_names), 25)
        self.assertNotIn("lifecycle_publication_backend_run_id", input_names)
        self.assertNotIn("lifecycle_publication_backend_artifact_name", input_names)
        self.assertNotIn("lifecycle_publication_backend_artifact_digest", input_names)
        self.assertGreaterEqual(
            workflow.count(
                "vars.CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_RUN_ID"
            ),
            3,
        )
        self.assertGreaterEqual(
            workflow.count(
                "vars.CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_BACKEND_ARTIFACT_DIGEST"
            ),
            3,
        )
        self.assertIn(
            "Authorization and publication require the exact read-only lifecycle provider",
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count(
                'canonical_artifact="stable-1.0-support-lifecycle-publication-backend"'
            ),
            2,
        )
        self.assertGreaterEqual(
            workflow.count(
                'canonical_entrypoint="cryptad_stable_maintenance_backend:lifecycle_factory"'
            ),
            2,
        )
        staging = workflow[
            workflow.index("- name: Stage exact redaction-safe candidate") :
            workflow.index("- name: Upload exact validated candidate")
        ]
        self.assertIn(
            'if [[ "$INPUT_OPERATION" == prepare-authorization', staging
        )
        self.assertIn("stableLifecyclePublicObservationReceipt", staging)
        immutable_names = _release_lifecycle_handoff_script()
        self.assertNotIn("public-observation", immutable_names)

    def test_publication_backend_wheel_is_deterministic_and_loadable_in_isolation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            builder = BACKEND_ROOT / "build_wheel.py"
            subprocess.run(
                [sys.executable, str(builder), "--out", str(first)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [sys.executable, str(builder), "--out", str(second)],
                check=True,
                capture_output=True,
                text=True,
            )
            first_wheels = list(first.glob("*.whl"))
            second_wheels = list(second.glob("*.whl"))
            self.assertEqual(1, len(first_wheels))
            self.assertEqual(1, len(second_wheels))
            self.assertEqual(first_wheels[0].read_bytes(), second_wheels[0].read_bytes())
            script = textwrap.dedent(
                """
                import importlib
                import os
                import sys
                sys.path.insert(0, sys.argv[1])
                module = importlib.import_module('cryptad_stable_maintenance_backend')
                os.environ['GITHUB_REPOSITORY'] = 'crypta-network/cryptad'
                os.environ['GITHUB_TOKEN'] = 'offline-test-token'
                backend = module.factory()
                names = ('observe_public_state', 'publish_target', 'verify_publication',
                         'observe_latest_pointer', 'activate_latest')
                if any(not callable(getattr(backend, name, None)) for name in names):
                    raise SystemExit(1)
                """
            )
            subprocess.run(
                [sys.executable, "-I", "-S", "-c", script, str(first_wheels[0])],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_publication_backend_accepts_certified_service_endpoint_paths(self) -> None:
        from cryptad_certification.engines.stable_1_0_ga_core import (
            _has_unambiguous_publication_path,
            canonical_public_https_uri,
        )

        source = str(BACKEND_ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(lambda: sys.path.remove(source))
        module = importlib.import_module(
            "cryptad_stable_maintenance_backend.provider"
        )

        for uri in (
            "https://deployment.example.com",
            "https://deployment.example.com/",
            "https://deployment.example.com/stable/",
            "https://deployment.example.com/stable/observe",
        ):
            with self.subTest(uri=uri):
                self.assertEqual(uri, canonical_public_https_uri(uri))
                self.assertTrue(_has_unambiguous_publication_path(uri))
                self.assertEqual(uri, module._canonical_https_uri(uri))

        for uri in (
            "https://deployment.example.com//",
            "https://deployment.example.com/stable//observe",
            "https://deployment.example.com/stable/./observe",
            "https://deployment.example.com/stable/../observe",
        ):
            with self.subTest(uri=uri):
                with self.assertRaisesRegex(module.ProviderError, "public-uri-invalid"):
                    module._canonical_https_uri(uri)

    def test_publication_backend_protocol_uses_schema_bound_public_topology(self) -> None:
        source = str(BACKEND_ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(lambda: sys.path.remove(source))
        module = importlib.import_module(
            "cryptad_stable_maintenance_backend.provider"
        )

        class Transport:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, dict[str, object]]] = []

            def request(self, method, uri, *, headers=None, body=None):
                request = json.loads(body)
                operation = request["operation"]
                self.calls.append((method, uri, request))
                if operation.startswith("publish-"):
                    target = (
                        "stableCatalog"
                        if operation == "publish-stable-catalog"
                        else "coreUpdate"
                    )
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-maintenance-deployment-mutation",
                        "target": target,
                        "candidateIdentityDigest": "sha256:" + "1" * 64,
                        "status": "created",
                    }
                elif operation == "observe-publication":
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-maintenance-deployment-observation",
                        "predecessorPointerDigest": "sha256:" + "2" * 64,
                        "latestCandidateIdentityDigest": None,
                        "targets": {"stableCatalog": "absent", "coreUpdate": "absent"},
                    }
                elif operation == "verify-publication":
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-maintenance-deployment-verification",
                        "maintenanceReceipt": {},
                        "coreUpdateReceipt": {},
                        "successorBaseline": {},
                        "historyEntry": {},
                    }
                elif operation == "observe-latest-pointer":
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-maintenance-pointer-observation",
                        "status": "observed",
                        "pointerDigest": "sha256:" + "2" * 64,
                        "activeBaselineDigest": "sha256:" + "3" * 64,
                        "candidateIdentityDigest": "sha256:" + "1" * 64,
                    }
                else:
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-maintenance-pointer-activation",
                        "status": "activated",
                        "activatedPointerDigest": "sha256:" + "4" * 64,
                    }
                encoded = json.dumps(response, indent=2, sort_keys=True).encode() + b"\n"
                return 200, {}, encoded

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def record(name, value):
                path = root / name
                path.write_bytes(
                    json.dumps(
                        value, ensure_ascii=False, indent=2, sort_keys=True
                    ).encode()
                    + b"\n"
                )
                return path

            (root / "catalog.json").write_bytes(b"catalog")
            (root / "catalog.sig").write_bytes(b"signature")
            core_info_value = {}
            core_info = record("core-info.json", core_info_value)
            candidate_input = {
                "stableCatalog": {
                    "fileName": "catalog.json",
                    "signatureFileName": "catalog.sig",
                }
            }
            candidate_input_path = record("candidate-input.json", candidate_input)
            candidate = {
                "candidateInputDigest": module._digest(
                    candidate_input_path.read_bytes()
                )
            }
            candidate_path = record("candidate.json", candidate)
            ga_baseline = {"stableMilestone": "1.0"}
            ga_baseline_path = record("ga-baseline.json", ga_baseline)
            predecessor_baseline = {"stableMilestone": "1.0"}
            predecessor_baseline_path = record(
                "predecessor-baseline.json", predecessor_baseline
            )
            evidence = {"evidenceRows": []}
            evidence_path = record("evidence.json", evidence)
            lineage = {
                "gaRoot": {
                    "maintenanceBaselineDigest": module._digest(
                        ga_baseline_path.read_bytes()
                    )
                }
            }
            lineage_path = record("lineage.json", lineage)
            provenance = {
                "lineageDigest": module._digest(lineage_path.read_bytes()),
                "predecessorBaselineDigest": module._digest(
                    predecessor_baseline_path.read_bytes()
                ),
                "evidenceDigest": module._digest(evidence_path.read_bytes()),
            }
            provenance_path = record(
                "stable-1.0-maintenance-provenance.json", provenance
            )
            core_plan = {"edition": 301}
            core_plan_path = record("core-publication-plan.json", core_plan)
            plan = {
                "githubReleasePageUri": "https://github.com/crypta-network/cryptad/releases/tag/v301",
                "deploymentServicePublicUri": "https://deployment.example.com/stable/observe",
                "latestPointerPublicUri": "https://state.example.com/stable/latest.json",
                "coreInfoDigest": module._digest(core_info.read_bytes()),
                "provenanceDigest": module._digest(provenance_path.read_bytes()),
                "stableCatalogTarget": {
                    "mirrorUris": ["https://mirror.example.com/stable/catalog.json"],
                    "rollbackUri": "https://catalog.example.com/stable/history/300.json",
                },
            }
            plan_path = record("publication-plan.json", plan)
            bundle = types.SimpleNamespace(
                plan_path=plan_path,
                plan=plan,
                candidate_path=candidate_path,
                candidate=candidate,
                candidate_input_path=candidate_input_path,
                candidate_input=candidate_input,
                lineage_path=lineage_path,
                lineage=lineage,
                core_plan_path=core_plan_path,
                core_plan=core_plan,
                core_info=core_info_value,
                legacy=root,
                core_info_path=core_info,
                ga_baseline_path=ga_baseline_path,
                ga_baseline=ga_baseline,
                predecessor_baseline_path=predecessor_baseline_path,
                predecessor_baseline=predecessor_baseline,
                evidence_path=evidence_path,
                evidence=evidence,
                authorization={"hotfixFollowUpObligationDigest": None},
                follow_up_obligation_path=None,
                follow_up_obligation=None,
                follow_up_closure_path=None,
                follow_up_closure=None,
            )
            request = types.SimpleNamespace(
                release_id="stable-1-0-maintenance-301",
                build_version="301",
                release_class="maintenance",
                candidate_identity_digest="sha256:" + "1" * 64,
                bundle=bundle,
            )
            transport = Transport()
            backend = module.StableMaintenanceBackend("offline-test-token", transport)
            backend._deployment_observation(request)
            backend.publish_target(
                "stableCatalog",
                request,
                types.SimpleNamespace(
                    purpose="stable-catalog",
                    value="https://capability.example.com/catalog",
                ),
            )
            backend.publish_target(
                "coreUpdate",
                request,
                types.SimpleNamespace(
                    purpose="core-update",
                    value="https://capability.example.com/core",
                ),
            )
            backend.verify_publication(request)
            receipt = {
                "releaseId": request.release_id,
                "candidateIdentityDigest": request.candidate_identity_digest,
                "deploymentServicePublicUri": plan["deploymentServicePublicUri"],
                "latestPointerPublicUri": plan["latestPointerPublicUri"],
            }
            activation = types.SimpleNamespace(
                receipt=receipt,
                expected_pointer_digest="sha256:" + "2" * 64,
                activated_pointer_digest="sha256:" + "4" * 64,
                activated_pointer_bytes=b"{}\n",
            )
            backend.observe_latest_pointer(activation)
            backend.activate_latest(
                activation,
                types.SimpleNamespace(
                    purpose="maintenance-state",
                    value="https://capability.example.com/state",
                ),
            )

            operations = [row[2]["operation"] for row in transport.calls]
            self.assertEqual(
                [
                    "observe-publication",
                    "publish-stable-catalog",
                    "publish-core-update",
                    "verify-publication",
                    "observe-latest-pointer",
                    "activate-latest-pointer",
                ],
                operations,
            )
            self.assertEqual(
                plan["latestPointerPublicUri"],
                transport.calls[-1][2]["subject"]["latestPointerPublicUri"],
            )
            verification_call = next(
                call
                for call in transport.calls
                if call[2]["operation"] == "verify-publication"
            )
            verification_subject = verification_call[2]["subject"]
            self.assertEqual(
                {
                    "releaseId",
                    "buildVersion",
                    "releaseClass",
                    "candidateIdentityDigest",
                    "publicationPlan",
                    "coreInfo",
                    "lineage",
                    "verificationInputs",
                },
                set(verification_subject),
            )
            bindings = verification_subject["verificationInputs"]
            self.assertEqual(
                {
                    "publicationPlan",
                    "candidate",
                    "candidateInput",
                    "lineage",
                    "corePublicationPlan",
                    "coreInfo",
                    "gaBaseline",
                    "predecessorBaseline",
                    "evidence",
                    "provenance",
                    "hotfixFollowUpObligation",
                    "hotfixFollowUpClosure",
                },
                set(bindings),
            )
            expected_paths = {
                "publicationPlan": plan_path,
                "candidate": candidate_path,
                "candidateInput": candidate_input_path,
                "lineage": lineage_path,
                "corePublicationPlan": core_plan_path,
                "coreInfo": core_info,
                "gaBaseline": ga_baseline_path,
                "predecessorBaseline": predecessor_baseline_path,
                "evidence": evidence_path,
                "provenance": provenance_path,
            }
            for name, path in expected_paths.items():
                self.assertEqual(
                    module._digest(path.read_bytes()), bindings[name]["digest"]
                )
                self.assertEqual(
                    json.loads(path.read_text(encoding="utf-8")),
                    bindings[name]["record"],
                )
            self.assertIsNone(bindings["hotfixFollowUpObligation"])
            self.assertIsNone(bindings["hotfixFollowUpClosure"])
            for _method, _uri, service_request in transport.calls[:3]:
                self.assertNotIn(
                    "verificationInputs", service_request.get("subject", {})
                )

            provenance_path.write_bytes(
                json.dumps(
                    {**provenance, "evidenceDigest": "sha256:" + "f" * 64},
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode()
                + b"\n"
            )
            with self.assertRaisesRegex(
                module.ProviderError, "verification-input-digest-mismatch"
            ):
                backend._verification_subject(request)

    def test_publication_backend_streams_large_assets_and_rejects_duplicate_names(
        self,
    ) -> None:
        source = str(BACKEND_ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(lambda: sys.path.remove(source))
        module = importlib.import_module(
            "cryptad_stable_maintenance_backend.provider"
        )

        class Transport:
            def __init__(self) -> None:
                self.calls: list[tuple[str, int]] = []

            def digest(self, uri, expected_size, *, headers=None):
                self.calls.append((uri, expected_size))
                return 200, expected_size, "sha256:" + "a" * 64

        size = 512 * 1024 * 1024
        plan = {
            "assets": [
                {
                    "fileName": "cryptad-301.exe",
                    "sizeBytes": size,
                    "digest": "sha256:" + "a" * 64,
                    "publicUri": "https://downloads.example.com/cryptad-301.exe",
                }
            ]
        }
        request = types.SimpleNamespace(bundle=types.SimpleNamespace(plan=plan))
        transport = Transport()
        backend = module.StableMaintenanceBackend("offline-test-token", transport)
        release = {"assets": [{"id": 7, "name": "cryptad-301.exe", "size": size}]}
        self.assertEqual("matching", backend._assets_status(request, release))
        self.assertEqual("matching", backend._artifact_status(request))
        self.assertEqual(
            [
                (
                    "https://api.github.com/repos/crypta-network/cryptad/releases/assets/7",
                    size,
                ),
                ("https://downloads.example.com/cryptad-301.exe", size),
            ],
            transport.calls,
        )
        duplicate = {
            "assets": [
                {"id": 7, "name": "cryptad-301.exe", "size": size},
                {"id": 8, "name": "cryptad-301.exe", "size": size},
            ]
        }
        self.assertEqual("conflict", backend._assets_status(request, duplicate))

    def test_publication_backend_requires_the_deterministic_release_title(self) -> None:
        source = str(BACKEND_ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(lambda: sys.path.remove(source))
        module = importlib.import_module(
            "cryptad_stable_maintenance_backend.provider"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            notes = "Stable maintenance notes\n"
            (root / "stable-1.0-maintenance-release-notes.md").write_text(
                notes, encoding="utf-8"
            )
            plan = {
                "expectedTag": "v301",
                "sourceCommit": "a" * 40,
                "githubReleasePageUri": (
                    "https://github.com/crypta-network/cryptad/releases/tag/v301"
                ),
            }
            request = types.SimpleNamespace(
                bundle=types.SimpleNamespace(plan=plan, legacy=root)
            )
            release = {
                "tag_name": "v301",
                "target_commitish": "a" * 40,
                "name": "Cryptad v301",
                "html_url": plan["githubReleasePageUri"],
                "body": notes,
                "draft": False,
                "prerelease": False,
                "assets": [],
            }
            backend = module.StableMaintenanceBackend("offline-test-token")
            with mock.patch.object(
                backend, "_github_json", return_value=(200, release)
            ):
                self.assertEqual("matching", backend._release(request)[0])
                release["name"] = "Modified release title"
                self.assertEqual("conflict", backend._release(request)[0])

    def test_publication_backend_resumes_exact_partial_asset_uploads(self) -> None:
        source = str(BACKEND_ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(lambda: sys.path.remove(source))
        module = importlib.import_module(
            "cryptad_stable_maintenance_backend.provider"
        )

        class Transport:
            def __init__(self) -> None:
                self.downloads: list[str] = []
                self.uploads: list[str] = []
                self.digest_value = module._digest(b"a")

            def digest(self, uri, expected_size, *, headers=None):
                self.downloads.append(uri)
                return 200, expected_size, self.digest_value

            def request(self, method, uri, *, headers=None, body=None):
                self.uploads.append(uri)
                return 201, {}, b"{}"

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ("cryptad-301.tar.gz", "cryptad-301.dmg", "cryptad-301.exe")
            plan = {
                "assets": [
                    {
                        "fileName": name,
                        "sizeBytes": 1,
                        "digest": module._digest(b"a"),
                    }
                    for name in names
                ]
            }
            for name in names:
                (root / name).write_bytes(b"a")
            request = types.SimpleNamespace(
                bundle=types.SimpleNamespace(plan=plan, legacy=root)
            )
            partial_release = {
                "id": 301,
                "assets": [{"id": 7, "name": names[1], "size": 1}],
            }
            transport = Transport()
            backend = module.StableMaintenanceBackend("offline-test-token", transport)

            self.assertEqual("absent", backend._assets_status(request, {"assets": []}))
            self.assertEqual([], transport.downloads)
            self.assertEqual("absent", backend._assets_status(request, partial_release))
            self.assertEqual(
                [
                    "https://api.github.com/repos/crypta-network/cryptad/"
                    "releases/assets/7"
                ],
                transport.downloads,
            )
            with mock.patch.object(
                backend, "_release", return_value=("matching", partial_release)
            ):
                backend._upload_assets(request)

            self.assertEqual(
                [
                    "https://uploads.github.com/repos/crypta-network/cryptad/"
                    "releases/301/assets?name=cryptad-301.tar.gz",
                    "https://uploads.github.com/repos/crypta-network/cryptad/"
                    "releases/301/assets?name=cryptad-301.exe",
                ],
                transport.uploads,
            )
            self.assertEqual(2, len(transport.downloads))

            unexpected = {
                "assets": [{"id": 8, "name": "unexpected.bin", "size": 1}]
            }
            self.assertEqual("conflict", backend._assets_status(request, unexpected))
            transport.digest_value = "sha256:" + "b" * 64
            self.assertEqual("conflict", backend._assets_status(request, partial_release))

    def test_publication_backend_producer_and_setup_are_canonically_pinned(self) -> None:
        producer = BACKEND_PRODUCER.read_text(encoding="utf-8")
        action = BACKEND_ACTION.read_text(encoding="utf-8")
        for value in (
            "stable-1.0-maintenance-publication-backend",
            "cryptad_stable_maintenance_backend:factory",
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            "artifact-metadata: write",
            '"${#first_rows[@]}" -ne 1',
            '"${#second_rows[@]}" -ne 1',
        ):
            self.assertIn(value, producer)
        self.assertIn(
            "stable-1.0-maintenance-publication-backend-producer.yml", action
        )
        self.assertIn("publication-provider wheel members are ambiguous", action)

    def test_windows_producer_builds_signs_rechecks_and_attests_consumer_contract(self) -> None:
        text = WINDOWS.read_text(encoding="utf-8")

        required = (
            "workflow_dispatch:",
            "runs-on: windows-latest",
            "environment: stable-1.0-maintenance-evidence",
            "jpackageInstallerWindowsExeCryptad",
            "signtool.FullName sign",
            "signtool.FullName verify",
            "Get-AuthenticodeSignature",
            "TimeStamperCertificate",
            "refs/heads/$expectedBranch",
            "git diff-index --quiet --cached HEAD --",
            "git diff-files --quiet --",
            '"kind": "stable-1.0-maintenance-external-package-producer"',
            '"authenticode": {',
            '"timestampStatus": "pass"',
            "stable-1.0-maintenance-windows-package-producer.json",
            "actions/attest@",
            "actions/upload-artifact@v6",
        )
        for value in required:
            self.assertIn(value, text)
        self.assertGreaterEqual(text.count("git diff-files --quiet --"), 2)
        self.assertIn("productionSigning\": True", text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("contents: write", text)

    def test_input_producer_uses_protected_exact_digest_intake_and_closed_phases(self) -> None:
        text = INPUTS.read_text(encoding="utf-8")

        required = (
            "workflow_dispatch:",
            "freeze-candidate",
            "prepare-authorization",
            "validate-authorization",
            "environment: stable-1.0-maintenance-evidence",
            "CRYPTAD_STABLE_MAINTENANCE_INPUT_BUNDLE_URL",
            "INPUT_BUNDLE_SHA256",
            "NoRedirect",
            "ProxyHandler({})",
            "PinnedHTTPSConnection",
            "PinnedHTTPSHandler",
            "connect_to_pinned",
            "server_hostname=self._tls_hostname",
            "is_global",
            'refs/heads/$expected_branch',
            "duplicate JSON key",
            'raw.decode("utf-8")',
            "ensure_ascii=False, indent=2, sort_keys=True",
            "if raw != canonical:",
            "noncanonical JSON bytes",
            "_maintenance_public_redaction_findings",
            "placeholder_findings",
            "phase bundle contains an unreferenced input",
            "stable-1.0-maintenance.json",
            "stable-1.0-maintenance-authorization.json",
            "actions/attest@",
            "actions/upload-artifact@v6",
        )
        for value in required:
            self.assertIn(value, text)
        self.assertNotIn("pull_request:", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("PROTECTED_BUNDLE_URL: ${{ inputs.", text)

    def test_protected_fetch_pins_validated_address_and_tls_hostname(self) -> None:
        namespace: dict[str, object] = {"__name__": "workflow_test"}
        exec(_input_producer_fetch_script(), namespace)
        socket_module = namespace["socket"]
        connection_class = namespace["PinnedHTTPSConnection"]

        class FakeSocket:
            def __init__(self, peer: str = "8.8.8.8") -> None:
                self.peer = peer
                self.connected_to: tuple[str, int] | None = None
                self.timeout: object = None
                self.closed = False

            def settimeout(self, timeout: object) -> None:
                self.timeout = timeout

            def bind(self, source_address: object) -> None:
                raise AssertionError(f"unexpected source bind: {source_address}")

            def connect(self, sockaddr: tuple[str, int]) -> None:
                self.connected_to = sockaddr

            def getpeername(self) -> tuple[str, int]:
                return (self.peer, 443)

            def close(self) -> None:
                self.closed = True

        class FakeTlsContext:
            def __init__(self) -> None:
                self.server_hostname: str | None = None
                self.raw_socket: FakeSocket | None = None

            def wrap_socket(
                self, raw_socket: FakeSocket, *, server_hostname: str
            ) -> object:
                self.raw_socket = raw_socket
                self.server_hostname = server_hostname
                return object()

        endpoint = (
            socket_module.AF_INET,
            socket_module.SOCK_STREAM,
            socket_module.IPPROTO_TCP,
            ("8.8.8.8", 443),
        )
        raw_socket = FakeSocket()
        tls_context = FakeTlsContext()
        with (
            mock.patch.object(socket_module, "socket", return_value=raw_socket),
            mock.patch.object(
                socket_module,
                "getaddrinfo",
                side_effect=AssertionError("the pinned connection must not resolve DNS again"),
            ),
        ):
            connection = connection_class(
                "bundle.example:443",
                pinned_endpoints=(endpoint,),
                tls_hostname="bundle.example",
                tls_port=443,
                context=tls_context,
                timeout=60,
            )
            connection.connect()

        self.assertEqual(("8.8.8.8", 443), raw_socket.connected_to)
        self.assertEqual(60, raw_socket.timeout)
        self.assertIs(raw_socket, tls_context.raw_socket)
        self.assertEqual("bundle.example", tls_context.server_hostname)

        rebound_socket = FakeSocket(peer="127.0.0.1")
        rebound_context = FakeTlsContext()
        with mock.patch.object(socket_module, "socket", return_value=rebound_socket):
            connection = connection_class(
                "bundle.example:443",
                pinned_endpoints=(endpoint,),
                tls_hostname="bundle.example",
                tls_port=443,
                context=rebound_context,
                timeout=60,
            )
            with self.assertRaises(OSError):
                connection.connect()
        self.assertTrue(rebound_socket.closed)
        self.assertIsNone(rebound_context.raw_socket)

    def test_input_producer_rejects_noncanonical_json_before_phase_acceptance(self) -> None:
        script = _input_producer_validation_script()

        value = {"label": "caf\N{LATIN SMALL LETTER E WITH ACUTE}", "status": "pass"}
        canonical = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        noncanonical_documents = (
            json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n",
            canonical.removesuffix(b"\n"),
            (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
            (
                json.dumps(
                    {"status": "pass", "label": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"},
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n"
            ).encode("utf-8"),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner_temp = root / "runner-temp"
            archive = runner_temp / "stable-maintenance-input" / "bundle.zip"
            archive.parent.mkdir(parents=True)
            environment = {
                **os.environ,
                "INPUT_PHASE": "freeze-candidate",
                "PYTHONPATH": str(ROOT / "tools/release-certification"),
                "RUNNER_TEMP": str(runner_temp),
            }

            def write_bundle(encoded: bytes) -> None:
                member = zipfile.ZipInfo("input.json")
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(member, encoded)

            for index, encoded in enumerate(noncanonical_documents):
                with self.subTest(index=index):
                    write_bundle(encoded)
                    completed = subprocess.run(
                        [sys.executable, "-c", script],
                        cwd=root,
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(0, completed.returncode)
                    self.assertIn("noncanonical JSON bytes", completed.stderr)

            write_bundle(canonical)
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertNotIn("noncanonical JSON bytes", completed.stderr)
            self.assertIn(
                "phase bundle lacks the canonical manifest/input layout", completed.stderr
            )

    def test_input_producer_accepts_only_the_canonical_checked_in_policy_path(self) -> None:
        script = _input_producer_validation_script()
        canonical_policy = "tools/release-certification/stable-1.0-maintenance-policy.json"
        example = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        example["release"].update(
            {
                "id": "stable-1-0-maintenance-301",
                "version": "301",
            }
        )
        example["policies"].update(
            {
                "artifactBaseUri": "https://artifacts.example.com/stable/maintenance/301/",
                "candidateSourceBranch": "release/301",
                "candidateSourceCommit": "a" * 40,
                "candidateBaseCommit": "b" * 40,
                "candidateSourceRef": "commit:" + "a" * 40,
                "expectedPredecessorBuild": "300",
                "expectedPredecessorProductDigest": "sha256:" + "c" * 64,
                "expectedPredecessorReleaseId": "stable-1-0-ga-300",
            }
        )
        example["policies"]["metadata"] = {
            "catalogPrimaryUri": "https://catalog.example.com/stable/catalog.json",
            "catalogMirrorUris": "https://mirror.example.com/stable/catalog.json",
            "catalogRollbackUri": "https://catalog.example.com/stable/history/7/catalog.json",
            "coreUpdatePublicUri": "https://updates.example.com/301/core-info.json",
            "deploymentServicePublicUri": "https://deployment.example.com/stable/observe",
            "githubReleasePageUri": "https://github.com/crypta-network/cryptad/releases/tag/v301",
            "latestPointerPublicUri": "https://state.example.com/stable/latest.json",
            "hotfixAffectedPlatforms": "not-applicable",
            "hotfixIncidentId": "not-applicable",
            "hotfixSeverity": "not-applicable",
        }
        self.assertEqual(canonical_policy, example["inputs"]["maintenancePolicy"])
        example["inputs"] = {
            "maintenanceCandidateAssets": "build/protected-inputs/candidate/assets",
            "maintenanceCandidate": "build/protected-inputs/candidate/candidate.json",
            "maintenancePolicy": canonical_policy,
            "predecessorBaseline": "build/protected-inputs/predecessor/maintenance-baseline.json",
        }

        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            policy = checkout / canonical_policy
            policy.parent.mkdir(parents=True)
            shutil.copyfile(POLICY, policy)
            runner_temp = checkout / "runner-temp"
            archive = runner_temp / "stable-maintenance-input" / "bundle.zip"
            archive.parent.mkdir(parents=True)
            environment = {
                **os.environ,
                "INPUT_RELEASE_ID": "stable-1-0-maintenance-301",
                "INPUT_BUILD_VERSION": "301",
                "INPUT_RELEASE_CLASS": "maintenance",
                "INPUT_CANDIDATE_COMMIT": "a" * 40,
                "PYTHONPATH": str(ROOT / "tools/release-certification"),
                "RUNNER_TEMP": str(runner_temp),
            }

            def write_bundle(
                manifest: dict[str, object],
                phase: str,
                *,
                signature_payload: bytes = b"detached-signature\n",
                extra_asset_directory: bool = False,
                extra_file: str | None = None,
                predecessor_baseline: dict[str, object] | None = None,
            ) -> None:
                manifest_member = zipfile.ZipInfo("stable-1.0-maintenance.json")
                manifest_member.create_system = 3
                manifest_member.external_attr = (stat.S_IFREG | 0o644) << 16
                protected_member = zipfile.ZipInfo("protected-inputs/")
                protected_member.create_system = 3
                protected_member.external_attr = (stat.S_IFDIR | 0o755) << 16
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(
                        manifest_member,
                        (
                            json.dumps(
                                manifest, ensure_ascii=False, indent=2, sort_keys=True
                            )
                            + "\n"
                        ).encode("utf-8"),
                    )
                    bundle.writestr(protected_member, b"")
                    predecessor = predecessor_baseline or {
                        "kind": "stable-1.0-maintenance-baseline",
                        "schemaVersion": 1,
                    }
                    predecessor_member = zipfile.ZipInfo(
                        "protected-inputs/predecessor/maintenance-baseline.json"
                    )
                    predecessor_member.create_system = 3
                    predecessor_member.external_attr = (stat.S_IFREG | 0o644) << 16
                    bundle.writestr(
                        predecessor_member,
                        (
                            json.dumps(
                                predecessor,
                                ensure_ascii=False,
                                indent=2,
                                sort_keys=True,
                            )
                            + "\n"
                        ).encode("utf-8"),
                    )
                    for key in (
                        "previousStableLifecycleLedger",
                        "previousStableLifecycleDescriptor",
                        "stableLifecycleAuthorization",
                        "stableLifecyclePublicationPlan",
                        "stableLifecyclePublicationReceipt",
                    ):
                        configured = manifest["inputs"].get(key)
                        if not isinstance(configured, str):
                            continue
                        relative = configured.removeprefix("build/protected-inputs/")
                        lifecycle_member = zipfile.ZipInfo(
                            f"protected-inputs/{relative}"
                        )
                        lifecycle_member.create_system = 3
                        lifecycle_member.external_attr = (stat.S_IFREG | 0o644) << 16
                        bundle.writestr(
                            lifecycle_member,
                            (
                                json.dumps(
                                    {"kind": key, "status": "pass"},
                                    ensure_ascii=False,
                                    indent=2,
                                    sort_keys=True,
                                )
                                + "\n"
                            ).encode("utf-8"),
                        )
                    if phase == "freeze-candidate":
                        catalog_bytes = b"catalog.version=1\n"
                        signature_bytes = b"detached-signature\n"
                        candidate = {
                            "stableCatalog": {
                                "fileName": "catalog.properties",
                                "sizeBytes": len(catalog_bytes),
                                "digest": "sha256:"
                                + hashlib.sha256(catalog_bytes).hexdigest(),
                                "signatureFileName": "catalog.properties.sig",
                                "signatureSizeBytes": len(signature_bytes),
                                "signatureDigest": "sha256:"
                                + hashlib.sha256(signature_bytes).hexdigest(),
                            }
                        }
                        candidate_member = zipfile.ZipInfo(
                            "protected-inputs/candidate/candidate.json"
                        )
                        candidate_member.create_system = 3
                        candidate_member.external_attr = (stat.S_IFREG | 0o644) << 16
                        bundle.writestr(
                            candidate_member,
                            (
                                json.dumps(
                                    candidate,
                                    ensure_ascii=False,
                                    indent=2,
                                    sort_keys=True,
                                )
                                + "\n"
                            ).encode("utf-8"),
                        )
                        for name, contents in (
                            ("catalog.properties", catalog_bytes),
                            ("catalog.properties.sig", signature_payload),
                        ):
                            asset = zipfile.ZipInfo(
                                f"protected-inputs/candidate/assets/{name}"
                            )
                            asset.create_system = 3
                            asset.external_attr = (stat.S_IFREG | 0o644) << 16
                            bundle.writestr(asset, contents)
                        if extra_asset_directory:
                            extra = zipfile.ZipInfo(
                                "protected-inputs/candidate/assets/unexpected/"
                            )
                            extra.create_system = 3
                            extra.external_attr = (stat.S_IFDIR | 0o755) << 16
                            bundle.writestr(extra, b"")
                    if extra_file is not None:
                        extra = zipfile.ZipInfo(extra_file)
                        extra.create_system = 3
                        extra.external_attr = (stat.S_IFREG | 0o644) << 16
                        bundle.writestr(extra, b"unreferenced public-safe data\n")

            for phase, mode in (
                ("freeze-candidate", "validate-only"),
                ("prepare-authorization", "prepare-authorization"),
            ):
                with self.subTest(phase=phase):
                    manifest = json.loads(json.dumps(example))
                    manifest["commands"]["stable-maintenance"]["mode"] = mode
                    if phase == "prepare-authorization":
                        manifest["inputs"].pop("stableMaintenanceAuthorization", None)
                    write_bundle(manifest, phase)
                    completed = subprocess.run(
                        [sys.executable, "-c", script],
                        cwd=checkout,
                        env={**environment, "INPUT_PHASE": phase},
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(0, completed.returncode, completed.stderr)

            successor = json.loads(json.dumps(example))
            successor["commands"]["stable-maintenance"]["mode"] = (
                "prepare-authorization"
            )
            successor_baseline = {
                "chainDepth": 1,
                "kind": "stable-1.0-maintenance-successor-baseline",
                "schemaVersion": 2,
            }
            write_bundle(
                successor,
                "prepare-authorization",
                predecessor_baseline=successor_baseline,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "prepare-authorization"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("post-GA maintenance requires the exact lifecycle", completed.stderr)

            successor_freeze = json.loads(json.dumps(successor))
            successor_freeze["commands"]["stable-maintenance"]["mode"] = "validate-only"
            write_bundle(
                successor_freeze,
                "freeze-candidate",
                predecessor_baseline=successor_baseline,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("post-GA maintenance requires the exact lifecycle", completed.stderr)

            partial = json.loads(json.dumps(successor))
            partial["inputs"]["previousStableLifecycleLedger"] = (
                "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-ledger.json"
            )
            write_bundle(
                partial,
                "prepare-authorization",
                predecessor_baseline=successor_baseline,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "prepare-authorization"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("exact ledger, descriptor", completed.stderr)

            complete = json.loads(json.dumps(successor))
            complete["inputs"].update(
                {
                    "previousStableLifecycleLedger": "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-ledger.json",
                    "previousStableLifecycleDescriptor": "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-descriptor.json",
                    "stableLifecycleAuthorization": "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-authorization-summary.json",
                    "stableLifecyclePublicationPlan": "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-publication-plan.json",
                    "stableLifecyclePublicationReceipt": "build/protected-inputs/lifecycle/stable-1.0-support-lifecycle-publication-receipt.json",
                }
            )
            write_bundle(
                complete,
                "prepare-authorization",
                predecessor_baseline=successor_baseline,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "prepare-authorization"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            complete_freeze = json.loads(json.dumps(complete))
            complete_freeze["commands"]["stable-maintenance"]["mode"] = "validate-only"
            write_bundle(
                complete_freeze,
                "freeze-candidate",
                predecessor_baseline=successor_baseline,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            mutated_signature = json.loads(json.dumps(example))
            write_bundle(
                mutated_signature,
                "freeze-candidate",
                signature_payload=b"substituted-signature\n",
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("catalog/signature bytes do not match", completed.stderr)

            extra_directory = json.loads(json.dumps(example))
            write_bundle(
                extra_directory,
                "freeze-candidate",
                extra_asset_directory=True,
            )
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("exact catalog/signature pair", completed.stderr)

            for phase, mode in (
                ("freeze-candidate", "validate-only"),
                ("prepare-authorization", "prepare-authorization"),
            ):
                for extra_file in ("unreferenced.txt", "sibling/unreferenced.txt"):
                    with self.subTest(phase=phase, extra_file=extra_file):
                        unreferenced = json.loads(json.dumps(example))
                        unreferenced["commands"]["stable-maintenance"]["mode"] = mode
                        write_bundle(
                            unreferenced,
                            phase,
                            extra_file=extra_file,
                        )
                        completed = subprocess.run(
                            [sys.executable, "-c", script],
                            cwd=checkout,
                            env={**environment, "INPUT_PHASE": phase},
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertNotEqual(0, completed.returncode)
                        self.assertIn("unreferenced input", completed.stderr)

            wrong_policy = json.loads(json.dumps(example))
            wrong_policy["inputs"]["maintenancePolicy"] = (
                "tools/release-certification/stable-1.0-known-limitations.json"
            )
            write_bundle(wrong_policy, "freeze-candidate")
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn("not the exact checked-in policy path", completed.stderr)

            escaped_input = json.loads(json.dumps(example))
            escaped_input["inputs"]["maintenanceCandidate"] = canonical_policy
            write_bundle(escaped_input, "freeze-candidate")
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=checkout,
                env={**environment, "INPUT_PHASE": "freeze-candidate"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(
                "maintenanceCandidate does not use the canonical protected-input root",
                completed.stderr,
            )

    def test_lifecycle_authority_chain_is_documented_and_retained_across_protected_handoffs(
        self,
    ) -> None:
        expected = {
            "previousStableLifecycleLedger": (
                "build/protected-inputs/lifecycle/"
                "stable-1.0-support-lifecycle-ledger.json"
            ),
            "previousStableLifecycleDescriptor": (
                "build/protected-inputs/lifecycle/"
                "stable-1.0-support-lifecycle-descriptor.json"
            ),
            "stableLifecycleAuthorization": (
                "build/protected-inputs/lifecycle/"
                "stable-1.0-support-lifecycle-authorization-summary.json"
            ),
            "stableLifecyclePublicationPlan": (
                "build/protected-inputs/lifecycle/"
                "stable-1.0-support-lifecycle-publication-plan.json"
            ),
            "stableLifecyclePublicationReceipt": (
                "build/protected-inputs/lifecycle/"
                "stable-1.0-support-lifecycle-publication-receipt.json"
            ),
        }
        manifest = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        self.assertEqual(
            expected,
            {key: manifest["inputs"].get(key) for key in expected},
        )

        producer = INPUTS.read_text(encoding="utf-8")
        self.assertIn("configured_lifecycle_keys", producer)
        self.assertIn("post-GA maintenance requires the exact lifecycle", producer)
        for key in expected:
            with self.subTest(producer_key=key):
                self.assertIn(f'"{key}"', producer)

        release = RELEASE.read_text(encoding="utf-8")
        for key, staged_name in (
            ("previousStableLifecycleLedger", "stable-lifecycle-ledger.json"),
            ("previousStableLifecycleDescriptor", "stable-lifecycle-descriptor.json"),
            (
                "stableLifecycleAuthorization",
                "stable-lifecycle-authorization-summary.json",
            ),
            (
                "stableLifecyclePublicationPlan",
                "stable-lifecycle-publication-plan.json",
            ),
            (
                "stableLifecyclePublicationReceipt",
                "stable-lifecycle-publication-receipt.json",
            ),
        ):
            with self.subTest(release_key=key):
                self.assertIn(f"{key} {staged_name}", release)
        self.assertIn(
            "cp -R build/prior-validated-candidate/protected-inputs build/protected-inputs",
            release,
        )
        self.assertIn(
            'mkdir -p "$root/freeze" "$root/packages" "$root/authenticated-inputs"',
            release,
        )
        self.assertIn(
            "build/prior-validated-candidate/authenticated-inputs",
            release,
        )
        self.assertIn(
            "lifecycle state changed after the prior attested phase",
            release,
        )
        self.assertIn(
            'cp -R build/stable-maintenance-publication/authenticated-inputs "$root/authenticated-inputs"',
            release,
        )

    def test_lifecycle_authority_chain_presence_cannot_change_across_protected_handoffs(
        self,
    ) -> None:
        script = _release_lifecycle_handoff_script()
        names = (
            "stable-lifecycle-ledger.json",
            "stable-lifecycle-descriptor.json",
            "stable-lifecycle-authorization-summary.json",
            "stable-lifecycle-publication-plan.json",
            "stable-lifecycle-publication-receipt.json",
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prior = root / "prior"
            current = root / "current"
            prior.mkdir()
            current.mkdir()

            def set_authority_chain(path: Path, present: bool) -> None:
                for name in names:
                    candidate = path / name
                    if present:
                        candidate.write_bytes((name + "\n").encode("utf-8"))
                    else:
                        candidate.unlink(missing_ok=True)

            for prior_present, current_present in ((True, False), (False, True)):
                with self.subTest(
                    prior_present=prior_present,
                    current_present=current_present,
                ):
                    set_authority_chain(prior, prior_present)
                    set_authority_chain(current, current_present)

                    completed = subprocess.run(
                        [sys.executable, "-c", script, str(prior), str(current)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                    self.assertNotEqual(0, completed.returncode)
                    self.assertIn(
                        "lifecycle authority-chain presence changed",
                        completed.stderr,
                    )

            set_authority_chain(prior, True)
            set_authority_chain(current, True)
            completed = subprocess.run(
                [sys.executable, "-c", script, str(prior), str(current)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_input_producer_authenticates_all_five_lifecycle_artifacts(self) -> None:
        workflow = INPUTS.read_text(encoding="utf-8")
        self.assertIn(
            'if "stableLifecyclePublicObservationReceipt" in inputs:', workflow
        )
        self.assertIn(
            "generated only by the protected maintenance workflow under the shared publication lock",
            workflow,
        )
        step = workflow[workflow.index(
            "      - name: Independently authenticate the exact lifecycle authority chain"
        ):]
        step = step[: step.index("\n      - name:", 8)]

        self.assertIn(
            "if: ${{ inputs.phase != 'validate-authorization' }}", step
        )
        self.assertIn(
            'signer="crypta-network/cryptad/.github/workflows/stable-1.0-support-lifecycle.yml"',
            step,
        )
        self.assertIn('gh attestation verify "$path"', step)
        self.assertIn('--source-digest "$INPUT_LIFECYCLE_SOURCE_COMMIT"', step)
        self.assertIn("--deny-self-hosted-runners", step)
        self.assertIn("^[0-9a-f]{40}$", step)
        for name in (
            "stable-1.0-support-lifecycle-ledger.json",
            "stable-1.0-support-lifecycle-descriptor.json",
            "stable-1.0-support-lifecycle-authorization-summary.json",
            "stable-1.0-support-lifecycle-publication-plan.json",
            "stable-1.0-support-lifecycle-publication-receipt.json",
        ):
            with self.subTest(name=name):
                self.assertIn(name, step)

    def test_release_consumer_rebinds_exact_windows_bytes_and_signer(self) -> None:
        text = RELEASE.read_text(encoding="utf-8")

        required = (
            "CRYPTAD_STABLE_MAINTENANCE_WINDOWS_SIGNER_WORKFLOW",
            "CRYPTAD_WINDOWS_CODE_SIGNING_CERTIFICATE_SHA1",
            'find "$download" -type f | wc -l',
            '.authenticode.status == "pass"',
            '.authenticode.timestampStatus == "pass"',
            ".authenticode.signerCertificateIdentityDigest == $signer_digest",
            ".assetDigest == $exe_digest",
            ".assetSizeBytes == $exe_size",
            'gh attestation verify "$exe"',
            'gh attestation verify "$producer"',
        )
        for value in required:
            self.assertIn(value, text)

    def test_linux_package_producer_installs_rpm_tools_before_gradle(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        install_start = workflow.index("      - name: Install Linux RPM packaging tools")
        install_end = workflow.index("\n      - name:", install_start + 8)
        install_step = workflow[install_start:install_end]
        build_start = workflow.index("      - name: Build package set once")

        self.assertIn("if: matrix.package_class == 'linux-and-portable'", install_step)
        self.assertIn("sudo apt-get install --yes rpm", install_step)
        self.assertIn("command -v rpm >/dev/null", install_step)
        self.assertIn("command -v rpmbuild >/dev/null", install_step)
        self.assertLess(install_start, build_start)

    def test_publication_preflight_accepts_only_safe_initial_states(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        step_start = workflow.index(
            "      - name: Preflight predecessor, authorization, freeze, and public conflicts"
        )
        step_end = workflow.index("\n      - name:", step_start + 8)
        step = workflow[step_start:step_end]

        for state in ("matching-existing", "resumable-prefix"):
            with self.subTest(state=state):
                self.assertIn(f'.publicState == "{state}"', step)
        self.assertNotIn('.publicState == "absent"', step)
        self.assertNotIn('.publicState == "partial"', step)

    def test_protected_publication_uses_only_verified_leumor_token_for_github_state(
        self,
    ) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        job_start = workflow.index("  protected-publication:")
        job_end = workflow.index("\n  independent-verification:", job_start)
        job = workflow[job_start:job_end]

        self.assertIn("contents: read", job)
        self.assertNotIn("contents: write", job)
        self.assertIn("github-token: ${{ github.token }}", job)
        self.assertIn("GH_TOKEN: ${{ github.token }}", job)

        identity_start = job.index(
            "      - name: Verify protected leumor GitHub publication identity"
        )
        identity_end = job.index("\n      - name:", identity_start + 8)
        identity_step = job[identity_start:identity_end]
        self.assertIn(
            "LEUMOR_GITHUB_TOKEN: ${{ secrets.LEUMOR_GITHUB_TOKEN }}",
            identity_step,
        )
        self.assertIn('[[ -z "$LEUMOR_GITHUB_TOKEN" ]]', identity_step)
        self.assertIn(
            'GH_TOKEN="$LEUMOR_GITHUB_TOKEN" gh api user --jq .login',
            identity_step,
        )
        self.assertIn('!= "leumor"', identity_step)

        for step_name in (
            "Preflight predecessor, authorization, freeze, and public conflicts",
            "Publish or idempotently verify exact bytes",
        ):
            with self.subTest(step=step_name):
                step_start = job.index(f"      - name: {step_name}")
                step_end = job.index("\n      - name:", step_start + 8)
                step = job[step_start:step_end]
                self.assertIn(
                    "GITHUB_TOKEN: ${{ secrets.LEUMOR_GITHUB_TOKEN }}", step
                )
                self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", step)

        mutation_start = job.index(
            "      - name: Publish or idempotently verify exact bytes"
        )
        self.assertLess(identity_start, mutation_start)

    def test_freeze_binds_the_sole_notarization_receipt_only_to_the_dmg(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        step_start = workflow.index(
            "      - name: Generate the canonical exact-byte freeze record"
        )
        step_end = workflow.index("\n      - name:", step_start + 8)
        step = workflow[step_start:step_end]

        required = (
            "select_candidate_dmg_for_freeze(",
            'os.environ["INPUT_RELEASE_CLASS"]',
            'candidate.get("changeScope", {})',
            'mac_assets[0].suffix.lower() != ".dmg"',
            'mac_receipt_value.get("fileName") != mac_assets[0].name',
            'mac_receipt_value.get("subjectDigest") != file_digest(mac_assets[0])',
            'mac_receipt_value.get("subjectSizeBytes") != mac_assets[0].stat().st_size',
            "if dmg_package is not None:",
            'mac_assets[0].name != dmg_path.name',
            'file_digest(mac_assets[0]) != file_digest(dmg_path)',
            '"pass" if package.get("packageType") == "dmg" else "not-applicable"',
            '"notarizationStatus": "pass" if is_dmg else "not-applicable"',
            '"notarizationReceiptDigest": mac_receipt_digest if is_dmg else None',
        )
        for value in required:
            self.assertIn(value, step)
        self.assertLess(
            step.index("for package in packages:\n              expected_notarization"),
            step.index("for package in packages:\n              path = selected"),
        )
        self.assertLess(
            step.index("cryptographic signing attestation failed for"),
            step.index("select_candidate_dmg_for_freeze("),
        )

    def test_macos_producer_signs_exact_dmg_before_notarization(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        step_start = workflow.index(
            "      - name: Build, Developer ID sign, notarize, staple, and verify macOS package once"
        )
        step_end = workflow.index("\n      - name:", step_start + 8)
        step = workflow[step_start:step_end]

        sign = (
            'codesign --force --timestamp --sign "$MACOS_DEVELOPER_ID_APPLICATION" '
            '\\\n            --keychain "$keychain" "$dmg"'
        )
        verify = 'codesign --verify --strict --verbose=2 "$dmg"'
        submit = 'xcrun notarytool submit "$dmg"'
        staple = 'xcrun stapler staple "$dmg"'
        validate = 'xcrun stapler validate "$dmg"'
        digest = 'shasum -a 256 "$dmg"'

        sign_index = step.index(sign)
        pre_notary_verify = step.index(verify, sign_index)
        submit_index = step.index(submit)
        staple_index = step.index(staple)
        validate_index = step.index(validate)
        final_verify = step.index(verify, staple_index)
        digest_index = step.index(digest)

        self.assertLess(sign_index, pre_notary_verify)
        self.assertLess(pre_notary_verify, submit_index)
        self.assertLess(submit_index, staple_index)
        self.assertLess(staple_index, validate_index)
        self.assertLess(validate_index, final_verify)
        self.assertLess(final_verify, digest_index)

    def test_freeze_cryptographically_verifies_exact_catalog_and_declared_key(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        verifier_step = workflow.index(
            "      - name: Build the trusted Stable catalog verifier"
        )
        freeze_step = workflow.index(
            "      - name: Generate the canonical exact-byte freeze record"
        )
        freeze_end = workflow.index("\n      - name:", freeze_step + 8)
        step = workflow[freeze_step:freeze_end]

        required = (
            "./gradlew :platform-devtools:installDist",
            "STABLE_CATALOG_TRUSTED_KEYS_BASE64: ${{ secrets.STABLE_CATALOG_TRUSTED_KEYS_BASE64 }}",
            'base64 --decode > "$trusted_keys"',
            'chmod 600 "$trusted_keys"',
            "unset STABLE_CATALOG_TRUSTED_KEYS_BASE64",
            "trap 'rm -rf \"$trusted_keys_dir\"' EXIT",
            '"catalog",',
            '"verify",',
            '"--catalog-file",',
            '"--catalog-signature-file",',
            '"--expected-key-id",',
            'catalog["signingKeyId"]',
            '"--trusted-keys-file",',
            "stdout=subprocess.DEVNULL",
            "stderr=subprocess.DEVNULL",
            "stable_catalog_verification_identity(",
            "catalog, file_digest(trusted_catalog_keys)",
            '"signingReceiptDigest": catalog_verification_digest',
            '"stableCatalogVerification": catalog_verification',
        )
        for value in required:
            self.assertIn(value, workflow if value.startswith("./gradlew") else step)
        self.assertLess(verifier_step, freeze_step)
        self.assertNotIn("public.key.base64", step)
        self.assertNotIn("signature.value.base64", step)

    def test_release_consumer_stages_optional_authenticated_follow_up_closure(self) -> None:
        text = RELEASE.read_text(encoding="utf-8")

        self.assertIn(
            ".inputs.hotfixFollowUpClosure?",
            text,
        )
        self.assertIn(
            "hotfixFollowUpClosure stable-1.0-hotfix-follow-up-closure.json",
            text,
        )

    def test_prepare_recreates_only_the_confined_empty_asset_directory(self) -> None:
        text = RELEASE.read_text(encoding="utf-8")
        step_start = text.index(
            "      - name: Materialize and verify prior frozen bytes for authorization preparation"
        )
        step_end = text.index("\n      - name:", step_start + 8)
        step = text[step_start:step_end]

        self.assertIn("if index in {1, 4} and not path.exists():", step)
        self.assertIn("resolved.relative_to(root)", step)
        self.assertIn("if index == 1 and not path.exists():", step)
        self.assertIn("path.mkdir(mode=0o755)", step)
        self.assertLess(step.index("resolved.relative_to(root)"), step.index("path.mkdir"))
        self.assertLess(step.index("path.mkdir"), step.index('! -d "$asset_root"'))
        self.assertLess(
            step.index('! -d "$asset_root"'),
            step.index('find "$asset_root" -mindepth 1 -print -quit'),
        )

    def test_independent_verifier_uses_shared_nonsecret_backend_identity(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        job_start = workflow.index("  independent-verification:")
        job_end = workflow.index("\n  activate-latest-baseline:", job_start)
        job = workflow[job_start:job_end]
        documentation = MAINTENANCE_DOC.read_text(encoding="utf-8")

        self.assertIn("environment: stable-1.0-maintenance-evidence", job)
        for variable in (
            "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SOURCE_COMMIT",
            "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_WHEEL_SHA256",
            "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SIGNER_WORKFLOW",
            "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND",
        ):
            with self.subTest(variable=variable):
                self.assertIn(f"${{{{ vars.{variable} }}}}", job)
                self.assertIn(variable, documentation)
        self.assertIn("repository-level Actions variables", documentation)
        self.assertIn("do not configure them only on a publication environment", documentation)

    def test_publication_backend_site_is_canonical_and_enforced_by_every_adapter_call(
        self,
    ) -> None:
        action = BACKEND_ACTION.read_text(encoding="utf-8")
        workflow = RELEASE.read_text(encoding="utf-8")

        self.assertIn('site="$(cd "$site" && pwd -P)"', action)
        self.assertIn('echo "site-directory=$site" >> "$GITHUB_OUTPUT"', action)
        self.assertIn("python3 -I -S - \"$site\" \"$INPUT_ENTRYPOINT\"", action)
        self.assertLess(
            action.index("origin = Path(module.__file__).resolve()"),
            action.index("getattr(module, factory_name, None)"),
        )
        binding = (
            "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SITE: "
            "${{ steps.publication-backend.outputs.site-directory }}"
        )
        self.assertEqual(4, workflow.count(binding))

    def test_independent_verifier_checks_core_receipt_verification_status(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        step_start = workflow.index(
            "      - name: Fetch and verify public tag, assets, catalog, updater, and package identities"
        )
        step_end = workflow.index("\n      - name:", step_start + 8)
        step = workflow[step_start:step_end]
        receipt_marker = "build/core-update-publication-receipt.json >/dev/null"
        marker_index = step.index(receipt_marker)
        check_start = step.rfind("jq -e '", 0, marker_index)
        core_receipt_check = step[check_start:marker_index]

        self.assertIn('.verificationStatus == "pass"', core_receipt_check)
        self.assertNotIn("finalVerificationStatus", core_receipt_check)

    def test_activation_uses_a_renewable_environment_scoped_authorization(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        job_start = workflow.index("  activate-latest-baseline:")
        job = workflow[job_start:]

        self.assertIn('"kind": "stable-1.0-maintenance-activation-authorization"', job)
        self.assertIn('"authority": "github-protected-environment"', job)
        self.assertIn('"allowedScope": "successor-baseline:activate"', job)
        self.assertIn("expires = now + dt.timedelta(minutes=30)", job)
        self.assertIn(
            '"originalAuthorizationDigest": digest(original_authorization_path)',
            job,
        )
        self.assertIn(
            '"expectedCurrentPointerDigest": expected_pointer_digest', job
        )
        self.assertIn('--activation-authorization "$activation_authorization"', job)
        self.assertNotIn("authorization expired before baseline activation", job)

    def test_activation_failure_audit_preserves_possible_pointer_mutation(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        marker = "build/stable-maintenance-baseline-activation-started"
        activation_start = workflow.index("      - name: Compare-and-swap latest-published pointer")
        activation_end = workflow.index("\n      - name:", activation_start + 8)
        activation_step = workflow[activation_start:activation_end]
        audit_start = workflow.index("      - name: Stage baseline activation outcome")
        audit_end = workflow.index("\n      - name:", audit_start + 8)
        audit_step = workflow[audit_start:audit_end]

        self.assertIn(f'activation_marker="{marker}"', activation_step)
        self.assertLess(
            activation_step.index('(umask 022; : > "$activation_marker")'),
            activation_step.index('python3 "$adapter"'),
        )
        for value in (
            "activationBoundaryMarkerStatus",
            "activationBoundaryEntered",
            "sideEffectsMayHaveOccurred",
            "observedPointerDigest",
            ".observedPointerDigest // empty",
        ):
            self.assertIn(value, audit_step)
        self.assertIn('cp "$marker" "$root/"', audit_step)
        self.assertIn('sideEffectsMayHaveOccurred: $activation_boundary_entered', audit_step)

    def test_publication_fallback_audit_records_attempted_targets(self) -> None:
        workflow = RELEASE.read_text(encoding="utf-8")
        step_start = workflow.index(
            "      - name: Record truthful partial state after a failed protected operation"
        )
        step_end = workflow.index("\n      - name:", step_start + 8)
        step = workflow[step_start:step_end]

        self.assertIn("attemptedTargets:", step)
        self.assertIn(
            '["artifactBase", "tag", "githubRelease", "assets", "stableCatalog", "coreUpdate"]',
            step,
        )
        self.assertIn(
            '$failure_category == "side-effecting-publication-failure"',
            step,
        )


if __name__ == "__main__":
    unittest.main()
