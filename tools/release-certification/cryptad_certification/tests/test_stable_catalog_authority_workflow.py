"""Contract tests for the protected Stable catalog-authority workflow."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from cryptad_certification.engines import stable_1_0_catalog_authority as authority
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_catalog_authority import _manifest

WORKFLOW = workspace_root() / ".github/workflows/stable-1.0-catalog-authority.yml"
GA_WORKFLOW = workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
PROTECTED_CLOSEOUT_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-protected-release-closeout.yml"
)
INDEPENDENT_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-independent-reproducibility.yml"
)
MIRROR_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-catalog-mirror-observation.yml"
)
RECOVERY_QUORUM_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-catalog-recovery-quorum.yml"
)
DRILL_ACCEPTANCE_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-catalog-drill-acceptance.yml"
)


def _job(text: str, name: str, next_name: str | None) -> str:
    start = text.index(f"\n  {name}:")
    if next_name is None:
        return text[start:]
    return text[start : text.index(f"\n  {next_name}:", start + 1)]


def _validation_python(text: str) -> str:
    marker = next(
        candidate
        for candidate in (
            "          python3 - <<'PY'\n",
            "          PYTHONPATH=tools/release-certification python3 - <<'PY'\n",
        )
        if candidate in text
    )
    start = text.index(marker) + len(marker)
    end = text.index("\n          PY", start)
    return "\n".join(line[10:] for line in text[start:end].splitlines()) + "\n"


class StableCatalogAuthorityWorkflowTest(unittest.TestCase):
    """Keeps catalog governance, publication, and observation authorities separated."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_when_triggered_expect_closed_manual_operations(self) -> None:
        dispatch = self.workflow[
            self.workflow.index("on:\n") : self.workflow.index("\n# Catalog governance")
        ]
        options = re.findall(r"^          - ([a-z0-9-]+)$", dispatch, re.MULTILINE)

        self.assertEqual(
            [
                "prepare-ceremony",
                "verify-ceremony",
                "prepare-publication",
                "publish-network-primary",
                "verify-publication",
                "verify-rotation-drill",
                "rollback-drill",
                "closeout",
            ],
            options,
        )
        self.assertIn("  workflow_dispatch:", dispatch)
        self.assertNotIn("pull_request:", dispatch)
        self.assertNotIn("push:", dispatch)
        self.assertNotIn("workflow_call:", dispatch)
        self.assertIn("\npermissions: {}\n", self.workflow)
        self.assertIn("group: stable-1-0-release-${{ inputs.build_version }}", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_workflow_when_source_validated_expect_exact_protected_identity(self) -> None:
        validation = _job(self.workflow, "validate-dispatch", "assemble-inputs")

        self.assertIn("if: github.ref_protected", validation)
        self.assertIn("ref: ${{ github.sha }}", validation)
        self.assertIn("persist-credentials: false", validation)
        self.assertIn('"$GITHUB_REF" != "refs/heads/release/$INPUT_BUILD_VERSION"', validation)
        self.assertIn('"$GITHUB_SHA" != "$INPUT_SOURCE_COMMIT"', validation)
        self.assertIn('"$WORKFLOW_SHA" != "$INPUT_SOURCE_COMMIT"', validation)
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', validation)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', validation)
        self.assertIn("duplicate JSON key", validation)
        self.assertIn("artifactDigest", validation)
        self.assertIn(
            're.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", artifact_name)',
            validation,
        )
        self.assertIn(
            'artifactName; test("^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")',
            validation,
        )
        self.assertIn("operation requires a bounded v1 artifact aggregate", validation)
        self.assertIn("operation artifact aggregate does not cover the exact evidence set", validation)
        self.assertNotIn('if operation != "closeout"', validation)
        self.assertIn('"prepare-publication",', validation)
        self.assertIn('"publish-network-primary",', validation)
        self.assertIn('"verify-publication",', validation)
        self.assertIn('"verify-rotation-drill", "rollback-drill", "closeout"', validation)
        self.assertIn('required_targets.update(publication_targets)', validation)
        self.assertIn('required_targets.update(rollback_targets)', validation)
        self.assertIn('required_targets.update(drill_targets)', validation)
        self.assertIn('required_targets.update(observation_targets)', validation)
        self.assertIn('if ceremony_type != "genesis":', validation)
        self.assertIn("workflow not in target_workflows[target]", validation)
        self.assertIn(".repository.full_name == $repository", validation)
        self.assertIn(".head_repository.full_name == $repository", validation)
        self.assertIn(".actor.login == \"leumor\"", validation)
        self.assertIn(".triggering_actor.login == \"leumor\"", validation)
        self.assertIn(".[0].digest == $digest", validation)

    def test_workflow_when_operation_selected_expect_exact_aggregate_member_set(self) -> None:
        common = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
        }
        publication = {
            "cryptad-app-catalog.properties",
            "cryptad-app-catalog.signature",
            "stable-1.0-ga-publication-plan.json",
            "stable-1.0-ga-publication-receipt.json",
            "stable-1.0-protected-release-public-observation.json",
        }
        rollback = {
            "stable-1.0-rollback-app-catalog.properties",
            "stable-1.0-rollback-app-catalog.signature",
        }
        observation = {
            "stable-1.0-live-usk-publication.json",
            "stable-1.0-catalog-mirror-observation.json",
        }
        drills = {"stable-1.0-catalog-drill-receipts.json"}
        expected = {
            "prepare-ceremony": common,
            "verify-ceremony": common,
            "prepare-publication": common | publication,
            "publish-network-primary": common | publication,
            "verify-publication": common | publication | observation,
            "verify-rotation-drill": common | rollback | drills,
            "rollback-drill": common | rollback | drills,
            "closeout": common | publication | rollback | observation | drills,
        }
        for operation, targets in expected.items():
            with self.subTest(operation=operation):
                completed = subprocess.run(
                    ("python3", "-c", _validation_python(self.workflow)),
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={
                        **os.environ,
                        "INPUT_OPERATION": operation,
                        "INPUT_RELEASE_ID": "stable-fixture",
                        "INPUT_BUILD_VERSION": "293",
                        "INPUT_SOURCE_COMMIT": "a" * 40,
                        "AUTHORITY_MANIFEST_JSON": json.dumps(
                            {
                                "release": {
                                    "releaseId": "stable-fixture",
                                    "buildVersion": 293,
                                    "sourceCommit": "a" * 40,
                                },
                                "ceremony": {"ceremonyType": "genesis"},
                                "recoveryAuthorization": {
                                    "authorizationType": "recovery-signature"
                                },
                                "publication": {
                                    "networkPrimary": {
                                        "publicUri": "crypta:USK@public/stable/293/catalog"
                                    }
                                },
                            }
                        ),
                        "PROTECTED_INPUT_COORDINATES": json.dumps(
                            self._coordinates_for_targets(targets)
                        ),
                        "NETWORK_CATALOG_SOURCE": (
                            "crypta:USK@public/stable/293/catalog"
                            if operation == "publish-network-primary"
                            else ""
                        ),
                    },
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

    def test_workflow_when_bootstrap_producer_is_substituted_expect_rejection(
        self,
    ) -> None:
        common = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
        }
        coordinates = self._retained_preparation_coordinates(common)

        completed = subprocess.run(
            ("python3", "-c", _validation_python(self.workflow)),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "INPUT_OPERATION": "prepare-ceremony",
                "INPUT_RELEASE_ID": "stable-fixture",
                "INPUT_BUILD_VERSION": "293",
                "INPUT_SOURCE_COMMIT": "a" * 40,
                "AUTHORITY_MANIFEST_JSON": json.dumps(
                    {
                        "release": {
                            "releaseId": "stable-fixture",
                            "buildVersion": 293,
                            "sourceCommit": "a" * 40,
                        },
                        "ceremony": {"ceremonyType": "genesis"},
                        "recoveryAuthorization": {
                            "authorizationType": "recovery-signature"
                        },
                        "publication": {
                            "networkPrimary": {
                                "publicUri": "crypta:USK@public/stable/293/catalog"
                            }
                        },
                    }
                ),
                "PROTECTED_INPUT_COORDINATES": json.dumps(coordinates),
                "NETWORK_CATALOG_SOURCE": "",
            },
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("role-confused", completed.stderr)

    def test_workflow_when_verifying_ceremony_expect_retained_preparation_roots_accepted(
        self,
    ) -> None:
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "stable-1.0-previous-public-key-transparency.json",
            "stable-1.0-previous-public-key-transparency.signature",
        }
        coordinates = self._retained_preparation_coordinates(targets)

        completed = self._run_validation(
            "verify-ceremony", coordinates, "recovery-signature"
        )

        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_workflow_when_release_id_is_maximum_expect_canonical_artifacts_accepted(
        self,
    ) -> None:
        release_id = "r" * 128
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
        }
        coordinates = self._coordinates_for_targets(targets)
        for coordinate in coordinates["artifacts"]:
            coordinate["artifactName"] = coordinate["artifactName"].replace(
                "stable-fixture", release_id
            )
        artifact_names = [
            coordinate["artifactName"] for coordinate in coordinates["artifacts"]
        ]
        environment = {
            **os.environ,
            "INPUT_OPERATION": "prepare-ceremony",
            "INPUT_RELEASE_ID": release_id,
            "INPUT_BUILD_VERSION": "293",
            "INPUT_SOURCE_COMMIT": "a" * 40,
            "AUTHORITY_MANIFEST_JSON": json.dumps(
                {
                    "release": {
                        "releaseId": release_id,
                        "buildVersion": 293,
                        "sourceCommit": "a" * 40,
                    },
                    "ceremony": {"ceremonyType": "genesis"},
                    "recoveryAuthorization": {
                        "authorizationType": "recovery-signature"
                    },
                    "publication": {
                        "networkPrimary": {
                            "publicUri": "crypta:USK@public/stable/293/catalog"
                        }
                    },
                }
            ),
            "PROTECTED_INPUT_COORDINATES": json.dumps(coordinates),
            "NETWORK_CATALOG_SOURCE": "",
        }

        completed = subprocess.run(
            ("python3", "-c", _validation_python(self.workflow)),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

        self.assertTrue(any(len(name) > 128 for name in artifact_names))
        self.assertTrue(all(len(name) <= 255 for name in artifact_names))
        self.assertEqual(0, completed.returncode, completed.stderr)
        coordinates["artifacts"][0]["artifactName"] = "a" * 256
        environment["PROTECTED_INPUT_COORDINATES"] = json.dumps(coordinates)
        rejected = subprocess.run(
            ("python3", "-c", _validation_python(self.workflow)),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("coordinate identity is invalid", rejected.stderr)

    @staticmethod
    def _coordinates_for_targets(targets: set[str]) -> dict[str, object]:
        protected = {"stable-1.0-protected-release-execution-summary.json"}
        independent = {
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
        }
        public_observation = {
            "stable-1.0-protected-release-public-observation.json",
        }
        live = {"stable-1.0-live-usk-publication.json"}
        mirror = {"stable-1.0-catalog-mirror-observation.json"}
        recovery_quorum = {
            "stable-1.0-protected-recovery-quorum-receipt.json"
        }
        previous_transparency = {
            "stable-1.0-previous-public-key-transparency.json",
            "stable-1.0-previous-public-key-transparency.signature",
        }
        drill_receipts = {"stable-1.0-catalog-drill-receipts.json"}
        rows = []
        for run_id, selected, workflow, artifact, sources in (
            (
                100,
                targets & protected,
                ".github/workflows/stable-1.0-protected-release-closeout.yml",
                "stable-1-0-protected-release-closeout-stable-fixture-293-100-1",
                {},
            ),
            (
                101,
                targets & independent,
                ".github/workflows/stable-1.0-independent-reproducibility.yml",
                "stable-1-0-independent-closeout-stable-fixture-293-101-1",
                {},
            ),
            (
                105,
                targets & public_observation,
                ".github/workflows/stable-1.0-public-observation.yml",
                "stable-1-0-public-observation-293-105-1",
                {
                    "stable-1.0-protected-release-public-observation.json": (
                        "stable-1.0-public-observation.json"
                    )
                },
            ),
            (
                102,
                targets
                - protected
                - independent
                - public_observation
                - live
                - mirror
                - recovery_quorum
                - previous_transparency
                - drill_receipts,
                ".github/workflows/stable-1.0-ga-promotion.yml",
                "stable-1-0-ga-catalog-authority-handoff-stable-fixture-293-102-1",
                {},
            ),
            (
                108,
                targets & previous_transparency,
                ".github/workflows/stable-1.0-catalog-authority.yml",
                "stable-1-0-catalog-authority-preparation-stable-fixture-293-108-1",
                {
                    "stable-1.0-previous-public-key-transparency.json": (
                        "catalog-authority-output/stable-1.0-public-key-transparency.json"
                    ),
                    "stable-1.0-previous-public-key-transparency.signature": (
                        "catalog-authority-output/stable-1.0-public-key-transparency.signature"
                    ),
                },
            ),
            (
                103,
                targets & live,
                ".github/workflows/stable-1.0-catalog-authority.yml",
                "stable-1-0-catalog-publication-stable-fixture-293-103-1",
                {},
            ),
            (
                104,
                targets & mirror,
                ".github/workflows/stable-1.0-catalog-mirror-observation.yml",
                "stable-1-0-catalog-mirror-observation-293-104-1",
                {
                    "stable-1.0-catalog-mirror-observation.json": (
                        "stable-1.0-catalog-mirror-observation.json"
                    )
                },
            ),
            (
                106,
                targets & recovery_quorum,
                ".github/workflows/stable-1.0-catalog-recovery-quorum.yml",
                "stable-1-0-catalog-recovery-quorum-293-106-1",
                {},
            ),
            (
                107,
                targets & drill_receipts,
                ".github/workflows/stable-1.0-catalog-drill-acceptance.yml",
                "stable-1-0-catalog-drill-acceptance-293-107-1",
                {},
            ),
        ):
            if not selected:
                continue
            rows.append(
                {
                    "artifactDigest": "sha256:" + "a" * 64,
                    "artifactName": artifact,
                    "members": [
                        {
                            "digest": "sha256:" + "b" * 64,
                            "sourcePath": sources.get(target, target),
                            "targetName": target,
                        }
                        for target in sorted(selected)
                    ],
                    "runAttempt": 1,
                    "runId": run_id,
                    "workflowPath": workflow,
                }
            )
        return {"schemaVersion": 1, "artifacts": rows}

    @staticmethod
    def _retained_preparation_coordinates(
        targets: set[str],
    ) -> dict[str, object]:
        previous_transparency = {
            "stable-1.0-previous-public-key-transparency.json": (
                "catalog-authority-output/stable-1.0-public-key-transparency.json"
            ),
            "stable-1.0-previous-public-key-transparency.signature": (
                "catalog-authority-output/stable-1.0-public-key-transparency.signature"
            ),
        }
        return {
            "schemaVersion": 1,
            "artifacts": [
                {
                    "artifactDigest": "sha256:" + "a" * 64,
                    "artifactName": (
                        "stable-1-0-catalog-authority-preparation-"
                        "stable-fixture-293-108-1"
                    ),
                    "members": [
                        {
                            "digest": "sha256:" + "b" * 64,
                            "sourcePath": previous_transparency.get(
                                target, f"catalog-authority-input/{target}"
                            ),
                            "targetName": target,
                        }
                        for target in sorted(targets)
                    ],
                    "runAttempt": 1,
                    "runId": 108,
                    "workflowPath": (
                        ".github/workflows/stable-1.0-catalog-authority.yml"
                    ),
                }
            ],
        }

    def test_workflow_when_actions_used_expect_full_sha_pins(self) -> None:
        actions = re.findall(r"^\s*uses:\s*([^\s#]+)", self.workflow, re.MULTILINE)

        self.assertTrue(actions)
        for action in actions:
            if action.startswith("./"):
                continue
            with self.subTest(action=action):
                self.assertRegex(
                    action,
                    r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$",
                )
        checkout_count = self.workflow.count("uses: actions/checkout@")
        self.assertEqual(checkout_count, self.workflow.count("ref: ${{ github.sha }}"))
        self.assertNotIn("ref: ${{ inputs.source_commit }}", self.workflow)

    def test_workflow_when_preparing_or_verifying_expect_no_secrets_or_mutation(self) -> None:
        prepare = _job(self.workflow, "prepare-authority", "verify-authority")
        verify = _job(self.workflow, "verify-authority", "publish-network-primary")

        for job in (prepare, verify):
            with self.subTest(job=job.splitlines()[1].strip()):
                self.assertNotIn("${{ secrets.", job)
                self.assertNotIn("publish-usk", job)
                self.assertNotIn("contents: write", job)
                self.assertNotIn("gh release", job)
                self.assertNotIn("git tag", job)
                self.assertIn("stable-catalog-authority", job)
        self.assertIn("--mode \"$INPUT_OPERATION\"", prepare)
        self.assertIn('if [[ "$INPUT_OPERATION" == "rollback-drill" ]]', verify)
        self.assertIn('certification_mode="verify-rotation-drill"', verify)
        self.assertIn("--mode \"$certification_mode\"", verify)
        self.assertIn("environment: stable-1-0-catalog-authority-preparation", prepare)
        self.assertIn("environment: stable-1-0-catalog-authority-verification", verify)

    def test_workflow_when_publishing_expect_one_secret_bearing_mutation_boundary(self) -> None:
        publish = _job(self.workflow, "publish-network-primary", "observe-publication")

        self.assertEqual(2, self.workflow.count("${{ secrets."))
        self.assertEqual(2, publish.count("${{ secrets."))
        self.assertIn("environment: stable-1-0-catalog-publication", publish)
        permission_block = publish[publish.index("    permissions:") : publish.index("    steps:")]
        self.assertIn("actions: read", permission_block)
        self.assertIn("contents: read", permission_block)
        self.assertNotIn("write", permission_block)
        self.assertEqual(1, self.workflow.count("crypta-app publish-usk"))
        self.assertIn("--live", publish)
        self.assertIn("--verify-live-fetch", publish)
        for member in (
            "cryptad-app-catalog.properties",
            "cryptad-app-catalog.signature",
            "trusted-catalog-keys.properties",
        ):
            self.assertIn(f"build/catalog-authority-publication-stage/{member}", publish)
        self.assertIn(
            'test "$(find build/catalog-authority-publication-stage -type f | wc -l)" -eq 3',
            publish,
        )
        self.assertIn(
            "--private-insert-uri-env CRYPTAD_STABLE_USK_PRIVATE_INSERT_URI",
            publish,
        )
        self.assertIn("--form-password-env CRYPTAD_PLATFORM_FORM_PASSWORD", publish)
        unset = publish.index(
            "unset CRYPTAD_STABLE_USK_PRIVATE_INSERT_URI CRYPTAD_PLATFORM_FORM_PASSWORD"
        )
        publish_status = publish.index("publication_status=$?")
        retry_evidence_guard = publish.index(
            'and .postPublishVerificationStatus == "failed"', publish_status
        )
        receipt = publish.index('--live-publication-result "$publication_result"', unset)
        verification_status = publish.index("verification_status=$?", receipt)
        redaction_guard = publish.index(".findingCount == 0", verification_status)
        digest_guard = publish.index(
            ".livePublicationResultDigest == $live_result_digest", redaction_guard
        )
        approved_copy = publish.index(
            'install -m 0600 "$publication_result"', digest_guard
        )
        retention_commit = publish.index(
            'mv "$retention_stage" "$retention_dir"', approved_copy
        )
        publication_failure = publish.index(
            'if [[ "$publication_status" -ne 0 ]]', retention_commit
        )
        verification_failure = publish.index(
            'if [[ "$verification_status" -ne 0 ]]', publication_failure
        )
        upload = publish.index(
            "Upload sanitized mutation evidence even after verification failure",
            verification_failure,
        )
        self.assertLess(publish_status, unset)
        self.assertLess(unset, retry_evidence_guard)
        self.assertLess(retry_evidence_guard, receipt)
        self.assertLess(receipt, verification_status)
        self.assertLess(verification_status, redaction_guard)
        self.assertLess(redaction_guard, digest_guard)
        self.assertLess(digest_guard, approved_copy)
        self.assertLess(receipt, approved_copy)
        self.assertLess(approved_copy, retention_commit)
        self.assertLess(retention_commit, publication_failure)
        self.assertLess(publication_failure, verification_failure)
        self.assertLess(approved_copy, upload)
        self.assertEqual(2, publish.count("set +e"))
        self.assertEqual(2, publish.count("set -e\n"))
        self.assertIn("id: publish", publish)
        self.assertIn(
            "if: always() && steps.publish.outcome != 'skipped'", publish
        )
        self.assertIn("if-no-files-found: error", publish[upload:])
        self.assertIn("stat -c '%s'", publish)
        self.assertIn('"$publication_result")" -gt 65536', publish)
        self.assertIn('sha256sum "$publication_result"', publish)
        self.assertIn('.catalogInsertStatus == "queued"', publish)
        self.assertIn('.signatureInsertStatus == "queued"', publish)
        self.assertIn('.postPublishVerificationStatus == "failed"', publish)
        self.assertIn('.schedulerRefreshVerificationStatus == "not_run"', publish)
        self.assertIn(
            'index("staging_sidecars_retained_until_live_insert_completion") != null',
            publish,
        )
        self.assertIn(
            'index("post_publish_fetch_verification_failed") != null', publish
        )
        self.assertIn('.redaction.status == "pass"', publish)
        self.assertIn(".operational == false", publish)
        self.assertIn('.publicationState == "partial"', publish)
        self.assertIn(
            'find "$retention_stage" -mindepth 1 -maxdepth 1 -type f | wc -l',
            publish,
        )
        self.assertIn(
            'find "$retention_stage" -mindepth 1 -maxdepth 1 | wc -l',
            publish,
        )
        self.assertIn(
            "publication_result=build/catalog-authority-execution/stable-1.0-live-usk-publication.json",
            publish,
        )
        self.assertNotIn(
            "publication_result=build/catalog-authority-output/stable-1.0-live-usk-publication.json",
            publish,
        )
        uploaded = publish[upload:]
        self.assertEqual(3, uploaded.count("build/catalog-authority-mutation-retention/"))
        self.assertIn("stable-1.0-live-usk-publication.json", uploaded)
        self.assertNotIn("cryptad-app-catalog.properties", uploaded)
        self.assertNotIn("trusted-catalog-keys.properties", uploaded)

    def test_workflow_when_routing_jobs_expect_managed_mutation_runner_only(self) -> None:
        job_order = (
            "validate-dispatch",
            "assemble-inputs",
            "prepare-authority",
            "verify-authority",
            "publish-network-primary",
            "observe-publication",
            "closeout",
            "retain-failure-closeout",
        )
        jobs = {
            name: _job(
                self.workflow,
                name,
                job_order[index + 1] if index + 1 < len(job_order) else None,
            )
            for index, name in enumerate(job_order)
        }

        publish = jobs["publish-network-primary"]
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, cryptad-stable-catalog-publication]",
            publish,
        )
        self.assertNotIn("runs-on: ubuntu-latest", publish)
        for name, job in jobs.items():
            if name == "publish-network-primary":
                continue
            with self.subTest(job=name):
                self.assertIn("runs-on: ubuntu-latest", job)
                self.assertNotIn("self-hosted", job)

    def test_workflow_when_publication_node_checked_expect_secret_free_bounded_preflight(
        self,
    ) -> None:
        publish = _job(self.workflow, "publish-network-primary", "observe-publication")
        preflight_name = "Verify managed localhost daemon readiness and publication contract"
        mutation_name = "Publish once through the existing localhost Platform API boundary"
        preflight_start = publish.index(preflight_name)
        mutation_start = publish.index(mutation_name)
        preflight = publish[preflight_start:mutation_start]

        self.assertLess(preflight_start, mutation_start)
        self.assertIn("node_base_url=http://127.0.0.1:7654", preflight)
        self.assertIn('"$node_base_url/api/v1/node/greeting"', preflight)
        self.assertIn('"$node_base_url/api/v1/platform/contract"', preflight)
        self.assertIn('.method == "POST" and .routeTemplate == "/queue/inserts/directory"', preflight)
        self.assertIn('.method == "POST" and .routeTemplate == "/content/fetch"', preflight)
        self.assertIn("for _attempt in {1..30}", preflight)
        self.assertIn("--connect-timeout 2", preflight)
        self.assertIn("--max-time 5", preflight)
        self.assertIn("--noproxy '*'", preflight)
        self.assertNotIn("${{ secrets.", preflight)
        self.assertNotIn("CRYPTAD_STABLE_USK_PRIVATE_INSERT_URI", preflight)
        self.assertNotIn("CRYPTAD_PLATFORM_FORM_PASSWORD", preflight)
        self.assertIn("--node-base-url http://127.0.0.1:7654", publish[mutation_start:])

    def test_workflow_when_observing_or_closing_expect_read_only_receipt_authority(self) -> None:
        assembly = _job(self.workflow, "assemble-inputs", "prepare-authority")
        observation = _job(self.workflow, "observe-publication", "closeout")
        closeout = _job(self.workflow, "closeout", "retain-failure-closeout")

        self.assertIn("environment: stable-1-0-catalog-observation", observation)
        self.assertIn("--mode verify-publication", observation)
        self.assertIn("environment: stable-1-0-catalog-authority-closeout", closeout)
        self.assertIn("--mode closeout", closeout)
        self.assertIn("Download each exact authenticated operation artifact in isolation", assembly)
        self.assertIn("stable_1_0_catalog_authority_inputs", assembly)
        self.assertIn("resolved-operation-coordinates.json", assembly)
        self.assertIn("actions/artifacts/$artifact_id/zip", assembly)
        self.assertIn("Upload exact assembled operation handoff", assembly)
        self.assertIn("needs: [validate-dispatch, assemble-inputs]", closeout)
        self.assertIn("Download exact assembled closeout inputs", closeout)
        self.assertIn("--evidence-dir build/catalog-authority-input", observation)
        self.assertNotIn(
            "build/catalog-authority-input/stable-1.0-catalog-mirror-observation.json",
            observation[observation.index("Upload bounded observation verification") :],
        )
        for job in (observation, closeout):
            self.assertNotIn("${{ secrets.", job)
            self.assertNotIn("publish-usk", job)
            self.assertNotIn("contents: write", job)
            self.assertNotIn("gh api --method", job)
            self.assertNotIn("gh release", job)

    def test_workflow_when_any_phase_runs_expect_authenticated_aggregate_handoff(self) -> None:
        job_order = (
            "prepare-authority",
            "verify-authority",
            "publish-network-primary",
            "observe-publication",
            "closeout",
            "retain-failure-closeout",
        )
        for index, name in enumerate(job_order[:-1]):
            job = _job(self.workflow, name, job_order[index + 1])
            with self.subTest(job=name):
                self.assertIn("needs: [validate-dispatch, assemble-inputs]", job)
                self.assertIn("actions/download-artifact@", job)
                self.assertIn("stable-1-0-catalog-authority-inputs-", job)
                self.assertIn("path: build/catalog-authority-input", job)

    def test_workflow_when_closing_expect_upstream_exact_members_are_retained(self) -> None:
        preparation = _job(self.workflow, "prepare-authority", "verify-authority")
        for member in (
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "stable-1.0-protected-release-public-observation.json",
        ):
            with self.subTest(member=member):
                self.assertIn(f"build/catalog-authority-input/{member}", preparation)
        ga = GA_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Stage exact verified catalog-authority handoff", ga)
        self.assertIn("stable-1-0-ga-catalog-authority-handoff-", ga)
        for member in (
            "cryptad-app-catalog.properties",
            "cryptad-app-catalog.signature",
            "stable-1.0-ga-publication-plan.json",
            "stable-1.0-ga-publication-receipt.json",
            "stable-1.0-rollback-app-catalog.properties",
            "stable-1.0-rollback-app-catalog.signature",
        ):
            with self.subTest(ga_member=member):
                self.assertIn(f'$stage/{member}', ga)
        observation = _job(self.workflow, "observe-publication", "closeout")
        self.assertIn("--evidence-dir build/catalog-authority-input", observation)

    def test_workflow_when_bootstrapping_expect_direct_authenticated_producers(self) -> None:
        validation = _job(self.workflow, "validate-dispatch", "assemble-inputs")
        protected = PROTECTED_CLOSEOUT_WORKFLOW.read_text(encoding="utf-8")
        independent = INDEPENDENT_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            '".github/workflows/stable-1.0-protected-release-closeout.yml"',
            validation,
        )
        self.assertIn(
            '".github/workflows/stable-1.0-independent-reproducibility.yml"',
            validation,
        )
        self.assertIn(
            '".github/workflows/stable-1.0-public-observation.yml"', validation
        )
        self.assertIn(
            '".github/workflows/stable-1.0-catalog-mirror-observation.yml"',
            validation,
        )
        self.assertIn(
            '".github/workflows/stable-1.0-catalog-recovery-quorum.yml"',
            validation,
        )
        self.assertIn("--mode closeout", protected)
        self.assertIn("stable-protected-release", protected)
        self.assertIn('contract["lifecycleState"] != "publicly-observed"', protected)
        self.assertIn(
            'contract["workflowCoordinates"].get("catalogAuthority") is not None',
            protected,
        )
        self.assertIn(
            "stable-1-0-protected-release-closeout-${{ inputs.release_id }}-",
            protected,
        )
        self.assertIn("\npermissions: {}\n", protected)
        self.assertIn(
            "environment: stable-1-0-protected-release-closeout", protected
        )
        self.assertIn(
            "protected closeout coordinate does not materialize evidence", protected
        )
        self.assertNotIn("contents: write", protected)
        self.assertNotIn("gh release", protected)
        self.assertNotIn("git tag", protected)
        for action in re.findall(r"^\s*uses:\s*([^\s#]+)", protected, re.MULTILINE):
            with self.subTest(protected_closeout_action=action):
                self.assertRegex(action, r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
        self.assertIn(
            "build/independent-reproducibility-output/stable-1.0-release-subject-inventory.json",
            independent,
        )

    def test_workflow_when_first_mirror_receipt_is_supplied_expect_direct_collector_only(
        self,
    ) -> None:
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "cryptad-app-catalog.properties",
            "cryptad-app-catalog.signature",
            "stable-1.0-ga-publication-plan.json",
            "stable-1.0-ga-publication-receipt.json",
            "stable-1.0-protected-release-public-observation.json",
            "stable-1.0-live-usk-publication.json",
            "stable-1.0-catalog-mirror-observation.json",
        }
        coordinates = self._coordinates_for_targets(targets)
        mirror = next(
            row
            for row in coordinates["artifacts"]
            if row["workflowPath"]
            == ".github/workflows/stable-1.0-catalog-mirror-observation.yml"
        )

        self.assertEqual(
            "stable-1-0-catalog-mirror-observation-293-104-1",
            mirror["artifactName"],
        )
        self.assertEqual(
            "stable-1.0-catalog-mirror-observation.json",
            mirror["members"][0]["sourcePath"],
        )

        mirror["workflowPath"] = ".github/workflows/stable-1.0-catalog-authority.yml"
        mirror["artifactName"] = (
            "stable-1-0-catalog-observation-stable-fixture-293-104-1"
        )
        mirror["members"][0]["sourcePath"] = (
            "catalog-authority-input/stable-1.0-catalog-mirror-observation.json"
        )
        completed = self._run_validation(
            "verify-publication", coordinates, "recovery-signature"
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("role-confused", completed.stderr)

    def test_workflow_when_protected_quorum_selected_expect_direct_two_boundary_producer(
        self,
    ) -> None:
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "stable-1.0-previous-public-key-transparency.json",
            "stable-1.0-previous-public-key-transparency.signature",
            "stable-1.0-protected-recovery-quorum-receipt.json",
        }
        coordinates = self._coordinates_for_targets(targets)

        completed = self._run_validation(
            "verify-ceremony", coordinates, "protected-recovery-quorum"
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        quorum = next(
            row
            for row in coordinates["artifacts"]
            if row["workflowPath"]
            == ".github/workflows/stable-1.0-catalog-recovery-quorum.yml"
        )
        quorum["workflowPath"] = ".github/workflows/stable-1.0-catalog-authority.yml"
        quorum["artifactName"] = (
            "stable-1-0-catalog-authority-verification-stable-fixture-293-106-1"
        )
        quorum["members"][0]["sourcePath"] = (
            "catalog-authority-input/stable-1.0-protected-recovery-quorum-receipt.json"
        )
        rejected = self._run_validation(
            "verify-ceremony", coordinates, "protected-recovery-quorum"
        )
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("role-confused", rejected.stderr)

    def test_workflow_when_protected_recovery_closes_expect_sixteen_member_handoff(
        self,
    ) -> None:
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "cryptad-app-catalog.properties",
            "cryptad-app-catalog.signature",
            "stable-1.0-ga-publication-plan.json",
            "stable-1.0-ga-publication-receipt.json",
            "stable-1.0-protected-release-public-observation.json",
            "stable-1.0-rollback-app-catalog.properties",
            "stable-1.0-rollback-app-catalog.signature",
            "stable-1.0-catalog-drill-receipts.json",
            "stable-1.0-live-usk-publication.json",
            "stable-1.0-catalog-mirror-observation.json",
            "stable-1.0-previous-public-key-transparency.json",
            "stable-1.0-previous-public-key-transparency.signature",
            "stable-1.0-protected-recovery-quorum-receipt.json",
        }
        coordinates = self._coordinates_for_targets(targets)
        assembly = _job(self.workflow, "assemble-inputs", "prepare-authority")
        closeout = _job(self.workflow, "closeout", "retain-failure-closeout")

        completed = self._run_validation(
            "closeout", coordinates, "protected-recovery-quorum"
        )

        self.assertEqual(16, len(targets))
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn(
            'test "$(find build/catalog-authority-input -type f | wc -l)" -le 16',
            assembly,
        )
        self.assertIn(
            'test "$(find build/catalog-authority-input -type f | wc -l)" -le 16',
            closeout,
        )
        self.assertNotIn(
            'test "$(find build/catalog-authority-input -type f | wc -l)" -le 15',
            self.workflow,
        )
        coordinates["artifacts"][0]["members"].append(
            {
                "sourcePath": "unexpected-evidence.json",
                "targetName": "unexpected-evidence.json",
                "digest": "sha256:" + "f" * 64,
            }
        )
        rejected = self._run_validation(
            "closeout", coordinates, "protected-recovery-quorum"
        )
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("role-confused", rejected.stderr)

    def test_workflow_when_drills_verified_expect_original_protected_receipts(
        self,
    ) -> None:
        validation = _job(self.workflow, "validate-dispatch", "assemble-inputs")
        allowlist_start = validation.index('case "$workflow" in')
        allowlist = validation[
            allowlist_start : validation.index("esac", allowlist_start)
        ]
        authenticated_producers = set(
            re.findall(r"\.github/workflows/[a-z0-9.-]+\.yml", allowlist)
        )
        targets = {
            "stable-1.0-protected-release-execution-summary.json",
            "stable-1.0-independent-reproducibility-summary.json",
            "stable-1.0-release-subject-inventory.json",
            "stable-1.0-previous-public-key-transparency.json",
            "stable-1.0-previous-public-key-transparency.signature",
            "stable-1.0-rollback-app-catalog.properties",
            "stable-1.0-rollback-app-catalog.signature",
            "stable-1.0-catalog-drill-receipts.json",
            "stable-1.0-protected-recovery-quorum-receipt.json",
        }
        coordinates = self._coordinates_for_targets(targets)

        completed = self._run_validation(
            "verify-rotation-drill", coordinates, "protected-recovery-quorum"
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {
                ".github/workflows/stable-1.0-catalog-authority.yml",
                ".github/workflows/stable-1.0-catalog-drill-acceptance.yml",
                ".github/workflows/stable-1.0-catalog-mirror-observation.yml",
                ".github/workflows/stable-1.0-catalog-recovery-quorum.yml",
                ".github/workflows/stable-1.0-ga-promotion.yml",
                ".github/workflows/stable-1.0-independent-reproducibility.yml",
                ".github/workflows/stable-1.0-protected-release-closeout.yml",
                ".github/workflows/stable-1.0-public-observation.yml",
            },
            authenticated_producers,
        )
        receipts = next(
            row
            for row in coordinates["artifacts"]
            if row["workflowPath"]
            == ".github/workflows/stable-1.0-catalog-drill-acceptance.yml"
        )
        receipts["workflowPath"] = (
            ".github/workflows/stable-1.0-catalog-authority.yml"
        )
        receipts["artifactName"] = (
            "stable-1-0-catalog-authority-verification-stable-fixture-293-107-1"
        )
        rejected = self._run_validation(
            "verify-rotation-drill", coordinates, "protected-recovery-quorum"
        )
        self.assertNotEqual(0, rejected.returncode)
        self.assertIn("role-confused", rejected.stderr)

    @staticmethod
    def _run_validation(
        operation: str, coordinates: dict[str, object], authorization_type: str
    ) -> subprocess.CompletedProcess[str]:
        manifest = {
            "release": {
                "releaseId": "stable-fixture",
                "buildVersion": 293,
                "sourceCommit": "a" * 40,
            },
            "ceremony": {"ceremonyType": "compromise-recovery"},
            "recoveryAuthorization": {"authorizationType": authorization_type},
            "publication": {
                "networkPrimary": {
                    "publicUri": "crypta:USK@public/stable/293/catalog"
                }
            },
        }
        return subprocess.run(
            ("python3", "-c", _validation_python(WORKFLOW.read_text(encoding="utf-8"))),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "INPUT_OPERATION": operation,
                "INPUT_RELEASE_ID": "stable-fixture",
                "INPUT_BUILD_VERSION": "293",
                "INPUT_SOURCE_COMMIT": "a" * 40,
                "AUTHORITY_MANIFEST_JSON": json.dumps(manifest),
                "PROTECTED_INPUT_COORDINATES": json.dumps(coordinates),
                "NETWORK_CATALOG_SOURCE": "",
            },
        )

    def test_mirror_workflow_when_manifest_identifiers_are_unsafe_expect_preadmission_rejection(
        self,
    ) -> None:
        mirror = MIRROR_WORKFLOW.read_text(encoding="utf-8")
        validation = _job(mirror, "validate-inputs", "collect-observation")
        manifest = _manifest()
        manifest["fixtureOnly"] = False
        release = manifest["release"]
        release_id = release["releaseId"]
        build_version = release["buildVersion"]
        coordinates = {
            "schemaVersion": 1,
            "artifacts": [
                {
                    "artifactDigest": "sha256:" + "a" * 64,
                    "artifactName": (
                        "stable-1-0-catalog-authority-preparation-"
                        f"{release_id}-{build_version}-108-1"
                    ),
                    "members": [
                        {
                            "digest": "sha256:" + "b" * 64,
                            "sourcePath": (
                                "catalog-authority-output/"
                                "stable-1.0-catalog-publication-plan.json"
                            ),
                            "targetName": (
                                "stable-1.0-catalog-publication-plan.json"
                            ),
                        }
                    ],
                    "runAttempt": 1,
                    "runId": 108,
                    "workflowPath": (
                        ".github/workflows/stable-1.0-catalog-authority.yml"
                    ),
                },
                {
                    "artifactDigest": "sha256:" + "c" * 64,
                    "artifactName": (
                        "stable-1-0-ga-catalog-authority-handoff-"
                        f"{release_id}-{build_version}-102-1"
                    ),
                    "members": [
                        {
                            "digest": "sha256:" + "d" * 64,
                            "sourcePath": "cryptad-app-catalog.properties",
                            "targetName": "cryptad-app-catalog.properties",
                        },
                        {
                            "digest": "sha256:" + "e" * 64,
                            "sourcePath": "cryptad-app-catalog.signature",
                            "targetName": "cryptad-app-catalog.signature",
                        },
                    ],
                    "runAttempt": 1,
                    "runId": 102,
                    "workflowPath": (
                        ".github/workflows/stable-1.0-ga-promotion.yml"
                    ),
                },
                {
                    "artifactDigest": "sha256:" + "f" * 64,
                    "artifactName": (
                        "stable-1-0-catalog-publication-"
                        f"{release_id}-{build_version}-103-1"
                    ),
                    "members": [
                        {
                            "digest": "sha256:" + "1" * 64,
                            "sourcePath": "stable-1.0-live-usk-publication.json",
                            "targetName": "stable-1.0-live-usk-publication.json",
                        }
                    ],
                    "runAttempt": 1,
                    "runId": 103,
                    "workflowPath": (
                        ".github/workflows/stable-1.0-catalog-authority.yml"
                    ),
                },
            ],
        }
        observed_at = (
            dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        def validate(candidate: dict[str, object]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ("python3", "-c", _validation_python(validation)),
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    **os.environ,
                    "PYTHONPATH": "tools/release-certification",
                    "INPUT_RELEASE_ID": str(release_id),
                    "INPUT_BUILD_VERSION": str(build_version),
                    "INPUT_SOURCE_COMMIT": str(release["sourceCommit"]),
                    "INPUT_OBSERVED_AT": observed_at,
                    "AUTHORITY_MANIFEST_JSON": json.dumps(candidate),
                    "PROTECTED_INPUT_COORDINATES": json.dumps(coordinates),
                },
            )

        accepted = validate(manifest)

        self.assertEqual(0, accepted.returncode, accepted.stderr)
        for field, unsafe_value in (
            (("publication", "networkPrimary", "locationId"), "../escape"),
            (("catalog", "catalogId"), "../node/greeting?ignored="),
        ):
            with self.subTest(field=field):
                unsafe = json.loads(json.dumps(manifest))
                target = unsafe
                for segment in field[:-1]:
                    target = target[segment]
                target[field[-1]] = unsafe_value

                rejected = validate(unsafe)

                self.assertNotEqual(0, rejected.returncode)
                self.assertIn("observation manifest is schema-invalid", rejected.stderr)

    def test_direct_producer_workflows_when_reviewed_expect_separated_authorities(
        self,
    ) -> None:
        mirror = MIRROR_WORKFLOW.read_text(encoding="utf-8")
        quorum = RECOVERY_QUORUM_WORKFLOW.read_text(encoding="utf-8")
        drills = DRILL_ACCEPTANCE_WORKFLOW.read_text(encoding="utf-8")

        for name, workflow in (
            ("mirror", mirror),
            ("quorum", quorum),
            ("drills", drills),
        ):
            with self.subTest(workflow=name):
                self.assertIn("  workflow_dispatch:", workflow)
                self.assertNotIn("pull_request:", workflow)
                self.assertNotIn("push:", workflow)
                self.assertIn("\npermissions: {}\n", workflow)
                self.assertIn("ref: ${{ github.sha }}", workflow)
                self.assertIn("if: github.ref_protected", workflow)
                self.assertNotIn("${{ secrets.", workflow)
                self.assertNotIn("publish-usk", workflow)
                self.assertNotIn("private-insert", workflow.lower())
                self.assertNotIn("contents: write", workflow)
                self.assertNotIn("gh release", workflow)
                self.assertNotIn("git tag", workflow)
                for action in re.findall(
                    r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE
                ):
                    self.assertRegex(action, r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
        self.assertIn("cryptad-stable-catalog-observation", mirror)
        self.assertIn("stable_1_0_catalog_observation", mirror)
        mirror_validation = _job(mirror, "validate-inputs", "collect-observation")
        self.assertIn(
            "validate_schema(manifest, authority.EXECUTION_SCHEMA)", mirror_validation
        )
        self.assertLess(
            mirror_validation.index(
                "validate_schema(manifest, authority.EXECUTION_SCHEMA)"
            ),
            mirror_validation.index('release = manifest.get("release", {})'),
        )
        self.assertIn("socket.getaddrinfo", mirror)
        self.assertIn(".is_global", mirror)
        self.assertIn('--resolve "${host}:443:${resolve_addresses}"', mirror)
        self.assertIn("--max-redirs 0", mirror)
        self.assertIn("requires curl 8.4.0 or newer", mirror)
        self.assertEqual(2, mirror.count('--max-filesize "$maximum"'))
        self.assertIn(
            'fetch_local_bounded "$catalog_fetch" \\\n'
            '                "build/catalog-observation-fetched/$location_id.catalog" 1048576',
            mirror,
        )
        self.assertIn(
            'fetch_local_bounded "$signature_fetch" \\\n'
            '                "build/catalog-observation-fetched/$location_id.signature" 65536',
            mirror,
        )
        self.assertIn('rm -f "$output.partial"', mirror)
        self.assertIn('stat -c \'%s\' "$partial"', mirror)
        self.assertIn('mv "$partial" "$output"', mirror)
        self.assertNotIn(
            'curl --fail --silent --show-error --noproxy \'*\' --connect-timeout 5 '
            '--max-time 90 --max-redirs 0 "$catalog_fetch"',
            mirror,
        )
        self.assertIn('collection_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"', mirror)
        self.assertIn('collection_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"', mirror)
        self.assertIn("observation._collection_window(", mirror)
        self.assertIn("observation._health_errors(", mirror)
        self.assertIn("observation._revision_digest(catalog, signature)", mirror)
        self.assertIn('--collection-started-at "$COLLECTION_STARTED_AT"', mirror)
        self.assertIn('--collection-completed-at "$COLLECTION_COMPLETED_AT"', mirror)
        self.assertNotIn(
            "catalog-authority-input/stable-1.0-catalog-mirror-observation.json",
            mirror,
        )
        self.assertIn("stable-1-0-key-ceremony-recovery-release", quorum)
        self.assertIn("stable-1-0-key-ceremony-recovery-security", quorum)
        self.assertIn("needs: [validate-transition, release-approval, security-approval]", quorum)
        self.assertIn('"approvalRole": approval["approvalRole"]', quorum)
        self.assertNotIn("recorded_approvals", quorum)
        self.assertIn("stable-1-0-catalog-drill-release", drills)
        self.assertIn("stable-1-0-catalog-drill-security", drills)
        self.assertEqual(
            2,
            drills.count(
                "dt.datetime.now(dt.timezone.utc).replace(microsecond=0)"
            ),
        )
        self.assertEqual(
            2,
            drills.count("maximum_completion_clock_skew = dt.timedelta(minutes=5)"),
        )
        self.assertEqual(
            2,
            drills.count(
                "drill evidence completion is future-dated beyond clock skew"
            ),
        )
        self.assertIn(
            "needs: [validate-evidence, release-approval, security-approval]",
            drills,
        )
        self.assertIn("stable-1.0-catalog-drill-receipts.json", drills)
        self.assertIn("manifest drill row does not bind its reviewed evidence receipt", drills)
        verify = _job(self.workflow, "verify-authority", "publish-network-primary")
        upload = verify[verify.index("Upload bounded verification evidence") :]
        self.assertNotIn("stable-1.0-protected-recovery-quorum-receipt.json", upload)

    def test_drill_acceptance_when_completion_is_future_dated_expect_rejection(
        self,
    ) -> None:
        manifest = _manifest()
        manifest["fixtureOnly"] = False
        manifest["ceremony"]["custodyClass"] = "offline-quorum"
        completed_at = (
            dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            + dt.timedelta(hours=1)
        ).isoformat().replace("+00:00", "Z")
        evidence_rows = []
        for index, claimed in enumerate(manifest["drills"]):
            receipt = {
                "drillType": claimed["drillType"],
                "status": "pass",
                "completedAt": completed_at,
                "evidenceDigests": [
                    "sha256:" + format(index, "x") * 64
                ],
                "receiptDigest": authority.ZERO_DIGEST,
            }
            receipt["receiptDigest"] = authority._semantic_digest(
                receipt, "receiptDigest"
            )
            claimed.update(
                {
                    "fixtureOnly": False,
                    "subjectDigest": receipt["receiptDigest"],
                    "completedAt": completed_at,
                }
            )
            evidence_rows.append(
                {
                    "drillType": receipt["drillType"],
                    "completedAt": completed_at,
                    "evidenceDigests": receipt["evidenceDigests"],
                }
            )
        completed = subprocess.run(
            (
                "python3",
                "-c",
                _validation_python(
                    DRILL_ACCEPTANCE_WORKFLOW.read_text(encoding="utf-8")
                ),
            ),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "PYTHONPATH": "tools/release-certification",
                "AUTHORITY_MANIFEST_JSON": json.dumps(manifest),
                "DRILL_EVIDENCE_JSON": json.dumps(
                    {"schemaVersion": 1, "drills": evidence_rows}
                ),
                "INPUT_RELEASE_ID": manifest["release"]["releaseId"],
                "INPUT_BUILD_VERSION": str(
                    manifest["release"]["buildVersion"]
                ),
                "INPUT_SOURCE_COMMIT": manifest["release"]["sourceCommit"],
            },
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("future-dated beyond clock skew", completed.stderr)

    def test_workflow_when_reviewed_expect_no_release_or_catalog_construction_authority(self) -> None:
        forbidden = (
            "gh release create",
            "gh release upload",
            "git tag",
            "git push",
            "certify.py stable-rc",
            "certify.py stable-ga",
            "crypta-app catalog create",
            "crypta-app catalog sign",
            "./gradlew build",
            "buildJar",
            "assembleCryptadDist",
            "./gradlew run",
            "runLauncher",
            "bin/cryptad",
            "systemctl",
            "pkill",
        )

        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, self.workflow)
        self.assertIn("./gradlew :platform-devtools:installDist", self.workflow)

    def test_workflow_when_failure_occurs_expect_bounded_nonoperational_audit(self) -> None:
        failure = _job(self.workflow, "retain-failure-closeout", None)

        self.assertIn("always()", failure)
        self.assertIn("permissions: {}", failure)
        self.assertNotIn("environment:", failure)
        self.assertNotIn("${{ secrets.", failure)
        self.assertNotIn("actions/checkout", failure)
        self.assertNotIn("${{ inputs.", failure)
        self.assertIn('status: "partial"', failure)
        self.assertIn("operationalComplete: false", failure)
        self.assertIn(
            'test "$(wc -c < build/catalog-authority-failure/partial-state.json)" -le 4096',
            failure,
        )

    @unittest.skipUnless(shutil.which("bash"), "workflow syntax test requires bash")
    def test_workflow_when_shell_blocks_parsed_expect_valid_bash(self) -> None:
        lines = self.workflow.splitlines()
        scripts: list[tuple[int, str]] = []
        for index, line in enumerate(lines):
            marker = re.match(r"^(\s*)run:\s*\|[-+]?\s*$", line)
            if marker is None:
                continue
            marker_indent = len(marker.group(1))
            body_indent = marker_indent + 2
            body: list[str] = []
            for candidate in lines[index + 1 :]:
                leading = len(candidate) - len(candidate.lstrip())
                if candidate.strip() and leading <= marker_indent:
                    break
                body.append(candidate[body_indent:] if len(candidate) >= body_indent else "")
            scripts.append((index + 1, "\n".join(body) + "\n"))

        self.assertTrue(scripts)
        for line_number, script in scripts:
            with self.subTest(line=line_number):
                completed = subprocess.run(
                    ("bash", "-n"),
                    input=script,
                    check=False,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
