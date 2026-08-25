"""Workflow and artifact-confinement tests for the external app pilot."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
import zipfile

from cryptad_certification.engines import stable_1_0_third_party_pilot_inputs as inputs
from cryptad_certification.tests.support import workspace_root


WORKFLOW = workspace_root() / ".github/workflows/stable-1.0-third-party-app-pilot.yml"
PRODUCER_WORKFLOW = (
    workspace_root()
    / ".github/workflows/stable-1.0-third-party-app-pilot-evidence.yml"
)
RUNTIME_WORKFLOW = (
    workspace_root()
    / ".github/workflows/stable-1.0-third-party-app-pilot-runtime.yml"
)
EXECUTION_SCHEMA = (
    workspace_root()
    / "tools/release-certification/schemas/stable-1.0-third-party-app-pilot-execution-v1.schema.json"
)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _archive(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in entries:
            info = zipfile.ZipInfo(name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, value)


def _bound_entries() -> list[tuple[str, bytes]]:
    handoff = {
        "cohort": [
            {
                "submissionFile": "version-1-submission.zip",
                "bundleFile": "version-1-bundle.zip",
            }
        ]
    }
    contract = {
        "evidence": {
            "externalHandoff": {"fileName": "external-handoff.json"},
            "reviewCohort": None,
        }
    }
    return [
        ("execution.json", json.dumps(contract).encode()),
        ("external-handoff.json", json.dumps(handoff).encode()),
        ("version-1-bundle.zip", b"bundle"),
        ("version-1-submission.zip", b"submission"),
    ]


class StableThirdPartyPilotWorkflowTest(unittest.TestCase):
    """Keeps import, reviewer, catalog, node, and closeout authorities separate."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.producer = PRODUCER_WORKFLOW.read_text(encoding="utf-8")
        cls.runtime = RUNTIME_WORKFLOW.read_text(encoding="utf-8")

    def test_producer_when_dispatched_expect_canonical_artifact_for_coordinator(self) -> None:
        self.assertIn(
            "stable-1-0-third-party-pilot-$PILOT_ID-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT",
            self.producer,
        )
        self.assertIn(
            '"$INPUT_EVIDENCE_WORKFLOW" != ".github/workflows/stable-1.0-third-party-app-pilot-evidence.yml"',
            self.workflow,
        )
        self.assertIn("environment: stable-1-0-third-party-pilot-import", self.producer)
        self.assertIn(".fixtureOnly == false", self.producer)
        self.assertIn(".selfTest == false", self.producer)
        self.assertNotIn("secrets.", self.producer)

    def test_coordinator_when_pilot_id_is_maximum_length_expect_artifact_name_accepted(
        self,
    ) -> None:
        schema = json.loads(EXECUTION_SCHEMA.read_text(encoding="utf-8"))
        pilot_id = "p" * 96
        artifact_name = (
            f"stable-1-0-third-party-pilot-{pilot_id}-"
            f"{'9' * 20}-{'9' * 10}"
        )

        self.assertRegex(pilot_id, schema["properties"]["pilotId"]["pattern"])
        self.assertEqual(157, len(artifact_name))
        self.assertGreater(len(artifact_name), 128)
        self.assertLessEqual(len(artifact_name), 255)
        self.assertRegex(
            artifact_name,
            r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$",
        )
        self.assertIn(
            '"$INPUT_EVIDENCE_ARTIFACT_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$',
            self.workflow,
        )
        self.assertIn(
            'expected_name="stable-1-0-third-party-pilot-'
            '$INPUT_PILOT_ID-$INPUT_EVIDENCE_RUN_ID-$INPUT_EVIDENCE_RUN_ATTEMPT"',
            self.workflow,
        )

    def test_workflow_when_dispatched_expect_closed_manual_operations(self) -> None:
        dispatch = self.workflow[
            self.workflow.index("on:\n") : self.workflow.index("\nconcurrency:")
        ]
        options = re.findall(r"^          - ([a-z0-9-]+)$", dispatch, re.MULTILINE)

        self.assertEqual(
            [
                "prepare-intake",
                "import-external-handoff",
                "verify-review-cohort",
                "verify-catalog-publication",
                "verify-runtime-drill",
                "closeout",
            ],
            options,
        )
        self.assertIn("workflow_dispatch:", dispatch)
        self.assertNotIn("pull_request:", dispatch)
        self.assertNotIn("push:", dispatch)
        self.assertNotIn("workflow_call:", dispatch)

    def test_workflow_when_source_selected_expect_exact_protected_identity(self) -> None:
        self.assertIn("if: github.ref_protected", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("fetch-depth: 1", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn('"$GITHUB_SHA" != "$INPUT_SOURCE_COMMIT"', self.workflow)
        self.assertIn('"$WORKFLOW_SHA" != "$INPUT_SOURCE_COMMIT"', self.workflow)
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', self.workflow)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', self.workflow)

    def test_workflows_when_repository_code_executes_expect_protected_event_sha_checkout(
        self,
    ) -> None:
        for workflow, checkout_count in (
            (self.producer, 2),
            (self.workflow, 6),
            (self.runtime, 1),
        ):
            with self.subTest(checkout_count=checkout_count):
                self.assertEqual(checkout_count, workflow.count("ref: ${{ github.sha }}"))
                self.assertNotIn("ref: ${{ inputs.source_commit }}", workflow)

        self.assertIn("EXPECTED_SOURCE_COMMIT: ${{ github.sha }}", self.producer)
        self.assertIn("EXPECTED_SOURCE_COMMIT: ${{ github.sha }}", self.workflow)
        self.assertIn("EXPECTED_SOURCE_COMMIT: ${{ github.sha }}", self.runtime)
        self.assertNotIn('--arg sha "${{ inputs.source_commit }}"', self.workflow)

    def test_workflow_when_permissions_examined_expect_minimal_read_only_authority(self) -> None:
        self.assertIn("\npermissions: {}\n", self.workflow)
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("id-token: write", self.workflow)
        self.assertNotIn("packages: write", self.workflow)
        self.assertNotIn("pull-requests: write", self.workflow)
        self.assertNotIn("actions: write", self.workflow)

    def test_workflow_when_jobs_examined_expect_distinct_protected_environments(self) -> None:
        environments = set(
            re.findall(r"^    environment: ([a-z0-9-]+)$", self.workflow, re.MULTILINE)
        )

        self.assertEqual(
            {
                "stable-1-0-third-party-pilot-import",
                "stable-1-0-third-party-pilot-review",
                "stable-1-0-third-party-pilot-catalog-observation",
                "stable-1-0-third-party-pilot-node-observation",
                "stable-1-0-third-party-pilot-closeout",
            },
            environments,
        )
        self.assertEqual(
            1,
            self.workflow.count("secrets.CRYPTAD_PROTECTED_RELEASE_READ_TOKEN"),
        )
        for forbidden_secret in (
            "CATALOG_SIGNING",
            "APP_SIGNING",
            "REVIEWER_SIGNING",
            "RECOVERY",
            "INSERT_URI",
            "FORM_PASSWORD",
            "NODE_TOKEN",
        ):
            self.assertNotIn(forbidden_secret, self.workflow)

    def test_workflow_when_external_archive_downloaded_expect_authentication_before_extraction(self) -> None:
        import_job = self.workflow[
            self.workflow.index("\n  import-external-handoff:") : self.workflow.index(
                "\n  verify-review-cohort:"
            )
        ]
        raw_download = import_job.index(
            'gh api "/repos/$GITHUB_REPOSITORY/actions/artifacts/$EXPECTED_ARTIFACT_ID/zip"'
        )
        confinement = import_job.index("stable_1_0_third_party_pilot_inputs")

        self.assertLess(raw_download, confinement)
        self.assertIn(".digest == env.EXPECTED_ARTIFACT_DIGEST", import_job)
        self.assertIn(".workflow_run.id ==", import_job)
        self.assertIn(".path == $workflow", import_job)
        self.assertIn(".head_sha == env.EXPECTED_SOURCE_COMMIT", import_job)
        self.assertNotIn("actions/download-artifact@", import_job)
        self.assertNotIn("unzip ", import_job)

    def test_workflow_when_actions_used_expect_exact_sha_pinning(self) -> None:
        action_uses = re.findall(
            r"uses: ([^\s]+)", self.workflow + self.producer + self.runtime
        )

        self.assertGreater(len(action_uses), 0)
        self.assertTrue(
            all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in action_uses),
            action_uses,
        )

    def test_workflow_when_catalog_and_runtime_verified_expect_existing_authorities_reused(self) -> None:
        self.assertIn("Verify PR-293 beta catalog publication", self.workflow)
        self.assertIn("Verify live-network collector receipt and exact runtime sequence", self.workflow)
        self.assertIn("--mode verify-catalog-publication", self.workflow)
        self.assertIn("--mode verify-runtime-drill", self.workflow)
        self.assertNotIn("publish-network-primary", self.workflow)
        self.assertNotIn("stable-ga", self.workflow)
        self.assertNotIn("git tag", self.workflow)
        self.assertNotIn("gh release", self.workflow)

    def test_runtime_producer_when_examined_expect_real_node_side_production_boundary(
        self,
    ) -> None:
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, cryptad-third-party-pilot-node]",
            self.runtime,
        )
        self.assertIn("environment: stable-1-0-third-party-pilot-node", self.runtime)
        self.assertIn(
            "Run isolated AppHost install update caution rollback and cleanup",
            self.runtime,
        )
        self.assertIn(
            "Sign exact runtime receipt with the pilot node attestation key",
            self.runtime,
        )
        self.assertIn("cryptad-third-party-pilot-runtime run", self.runtime)
        self.assertIn(
            "Authenticate review catalog and publisher approval before node provisioning",
            self.runtime,
        )
        self.assertIn("--mode verify-catalog-publication", self.runtime)
        self.assertIn("--require-managed-daemon", self.runtime)
        self.assertIn(
            "--require-daemon-identity managed-daemon-product-attestation-v1",
            self.runtime,
        )
        self.assertIn(
            "--require-apphost-policy stable-1.0-pilot-publisher-v1",
            self.runtime,
        )
        self.assertIn("cryptad-third-party-pilot-runtime seal", self.runtime)
        self.assertIn("steps.observation.outputs.artifact-digest", self.runtime)
        self.assertIn("--mode verify-runtime-drill", self.runtime)
        self.assertNotIn("contents: write", self.runtime)
        self.assertNotIn("id-token: write", self.runtime)
        self.assertNotIn("CATALOG_SIGNING", self.runtime)
        self.assertNotIn("REVIEWER_SIGNING", self.runtime)
        self.assertNotIn("INSERT_URI", self.runtime)

    def test_runtime_producer_when_source_artifact_selected_expect_exact_pilot_binding(
        self,
    ) -> None:
        expected_name = (
            'expected_name="stable-1-0-third-party-pilot-normalized-'
            '$EXPECTED_PILOT_ID-$EXPECTED_RUN_ID-$source_run_attempt"'
        )

        self.assertIn("source_run_attempt=", self.runtime)
        self.assertIn(
            "normalized_artifact_digest: sha256:${{ steps.upload.outputs.artifact-digest }}",
            self.workflow,
        )
        self.assertIn(".run_attempt | select", self.runtime)
        self.assertIn(expected_name, self.runtime)
        self.assertIn(
            '[[ "$EXPECTED_ARTIFACT_NAME" != "$expected_name" ]]', self.runtime
        )
        self.assertIn(
            ".pilotId == env.EXPECTED_PILOT_ID", self.runtime
        )
        self.assertIn(
            ".repository.sourceCommit == env.EXPECTED_SOURCE_COMMIT", self.runtime
        )
        self.assertIn(".fixtureOnly == false", self.runtime)
        self.assertIn(".selfTest == false", self.runtime)
        self.assertLess(
            self.runtime.index(
                "Bind downloaded execution contract to runtime dispatch"
            ),
            self.runtime.index(
                "Run isolated AppHost install update caution rollback and cleanup"
            ),
        )

    def test_workflow_when_stage_fails_expect_only_safe_diagnostics_retained(self) -> None:
        self.assertIn("if: failure()", self.workflow)
        self.assertGreaterEqual(self.workflow.count("if: always()"), 4)
        self.assertIn("third-party-pilot-import-result", self.workflow)
        self.assertNotIn("$RUNNER_TEMP/pilot-evidence.zip\n          if-no-files-found", self.workflow)


class StableThirdPartyPilotInputsTest(unittest.TestCase):
    """Authenticates bytes before materializing flat bounded evidence members."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "artifact.zip"

    def test_assemble_when_archive_is_exact_expect_flat_private_files(self) -> None:
        _archive(
            self.archive,
            _bound_entries(),
        )
        output = self.root / "output"

        inputs.assemble(
            self.archive,
            _digest(self.archive.read_bytes()),
            self.archive.stat().st_size,
            output,
        )

        self.assertEqual(
            [
                "execution.json",
                "external-handoff.json",
                "version-1-bundle.zip",
                "version-1-submission.zip",
            ],
            sorted(path.name for path in output.iterdir()),
        )
        if os.name != "nt":
            self.assertTrue(
                all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
            )

    def test_assemble_when_digest_differs_expect_no_member_materialized(self) -> None:
        _archive(self.archive, _bound_entries())
        output = self.root / "output"

        with self.assertRaisesRegex(ValueError, "digest differs"):
            inputs.assemble(
                self.archive,
                _digest(b"wrong"),
                self.archive.stat().st_size,
                output,
            )

        self.assertFalse(output.exists())

    def test_assemble_when_safe_member_is_unbound_expect_no_member_materialized(self) -> None:
        entries = _bound_entries()
        entries.append(("unreferenced.json", b"{}"))
        _archive(self.archive, sorted(entries))
        output = self.root / "output"

        with self.assertRaisesRegex(ValueError, "missing or unbound members"):
            inputs.assemble(
                self.archive,
                _digest(self.archive.read_bytes()),
                self.archive.stat().st_size,
                output,
            )

        self.assertFalse(output.exists())

    def test_assemble_when_member_traverses_expect_no_partial_output(self) -> None:
        _archive(self.archive, [("../escape.json", b"{}")])
        output = self.root / "output"

        with self.assertRaisesRegex(ValueError, "unsafe member"):
            inputs.assemble(
                self.archive,
                _digest(self.archive.read_bytes()),
                self.archive.stat().st_size,
                output,
            )

        self.assertFalse(output.exists())
        self.assertFalse((self.root / "escape.json").exists())

    def test_assemble_when_member_is_nested_expect_fail_closed(self) -> None:
        _archive(self.archive, [("nested/execution.json", b"{}")])

        with self.assertRaisesRegex(ValueError, "unsafe member"):
            inputs.assemble(
                self.archive,
                _digest(self.archive.read_bytes()),
                self.archive.stat().st_size,
                self.root / "output",
            )

    def test_assemble_when_case_collision_exists_expect_fail_closed(self) -> None:
        _archive(
            self.archive,
            [("EXECUTION.JSON", b"{}"), ("execution.json", b"{}")],
        )

        with self.assertRaisesRegex(ValueError, "case-colliding"):
            inputs.assemble(
                self.archive,
                _digest(self.archive.read_bytes()),
                self.archive.stat().st_size,
                self.root / "output",
            )

    def test_assemble_when_unexpected_executable_name_exists_expect_fail_closed(self) -> None:
        _archive(self.archive, [("run.sh", b"exit 0")])

        with self.assertRaisesRegex(ValueError, "unsafe member"):
            inputs.assemble(
                self.archive,
                _digest(self.archive.read_bytes()),
                self.archive.stat().st_size,
                self.root / "output",
            )


if __name__ == "__main__":
    unittest.main()
