"""Offline structural tests for the Stable 1.0 release-train workflow."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = ROOT / ".github/workflows/stable-1.0-backport-release-train.yml"
REVIEW_WORKFLOW = (
    ROOT
    / ".github/workflows/stable-1.0-backport-review-authorization.yml"
)


class StableBackportWorkflowTests(unittest.TestCase):
    """Freeze the workflow's read-only, exact-identity, public-safe boundary."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.review_workflow = REVIEW_WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_has_only_the_four_closed_operations(self) -> None:
        self.assertIn("  workflow_dispatch:", self.workflow)
        self.assertNotIn("  workflow_call:", self.workflow)
        dispatch_start = self.workflow.index("      operation:")
        dispatch = self.workflow[
            dispatch_start : self.workflow.index("      release_id:", dispatch_start)
        ]
        options = re.findall(r"^          - ([a-z-]+)$", dispatch, flags=re.MULTILINE)
        self.assertEqual(
            options,
            [
                "evaluate-intake",
                "prepare-candidate",
                "validate-authorization",
                "verify-release-completion",
            ],
        )

    def test_workflow_materializes_the_required_vulnerability_summary_handoff(
        self,
    ) -> None:
        self.assertIn(
            "Materialize authenticated vulnerability summary outside public roots",
            self.workflow,
        )
        self.assertIn(
            "CRYPTAD_STABLE_VULNERABILITY_SUMMARY_ROOT",
            self.workflow,
        )
        self.assertIn(
            '.policies.stableVulnerabilityGovernance == "required"',
            self.workflow,
        )
        self.assertIn(
            "stable-1.0-vulnerability-summary.json",
            self.workflow,
        )
        for expected in (
            "stable_backport_protected_handoff.py open",
            "CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64",
            "stable-1.0-vulnerability-successor-binding.json",
            "stable-1.0-vulnerability-summary-provenance.json",
            "sealed-successor/stable-1.0-protected-handoff.enc",
            "sealed-successor/stable-1.0-protected-handoff.json",
            "stable_vulnerability_actions_tip.py",
            "verify-promotion",
            '--environment-file "$GITHUB_ENV"',
        ):
            self.assertIn(expected, self.workflow)
        self.assertIn(
            "concurrency:\n"
            "      group: >-\n"
            "        ${{ inputs.operation != 'verify-release-completion'\n"
            "        && 'stable-1-0-vulnerability-ledger'",
            self.workflow,
        )
        self.assertIn("      cancel-in-progress: false", self.workflow)
        self.assertIn(
            'if [[ "$OPERATION" != verify-release-completion ]]',
            self.workflow,
        )
        self.assertNotIn(
            'source="build/stable-backport-input/protected-inputs/$summary_name"',
            self.workflow,
        )

    @unittest.skipUnless(shutil.which("bash"), "workflow syntax test requires bash")
    def test_every_multiline_workflow_shell_block_parses(self) -> None:
        for workflow_path in (WORKFLOW, REVIEW_WORKFLOW):
            lines = workflow_path.read_text(encoding="utf-8").splitlines()
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
                    body.append(
                        candidate[body_indent:]
                        if len(candidate) >= body_indent
                        else ""
                    )
                scripts.append((index + 1, "\n".join(body) + "\n"))

            self.assertTrue(scripts, f"no shell blocks found in {workflow_path}")
            for line_number, script in scripts:
                with self.subTest(
                    workflow=workflow_path.name,
                    line=line_number,
                ):
                    completed = subprocess.run(
                        ("bash", "-n"),
                        input=script,
                        check=False,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertEqual(
                        0,
                        completed.returncode,
                        completed.stdout + completed.stderr,
                    )

    def test_protected_environments_require_credential_free_ref_preflight(
        self,
    ) -> None:
        preflight_start = self.workflow.index("  protected-ref-preflight:")
        validation_start = self.workflow.index("  validate-release-train:")
        preflight = self.workflow[preflight_start:validation_start]
        validation_header = self.workflow[
            validation_start : self.workflow.index(
                "\n    steps:", validation_start
            )
        ]

        self.assertLess(preflight_start, validation_start)
        self.assertIn("permissions: {}", preflight)
        self.assertNotIn("environment:", preflight)
        self.assertNotIn("secrets.", preflight)
        self.assertNotIn("github.token", preflight)
        self.assertNotIn("actions/checkout", preflight)
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', preflight)
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', preflight)
        self.assertIn(
            'WORKFLOW_REF: ${{ github.workflow_ref }}',
            preflight,
        )
        self.assertIn(
            'WORKFLOW_SHA: ${{ github.workflow_sha }}',
            preflight,
        )
        self.assertIn('needs: protected-ref-preflight', validation_header)
        self.assertIn("environment:", validation_header)

    def test_operations_map_to_closed_engine_modes(self) -> None:
        for operation, mode in (
            ("evaluate-intake", "evaluate"),
            ("prepare-candidate", "prepare-candidate"),
            ("validate-authorization", "validate-authorization"),
            ("verify-release-completion", "verify-release-completion"),
        ):
            with self.subTest(operation=operation):
                self.assertIn(f"{operation})\n              command_mode={mode}", self.workflow)
        self.assertIn(
            "python3 tools/release-certification/certify.py stable-backport",
            self.workflow,
        )

    def test_token_permissions_are_read_only(self) -> None:
        self.assertIn("\npermissions: {}\n", self.workflow)
        permissions = re.findall(
            r"^    permissions:\n((?:^      .+\n)+)",
            self.workflow,
            flags=re.MULTILINE,
        )
        self.assertEqual(
            permissions,
            ["      actions: read\n      contents: read\n"],
        )
        for forbidden in (
            "actions: write",
            "attestations: write",
            "contents: write",
            "deployments: write",
            "id-token: write",
            "packages: write",
            "pull-requests: write",
            "security-events: write",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_checkout_is_exact_and_does_not_persist_credentials(self) -> None:
        self.assertIn("ref: ${{ inputs.source_commit }}", self.workflow)
        self.assertIn("fetch-depth: 0", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn('"$GITHUB_SHA" != "$INPUT_SOURCE_COMMIT"', self.workflow)
        self.assertIn('"$GITHUB_WORKFLOW_SHA" != "$INPUT_SOURCE_COMMIT"', self.workflow)
        self.assertIn("INPUT_CANDIDATE_COMMIT: ${{ inputs.candidate_commit }}", self.workflow)
        self.assertIn(
            ".policies.candidateSourceCommit == $candidate",
            self.workflow,
        )
        self.assertIn(
            '.policies.candidateSourceRef == ("commit:" + $candidate)',
            self.workflow,
        )
        self.assertIn('"$(git rev-parse \'HEAD^{commit}\')"', self.workflow)
        self.assertIn('REF_PROTECTED: ${{ github.ref_protected }}', self.workflow)

    def test_lane_and_ref_roles_are_closed(self) -> None:
        self.assertIn("routine-maintenance)", self.workflow)
        self.assertIn('candidate_ref="refs/heads/release/$INPUT_BUILD_VERSION"', self.workflow)
        self.assertIn("security-hotfix)", self.workflow)
        self.assertIn('candidate_ref="refs/heads/hotfix/$INPUT_BUILD_VERSION"', self.workflow)
        self.assertIn(
            "Completion verification must execute from protected main.",
            self.workflow,
        )

    def test_routine_base_uses_authenticated_protected_develop_lineage(self) -> None:
        self.assertIn(
            'gh api "repos/$GITHUB_REPOSITORY/branches/develop"',
            self.workflow,
        )
        self.assertIn(
            "select(.protected == true) | .commit.sha",
            self.workflow,
        )
        self.assertIn(
            'git merge-base --is-ancestor \\\n'
            '              "$development_lineage" "$protected_develop_tip"',
            self.workflow,
        )
        self.assertNotIn(
            'git rev-list "$protected_develop_tip" -- | grep -Fqx "$lineage"',
            self.workflow,
        )
        self.assertIn(
            ".policies.developmentLineageCommit == $lineage",
            self.workflow,
        )
        self.assertIn(
            "developmentLineageCommit:",
            self.workflow,
        )

    def test_hotfix_base_uses_exact_authenticated_protected_main_tip(self) -> None:
        self.assertIn(
            'gh api "repos/$GITHUB_REPOSITORY/branches/main"',
            self.workflow,
        )
        self.assertIn(
            '"$main_lineage" != "$protected_main_tip"',
            self.workflow,
        )
        self.assertIn(
            ".policies.mainLineageCommit == $lineage",
            self.workflow,
        )
        self.assertIn(
            ".policies.mainLineageCommit == $mainLineage",
            self.workflow,
        )
        self.assertIn("mainLineageCommit:", self.workflow)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("bash", "git", "jq")),
        "workflow state-transition test requires bash, git, and jq",
    )
    def test_hotfix_completion_accepts_post_publication_main_merge_tip(
        self,
    ) -> None:
        step_start = self.workflow.index(
            "      - name: Authenticate exact protected branch lineage"
        )
        step_end = self.workflow.index(
            "      - name: Bind exact prior phase evidence into protected inputs",
            step_start,
        )
        step = self.workflow[step_start:step_end]
        run_marker = "        run: |\n"
        script = textwrap.dedent(step[step.index(run_marker) + len(run_marker) :])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git_environment = {
                **os.environ,
                "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }

            def git(*arguments: str) -> str:
                return subprocess.run(
                    ("git", *arguments),
                    cwd=root,
                    env=git_environment,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).stdout.strip()

            git("init", "-q", "--initial-branch=main")
            (root / "node.txt").write_text("published predecessor\n", encoding="utf-8")
            git("add", "node.txt")
            git(
                "-c",
                "user.name=Cryptad Fixture",
                "-c",
                "user.email=fixture@crypta.invalid",
                "commit",
                "-q",
                "-m",
                "published predecessor",
            )
            frozen_main = git("rev-parse", "HEAD")
            git("checkout", "-q", "-b", "hotfix/301")
            (root / "node.txt").write_text("critical correction\n", encoding="utf-8")
            git("add", "node.txt")
            git(
                "-c",
                "user.name=Cryptad Fixture",
                "-c",
                "user.email=fixture@crypta.invalid",
                "commit",
                "-q",
                "-m",
                "critical correction",
            )
            git("checkout", "-q", "main")
            git(
                "-c",
                "user.name=Cryptad Fixture",
                "-c",
                "user.email=fixture@crypta.invalid",
                "merge",
                "--no-ff",
                "-q",
                "-m",
                "merge hotfix 301",
                "hotfix/301",
            )
            protected_main_tip = git("rev-parse", "HEAD")
            manifest = (
                root
                / "build/stable-backport-input/manifest/stable-backport-manifest.json"
            )
            provenance = (
                root
                / "build/stable-backport-prior/"
                "stable-1.0-release-train-workflow-provenance.json"
            )
            manifest.parent.mkdir(parents=True)
            provenance.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({"policies": {"mainLineageCommit": frozen_main}}),
                encoding="utf-8",
            )
            provenance.write_text(
                json.dumps(
                    {
                        "developmentLineageCommit": None,
                        "mainLineageCommit": frozen_main,
                    }
                ),
                encoding="utf-8",
            )
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$PROTECTED_MAIN_RESPONSE\"\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            environment = {
                **git_environment,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                "GITHUB_REPOSITORY": "crypta-network/cryptad",
                "INPUT_OPERATION": "verify-release-completion",
                "INPUT_RELEASE_LANE": "security-hotfix",
                "PROTECTED_MAIN_RESPONSE": json.dumps(
                    {
                        "protected": True,
                        "commit": {"sha": protected_main_tip},
                    }
                ),
                "RUNNER_TEMP": str(runner_temp),
            }

            completed = subprocess.run(
                ("bash", "-c", script),
                cwd=root,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(
                0,
                completed.returncode,
                completed.stdout + completed.stderr,
            )
            prepublication_environment = {
                **environment,
                "INPUT_OPERATION": "validate-authorization",
            }
            rejected = subprocess.run(
                ("bash", "-c", script),
                cwd=root,
                env=prepublication_environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn(
                "Protected main advanced after the hotfix lineage was frozen.",
                rejected.stdout,
            )

    def test_protected_intake_is_exact_digest_and_not_uploaded(self) -> None:
        self.assertIn(
            "tools/release-certification/protected/stable_lifecycle_input_producer.py",
            self.workflow,
        )
        self.assertIn("--expected-digest \"$INPUT_BUNDLE_DIGEST\"", self.workflow)
        self.assertIn(
            "CRYPTAD_STABLE_BACKPORT_INPUT_BUNDLE_URL",
            self.workflow,
        )
        self.assertIn(
            "CRYPTAD_STABLE_BACKPORT_INPUT_BUNDLE_BEARER_TOKEN",
            self.workflow,
        )
        upload = self.workflow[self.workflow.index(
            "      - name: Upload allowlisted public-safe train projection"
        ) :]
        self.assertIn("path: build/stable-backport-public/", upload)
        self.assertNotIn("build/stable-backport-input", upload)
        self.assertNotIn("protected-inputs", upload)

    def test_public_upload_is_allowlisted_and_redaction_gated(self) -> None:
        stage = self.workflow[
            self.workflow.index(
                "      - name: Stage protected handoff and allowlisted public-safe projection"
            ) :
            self.workflow.index(
                "      - name: Upload encrypted protected release-train handoff"
            )
        ]
        self.assertIn('.redaction.status == "pass"', stage)
        self.assertIn(".redaction.findingCount == 0", stage)
        self.assertIn(
            '.status == "pass" and .findingCount == 0 and .findings == []',
            stage,
        )
        for protected_public_name in (
            "stable-1.0-release-train-summary.json",
            "stable-1.0-release-train-report.md",
            "stable-1.0-release-train-queue-public.json",
            "stable-1.0-release-train-validation-public.json",
        ):
            with self.subTest(protected_public_name=protected_public_name):
                self.assertIn(
                    f'copy_to "$handoff" {protected_public_name}',
                    stage,
                )
        for public_name in (
            "stable-1.0-release-train-queue-public.json",
            "stable-1.0-release-train-validation-public.json",
        ):
            with self.subTest(public_name=public_name):
                self.assertIn(
                    f'copy_to "$public_stage" {public_name}',
                    stage,
                )
        for protected_only_name in (
            "summary.json",
            "redaction-report.json",
            "stable-1.0-release-train-summary.json",
            "stable-1.0-release-train-report.md",
            "stable-1.0-release-train-workflow-provenance.json",
            "workflow-handoff-checksums.txt",
        ):
            with self.subTest(protected_only_name=protected_only_name):
                self.assertNotIn(
                    f'"$public_stage/{protected_only_name}"',
                    stage,
                )
                self.assertNotIn(
                    f'"$public_stage" {protected_only_name}',
                    stage,
                )
        self.assertNotIn("workflow-public-checksums.txt", stage)
        self.assertIn(
            "protected/stable_backport_protected_handoff.py",
            stage,
        )
        self.assertIn(
            "--out build/stable-backport-protected-upload",
            stage,
        )
        self.assertIn(
            'find "$public_stage" -mindepth 1 -maxdepth 1 -printf \'%f\\n\'',
            stage,
        )
        self.assertIn(
            'if [[ "$actual_public_files" != "$expected_public_files" ]]',
            stage,
        )
        self.assertIn(
            "Public release-train artifact violates its exact two-file allowlist.",
            stage,
        )
        for protected_name in (
            "stable-1.0-release-train-checksums.txt",
            "stable-1.0-release-train-provenance.json",
            "stable-1.0-release-train-queue.json",
            "stable-1.0-release-train-validation.json",
            "stable-1.0-release-train-authorization-summary.json",
            "stable-1.0-release-train-completion.json",
        ):
            with self.subTest(protected_name=protected_name):
                self.assertIn(protected_name, stage)
                self.assertNotIn(f'"$public_stage" {protected_name}', stage)
        for private_or_internal in (
            "stable-1.0-fix-intake.json",
            "stable-1.0-backport-plan.json",
            "review-authorizations.json",
        ):
            self.assertNotIn(f"copy_to {private_or_internal}", stage)
        self.assertIn(
            'copy_to "$handoff" stable-1.0-release-train-queue.json',
            stage,
        )
        self.assertIn(
            'copy_to "$handoff" stable-1.0-release-train-completion.json',
            stage,
        )
        self.assertIn(
            '"$INPUT_OPERATION" == validate-authorization', stage
        )
        self.assertIn(
            '"$INPUT_OPERATION" == verify-release-completion', stage
        )

    def test_prior_handoff_is_exact_and_non_wildcard(self) -> None:
        for name in (
            "prior_run_id",
            "prior_artifact_name",
            "prior_artifact_digest",
            "prior_source_commit",
            "prior_workflow_ref",
        ):
            self.assertIn(f"      {name}:", self.workflow)
        self.assertIn(
            "crypta-network/cryptad/.github/workflows/"
            "stable-1.0-backport-release-train.yml@$INPUT_PRIOR_SOURCE_COMMIT",
            self.workflow,
        )
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/$INPUT_PRIOR_RUN_ID"',
            self.workflow,
        )
        self.assertIn('gh run download "$INPUT_PRIOR_RUN_ID"', self.workflow)
        self.assertIn(
            ".name == $name and .digest == $digest and .expired == false",
            self.workflow,
        )
        self.assertIn(
            ".queueDigest == $validation[0].queueDigest",
            self.workflow,
        )
        self.assertIn(
            "stableBackportFrozenValidation",
            self.workflow,
        )
        self.assertIn(
            "Initial intake evaluation cannot consume a prior train handoff.",
            self.workflow,
        )
        self.assertIn('.event == "workflow_dispatch"', self.workflow)
        self.assertNotIn('.event == "workflow_call"', self.workflow)
        self.assertIn(
            "Prior release-train handoff coordinates are incomplete or ambiguous.",
            self.workflow,
        )

    def test_artifact_name_bound_covers_the_full_release_id_contract(
        self,
    ) -> None:
        full_release_id = "r" * 128
        longest_phase_name = (
            "stable-1.0-backport-verify-release-completion-"
            f"{full_release_id}-301"
        )

        self.assertLessEqual(len(longest_phase_name), 256)
        self.assertEqual(
            self.workflow.count(
                'current_artifact_name="stable-1.0-backport-'
                '$INPUT_OPERATION-$INPUT_RELEASE_ID-$INPUT_BUILD_VERSION"'
            ),
            2,
        )
        self.assertEqual(
            self.workflow.count(
                "(( ${#current_artifact_name} > 256 ))"
            ),
            2,
        )
        self.assertIn(
            "${#INPUT_PRIOR_ARTIFACT_NAME} -gt 256",
            self.workflow,
        )
        self.assertNotIn(
            "${#INPUT_PRIOR_ARTIFACT_NAME} -gt 128",
            self.workflow,
        )

    def test_artifact_name_variables_are_defined_in_their_shell_steps(
        self,
    ) -> None:
        authentication_start = self.workflow.index(
            "      - name: Authenticate operation, source, and prior handoff"
        )
        authentication_end = self.workflow.index(
            "      - name: Authenticate and download exact prior phase artifact",
            authentication_start,
        )
        authentication = self.workflow[authentication_start:authentication_end]
        staging_start = self.workflow.index(
            "      - name: Stage protected handoff and allowlisted public-safe projection"
        )
        staging_end = self.workflow.index(
            "      - name: Upload encrypted protected release-train handoff",
            staging_start,
        )
        staging = self.workflow[staging_start:staging_end]

        self.assertIn(
            'current_artifact_name="stable-1.0-backport-'
            '$INPUT_OPERATION-$INPUT_RELEASE_ID-$INPUT_BUILD_VERSION"',
            authentication,
        )
        self.assertIn("${#current_artifact_name}", authentication)
        self.assertNotIn("handoff_artifact_name", authentication)
        self.assertIn(
            'handoff_artifact_name="stable-1.0-backport-'
            '$INPUT_OPERATION-$INPUT_RELEASE_ID-$INPUT_BUILD_VERSION"',
            staging,
        )
        self.assertIn(
            '--arg artifactName "$handoff_artifact_name"',
            staging,
        )
        self.assertNotIn("current_artifact_name", staging)

    def test_prepare_allows_the_evaluated_candidate_to_advance(self) -> None:
        handoff_start = self.workflow.index(
            "      - name: Authenticate and download exact prior phase artifact"
        )
        handoff_end = self.workflow.index(
            "      - name: Fetch and safely expand exact protected inputs",
            handoff_start,
        )
        handoff = self.workflow[handoff_start:handoff_end]

        self.assertIn(
            '$operation == "evaluate-intake"\n'
            "                or .candidateCommit == $candidate",
            handoff,
        )
        evolution_start = self.workflow.index(
            "      - name: Authenticate evaluated queue evolution"
        )
        evolution_end = self.workflow.index(
            "      - name: Stage protected handoff and allowlisted public-safe projection",
            evolution_start,
        )
        evolution = self.workflow[evolution_start:evolution_end]
        self.assertIn(
            "if: inputs.operation == 'prepare-candidate'",
            evolution,
        )
        self.assertIn(
            "protected/stable_backport_phase_handoff.py",
            evolution,
        )
        self.assertIn(
            "--evaluated-queue",
            evolution,
        )
        self.assertIn(
            "build/stable-backport-prior/"
            "stable-1.0-release-train-queue-public.json",
            evolution,
        )
        self.assertIn(
            "--prepared-queue",
            evolution,
        )

    def test_authoritative_handoffs_are_encrypted_before_actions_upload(
        self,
    ) -> None:
        upload = self.workflow[
            self.workflow.index(
                "      - name: Upload encrypted protected release-train handoff"
            ) :
            self.workflow.index(
                "      - name: Upload allowlisted public-safe train projection"
            )
        ]
        self.assertIn(
            "path: build/stable-backport-protected-upload/",
            upload,
        )
        self.assertNotIn("path: build/stable-backport-handoff/", upload)
        self.assertIn(
            "CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64: "
            "${{ secrets.CRYPTAD_STABLE_BACKPORT_HANDOFF_KEY_BASE64 }}",
            self.workflow,
        )
        self.assertGreaterEqual(
            self.workflow.count(
                "protected/stable_backport_protected_handoff.py"
            ),
            4,
        )
        self.assertIn(
            "--bundle \"$sealed\"",
            self.workflow,
        )
        self.assertIn(
            "--bundle \"$sealed_root\"",
            self.workflow,
        )

        review_upload = self.review_workflow[
            self.review_workflow.index(
                "      - name: Upload encrypted protected review authorization"
            ) :
        ]
        self.assertIn(
            "path: build/stable-backport-review-protected-upload/",
            review_upload,
        )
        self.assertNotIn(
            "path: build/stable-backport-review-authorization/",
            review_upload,
        )
        self.assertIn(
            "protected/stable_backport_protected_handoff.py",
            self.review_workflow,
        )

    def test_predecessor_completion_is_reauthenticated_for_each_successor(
        self,
    ) -> None:
        for name in (
            "predecessor_completion_run_id",
            "predecessor_completion_artifact_name",
            "predecessor_completion_artifact_digest",
            "predecessor_completion_source_commit",
            "predecessor_completion_workflow_ref",
        ):
            self.assertIn(f"      {name}:", self.workflow)
        self.assertIn(
            "Authenticate predecessor completion workflow and protected refs",
            self.workflow,
        )
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/$PREDECESSOR_COMPLETION_RUN_ID"',
            self.workflow,
        )
        self.assertIn(
            'cmp --silent "$configured_completion" "$downloaded_completion"',
            self.workflow,
        )
        self.assertIn(
            'cmp --silent "$configured_validation" "$downloaded_validation"',
            self.workflow,
        )
        self.assertIn(
            'cmp --silent "$configured_queue" "$downloaded_queue"',
            self.workflow,
        )
        self.assertIn("first_parent_contains", self.workflow)
        self.assertIn(
            "previousStableBackportCompletionHandoff",
            self.workflow,
        )
        self.assertIn(
            "stable-1.0-release-train-predecessor-completion-handoff.json",
            self.workflow,
        )
        self.assertIn(
            "producer_operation=reauthenticate-predecessor-completion",
            self.workflow,
        )
        self.assertIn(
            "producer_evidence_source=protected-input-bundle",
            self.workflow,
        )
        self.assertIn(
            'producer_evidence_digest="$INPUT_BUNDLE_DIGEST"',
            self.workflow,
        )
        self.assertIn(
            'downloaded_completion="$configured_completion"',
            self.workflow,
        )
        self.assertNotIn(
            "A successor queue requires exact predecessor completion coordinates.",
            self.workflow,
        )

    def test_provenance_review_requires_an_exact_protected_producer(
        self,
    ) -> None:
        self.assertIn(
            "review_authorization_handoffs:",
            self.workflow,
        )
        self.assertIn(
            "Authenticate independent provenance-review authorizations",
            self.workflow,
        )
        self.assertIn(
            '.path == ".github/workflows/stable-1.0-backport-review-authorization.yml"',
            self.workflow,
        )
        self.assertIn(
            ".name == $name and .digest == $digest and .expired == false",
            self.workflow,
        )
        self.assertIn(
            "stableBackportReviewAuthorizations",
            self.workflow,
        )
        self.assertIn(
            "environment: stable-1.0-backport-review",
            self.review_workflow,
        )
        self.assertIn(
            'and . == sort\' <<< "$FOCUSED_TEST_IDS"',
            self.review_workflow,
        )
        self.assertIn("or expires <= now", self.review_workflow)
        self.assertLess(
            self.review_workflow.index("or expires <= now"),
            self.review_workflow.index(
                "stage=build/stable-backport-review-authorization"
            ),
        )
        review_preflight = self.review_workflow[
            self.review_workflow.index("  protected-ref-preflight:") :
            self.review_workflow.index("  authorize-review:")
        ]
        self.assertIn("permissions: {}", review_preflight)
        self.assertNotIn("environment:", review_preflight)
        self.assertIn("needs: protected-ref-preflight", self.review_workflow)
        self.assertIn("persist-credentials: false", self.review_workflow)
        for forbidden in (
            "actions: write",
            "contents: write",
            "deployments: write",
            "id-token: write",
            "pull-requests: write",
        ):
            self.assertNotIn(forbidden, self.review_workflow)

    def test_authorization_uses_a_separate_protected_environment(self) -> None:
        self.assertIn(
            "inputs.operation == 'validate-authorization'",
            self.workflow,
        )
        self.assertIn("stable-1.0-backport-authorization", self.workflow)
        self.assertIn("stable-1.0-backport-evidence", self.workflow)

    def test_maintenance_handoff_stages_the_exact_train_validation(self) -> None:
        maintenance = (
            ROOT / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")
        expected_files_start = maintenance.index("          expected_files=(")
        expected_files_end = maintenance.index(
            "          actual_files=", expected_files_start
        )
        expected_files = maintenance[expected_files_start:expected_files_end]
        self.assertIn(
            "            stable-1.0-release-train-queue.json\n",
            expected_files,
        )
        self.assertIn(
            "            stable-1.0-release-train-queue-public.json\n",
            expected_files,
        )
        self.assertIn(
            "            stable-1.0-release-train-validation-public.json\n",
            expected_files,
        )
        self.assertIn("workflow-handoff-checksums.txt", expected_files)
        self.assertNotIn("workflow-public-checksums.txt", expected_files)
        self.assertIn(
            "stable-1.0-release-train-predecessor-completion-handoff.json",
            maintenance,
        )
        self.assertIn(
            "stableBackportReleaseTrainValidation \\\n"
            "              stable-1.0-release-train-validation.json",
            maintenance,
        )
        self.assertIn(
            "stableBackportReleaseTrainAuthorization \\\n"
            "              stable-1.0-release-train-authorization-summary.json",
            maintenance,
        )
        self.assertIn(
            'cmp --silent "$prior_train" "$current_train"',
            maintenance,
        )
        self.assertIn(
            '"$prior_train_authorization" "$current_train_authorization"',
            maintenance,
        )
        train_staging = maintenance[
            maintenance.index(
                'if [[ "$INPUT_OPERATION" == freeze-candidate',
                maintenance.index("          stage_authenticated_input()"),
            ) :
            maintenance.index(
                "            stage_authenticated_input maintenanceCandidate",
                maintenance.index("          stage_authenticated_input()"),
            )
        ]
        self.assertIn("stableBackportReleaseTrainValidation", train_staging)
        self.assertIn("stableBackportReleaseTrainAuthorization", train_staging)
        self.assertIn(
            '"$INPUT_OPERATION" == prepare-authorization', train_staging
        )
        self.assertIn(
            '"$INPUT_OPERATION" == validate-authorization', train_staging
        )
        self.assertIn(
            "maintenance freeze/authorization handoff", train_staging
        )
        self.assertIn(
            ".queueDigest == $validation[0].queueDigest",
            maintenance,
        )
        self.assertIn(
            ".candidateCommit == $validation[0].candidateCommit",
            maintenance,
        )
        queue_gate_start = maintenance.index(
            "          expected_lane=routine-maintenance"
        )
        queue_gate_end = maintenance.index(
            "          jq -e \\\n"
            "            --arg repository",
            queue_gate_start,
        )
        queue_gate = maintenance[queue_gate_start:queue_gate_end]
        self.assertIn('$validation[0].decision == "go"', queue_gate)
        self.assertIn('$validation[0].mode == "validate-authorization"', queue_gate)
        self.assertIn(
            "$validation[0].release.releaseClass",
            queue_gate,
        )
        self.assertIn('if $lane == "security-hotfix"', queue_gate)
        self.assertIn('.obligationType == "hotfix-follow-up"', queue_gate)
        self.assertIn(".carriedObligationIds == []", queue_gate)
        self.assertIn('.status == "blocked"', queue_gate)
        self.assertIn('.status == "ready"', queue_gate)

    def test_maintenance_authenticates_the_protected_train_producer(self) -> None:
        maintenance = (
            ROOT / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")
        for name in (
            "stableBackportRunId",
            "stableBackportArtifactName",
            "stableBackportArtifactDigest",
        ):
            self.assertIn(f".policies.metadata.{name}", maintenance)
        self.assertIn(
            '.path == ".github/workflows/stable-1.0-backport-release-train.yml"',
            maintenance,
        )
        self.assertIn('.event == "workflow_dispatch"', maintenance)
        self.assertNotIn('.event == "workflow_call"', maintenance)
        self.assertIn(
            ".name == $name and .expired == false and .digest == $digest",
            maintenance,
        )
        self.assertIn(
            'and .operation == "validate-authorization"',
            maintenance,
        )
        self.assertIn(
            "Protected input producer substituted the authorized release train.",
            maintenance,
        )
        self.assertIsNone(
            re.search(
                r"\[\[(?:(?!\]\]).)*\bcmp --silent\b",
                maintenance,
                flags=re.DOTALL,
            ),
            "cmp must execute outside [[ ]] so the workflow remains valid Bash",
        )
        self.assertIn(
            '[[ -e "$configured" ]] \\\n'
            '                && ! cmp --silent "$root/$source_name" '
            '"$configured"; then',
            maintenance,
        )
        self.assertIn(
            '[[ -L "$prior_train" || ! -f "$prior_train" \\\n'
            '                    || -L "$prior_train_authorization" \\\n'
            '                    || ! -f "$prior_train_authorization" ]] \\\n'
            '                  || ! cmp --silent "$prior_train" "$current_train"',
            maintenance,
        )

    def test_completion_reachability_uses_pipefail_safe_git_ancestry(self) -> None:
        completion_start = self.workflow.index(
            "      - name: Authenticate protected main and develop reconciliation tips"
        )
        completion_end = self.workflow.index(
            "      - name: Run side-effect-free release-train certification",
            completion_start,
        )
        completion = self.workflow[completion_start:completion_end]
        fetch = (
            "git fetch --no-tags --no-recurse-submodules origin \\\n"
            '            "$main_tip" "$develop_tip"'
        )

        self.assertIn(fetch, completion)
        self.assertLess(
            completion.index(fetch),
            completion.index('git cat-file -e "$protected_tip^{commit}"'),
        )
        self.assertIn(
            'git merge-base --is-ancestor "$merge_commit" "$protected_tip"',
            completion,
        )
        self.assertNotIn(
            'git rev-list "$protected_tip" -- | grep -Fqx "$merge_commit"',
            completion,
        )

    def test_upload_artifact_digest_is_normalized_to_canonical_form(self) -> None:
        record_step = self.workflow[
            self.workflow.index(
                "      - name: Record exact uploaded artifact digest"
            ) :
        ]
        self.assertIn(
            'if [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then',
            record_step,
        )
        self.assertIn(
            'digest="sha256:$digest"',
            record_step,
        )
        self.assertIn(
            '"$digest" =~ ^sha256:[0-9a-f]{64}$',
            record_step,
        )
        self.assertIn(
            'echo "- Encrypted handoff digest: \\`$handoff_digest\\`"',
            record_step,
        )
        self.assertIn(
            'echo "- Public projection digest: \\`$public_digest\\`"',
            record_step,
        )

    def test_workflow_contains_no_git_or_publication_mutation(self) -> None:
        forbidden_patterns = (
            r"\bgit\s+(?:checkout|switch)\s+(?:-b|-c)\b",
            r"\bgit\s+cherry-pick\b",
            r"\bgit\s+commit\b",
            r"\bgit\s+merge(?:[ \t]|$)",
            r"\bgit\s+push\b",
            r"\bgit\s+tag\b",
            r"\bgh\s+(?:pr|release)\s+(?:create|edit|delete|close|merge|upload)\b",
            r"\bfcpput\b",
            r"\bfcpupload\b",
            r"\bstable_maintenance_publication\.py\b",
            r"\bstable_lifecycle_publication\.py\b",
        )
        for workflow_name, workflow in (
            ("release-train", self.workflow),
            ("provenance-review", self.review_workflow),
        ):
            for pattern in forbidden_patterns:
                with self.subTest(workflow=workflow_name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, workflow))


if __name__ == "__main__":
    unittest.main()
