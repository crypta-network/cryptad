"""Isolated deterministic Git fixtures for Stable backport provenance."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cryptad_certification.stable_backport_git as stable_backport_git
from cryptad_certification.io import read_json
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_backport_git import (
    GitInspectionError,
    GitInspector,
    NonAutomaticMergeResolutionError,
)

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
REPOSITORY_IDENTITY = "github.com/crypta-network/cryptad"
RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = RELEASE_CERTIFICATION_ROOT / "schemas"


class StableBackportPolicySchemaTest(unittest.TestCase):
    def test_policy_is_closed_and_uses_the_canonical_vocabularies(self) -> None:
        policy = read_json(
            RELEASE_CERTIFICATION_ROOT
            / "stable-1.0-backport-release-train-policy.json"
        )

        self.assertEqual(
            validate_schema(
                policy,
                "stable-1.0-backport-release-train-policy-v1.schema.json",
            ),
            [],
        )
        self.assertEqual(policy["schemaVersion"], 1)
        self.assertEqual(policy["policyVersion"], 1)
        self.assertEqual(
            policy["classifications"],
            [
                "compatible-bug-fix",
                "security-fix",
                "platform-api-compatible-addition",
                "platform-api-deprecation",
                "stable-catalog-app-patch",
                "packaging-installer-fix",
                "release-tooling-fix",
                "documentation-support-fix",
                "unsupported-feature-change",
                "breaking-change",
            ],
        )
        self.assertEqual(
            policy["dispositions"],
            [
                "routine-maintenance",
                "security-hotfix",
                "future-milestone",
                "deferred",
                "rejected",
            ],
        )
        self.assertEqual(
            policy["noFork"],
            {
                "singleAuthenticatedPublicationChain": True,
                "latestPointerImmediatePredecessorRequired": True,
                "historicalBuildBytesImmutable": True,
                "parallelStableBranchesAllowed": False,
            },
        )
        self.assertTrue(
            policy["releaseLanePolicy"]["routine-maintenance"][
                "protectedDevelopmentLineageRequired"
            ]
        )
        self.assertTrue(
            policy["releaseLanePolicy"]["routine-maintenance"][
                "exactDevelopmentMergeBaseRequired"
            ]
        )
        self.assertTrue(
            policy["releaseLanePolicy"]["routine-maintenance"][
                "developmentFirstParentBaseRequired"
            ]
        )
        self.assertFalse(
            policy["releaseLanePolicy"]["security-hotfix"][
                "protectedDevelopmentLineageRequired"
            ]
        )
        self.assertIn(
            "stable-maintenance.backport-release-train",
            policy["nonWaivableBlockers"],
        )
        self.assertTrue(
            policy["postReleaseReconciliation"]["automaticMergeTreeRequired"]
        )
        self.assertEqual(
            policy["postReleaseReconciliation"][
                "manualResolutionObligationTypes"
            ],
            {
                "main": "post-release-main-merge",
                "routineDevelop": "post-release-develop-merge",
                "hotfixDevelop": "hotfix-develop-merge-back",
            },
        )
        self.assertTrue(
            policy["postReleaseReconciliation"][
                "manualResolutionCreatesCarriedObligation"
            ]
        )
        maintenance_policy = read_json(
            RELEASE_CERTIFICATION_ROOT / "stable-1.0-maintenance-policy.json"
        )
        routine_soak_hours = (
            maintenance_policy["evidenceWindows"][
                "minimumLiveNetworkDurationSeconds"
            ]
            // 3600
        )
        self.assertGreaterEqual(
            policy["authorization"]["maximumValidityHours"],
            routine_soak_hours + 24,
        )
        excessive = copy.deepcopy(policy)
        excessive["authorization"]["maximumValidityHours"] = 169
        self.assertTrue(
            any(
                "$.authorization.maximumValidityHours is above the schema maximum"
                in error
                for error in validate_schema(
                    excessive,
                    "stable-1.0-backport-release-train-policy-v1.schema.json",
                )
            )
        )

    def test_every_declared_schema_object_is_closed(self) -> None:
        schema_names = (
            "stable-1.0-backport-common-v1.schema.json",
            "stable-1.0-backport-release-train-policy-v1.schema.json",
            "stable-1.0-fix-intake-v1.schema.json",
            "stable-1.0-fix-record-v1.schema.json",
            "stable-1.0-backport-plan-v1.schema.json",
            "stable-1.0-backport-lineage-v1.schema.json",
            "stable-1.0-release-train-queue-v1.schema.json",
            "stable-1.0-release-train-candidate-v1.schema.json",
            "stable-1.0-release-train-validation-v1.schema.json",
            "stable-1.0-release-train-validation-public-v1.schema.json",
            "stable-1.0-release-train-authorization-v1.schema.json",
            "stable-1.0-release-train-completion-v1.schema.json",
            "stable-1.0-release-train-summary-v1.schema.json",
            "stable-1.0-release-train-provenance-v1.schema.json",
            "stable-1.0-release-train-redaction-v1.schema.json",
        )

        def assert_closed(value: object, location: str) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(
                        value.get("additionalProperties"),
                        False,
                        f"{location} is not closed",
                    )
                for key, child in value.items():
                    assert_closed(child, f"{location}.{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    assert_closed(child, f"{location}[{index}]")

        for schema_name in schema_names:
            with self.subTest(schema=schema_name):
                assert_closed(read_json(SCHEMA_ROOT / schema_name), schema_name)

    def test_fix_record_schema_rejects_unknown_fields(self) -> None:
        fix = self._fix_record()

        self.assertEqual(validate_schema(fix, "stable-1.0-fix-record-v1.schema.json"), [])
        changed = copy.deepcopy(fix)
        changed["privateIssueUrl"] = "https://private.invalid/incident"
        self.assertTrue(
            validate_schema(changed, "stable-1.0-fix-record-v1.schema.json")
        )

    def test_validation_requires_authorization_field_and_public_fix_projection(self) -> None:
        validation = {
            "schemaVersion": 1,
            "kind": "stable-1.0-release-train-validation",
            "generatedAt": "2026-01-01T00:00:00Z",
            "stableMilestone": "1.0",
            "mode": "validate-authorization",
            "trainId": "stable-train-build-2",
            "release": {
                "releaseId": "stable-2",
                "releaseClass": "maintenance",
                "buildVersion": "2",
                "tag": "v2",
            },
            "policyDigest": DIGEST,
            "queueDigest": DIGEST,
            "planDigest": DIGEST,
            "candidateDigest": DIGEST,
            "predecessorCommit": "a" * 40,
            "candidateCommit": "b" * 40,
            "hotfixFollowUpClosureDigest": None,
            "requiredFixIds": ["stable-fix-" + "a" * 16],
            "includedFixIds": ["stable-fix-" + "a" * 16],
            "omittedFixIds": [],
            "deferredFixIds": [],
            "unaccountedCommitIds": [],
            "publicFixes": [
                {
                    "fixId": "stable-fix-" + "a" * 16,
                    "classification": "compatible-bug-fix",
                    "severity": "moderate",
                    "publicSummary": "Updater selection remains compatible.",
                    "affectedComponentSummary": "Updater selection",
                    "provenanceMode": "inherited",
                    "lineageDigest": DIGEST,
                    "publicProjectionDigest": DIGEST,
                    "incidentOpaqueId": None,
                    "advisoryOpaqueId": None,
                    "publicSecuritySummary": None,
                    "securityPublicProjectionDigest": None,
                    "disclosureState": None,
                }
            ],
            "evidenceResults": [
                {
                    "fixId": "stable-fix-" + "a" * 16,
                    "evidenceId": "stable-backport.candidate-bound-tests",
                    "status": "pass",
                    "evidenceDigest": DIGEST,
                    "generatedAt": "2026-01-01T00:00:00Z",
                    "expiresAt": "2026-01-02T00:00:00Z",
                    "freshnessDeadlineAt": "2026-01-02T00:00:00Z",
                    "candidateBound": True,
                    "predecessorBound": True,
                    "fresh": True,
                }
            ],
            "blockers": [],
            "authorizationRequired": True,
            "authorization": {
                "authorizationDigest": DIGEST,
                "status": "valid",
                "expiresAt": "2026-01-02T00:00:00Z",
                "role": "stable-maintenance-train-manager",
            },
            "decision": "go",
            "validationDigest": OTHER_DIGEST,
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        }

        self.assertEqual(
            validate_schema(
                validation,
                "stable-1.0-release-train-validation-v1.schema.json",
            ),
            [],
        )
        preauthorization = copy.deepcopy(validation)
        preauthorization["mode"] = "prepare-candidate"
        preauthorization["authorization"] = None
        self.assertEqual(
            validate_schema(
                preauthorization,
                "stable-1.0-release-train-validation-v1.schema.json",
            ),
            [],
        )
        for field in ("authorization", "publicFixes"):
            with self.subTest(field=field):
                changed = copy.deepcopy(validation)
                changed.pop(field)
                self.assertTrue(
                    validate_schema(
                        changed,
                        "stable-1.0-release-train-validation-v1.schema.json",
                    )
                )

    @staticmethod
    def _fix_record() -> dict:
        return {
            "schemaVersion": 1,
            "kind": "stable-1.0-fix-record",
            "stableMilestone": "1.0",
            "fixId": "stable-fix-" + "a" * 16,
            "publicTitle": "Bounded compatible fix",
            "publicSummary": "Corrects candidate behavior without changing stable contracts.",
            "classification": "compatible-bug-fix",
            "disposition": "routine-maintenance",
            "releaseLane": "routine-maintenance",
            "severity": "moderate",
            "risk": "low",
            "affectedScope": {
                "components": ["core-updater"],
                "packageKeys": [],
                "appIds": [],
                "platformApiIds": [],
                "contentProfileIds": [],
                "dataSchemaIds": [],
                "affectedBuilds": ["1"],
            },
            "source": {
                "repositoryIdentity": REPOSITORY_IDENTITY,
                "objectFormat": "sha1",
                "sourceCommit": "a" * 40,
                "sourceBranchRole": "canonical-development",
            },
            "provenance": {
                "mode": None,
                "candidateCommit": None,
                "candidateBranchRole": None,
                "stablePatchId": None,
                "sourceTreeOid": "b" * 40,
                "sourceTreeDigest": DIGEST,
                "sourceDiffDigest": DIGEST,
                "candidateTreeOid": None,
                "candidateTreeDigest": None,
                "candidateDiffDigest": None,
                "touchedPaths": ["src/main/java/example/Fix.java"],
                "mergeBaseCommit": None,
                "sourceBaseCommit": None,
                "targetBaseCommit": None,
                "conflictPaths": [],
                "normalizedDiffEvidenceDigest": None,
                "reviewerAuthorizationDigest": None,
                "focusedTestEvidenceIds": [],
                "noUnrelatedFeatureChange": None,
            },
            "security": None,
            "ownership": {
                "ownerRole": "stable-fix-owner",
                "reviewerRole": None,
                "authorizationDigest": None,
            },
            "schedule": {
                "submittedAt": "2026-01-01T00:00:00Z",
                "decisionAt": None,
                "deadlineAt": None,
                "targetTrainId": "stable-train-build-2",
                "reviewAt": None,
                "rationale": "Candidate intake pending triage.",
            },
            "evidence": [],
            "state": "submitted",
            "stateTransitions": [
                {
                    "sequence": 0,
                    "from": None,
                    "to": "submitted",
                    "occurredAt": "2026-01-01T00:00:00Z",
                    "actorRole": "stable-fix-owner",
                    "reasonCode": "initial-submission",
                    "evidenceDigest": DIGEST,
                }
            ],
            "supersedingFixId": None,
            "privateRecordDigest": None,
            "publicProjectionDigest": DIGEST,
        }


class _Repository:
    def __init__(self, root: Path, *, object_format: str = "sha1") -> None:
        self.root = root
        self._clock = 0
        self.run(
            "init",
            "-q",
            "--initial-branch=main",
            f"--object-format={object_format}",
        )

    def run(
        self,
        *arguments: str,
        check: bool = True,
        dates: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            name: value
            for name, value in os.environ.items()
            if name
            in {
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "TMPDIR",
                "TMP",
                "TEMP",
            }
        }
        environment.update(
            {
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_EDITOR": "true",
            }
        )
        if dates:
            self._clock += 1
            timestamp = f"2001-01-01T00:{self._clock:02d}:00+00:00"
            environment["GIT_AUTHOR_DATE"] = timestamp
            environment["GIT_COMMITTER_DATE"] = timestamp
        return subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            env=environment,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def commit(
        self,
        message: str,
        files: dict[str, str | bytes | None],
        *,
        allow_empty: bool = False,
    ) -> str:
        for relative, value in files.items():
            target = self.root / relative
            if value is None:
                target.unlink(missing_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                target.write_bytes(value)
            else:
                target.write_text(value, encoding="utf-8")
        self.run("add", "-A")
        arguments = [
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "commit",
            "-q",
            "-m",
            message,
        ]
        if allow_empty:
            arguments.append("--allow-empty")
        self.run(*arguments, dates=True)
        return self.head()

    def head(self) -> str:
        return self.run("rev-parse", "HEAD").stdout.strip()

    def branch(self, name: str, start: str | None = None) -> None:
        arguments = ["checkout", "-q", "-b", name]
        if start is not None:
            arguments.append(start)
        self.run(*arguments)

    def checkout(self, name: str) -> None:
        self.run("checkout", "-q", name)

    def cherry_pick(self, commit: str) -> str:
        self.run(
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "cherry-pick",
            commit,
            dates=True,
        )
        return self.head()

    def merge(self, tip: str, message: str) -> str:
        self.run(
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "merge",
            "--no-ff",
            "-q",
            "-m",
            message,
            tip,
            dates=True,
        )
        return self.head()


class StableBackportGitTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve()
        self.repository = _Repository(self.root)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def inspector(self, **options: int) -> GitInspector:
        return GitInspector(
            self.root,
            expected_repository_identity=REPOSITORY_IDENTITY,
            **options,
        )

    def object_database_snapshot(self) -> dict[str, bytes]:
        objects = self.root / ".git" / "objects"
        return {
            path.relative_to(objects).as_posix(): path.read_bytes()
            for path in objects.rglob("*")
            if path.is_file()
        }

    def test_linear_inherited_history_records_exact_identity(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n"})
        source = self.repository.commit("fix", {"app.txt": "fixed\n"})
        candidate = self.repository.commit("candidate", {"notes.txt": "safe\n"})

        inspector = self.inspector()
        provenance = inspector.verify_inherited(source, candidate, DIGEST)

        self.assertTrue(inspector.is_ancestor(base, candidate))
        self.assertEqual(provenance.mode, "inherited")
        self.assertEqual(provenance.source_commit, source)
        self.assertEqual(provenance.candidate_commit, source)
        self.assertEqual(provenance.reviewer_authorization_digest, DIGEST)
        self.assertEqual(provenance.touched_paths, ("app.txt",))

    def test_clean_cherry_pick_requires_patch_scope_and_authorization(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n", "target.txt": "base\n"})
        self.repository.branch("source", base)
        source = self.repository.commit("fix", {"app.txt": "fixed\n"})
        self.repository.checkout("main")
        self.repository.commit("target context", {"target.txt": "target\n"})
        candidate_commit = self.repository.cherry_pick(source)
        candidate_tip = self.repository.commit("metadata", {"notes.txt": "candidate\n"})

        inspector = self.inspector()
        provenance = inspector.verify_clean_cherry_pick(
            source,
            candidate_commit,
            candidate_tip,
            DIGEST,
            ["app.txt"],
        )

        self.assertEqual(provenance.mode, "clean-cherry-pick")
        self.assertNotEqual(provenance.source_commit, provenance.candidate_commit)
        self.assertEqual(
            inspector.stable_patch_id(source),
            inspector.stable_patch_id(candidate_commit),
        )
        with self.assertRaises(GitInspectionError):
            inspector.verify_clean_cherry_pick(
                source,
                candidate_commit,
                candidate_tip,
                "",
                ["app.txt"],
            )
        with self.assertRaises(GitInspectionError):
            inspector.verify_clean_cherry_pick(
                source,
                candidate_commit,
                candidate_tip,
                DIGEST,
                ["target.txt"],
            )

    def test_patch_id_match_cannot_authorize_extra_unrelated_hunks(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n"})
        self.repository.branch("source", base)
        source = self.repository.commit("fix", {"app.txt": "fixed\n"})
        self.repository.checkout("main")
        candidate = self.repository.commit(
            "fix plus cleanup",
            {"app.txt": "fixed\n", "cleanup.txt": "unrelated\n"},
        )

        with self.assertRaises(GitInspectionError):
            self.inspector().verify_clean_cherry_pick(
                source,
                candidate,
                candidate,
                DIGEST,
                ["app.txt", "cleanup.txt"],
            )

    def test_patch_id_whitespace_equivalence_is_not_exact_patch_provenance(
        self,
    ) -> None:
        base = self.repository.commit("base", {"app.txt": "value = 1\n"})
        self.repository.branch("source", base)
        source = self.repository.commit("fix", {"app.txt": "value = 2\n"})
        self.repository.checkout("main")
        candidate = self.repository.commit("different bytes", {"app.txt": "value=2\n"})
        inspector = self.inspector()
        self.assertEqual(
            inspector.stable_patch_id(source),
            inspector.stable_patch_id(candidate),
        )

        with self.assertRaisesRegex(GitInspectionError, "normalized patch-content"):
            inspector.verify_clean_cherry_pick(
                source,
                candidate,
                candidate,
                DIGEST,
                ["app.txt"],
            )

    def test_manual_conflict_resolution_requires_exact_bases_review_and_tests(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n"})
        self.repository.branch("source", base)
        source = self.repository.commit("source fix", {"app.txt": "source\n"})
        source_base = self.repository.run("rev-parse", f"{source}^").stdout.strip()
        self.repository.checkout("main")
        target_base = self.repository.commit("target context", {"app.txt": "target\n"})
        candidate = self.repository.commit("reviewed resolution", {"app.txt": "resolved\n"})

        inspector = self.inspector()
        normalized_evidence = inspector.manual_conflict_evidence_digest(
            source,
            candidate,
            ["app.txt"],
        )
        provenance = inspector.verify_manual_conflict_resolution(
            source_commit=source,
            candidate_commit=candidate,
            candidate_tip=candidate,
            source_base_commit=source_base,
            target_base_commit=target_base,
            expected_merge_base_commit=base,
            conflict_paths=["app.txt"],
            allowed_paths=["app.txt"],
            reviewer_authorization_digest=DIGEST,
            focused_test_evidence_ids=["stable-backport.focused-test"],
            normalized_diff_evidence_digest=normalized_evidence,
            no_unrelated_feature_change=True,
        )

        self.assertEqual(provenance.mode, "manual-conflict-resolution")
        self.assertIsNone(provenance.stable_patch_id)
        self.assertEqual(provenance.merge_base_commit, base)
        for changed in (
            {"reviewer_authorization_digest": ""},
            {"focused_test_evidence_ids": []},
            {"conflict_paths": []},
            {"no_unrelated_feature_change": False},
        ):
            arguments = {
                "source_commit": source,
                "candidate_commit": candidate,
                "candidate_tip": candidate,
                "source_base_commit": source_base,
                "target_base_commit": target_base,
                "expected_merge_base_commit": base,
                "conflict_paths": ["app.txt"],
                "allowed_paths": ["app.txt"],
                "reviewer_authorization_digest": DIGEST,
                "focused_test_evidence_ids": ["stable-backport.focused-test"],
                "normalized_diff_evidence_digest": normalized_evidence,
                "no_unrelated_feature_change": True,
            }
            arguments.update(changed)
            with self.subTest(changed=changed), self.assertRaises(GitInspectionError):
                inspector.verify_manual_conflict_resolution(**arguments)

    def test_full_object_ids_reject_abbreviations_revision_expressions_and_noncommits(self) -> None:
        commit = self.repository.commit("base", {"app.txt": "base\n"})
        blob = self.repository.run("hash-object", "-w", "app.txt").stdout.strip()
        inspector = self.inspector()

        for invalid in (
            commit[:12],
            commit.upper(),
            "HEAD~1",
            "main:app.txt",
            "HEAD@{1}",
            "f" * 40,
            blob,
        ):
            with self.subTest(object_id=invalid), self.assertRaises(GitInspectionError):
                inspector.validate_commit_oid(invalid)

    def test_repository_root_is_exact_confined_non_shallow_and_symlink_free(self) -> None:
        self.repository.commit("base", {"app.txt": "base\n"})
        nested = self.root / "nested"
        nested.mkdir()
        with self.assertRaises(GitInspectionError):
            GitInspector(nested, expected_repository_identity=REPOSITORY_IDENTITY)
        symlink = self.root.parent / f"{self.root.name}-link"
        try:
            symlink.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(GitInspectionError):
                GitInspector(symlink, expected_repository_identity=REPOSITORY_IDENTITY)
        finally:
            symlink.unlink(missing_ok=True)
        with self.assertRaises(GitInspectionError):
            GitInspector(
                self.root,
                expected_repository_identity="https://user:secret@example.invalid/repo",
            )

    def test_replacement_objects_do_not_substitute_inspected_commit(self) -> None:
        original = self.repository.commit("base", {"app.txt": "base\n"})
        replacement = self.repository.commit("replacement", {"app.txt": "replacement\n"})
        original_tree = self.repository.run(
            "--no-replace-objects", "show", "-s", "--format=%T", original
        ).stdout.strip()
        self.repository.run("replace", original, replacement)

        inspected = self.inspector().inspect_commit(original)

        self.assertEqual(inspected.tree_oid, original_tree)
        self.assertNotEqual(inspected.identity.commit, replacement)

    def test_alternate_object_database_and_grafts_are_rejected(self) -> None:
        self.repository.commit("base", {"app.txt": "base\n"})
        alternate = self.root / ".git/objects/info/alternates"
        alternate.write_text(self.root.parent.as_posix() + "\n", encoding="utf-8")
        with self.assertRaises(GitInspectionError):
            self.inspector()
        alternate.unlink()
        grafts = self.root / ".git/info/grafts"
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text("", encoding="utf-8")
        with self.assertRaises(GitInspectionError):
            self.inspector()

    def test_symlinked_object_database_is_rejected(self) -> None:
        self.repository.commit("base", {"app.txt": "base\n"})
        object_directory = self.root / ".git" / "objects"
        external_object_directory = (
            self.root.parent / f"{self.root.name}-external-objects"
        )
        object_directory.rename(external_object_directory)
        object_directory.symlink_to(
            external_object_directory, target_is_directory=True
        )
        try:
            with self.assertRaisesRegex(GitInspectionError, "confined"):
                self.inspector()
        finally:
            object_directory.unlink(missing_ok=True)
            external_object_directory.rename(object_directory)

    def test_nested_symlinks_in_object_database_are_rejected(self) -> None:
        commit = self.repository.commit("base", {"app.txt": "base\n"})
        object_directory = self.root / ".git" / "objects"
        for relative in ("pack", commit[:2]):
            nested_directory = object_directory / relative
            external_directory = (
                self.root.parent
                / f"{self.root.name}-external-objects-{relative}"
            )
            nested_directory.rename(external_directory)
            nested_directory.symlink_to(
                external_directory, target_is_directory=True
            )
            try:
                with self.subTest(relative=relative), self.assertRaisesRegex(
                    GitInspectionError, "confined"
                ):
                    self.inspector()
            finally:
                nested_directory.unlink(missing_ok=True)
                external_directory.rename(nested_directory)

    def test_merge_and_empty_commits_cannot_be_patch_provenance(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n"})
        self.repository.branch("topic", base)
        topic = self.repository.commit("topic", {"topic.txt": "topic\n"})
        self.repository.checkout("main")
        self.repository.commit("main", {"main.txt": "main\n"})
        merge = self.repository.merge(topic, "merge topic")
        empty = self.repository.commit("empty", {}, allow_empty=True)
        inspector = self.inspector()

        self.assertTrue(inspector.inspect_commit(merge).is_merge)
        self.assertTrue(inspector.inspect_commit(empty).is_empty)
        for commit in (merge, empty):
            with self.subTest(commit=commit), self.assertRaises(GitInspectionError):
                inspector.stable_patch_id(commit)

    def test_binary_rename_and_copy_evidence_is_bounded_and_exact(self) -> None:
        self.repository.commit(
            "base",
            {"old.txt": "rename me\n", "image.bin": bytes(range(32))},
        )
        self.repository.run("mv", "old.txt", "new.txt")
        rename = self.repository.commit(
            "rename and binary",
            {"image.bin": bytes(range(31, -1, -1))},
        )

        inspected = self.inspector().inspect_commit(rename)

        self.assertTrue(inspected.contains_binary_patch)
        self.assertTrue(inspected.contains_rename_or_copy)
        self.assertEqual(inspected.touched_paths, ("image.bin", "new.txt", "old.txt"))
        self.assertTrue(inspected.tree_digest.startswith("sha256:"))
        self.assertTrue(inspected.diff_digest.startswith("sha256:"))

    def test_unchanged_source_copy_is_recorded_explicitly(self) -> None:
        self.repository.commit("base", {"source.txt": "copy me\n"})
        copied = self.repository.commit("copy", {"copy.txt": "copy me\n"})

        inspected = self.inspector().inspect_commit(copied)

        self.assertTrue(inspected.contains_rename_or_copy)
        self.assertEqual(inspected.changes[0].status, "C100")
        self.assertEqual(inspected.changes[0].old_path, "source.txt")
        self.assertEqual(inspected.changes[0].new_path, "copy.txt")

    def test_unsafe_git_path_is_rejected_from_public_evidence(self) -> None:
        self.repository.commit("base", {"safe.txt": "safe\n"})
        self.repository.commit("unsafe", {"unsafe\nname.txt": "unsafe\n"})

        with self.assertRaises(GitInspectionError):
            self.inspector().inspect_commit(self.repository.head())

    def test_output_limit_is_enforced_without_disclosing_git_output(self) -> None:
        commit = self.repository.commit("large", {"large.txt": "x" * 4096})

        with self.assertRaisesRegex(GitInspectionError, "policy bound"):
            self.inspector(max_output_bytes=1024).inspect_commit(commit)

    def test_output_limit_terminates_git_before_command_completion(self) -> None:
        script = (
            "import pathlib,sys,time;"
            "stream=getattr(sys,sys.argv[2]);"
            "stream.buffer.write(b'x'*4096);"
            "stream.flush();"
            "time.sleep(1);"
            "pathlib.Path(sys.argv[1]).write_text('completed',encoding='utf-8')"
        )
        inspector = object.__new__(GitInspector)
        inspector._root = self.root  # noqa: SLF001
        inspector._environment = GitInspector._sanitized_environment()  # noqa: SLF001
        inspector._max_output_bytes = 1024  # noqa: SLF001
        inspector._timeout_seconds = 5  # noqa: SLF001

        for output_stream in ("stdout", "stderr"):
            marker = self.root / f"{output_stream}-command-completed"
            with self.subTest(output_stream=output_stream), mock.patch.object(
                stable_backport_git,
                "_READ_ONLY_GIT_PREFIX",
                (
                    sys.executable,
                    "-c",
                    script,
                    str(marker),
                    output_stream,
                ),
            ), self.assertRaisesRegex(GitInspectionError, "policy bound"):
                inspector._run_result(("ignored",))  # noqa: SLF001
            self.assertFalse(marker.exists())

    def test_routine_and_hotfix_branch_roles_use_exact_graph_not_branch_names(self) -> None:
        predecessor = self.repository.commit("published", {"app.txt": "published\n"})
        development = self.repository.commit("development", {"dev.txt": "development\n"})
        self.repository.branch("release-2", development)
        routine_candidate = self.repository.commit("routine", {"fix.txt": "routine\n"})
        self.repository.checkout("main")
        development_tip = self.repository.commit(
            "later development", {"future.txt": "future\n"}
        )
        protected_main_tip = self.repository.merge(
            routine_candidate, "reconcile published candidate"
        )
        inspector = self.inspector()

        routine = inspector.verify_branch_role(
            lane="routine-maintenance",
            candidate_build="2",
            candidate_commit=routine_candidate,
            branch_base=development,
            authorized_lineage_commit=development_tip,
            authenticated_predecessor_commit=predecessor,
        )
        self.assertEqual(routine.branch_role, "routine-release-candidate")
        with self.assertRaises(GitInspectionError):
            inspector.verify_branch_role(
                lane="routine-maintenance",
                candidate_build="2",
                candidate_commit=routine_candidate,
                branch_base=predecessor,
                authorized_lineage_commit=development_tip,
                authenticated_predecessor_commit=predecessor,
            )
        self.repository.branch("not-a-trusted-hotfix-label", protected_main_tip)
        hotfix_candidate = self.repository.commit("hotfix", {"security.txt": "fixed\n"})
        hotfix = inspector.verify_branch_role(
            lane="security-hotfix",
            candidate_build="3",
            candidate_commit=hotfix_candidate,
            branch_base=protected_main_tip,
            authorized_lineage_commit=protected_main_tip,
            authenticated_predecessor_commit=routine_candidate,
        )
        self.assertEqual(hotfix.branch_role, "security-hotfix-candidate")
        self.repository.branch("pre-reconciliation-hotfix", routine_candidate)
        stale_hotfix_candidate = self.repository.commit(
            "stale hotfix", {"stale-security.txt": "fixed\n"}
        )
        with self.assertRaises(GitInspectionError):
            inspector.verify_branch_role(
                lane="security-hotfix",
                candidate_build="3",
                candidate_commit=stale_hotfix_candidate,
                branch_base=routine_candidate,
                authorized_lineage_commit=protected_main_tip,
                authenticated_predecessor_commit=routine_candidate,
            )
        with self.assertRaises(GitInspectionError):
            inspector.verify_branch_role(
                lane="security-hotfix",
                candidate_build="3",
                candidate_commit=hotfix_candidate,
                branch_base=protected_main_tip,
                authorized_lineage_commit=None,
                authenticated_predecessor_commit=routine_candidate,
            )

    def test_routine_branch_base_must_be_on_develop_first_parent_chain(self) -> None:
        predecessor = self.repository.commit("published", {"app.txt": "published\n"})
        development = self.repository.commit("development", {"dev.txt": "development\n"})
        self.repository.branch("side", predecessor)
        side = self.repository.commit("side", {"side.txt": "side\n"})
        self.repository.checkout("main")
        develop_tip = self.repository.merge(side, "merge side into develop")
        self.repository.branch("release-from-side", side)
        candidate = self.repository.commit("candidate", {"fix.txt": "fixed\n"})

        with self.assertRaisesRegex(GitInspectionError, "first-parent lineage"):
            self.inspector().verify_branch_role(
                lane="routine-maintenance",
                candidate_build="2",
                candidate_commit=candidate,
                branch_base=side,
                authorized_lineage_commit=develop_tip,
                authenticated_predecessor_commit=predecessor,
            )
        self.assertTrue(
            self.inspector().is_first_parent_ancestor(development, develop_tip)
        )

    def test_candidate_build_version_is_read_from_the_exact_commit(self) -> None:
        candidate = self.repository.commit(
            "candidate",
            {"build.gradle.kts": 'version = "301"\n'},
        )
        inspector = self.inspector()

        self.assertTrue(inspector.verify_project_build_version(candidate, "301"))
        with self.assertRaises(GitInspectionError):
            inspector.verify_project_build_version(candidate, "302")

    def test_no_fork_and_candidate_coverage_require_latest_predecessor(self) -> None:
        predecessor = self.repository.commit("published", {"app.txt": "published\n"})
        first = self.repository.commit("first", {"one.txt": "one\n"})
        second = self.repository.commit("second", {"two.txt": "two\n"})
        inspector = self.inspector()

        self.assertTrue(inspector.verify_no_fork(predecessor, predecessor, second))
        self.assertEqual(inspector.candidate_commits(predecessor, second), (first, second))
        with self.assertRaises(GitInspectionError):
            inspector.verify_no_fork(first, predecessor, second)
        self.repository.branch("fork", predecessor)
        fork = self.repository.commit("fork", {"fork.txt": "fork\n"})
        with self.assertRaises(GitInspectionError):
            inspector.candidate_commits(second, fork)

    def test_no_ff_merge_requires_exact_two_parent_graph_and_attestation(self) -> None:
        base = self.repository.commit("base", {"app.txt": "base\n"})
        self.repository.branch("topic", base)
        tip = self.repository.commit("topic", {"fix.txt": "fixed\n"})
        self.repository.checkout("main")
        first_parent = self.repository.commit("main context", {"main.txt": "context\n"})
        merge = self.repository.merge(tip, "merge release")
        inspector = self.inspector()
        attestation = inspector.reconciliation_attestation_digest(
            protected_ref="refs/heads/main",
            protected_tip=merge,
            merge_commit=merge,
            first_parent=first_parent,
            merged_tip=tip,
        )

        evidence = inspector.verify_no_ff_merge(
            merge_commit=merge,
            first_parent=first_parent,
            merged_tip=tip,
            protected_ref="refs/heads/main",
            protected_tip=merge,
            expected_protected_ref="refs/heads/main",
            workflow_attestation_digest=attestation,
        )
        self.assertTrue(evidence.graph_verified)
        self.assertEqual(evidence.parent_count, 2)
        self.assertEqual(inspector.merge_resolution_paths(merge), ())
        for changed in (
            {"first_parent": base},
            {"merged_tip": first_parent},
            {"workflow_attestation_digest": ""},
            {"protected_ref": "refs/heads/develop"},
            {"protected_tip": first_parent},
        ):
            arguments = {
                "merge_commit": merge,
                "first_parent": first_parent,
                "merged_tip": tip,
                "protected_ref": "refs/heads/main",
                "protected_tip": merge,
                "expected_protected_ref": "refs/heads/main",
                "workflow_attestation_digest": attestation,
            }
            arguments.update(changed)
            with self.subTest(changed=changed), self.assertRaises(GitInspectionError):
                inspector.verify_no_ff_merge(**arguments)

        self.repository.branch("spoofed-protected-tip", first_parent)
        spoofed_first_parent = self.repository.commit(
            "protected context", {"protected.txt": "context\n"}
        )
        spoofed_tip = self.repository.merge(
            merge, "merge reconciliation only as a side parent"
        )
        spoofed_attestation = inspector.reconciliation_attestation_digest(
            protected_ref="refs/heads/main",
            protected_tip=spoofed_tip,
            merge_commit=merge,
            first_parent=first_parent,
            merged_tip=tip,
        )
        self.assertTrue(inspector.is_ancestor(merge, spoofed_tip))
        self.assertFalse(
            inspector.is_first_parent_ancestor(merge, spoofed_tip)
        )
        with self.assertRaisesRegex(GitInspectionError, "first-parent"):
            inspector.verify_no_ff_merge(
                merge_commit=merge,
                first_parent=first_parent,
                merged_tip=tip,
                protected_ref="refs/heads/main",
                protected_tip=spoofed_tip,
                expected_protected_ref="refs/heads/main",
                workflow_attestation_digest=spoofed_attestation,
            )
        self.assertNotEqual(spoofed_first_parent, merge)

    def test_merge_resolution_paths_expose_content_hidden_by_merge_context(
        self,
    ) -> None:
        base = self.repository.commit("base", {"shared.txt": "base\n"})
        self.repository.branch("topic", base)
        tip = self.repository.commit("topic", {"shared.txt": "topic\n"})
        self.repository.checkout("main")
        self.repository.commit("main", {"shared.txt": "main\n"})
        conflicted = self.repository.run(
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "merge",
            "--no-ff",
            "-q",
            "-m",
            "conflicted merge",
            tip,
            check=False,
            dates=True,
        )
        self.assertNotEqual(conflicted.returncode, 0)
        merge = self.repository.commit(
            "reviewed resolution",
            {"shared.txt": "reviewed resolution\n"},
        )
        before = self.object_database_snapshot()

        self.assertEqual(
            self.inspector().merge_resolution_paths(merge),
            ("shared.txt",),
        )
        self.assertEqual(self.object_database_snapshot(), before)

    def test_merge_resolution_matching_one_parent_is_not_merge_context(self) -> None:
        base = self.repository.commit("base", {"shared.txt": "base\n"})
        self.repository.branch("topic", base)
        tip = self.repository.commit("topic", {"shared.txt": "accepted topic fix\n"})
        self.repository.checkout("main")
        first_parent = self.repository.commit(
            "main", {"shared.txt": "main context\n"}
        )
        conflicted = self.repository.run(
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "merge",
            "--no-ff",
            "-q",
            "-m",
            "conflicted merge",
            tip,
            check=False,
            dates=True,
        )
        self.assertNotEqual(conflicted.returncode, 0)
        merge = self.repository.commit(
            "discard topic resolution",
            {"shared.txt": "main context\n"},
        )
        before = self.object_database_snapshot()

        self.assertEqual(
            self.inspector().merge_resolution_paths(merge),
            ("shared.txt",),
        )
        inspector = self.inspector()
        attestation = inspector.reconciliation_attestation_digest(
            protected_ref="refs/heads/main",
            protected_tip=merge,
            merge_commit=merge,
            first_parent=first_parent,
            merged_tip=tip,
        )
        with self.assertRaisesRegex(
            NonAutomaticMergeResolutionError,
            "non-automatic content resolution",
        ) as raised:
            inspector.verify_no_ff_merge(
                merge_commit=merge,
                first_parent=first_parent,
                merged_tip=tip,
                protected_ref="refs/heads/main",
                protected_tip=merge,
                expected_protected_ref="refs/heads/main",
                workflow_attestation_digest=attestation,
            )
        self.assertEqual(raised.exception.evidence.merge_commit, merge)
        self.assertEqual(
            raised.exception.resolution_paths,
            ("shared.txt",),
        )
        self.assertEqual(self.object_database_snapshot(), before)

    def test_merge_resolution_does_not_execute_repository_merge_driver(
        self,
    ) -> None:
        base = self.repository.commit(
            "base",
            {
                ".gitattributes": "shared.txt merge=release-test\n",
                "shared.txt": "base\n",
            },
        )
        self.repository.branch("topic", base)
        topic = self.repository.commit("topic", {"shared.txt": "topic\n"})
        self.repository.checkout("main")
        main = self.repository.commit("main", {"shared.txt": "main\n"})
        main_tree = self.repository.run(
            "rev-parse", f"{main}^{{tree}}"
        ).stdout.strip()
        merge = self.repository.run(
            "-c",
            "user.name=Cryptad Fixture",
            "-c",
            "user.email=fixture@crypta.invalid",
            "commit-tree",
            main_tree,
            "-p",
            main,
            "-p",
            topic,
            "-m",
            "recorded merge",
            dates=True,
        ).stdout.strip()
        marker = self.root / "merge-driver-ran"
        self.repository.run(
            "config",
            "merge.release-test.driver",
            f"touch {marker.as_posix()}; true",
        )
        before = self.object_database_snapshot()

        paths = self.inspector().merge_resolution_paths(merge)

        self.assertFalse(marker.exists())
        self.assertEqual(paths, ("shared.txt",))
        self.assertEqual(self.object_database_snapshot(), before)

    def test_sha256_repository_full_object_ids_when_supported(self) -> None:
        probe_root = self.root / "sha256"
        probe_root.mkdir()
        try:
            repository = _Repository(probe_root, object_format="sha256")
        except subprocess.CalledProcessError:
            self.skipTest("installed Git does not support SHA-256 repositories")
        commit = repository.commit("sha256", {"app.txt": "sha256\n"})
        inspector = GitInspector(
            probe_root.resolve(),
            expected_repository_identity=REPOSITORY_IDENTITY,
        )

        self.assertEqual(inspector.object_format, "sha256")
        self.assertEqual(len(commit), 64)
        self.assertEqual(inspector.validate_commit_oid(commit), commit)
        self.assertIn(len(inspector.stable_patch_id(commit)), (40, 64))

    def test_subprocess_api_never_uses_shell_interpolation(self) -> None:
        module_path = (
            Path(__file__).resolve().parents[1] / "stable_backport_git.py"
        )
        source = module_path.read_text(encoding="utf-8")

        self.assertNotIn("shell=True", source)
        self.assertNotIn('("fetch",', source)
        self.assertNotIn('("push",', source)
        self.assertNotIn('("cherry-pick",', source)
        self.assertNotIn('\"merge\", \"--no-ff\"', source)


if __name__ == "__main__":
    unittest.main()
