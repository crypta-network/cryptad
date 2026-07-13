"""Tests for manifests, envelopes, workspaces, migration, and source size."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from cryptad_certification.envelope import from_legacy, validate_envelope
from cryptad_certification.io import read_json, write_json
from cryptad_certification.manifest import ManifestError, load_manifest
from cryptad_certification.migration import execute as migrate
from cryptad_certification.models import EvidenceEnvelope
from cryptad_certification.legacy import execute as execute_engine
from cryptad_certification.redaction import scan_value
from cryptad_certification.tests.support import workspace_root, write_manifest
from cryptad_certification.workspace import WorkspaceError, prepare_context, prepare_run_root


class ManifestTest(unittest.TestCase):
    def test_valid_manifest_creates_marked_release_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root)
            manifest = load_manifest(path, root)
            run_root = prepare_run_root(manifest)
            context = prepare_context(root, manifest, "core")
            self.assertEqual(run_root, context.run_root)
            self.assertTrue((run_root / ".cryptad-certification-run.json").is_file())

    def test_manifest_schema_version_requires_the_exact_integer_type(self) -> None:
        for schema_version in (True, False, 1.0, "1", None):
            with self.subTest(schema_version=schema_version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = write_manifest(root, schemaVersion=schema_version)

                with self.assertRaisesRegex(ManifestError, "schemaVersion must be 1"):
                    load_manifest(path, root)

    def test_manifest_requires_the_release_version_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(
                root,
                release={"id": "missing-version", "profile": "pr"},
            )

            with self.assertRaisesRegex(ManifestError, "missing release fields: version"):
                load_manifest(path, root)

    def test_secret_like_manifest_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret_key = "token-not-a-real-token"
            path = write_manifest(
                root,
                commands={"production-beta": {secret_key: "unsafe"}},
            )
            with self.assertRaises(ManifestError) as raised:
                load_manifest(path, root)
            self.assertNotIn(secret_key, str(raised.exception))

    def test_secret_material_in_manifest_values_is_rejected_without_echoing_it(self) -> None:
        secret_values = {
            "private-uri": "SSK@private,insert,AQECAAE/release",
            "private-key": "-----BEGIN PRIVATE KEY-----\nnot-a-real-key",
            "authorization": "Bearer abcdefghijklmnop",
            "assignment": "password=not-a-real-password",
            "cookie": "Cookie: session=not-a-real-session",
            "url-credentials": "https://operator:not-a-real-password@example.invalid/evidence",
        }
        for case, secret in secret_values.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = write_manifest(
                    root,
                    inputs={"previousCandidate": secret},
                )

                with self.assertRaisesRegex(ManifestError, "forbidden") as raised:
                    load_manifest(path, root)

                self.assertNotIn(secret, str(raised.exception))

    def test_unknown_manifest_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root, unexpected=True)
            with self.assertRaises(ManifestError):
                load_manifest(path, root)

    def test_secret_bearing_command_option_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root, commands={"live-network-beta": {"args": ["--form-password", "unsafe"]}})
            with self.assertRaises(ManifestError):
                load_manifest(path, root)

    def test_requirement_values_must_be_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root, requirements={"history": "true"})
            with self.assertRaises(ManifestError):
                load_manifest(path, root)

    def test_required_history_may_be_missing_for_gate_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root, requirements={"history": True})

            manifest = load_manifest(path, root)

            self.assertTrue(manifest.requirements["history"])
            self.assertNotIn("releaseHistory", manifest.inputs)

    def test_output_reset_must_be_a_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(
                root,
                output={"root": "build/release-certification", "reset": "false"},
            )
            with self.assertRaisesRegex(ManifestError, "output.reset must be a boolean"):
                load_manifest(path, root)

    def test_unknown_gate_map_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root, requirements={"liveNetwrok": True})
            with self.assertRaises(ManifestError):
                load_manifest(path, root)

    def test_reset_refuses_an_unmarked_existing_release_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(
                root,
                output={"root": "build/release-certification", "reset": True},
            )
            target = root / "build/release-certification/self-test-release"
            target.mkdir(parents=True)
            (target / "unrelated.txt").write_text("keep", encoding="utf-8")
            manifest = load_manifest(path, root)
            with self.assertRaises(ValueError):
                prepare_run_root(manifest)
            self.assertTrue((target / "unrelated.txt").is_file())

    def test_reuse_refuses_an_unmarked_existing_release_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root)
            target = root / "build/release-certification/self-test-release"
            target.mkdir(parents=True)
            unrelated = target / "unrelated.txt"
            unrelated.write_text("keep", encoding="utf-8")

            manifest = load_manifest(path, root)
            with self.assertRaisesRegex(ValueError, "refusing to use unmarked"):
                prepare_run_root(manifest)

            self.assertTrue(unrelated.is_file())
            self.assertFalse((target / ".cryptad-certification-run.json").exists())

    def test_component_context_rejects_a_symlinked_component_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            run_root = prepare_run_root(manifest)
            outside = root / "outside-component"
            outside.mkdir()
            component = run_root / "component"
            try:
                component.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with self.assertRaisesRegex(WorkspaceError, "contains a symlink"):
                prepare_context(root, manifest, "component")

            self.assertFalse((outside / "artifacts").exists())

    def test_component_context_rejects_a_symlinked_artifacts_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            run_root = prepare_run_root(manifest)
            component = run_root / "component"
            component.mkdir()
            outside = root / "outside-artifacts"
            outside.mkdir()
            try:
                (component / "artifacts").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with self.assertRaisesRegex(WorkspaceError, "contains a symlink"):
                prepare_context(root, manifest, "component")

    def test_component_context_rejects_a_path_outside_the_run_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)

            with self.assertRaisesRegex(WorkspaceError, "escapes release workspace"):
                prepare_context(root, manifest, "../outside-component")

            self.assertFalse(
                (manifest.output.root / "outside-component").exists()
            )


class SchemaContractTest(unittest.TestCase):
    def test_passing_redaction_schema_requires_zero_findings(self) -> None:
        schema = read_json(
            workspace_root()
            / "tools/release-certification/schemas/evidence-envelope-v2.schema.json"
        )
        passing_redaction = schema["properties"]["redaction"]["allOf"][0]["then"][
            "properties"
        ]

        self.assertEqual({"const": 0}, passing_redaction["findingCount"])
        self.assertEqual({"maxItems": 0}, passing_redaction["findings"])

    def test_manifest_schema_requires_runtime_non_empty_strings(self) -> None:
        schema = read_json(
            workspace_root()
            / "tools/release-certification/schemas/release-run-v1.schema.json"
        )
        properties = schema["properties"]

        self.assertEqual(1, properties["release"]["properties"]["version"]["minLength"])
        self.assertEqual(1, properties["output"]["properties"]["root"]["minLength"])
        self.assertEqual(
            1,
            properties["commands"]["additionalProperties"]["properties"]["mode"][
                "minLength"
            ],
        )


class EnvelopeTest(unittest.TestCase):
    def test_common_envelope_validates_release_binding(self) -> None:
        value = EvidenceEnvelope(
            kind="test",
            generated_at="2026-01-01T00:00:00Z",
            subject={"releaseId": "candidate", "version": "1", "profile": "pr", "component": "test"},
            result={"status": "pass", "decision": None, "promotionReady": None, "exitCode": 0},
            counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
            redaction={"status": "pass", "findingCount": 0, "findings": [], "guarantees": {}},
        ).to_json()
        validate_envelope(value, "test", "candidate")
        with self.assertRaises(ValueError):
            validate_envelope(value, "test", "another-candidate")

    def test_passing_redaction_rejects_reported_findings(self) -> None:
        value = EvidenceEnvelope(
            kind="test",
            generated_at="2026-01-01T00:00:00Z",
            subject={"releaseId": "candidate", "version": "1", "profile": "pr", "component": "test"},
            result={"status": "pass", "decision": None, "promotionReady": None, "exitCode": 0},
            counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
            redaction={
                "status": "pass",
                "findingCount": 1,
                "findings": [{"category": "secret-material"}],
                "guarantees": {},
            },
        ).to_json()

        with self.assertRaisesRegex(ValueError, "passing redaction requires zero findings"):
            validate_envelope(value, "test", "candidate")

    def test_complete_envelope_contract_rejects_missing_or_inconsistent_fields(self) -> None:
        value = EvidenceEnvelope(
            kind="test",
            generated_at="2026-01-01T00:00:00Z",
            subject={"releaseId": "candidate", "version": "1", "profile": "pr", "component": "test"},
            result={"status": "pass", "decision": None, "promotionReady": None, "exitCode": 0},
            counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
            redaction={"status": "pass", "findingCount": 0, "findings": [], "guarantees": {}},
        ).to_json()
        for field in (
            "kind",
            "generatedAt",
            "subject",
            "result",
            "counts",
            "evidence",
            "issues",
            "waivers",
            "redaction",
            "inputs",
            "artifacts",
            "payload",
        ):
            with self.subTest(missing=field):
                malformed = copy.deepcopy(value)
                malformed.pop(field)
                with self.assertRaisesRegex(ValueError, "missing fields"):
                    validate_envelope(malformed, "test", "candidate")

        malformed_cases = {
            "subject": lambda item: item["subject"].pop("component"),
            "result": lambda item: item["result"].update({"exitCode": True}),
            "nonzero-pass": lambda item: item["result"].update({"exitCode": 7}),
            "counts": lambda item: item["counts"].update({"evidence": 1}),
            "issues": lambda item: item["issues"].pop("warnings"),
            "redaction": lambda item: item["redaction"].update({"findingCount": 1}),
            "redaction-guarantee": lambda item: item["redaction"]["guarantees"].update(
                {"secretMaterialRedacted": False}
            ),
            "artifacts": lambda item: item.update({"artifacts": {"summary": 1}}),
        }
        for name, mutate in malformed_cases.items():
            with self.subTest(malformed=name):
                malformed = copy.deepcopy(value)
                mutate(malformed)
                with self.assertRaises(ValueError):
                    validate_envelope(malformed, "test", "candidate")

    def test_legacy_evidence_cannot_be_relabelled_as_another_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "identity")
            with self.assertRaisesRegex(ValueError, "does not match manifest"):
                from_legacy(
                    context,
                    "test",
                    {
                        "schemaVersion": 1,
                        "releaseId": "another-candidate",
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                    0,
                    {},
                )

    def test_nonzero_legacy_exit_forces_failed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "failed-process")

            envelope = from_legacy(
                context,
                "test",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "promotionReady": True,
                    "redaction": {"status": "pass", "findings": []},
                },
                7,
                {},
            )

            self.assertEqual("fail", envelope.result["status"])
            self.assertEqual(7, envelope.result["exitCode"])
            self.assertFalse(envelope.result["promotionReady"])
            validate_envelope(envelope.to_json(), "test", "self-test-release")

    def test_missing_redaction_scans_the_complete_legacy_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "fallback-redaction")

            safe = from_legacy(
                context,
                "test",
                {"schemaVersion": 1, "status": "pass", "plan": ["safe"]},
                0,
                {},
            )
            unsafe = from_legacy(
                context,
                "test",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "promotionReady": True,
                    "operatorPath": "/home/alice/private-summary.json",
                },
                0,
                {},
            )

            self.assertEqual("pass", safe.redaction["status"])
            self.assertTrue(safe.redaction["guarantees"]["legacyPayloadScanned"])
            self.assertEqual("fail", unsafe.redaction["status"])
            self.assertEqual("fail", unsafe.result["status"])
            self.assertEqual(1, unsafe.result["exitCode"])
            self.assertFalse(unsafe.result["promotionReady"])
            self.assertEqual("absolute-path", unsafe.redaction["findings"][0]["category"])

    def test_missing_redaction_rejects_nested_sensitive_field_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "fallback-sensitive-field")

            envelope = from_legacy(
                context,
                "test",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "details": {"formPassword": "hunter2"},
                },
                0,
                {},
            )

            self.assertEqual("fail", envelope.result["status"])
            self.assertEqual(1, envelope.result["exitCode"])
            self.assertEqual("fail", envelope.redaction["status"])
            self.assertEqual(
                "sensitive-field",
                envelope.redaction["findings"][0]["category"],
            )

    def test_scanner_accepts_canonical_sanitized_engine_output(self) -> None:
        value = {
            "commands": {
                "args": [
                    "<path>/python3",
                    "<repo>/tools/release-certification/engine_entry.py",
                ],
                "stdout_tail": "warn: <workdir>/candidate/report.md",
            },
            "source": "<repo>/first/summary.json; <repo>/second/summary.json",
            "scripts": ["./crypta-platform.js", "./app.js"],
            "routes": [
                "POST /api/v1/content/fetch",
                "GET /app-data/status",
                "/trust-graph/audit",
                "/apps/publisher/",
            ],
            "negativeFindingsByPath": {
                "fixtures/redaction-authorization-header.json": ["authorization-header"],
                "fixtures/redaction-app-token.json": "<redacted>",
            },
            "negativeFixtureResults": {
                "fixtures/redaction-private-insert-uri.json": {
                    "detectedKinds": ["credential-or-path marker", "private insert URI"],
                    "expectedKind": "private insert URI",
                    "passes": True,
                }
            },
            "checks": {"safeErrorsAndNoRawContentCovered": True},
            "privateKeySource": "missing",
            "privateKeyFingerprint": f"sha256:{'a' * 64}",
            "rawBodyHash": "b" * 64,
            "rawRequestBodyCount": 0,
            "redacted": {
                "privateInsertUri": "<redacted-uri>",
                "rawRequestBody": "<redacted>",
            },
        }

        self.assertEqual([], scan_value(value))

    def test_scanner_rejects_malformed_sanitized_engine_output(self) -> None:
        cases = {
            "placeholder-traversal": {"path": "<path>/../private/key.pem"},
            "local-path-in-route-like-root": {"workspaceRoot": "/apps/cryptad/build"},
            "unredacted-sensitive-source": {"privateKeySource": "operator-key.pem"},
            "absence-word-as-secret": {"formPassword": "missing"},
            "container-under-fingerprint": {
                "privateKeyFingerprint": {"content": "private key material"}
            },
            "container-under-hash": {
                "rawBodyHash": {"content": "private message body"}
            },
            "container-under-redacted": {
                "rawBodyRedacted": {"content": "private message body"}
            },
            "malformed-hash": {"rawBodyHash": "not-a-sha256-digest"},
            "malformed-negative-fixture": {
                "negativeFindingsByPath": {
                    "fixtures/redaction-app-token.json": "hunter2",
                }
            },
        }

        for name, value in cases.items():
            with self.subTest(name=name):
                self.assertTrue(scan_value(value))

    def test_false_or_malformed_redaction_metadata_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "redaction-metadata")
            cases = {
                "false-guarantee": {
                    "status": "pass",
                    "findings": [],
                    "secretMaterialRedacted": False,
                },
                "false-nested-guarantee": {
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {"secretMaterialRedacted": False},
                },
                "malformed-block": "pass",
                "malformed-findings": {"status": "pass", "findings": "none"},
                "malformed-status": {"status": [], "findings": []},
                "malformed-finding-count": {
                    "status": "pass",
                    "findingCount": 1,
                    "findings": [],
                },
                "malformed-guarantees": {
                    "status": "pass",
                    "findings": [],
                    "guarantees": {"secretMaterialRedacted": "yes"},
                },
            }

            for case, redaction in cases.items():
                with self.subTest(case=case):
                    envelope = from_legacy(
                        context,
                        "test",
                        {
                            "schemaVersion": 1,
                            "status": "pass",
                            "redaction": redaction,
                        },
                        0,
                        {},
                    )

                    self.assertEqual("fail", envelope.redaction["status"])
                    self.assertEqual("fail", envelope.result["status"])
                    self.assertEqual(1, envelope.result["exitCode"])

    def test_negative_live_redaction_facts_are_normalized_as_positive_guarantees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "live-redaction")
            safe_redaction = {
                "status": "pass",
                "findings": [],
                "forbiddenPatternsChecked": True,
                "rawBodiesStored": False,
                "privateInsertUrisStored": False,
                "localPathsStored": False,
                "formPasswordStored": False,
                "tokenValuesStored": False,
                "rawSignaturesStored": False,
            }

            safe = from_legacy(
                context,
                "live-network-beta-smoke",
                {
                    "schemaVersion": 1,
                    "status": "warning",
                    "redaction": safe_redaction,
                },
                0,
                {},
            )
            unsafe_redaction = dict(safe_redaction)
            unsafe_redaction["rawBodiesStored"] = True
            unsafe = from_legacy(
                context,
                "live-network-beta-smoke",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "redaction": unsafe_redaction,
                },
                0,
                {},
            )

            self.assertEqual("warn", safe.result["status"])
            self.assertEqual(0, safe.result["exitCode"])
            self.assertEqual("pass", safe.redaction["status"])
            self.assertTrue(safe.redaction["guarantees"]["rawBodiesNotStored"])
            self.assertNotIn("rawBodiesStored", safe.redaction["guarantees"])
            validate_envelope(
                safe.to_json(),
                "live-network-beta-smoke",
                "self-test-release",
            )
            self.assertEqual("fail", unsafe.result["status"])
            self.assertEqual(1, unsafe.result["exitCode"])
            self.assertEqual("fail", unsafe.redaction["status"])
            self.assertFalse(unsafe.redaction["guarantees"]["rawBodiesNotStored"])

    def test_production_launch_decision_is_promoted_into_the_common_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")

            envelope = from_legacy(
                context,
                "production-beta-release",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "goNoGo": {"decision": "go-with-waivers"},
                    "redaction": {"status": "pass", "findings": []},
                },
                0,
                {},
            )

            self.assertEqual("go-with-waivers", envelope.result["decision"])

    def test_manifest_input_paths_are_resolved_before_envelope_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={
                        "previousCandidate": "build/history.json",
                        "releaseHistory": "../../home/alice/release-summary.json",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "input-redaction")

            envelope = from_legacy(
                context,
                "test",
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "redaction": {"status": "pass", "findings": []},
                },
                0,
                {},
            )

            self.assertEqual(
                "<repo>/build/history.json",
                envelope.inputs["previousCandidate"],
            )
            self.assertEqual("<external-input>", envelope.inputs["releaseHistory"])
            self.assertNotIn("alice", str(envelope.to_json()))


class MigrationTest(unittest.TestCase):
    def test_migrates_valid_v1_history_into_v2_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.json"
            write_json(
                legacy,
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/previous-candidate")
            self.assertEqual(0, migrate(context, "previous-candidate"))
            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual(2, summary["schemaVersion"])
            self.assertEqual("migrated-v1-previous-candidate", summary["kind"])

    def test_migration_rejects_present_non_integer_schema_versions(self) -> None:
        for schema_version in (True, False, 1.0, "1", None, 2):
            with self.subTest(schema_version=schema_version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "legacy.json"
                write_json(
                    legacy,
                    {
                        "schemaVersion": schema_version,
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
                manifest = load_manifest(path, root)
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "migration/previous-candidate")

                with self.assertRaisesRegex(ValueError, "legacy schemaVersion 1"):
                    migrate(context, "previous-candidate")

                self.assertFalse((context.component_dir / "summary.json").exists())

    def test_migration_allows_an_omitted_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.json"
            write_json(
                legacy,
                {
                    "status": "pass",
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/previous-candidate")

            self.assertEqual(0, migrate(context, "previous-candidate"))

            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual(1, summary["payload"]["migration"]["sourceSchemaVersion"])

    def test_rejects_v1_history_with_common_absolute_local_paths(self) -> None:
        local_paths = (
            "/home/operator/release",
            "/etc/cryptad/form-password",
            "/srv/runner/work/release-summary.json",
            "/root/.crypta/history.json",
            "/app/secrets/catalog-key",
            r"C:\ProgramData\Cryptad\release-summary.json",
            "<repo>/../../etc/passwd",
            "<repo>//etc/passwd",
            r"<repo>/build\release-summary.json",
            "<repo>/build/summary.json /etc/passwd",
        )
        for local_path in local_paths:
            with self.subTest(local_path=local_path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "legacy.json"
                write_json(
                    legacy,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "workspace": local_path,
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
                manifest = load_manifest(path, root)
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "migration/previous-candidate")

                with self.assertRaisesRegex(ValueError, "absolute-path scan"):
                    migrate(context, "previous-candidate")

                self.assertFalse(
                    (context.component_dir / "artifacts/migrated-summary.json").exists()
                )
                self.assertFalse((context.component_dir / "summary.json").exists())

    def test_migrates_release_history_with_sanitized_repo_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "release-history.json"
            write_json(
                legacy,
                {
                    "schemaVersion": 1,
                    "tool": "release-certification",
                    "status": "pass",
                    "summaryPath": "<repo>/build/release-certification/summary.json",
                    "reportPath": "<repo>/build/release-certification/report.md",
                    "artifactsDir": "<repo>/build/release-certification/artifacts",
                    "workspaceRoot": "<repo>/.",
                    "evidence": [
                        {
                            "id": "interop.smoke",
                            "status": "pass",
                            "source": "<repo>/build/interop-smoke/summary.json",
                        }
                    ],
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            path = write_manifest(root, inputs={"releaseHistory": legacy.name})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/release-history")

            self.assertEqual(0, migrate(context, "release-history"))

            migrated = read_json(
                context.component_dir / "artifacts/migrated-summary.json"
            )
            self.assertEqual(
                "<repo>/build/release-certification/summary.json",
                migrated["summaryPath"],
            )
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("pass", envelope["result"]["status"])

    def test_rejects_v1_history_with_nested_sensitive_payload_fields(self) -> None:
        sensitive_payloads = {
            "basic-authorization": {"headerValue": "Basic dXNlcjpwYXNzd29yZA=="},
            "form-password": {"formPassword": "hunter2"},
            "api-token": {"apiToken": "synthetic-token-value"},
            "private-key": {"privateKey": "opaque-private-key-material"},
            "private-insert-uri": {"privateInsertUri": "opaque-private-insert-material"},
            "raw-app-data": {"rawAppData": {"record": "private-value"}},
            "request-body": {"requestBody": "private request payload"},
        }
        for case, payload in sensitive_payloads.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "legacy.json"
                write_json(
                    legacy,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "details": {"nested": payload},
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
                manifest = load_manifest(path, root)
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "migration/previous-candidate")

                with self.assertRaisesRegex(ValueError, "private-material and absolute-path scan"):
                    migrate(context, "previous-candidate")

                self.assertFalse(
                    (context.component_dir / "artifacts/migrated-summary.json").exists()
                )
                self.assertFalse((context.component_dir / "summary.json").exists())

    def test_migration_rejects_misclassified_or_malformed_public_routes(self) -> None:
        unsafe_routes = {
            "route-shaped-workspace": {"workspaceRoot": "/apps/cryptad/build"},
            "route-traversal": {"routes": ["/api/v1/../../etc/passwd"]},
            "encoded-route-traversal": {"routes": ["/api/v1/%2e%2e/etc/passwd"]},
            "nested-encoded-route-traversal": {
                "routes": ["/api/v1/%2525252e%2525252e/etc/passwd"]
            },
        }
        for case, details in unsafe_routes.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "legacy.json"
                write_json(
                    legacy,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "details": details,
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
                manifest = load_manifest(path, root)
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "migration/previous-candidate")

                with self.assertRaisesRegex(ValueError, "absolute-path scan"):
                    migrate(context, "previous-candidate")

                self.assertFalse(
                    (context.component_dir / "artifacts/migrated-summary.json").exists()
                )
                self.assertFalse((context.component_dir / "summary.json").exists())

    def test_migration_allows_safe_redaction_facts_and_public_routes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.json"
            write_json(
                legacy,
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "details": {
                        "apiTokenId": "redacted-key-id",
                        "formPasswordProvidedFromEnvironment": True,
                        "privateInsertUriNotPersisted": True,
                        "rawAppDataIncluded": False,
                        "routes": [
                            "/api/v1/apps",
                            "/apps/feed-reader/",
                            "/app/node/",
                            "/core-update/",
                        ],
                    },
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            path = write_manifest(root, inputs={"previousCandidate": "legacy.json"})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/previous-candidate")

            self.assertEqual(0, migrate(context, "previous-candidate"))
            self.assertTrue((context.component_dir / "summary.json").is_file())

    def test_rejects_nonpassing_v1_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.json"
            write_json(legacy, {"schemaVersion": 1, "status": "fail"})
            path = write_manifest(root, inputs={"releaseHistory": "legacy.json"})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/release-history")
            with self.assertRaisesRegex(ValueError, "passing status"):
                migrate(context, "release-history")

    def test_migrates_v1_history_with_passing_boolean_redaction_guarantees(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = root / "legacy.json"
            write_json(
                legacy,
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "redaction": {
                        "secretMaterialRedacted": True,
                        "absolutePathsSanitized": True,
                    },
                },
            )
            path = write_manifest(root, inputs={"releaseHistory": "legacy.json"})
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "migration/release-history")

            self.assertEqual(0, migrate(context, "release-history"))

            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual("pass", summary["redaction"]["status"])
            self.assertEqual(
                {
                    "absolutePathsSanitized": True,
                    "secretMaterialRedacted": True,
                },
                summary["redaction"]["guarantees"],
            )

    def test_rejects_missing_malformed_or_failing_v1_redaction(self) -> None:
        invalid_redaction = {
            "missing": None,
            "string": "fail",
            "empty": {},
            "status-without-findings": {"status": "pass"},
            "malformed-findings": {"status": "pass", "findings": "none"},
            "failed-status": {"status": "fail", "findings": []},
            "nonempty-findings": {"status": "pass", "findings": ["unsafe evidence"]},
            "failed-guarantee": {"secretMaterialRedacted": False},
            "failed-nested-guarantee": {
                "status": "pass",
                "findings": [],
                "guarantees": {"rawBodiesExcluded": False},
            },
            "malformed-nested-guarantee": {
                "status": "pass",
                "findings": [],
                "guarantees": {"rawBodiesExcluded": "true"},
            },
            "no-passing-signal": {"findings": []},
            "unknown-boolean": {"unrelated": True},
            "malformed-status": {"status": [], "findings": []},
            "malformed-finding-count": {
                "status": "pass",
                "findingCount": "0",
                "findings": [],
            },
            "inconsistent-finding-count": {
                "status": "pass",
                "findingCount": 1,
                "findings": [],
            },
        }
        for case, redaction in invalid_redaction.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                legacy = root / "legacy.json"
                value: dict[str, object] = {"schemaVersion": 1, "status": "pass"}
                if case != "missing":
                    value["redaction"] = redaction
                write_json(legacy, value)
                path = write_manifest(root, inputs={"releaseHistory": "legacy.json"})
                manifest = load_manifest(path, root)
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "migration/release-history")

                with self.assertRaisesRegex(ValueError, "redaction"):
                    migrate(context, "release-history")

                self.assertFalse((context.component_dir / "summary.json").exists())


class SourceSizeTest(unittest.TestCase):
    def test_all_release_certification_python_files_are_at_most_5000_lines(self) -> None:
        root = workspace_root() / "tools" / "release-certification"
        oversized = {
            path.relative_to(root).as_posix(): len(path.read_text(encoding="utf-8").splitlines())
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts and len(path.read_text(encoding="utf-8").splitlines()) > 5000
        }
        self.assertEqual({}, oversized)


class CommandIntegrationTest(unittest.TestCase):
    def test_network_scale_command_writes_a_bound_v2_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_manifest(root)
            manifest = load_manifest(path, root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "network-scale-soak")
            self.assertEqual(0, execute_engine(context, "network-scale-soak"))
            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual(2, summary["schemaVersion"])
            self.assertEqual("network-scale-soak", summary["kind"])
            self.assertEqual("self-test-release", summary["subject"]["releaseId"])
            self.assertEqual("pass", summary["redaction"]["status"])

    def test_successful_multi_node_plan_and_schema_are_passing_actions(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            for action in ("plan", "schema"):
                with self.subTest(action=action):
                    manifest = load_manifest(
                        write_manifest(
                            output,
                            release={
                                "id": f"self-test-{action}",
                                "version": "self-test",
                                "profile": "pr",
                            },
                        ),
                        root,
                        output,
                    )
                    prepare_run_root(manifest)
                    context = prepare_context(root, manifest, f"multi-node-beta/{action}")

                    self.assertEqual(0, execute_engine(context, "multi-node-beta", action))

                    summary = read_json(context.component_dir / "summary.json")
                    self.assertEqual(0, summary["result"]["exitCode"])
                    self.assertEqual("pass", summary["result"]["status"])
