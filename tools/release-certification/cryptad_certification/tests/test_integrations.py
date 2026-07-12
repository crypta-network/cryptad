"""Integration contracts for manifests, adapters, orchestration, and workflows."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import cli, legacy
from cryptad_certification.engines import (
    app_platform_smoke,
    live_network_beta_smoke,
    multi_node_beta_soak,
    production_beta_go_no_go_dashboard,
    production_beta_release,
    release_certification,
    security_response_runbook,
    stable_1_0_readiness,
)
from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.manifest import load_manifest
from cryptad_certification.models import EvidenceEnvelope, RunContext
from cryptad_certification.tests.support import workspace_root, write_manifest
from cryptad_certification.workspace import prepare_context, prepare_run_root


class CollectionIntegrationTest(unittest.TestCase):
    def test_release_collection_runs_every_candidate_scoped_collector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    requirements={"liveNetwork": True, "multiNodeSoak": True},
                    execution={"collectEvidence": True},
                ),
                root,
            )
            calls: list[tuple[str, str | None]] = []

            def capture(
                workspace: Path,
                configured_manifest: object,
                command: str,
                action: str | None = None,
            ) -> int:
                self.assertEqual(root, workspace)
                self.assertIs(manifest, configured_manifest)
                calls.append((command, action))
                return 0

            with mock.patch.object(cli, "_execute_component", side_effect=capture):
                cli._collect_release_evidence(root, manifest)

            self.assertEqual(
                [
                    ("app-platform", None),
                    ("network-scale-soak", None),
                    ("multi-node-beta", "run"),
                    ("security-response", "verify"),
                    ("security-response", "drill-run-all"),
                    ("security-response", "drill-verify-all"),
                    ("live-network-beta", None),
                ],
                calls,
            )

    def test_internal_collection_replaces_an_existing_component_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            stale_context = prepare_context(root, manifest, "app-platform")
            stale_summary = stale_context.component_dir / "summary.json"
            stale_artifact = stale_context.component_dir / "artifacts/stale.json"
            write_json(stale_summary, {"schemaVersion": 2, "result": {"status": "pass"}})
            write_json(stale_artifact, {"source": "previous invocation"})

            def execute(context: RunContext, command: str, action: str | None) -> int:
                self.assertEqual("app-platform", command)
                self.assertIsNone(action)
                component_dir = context.component_dir
                self.assertFalse((component_dir / "summary.json").exists())
                self.assertFalse((component_dir / "artifacts/stale.json").exists())
                return 0

            with mock.patch.object(cli, "execute_engine", side_effect=execute) as engine:
                self.assertEqual(0, cli._execute_component(root, manifest, "app-platform"))

            engine.assert_called_once()

    def test_internal_collection_rejects_a_symlinked_parent_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            run_root = prepare_run_root(manifest)
            preserved_component = run_root / "preserved-security-response/verify"
            preserved_component.mkdir(parents=True)
            preserved_file = preserved_component / "keep.json"
            write_json(preserved_file, {"preserved": True})
            symlinked_parent = run_root / "security-response"
            try:
                symlinked_parent.symlink_to(
                    preserved_component.parent,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(cli, "execute_engine") as engine:
                with self.assertRaisesRegex(ValueError, "contains a symlink"):
                    cli._execute_component(
                        root,
                        manifest,
                        "security-response",
                        "verify",
                    )

            engine.assert_not_called()
            self.assertTrue(preserved_file.is_file())

    def test_completed_aggregate_is_rejected_before_recollecting_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                execution={"collectEvidence": True},
            )
            manifest = load_manifest(manifest_path, root)
            run_root = prepare_run_root(manifest)
            aggregate_dir = run_root / "release-certification"
            aggregate_dir.mkdir()
            old_summary = {"schemaVersion": 2, "result": {"status": "pass"}}
            write_json(aggregate_dir / "summary.json", old_summary)
            app_platform = prepare_context(root, manifest, "app-platform")
            preserved = app_platform.component_dir / "preserved-evidence.json"
            write_json(preserved, {"candidate": "original"})

            with (
                mock.patch.object(cli, "_collect_release_evidence") as collect,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "release-certification",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(2, code)
            collect.assert_not_called()
            self.assertEqual(old_summary, read_json(aggregate_dir / "summary.json"))
            self.assertFalse((aggregate_dir / "artifacts").exists())
            self.assertEqual({"candidate": "original"}, read_json(preserved))

    def test_security_drill_summary_keeps_its_redacted_artifact_set(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            manifest = load_manifest(write_manifest(output), root, output)
            prepare_run_root(manifest)
            run_context = prepare_context(
                root,
                manifest,
                "security-response/drill-run-all",
            )
            verify_context = prepare_context(
                root,
                manifest,
                "security-response/drill-verify-all",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    legacy.execute(
                        run_context,
                        "security-response",
                        "drill-run-all",
                    ),
                )
                self.assertEqual(
                    0,
                    legacy.execute(
                        verify_context,
                        "security-response",
                        "drill-verify-all",
                    ),
                )
            summary = read_json(verify_context.component_dir / "artifacts/legacy-summary.json")
            self.assertEqual("pr", summary["mode"])
            self.assertTrue(summary["nonRelease"])
            self.assertFalse(summary["promotionReady"])
            artifact_names = {
                entry["artifact"]
                for entry in summary["artifacts"]
                if isinstance(entry, dict) and isinstance(entry.get("artifact"), str)
            }
            self.assertEqual(7, len(artifact_names))
            for name in artifact_names:
                self.assertTrue((verify_context.component_dir / "artifacts" / name).is_file())

            consumer_output = output / "consumer-output"
            consumer_manifest = load_manifest(
                write_manifest(
                    output / "consumer-manifest",
                    inputs={
                        "securityDrills": str(
                            verify_context.component_dir / "summary.json"
                        )
                    },
                ),
                root,
                consumer_output,
            )
            prepare_run_root(consumer_manifest)
            consumer_context = prepare_context(
                root,
                consumer_manifest,
                "release-certification",
            )

            extracted = legacy._legacy_input_path(consumer_context, "securityDrills")

            self.assertIsNotNone(extracted)
            for name in artifact_names:
                self.assertTrue((extracted.parent / name).is_file())


class AdapterIntegrationTest(unittest.TestCase):
    def test_symlinked_legacy_output_is_rejected_before_engine_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")
            external = root / "external-legacy-output"
            external.mkdir()
            legacy_output = context.component_dir / "artifacts/legacy"
            try:
                legacy_output.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(app_platform_smoke, "main") as engine:
                with self.assertRaisesRegex(ValueError, "legacy output path contains a symlink"):
                    legacy.execute(context, "app-platform")

            engine.assert_not_called()
            self.assertEqual([], list(external.iterdir()))

    def test_symlinked_extracted_input_directory_is_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = EvidenceEnvelope(
                kind="app-platform-smoke",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "app-platform",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
            ).to_json()
            write_json(root / "app-platform-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            external = root / "external-inputs"
            external.mkdir()
            input_dir = context.component_dir / "artifacts/inputs"
            try:
                input_dir.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with self.assertRaisesRegex(
                ValueError,
                "extracted input path contains a symlink",
            ):
                legacy._legacy_input_path(context, "appPlatform")

            self.assertEqual([], list(external.iterdir()))

    def test_required_missing_history_reaches_the_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": "self-test",
                        "profile": "release-candidate",
                    },
                    requirements={"history": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                out = Path(arguments[arguments.index("--out-dir") + 1])
                write_json(
                    out / "release-certification-summary.json",
                    {
                        "schemaVersion": 1,
                        "tool": "release-certification",
                        "status": "fail",
                        "blockers": ["required release history is missing"],
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                write_text(
                    out / "release-certification-report.md",
                    "# Release certification\n\nRequired release history is missing.\n",
                )
                return 1

            with mock.patch.object(release_certification, "main", side_effect=run):
                self.assertEqual(
                    1,
                    legacy.execute(context, "release-certification"),
                )

            previous = Path(captured[captured.index("--previous-summary") + 1])
            self.assertFalse(previous.exists())
            self.assertIn("--require-history", captured)
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("fail", envelope["result"]["status"])
            self.assertTrue((context.component_dir / "report.md").is_file())

    def test_release_adapter_preserves_the_shared_history_directory_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    execution={"writeHistory": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            self.assertIn("--write-history", captured)
            self.assertNotIn("--history-dir", captured)

    def test_release_adapter_honors_an_explicit_history_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    policies={"historyDir": "build/shared-certification-history"},
                    execution={"writeHistory": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            history_dir_index = captured.index("--history-dir")
            self.assertEqual(
                root / "build/shared-certification-history",
                Path(captured[history_dir_index + 1]),
            )

    def test_live_network_safe_negative_redaction_fields_remain_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "live-network-beta")

            def write_safe_summary(arguments: list[str]) -> int:
                out = Path(arguments[arguments.index("--out-dir") + 1])
                write_json(
                    out / "summary.json",
                    {
                        "schemaVersion": 1,
                        "status": "warning",
                        "redaction": {
                            "status": "pass",
                            "findings": [],
                            "forbiddenPatternsChecked": True,
                            "rawBodiesStored": False,
                            "privateInsertUrisStored": False,
                            "localPathsStored": False,
                        },
                    },
                )
                return 0

            with mock.patch.object(
                live_network_beta_smoke,
                "main",
                side_effect=write_safe_summary,
            ):
                self.assertEqual(0, legacy.execute(context, "live-network-beta"))

            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("warn", envelope["result"]["status"])
            self.assertEqual(0, envelope["result"]["exitCode"])
            self.assertEqual("pass", envelope["redaction"]["status"])
            self.assertTrue(
                envelope["redaction"]["guarantees"]["rawBodiesNotStored"]
            )
            consumer_manifest_root = root / "consumer-manifest"
            consumer_manifest_root.mkdir()
            consumer_manifest = load_manifest(
                write_manifest(
                    consumer_manifest_root,
                    inputs={"liveNetwork": str(context.component_dir / "summary.json")},
                ),
                root,
                root / "consumer-output",
            )
            prepare_run_root(consumer_manifest)
            consumer_context = prepare_context(
                root,
                consumer_manifest,
                "release-certification",
            )
            extracted = legacy._legacy_input_path(consumer_context, "liveNetwork")
            self.assertIsNotNone(extracted)
            self.assertEqual("warning", read_json(extracted)["status"])

    def test_component_input_rejects_a_nonzero_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = EvidenceEnvelope(
                kind="app-platform-smoke",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "app-platform",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 7,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
            ).to_json()
            write_json(root / "app-platform-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")

            with self.assertRaisesRegex(ValueError, "nonzero"):
                legacy._legacy_input_path(context, "appPlatform")

            self.assertFalse(
                (context.component_dir / "artifacts/inputs/appPlatform.json").exists()
            )

    def test_nightly_profile_reaches_the_nightly_release_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "nightly-candidate",
                        "version": "self-test",
                        "profile": "nightly",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            self.assertEqual("nightly", captured[captured.index("--mode") + 1])

    def test_command_modes_cannot_override_the_manifest_release_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                command: {"mode": "pr"}
                for command in (
                    "app-platform",
                    "live-network-beta",
                    "release-certification",
                    "production-beta",
                    "go-no-go",
                )
            }
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "strict-candidate",
                        "version": "self-test",
                        "profile": "release-candidate",
                    },
                    commands=commands,
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "mode-validation")

            for command in commands:
                with self.subTest(command=command):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"commands\.{command}\.mode cannot override release\.profile",
                    ):
                        legacy._mode(context, command)

    def test_security_drills_preserve_supported_non_release_profiles(self) -> None:
        for profile in ("pr", "nightly", "developer-dry-run"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": f"{profile}-candidate",
                            "version": "self-test",
                            "profile": profile,
                        },
                    ),
                    root,
                )
                prepare_run_root(manifest)
                context = prepare_context(
                    root,
                    manifest,
                    "security-response/drill-run-all",
                )
                captured: list[str] = []

                with mock.patch.object(
                    security_response_runbook,
                    "main",
                    side_effect=lambda args: captured.extend(args) or 0,
                ):
                    legacy._run_passthrough(
                        context,
                        "security-response",
                        "drill-run-all",
                    )

                self.assertEqual(profile, captured[captured.index("--mode") + 1])

    def test_pr_app_platform_collection_skips_gradle_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")
            captured: list[str] = []

            with mock.patch.object(
                app_platform_smoke,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_app_platform(context)

            self.assertEqual("pr", captured[captured.index("--mode") + 1])
            self.assertIn("--skip-gradle", captured)

    def test_multi_node_actions_use_the_structured_topology_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = root / "release-topology.json"
            write_json(topology, {"topology": "release-specific"})
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"multiNodeSoakConfig": "release-topology.json"},
                    commands={
                        "multi-node-beta": {
                            "args": ["--config", "ignored-topology.json"]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)

            for action in ("plan", "run"):
                with self.subTest(action=action):
                    context = prepare_context(root, manifest, f"multi-node-beta/{action}")
                    captured: list[str] = []
                    with mock.patch.object(
                        multi_node_beta_soak,
                        "main",
                        side_effect=lambda args: captured.extend(args) or 0,
                    ):
                        legacy._run_passthrough(context, "multi-node-beta", action)

                    self.assertEqual(1, captured.count("--config"))
                    config_index = captured.index("--config")
                    self.assertEqual(topology.resolve(), Path(captured[config_index + 1]))
                    self.assertNotIn("ignored-topology.json", captured)

    def test_required_live_multi_node_run_fails_without_reachable_nodes(self) -> None:
        cases = (
            ("configured-live", "live", None),
            ("overridden-live", "simulated", "live"),
        )
        for name, config_mode, override_mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                topology = root / "release-topology.json"
                config = multi_node_beta_soak.load_config(None)
                config["mode"] = config_mode
                write_json(topology, config)
                command = {} if override_mode is None else {"mode": override_mode}
                manifest = load_manifest(
                    write_manifest(
                        root,
                        requirements={"multiNodeSoak": True},
                        inputs={"multiNodeSoakConfig": topology.name},
                        commands={"multi-node-beta": command},
                    ),
                    root,
                )
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "multi-node-beta/run")

                self.assertEqual(
                    1,
                    legacy.execute(context, "multi-node-beta", "run"),
                )

                envelope = read_json(context.component_dir / "summary.json")
                self.assertEqual("fail", envelope["result"]["status"])
                self.assertIn(
                    "live mode required at least one reachable localhost node",
                    envelope["payload"]["legacy"]["blockers"],
                )

    def test_multi_node_plan_ignores_external_output_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external_plan = root / "external-plan.json"
            external_report = root / "external-report.md"
            external_dir = root / "external-output"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "multi-node-beta": {
                            "args": [
                                f"--out={external_plan}",
                                "--report",
                                str(external_report),
                                "--out-dir",
                                str(external_dir),
                            ]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "multi-node-beta/plan")
            captured: list[str] = []

            def generate_plan(args: list[str]) -> int:
                captured.extend(args)
                output = Path(args[args.index("--out") + 1])
                write_json(
                    output,
                    {
                        "status": "pass",
                        "planMarker": "candidate-scoped-plan",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                return 0

            with mock.patch.object(
                multi_node_beta_soak,
                "main",
                side_effect=generate_plan,
            ):
                self.assertEqual(0, legacy.execute(context, "multi-node-beta", "plan"))

            scoped_plan = context.component_dir / "artifacts/legacy/plan.json"
            self.assertEqual(scoped_plan, Path(captured[captured.index("--out") + 1]))
            self.assertNotIn("--report", captured)
            self.assertNotIn("--out-dir", captured)
            self.assertFalse(external_plan.exists())
            self.assertFalse(external_report.exists())
            self.assertFalse(external_dir.exists())
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual(
                "candidate-scoped-plan",
                envelope["payload"]["legacy"]["planMarker"],
            )

    def test_abbreviated_controlled_output_option_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            escaped_plan = root / "escaped-plan.json"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "multi-node-beta": {
                            "args": ["--ou", str(escaped_plan)],
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "multi-node-beta/plan")

            with mock.patch.object(multi_node_beta_soak, "main") as engine:
                with self.assertRaisesRegex(
                    ValueError,
                    "abbreviated controlled option: --ou",
                ):
                    legacy._run_passthrough(context, "multi-node-beta", "plan")

            engine.assert_not_called()
            self.assertFalse(escaped_plan.exists())

    def test_abbreviated_controlled_options_are_rejected_for_every_adapter(self) -> None:
        cases = {
            "app-platform": "--work",
            "live-network-beta": "--out-d",
            "multi-node-beta": "--conf",
            "security-response": "--summary-o",
            "release-certification": "--mo",
            "production-beta": "--release-i",
            "go-no-go": "--waiv",
            "stable-readiness": "--pol",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        command: {"args": [abbreviation, "controlled-value"]}
                        for command, abbreviation in cases.items()
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "abbreviation-validation")

            for command, abbreviation in cases.items():
                with self.subTest(command=command, abbreviation=abbreviation):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"abbreviated controlled option: {abbreviation}",
                    ):
                        legacy._args(context, command)

    def test_security_drill_run_ignores_external_output_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external_dir = root / "external-drills"
            external_summary = root / "external-summary.json"
            external_notes = root / "external-notes.md"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "security-response": {
                            "args": [
                                "--out-dir",
                                str(external_dir),
                                f"--summary-out={external_summary}",
                                "--release-notes-out",
                                str(external_notes),
                            ]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "security-response/drill-run-all")
            captured: list[str] = []

            def generate_summary(args: list[str]) -> int:
                captured.extend(args)
                output = Path(args[args.index("--summary-out") + 1])
                write_json(
                    output,
                    {
                        "status": "pass",
                        "releaseId": "self-test-release",
                        "summaryMarker": "candidate-scoped-security-summary",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                return 0

            with mock.patch.object(
                security_response_runbook,
                "main",
                side_effect=generate_summary,
            ):
                self.assertEqual(
                    0,
                    legacy.execute(
                        context,
                        "security-response",
                        "drill-run-all",
                    ),
                )

            scoped = context.component_dir / "artifacts/legacy"
            self.assertEqual(scoped / "drills", Path(captured[captured.index("--out-dir") + 1]))
            self.assertEqual(
                scoped / "summary.json",
                Path(captured[captured.index("--summary-out") + 1]),
            )
            self.assertEqual(
                scoped / "security-release-notes-draft.md",
                Path(captured[captured.index("--release-notes-out") + 1]),
            )
            self.assertFalse(external_dir.exists())
            self.assertFalse(external_summary.exists())
            self.assertFalse(external_notes.exists())
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual(
                "candidate-scoped-security-summary",
                envelope["payload"]["legacy"]["summaryMarker"],
            )

    def test_release_adapter_unwraps_candidate_bound_migrated_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrated = root / "history-v2.json"
            legacy_history = {
                "schemaVersion": 1,
                "tool": "release-certification",
                "status": "pass",
                "evidence": [{"id": "interop.smoke", "status": "pass"}],
                "redaction": {"status": "pass", "findings": []},
            }
            write_json(
                migrated,
                {
                    "schemaVersion": 2,
                    "kind": "migrated-v1-release-history",
                    "generatedAt": "2026-01-01T00:00:00Z",
                    "subject": {
                        "releaseId": "self-test-release",
                        "version": "self-test",
                        "profile": "pr",
                        "component": "migration/release-history",
                    },
                    "result": {
                        "status": "pass",
                        "decision": None,
                        "promotionReady": None,
                        "exitCode": 0,
                    },
                    "counts": {"evidence": 1, "blockers": 0, "warnings": 0, "waivers": 0},
                    "evidence": [{"id": "interop.smoke", "status": "pass"}],
                    "issues": {"blockers": [], "warnings": []},
                    "waivers": [],
                    "redaction": {"status": "pass", "findingCount": 0, "findings": [], "guarantees": {}},
                    "inputs": {},
                    "artifacts": {},
                    "payload": {"legacy": legacy_history},
                },
            )
            manifest = load_manifest(
                write_manifest(
                    root,
                    requirements={"history": True},
                    inputs={"releaseHistory": "history-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                return 0

            with mock.patch.object(release_certification, "main", side_effect=run):
                legacy._run_release_certification(context)

            history_path = Path(captured[captured.index("--previous-summary") + 1])
            self.assertEqual(legacy_history, read_json(history_path))
            self.assertIn("--require-history", captured)

    def test_stable_adapter_accepts_warning_go_no_go_evidence_for_waiver_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy_dashboard = {
                "schemaVersion": 1,
                "releaseId": "self-test-release",
                "decision": "go-with-waivers",
                "status": "warn",
                "waiversUsed": [{"id": "accepted-waiver"}],
            }
            envelope = EvidenceEnvelope(
                kind="production-beta-go-no-go",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "stable-review",
                    "component": "go-no-go",
                },
                result={
                    "status": "warn",
                    "decision": "go-with-waivers",
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 1},
                waivers=[{"id": "accepted-waiver"}],
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": legacy_dashboard},
            ).to_json()
            write_json(root / "go-no-go-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": "self-test",
                        "profile": "stable-review",
                    },
                    inputs={"goNoGo": "go-no-go-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "stable-readiness")
            captured: list[str] = []

            with mock.patch.object(
                stable_1_0_readiness,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_stable_readiness(context)

            extracted = Path(captured[captured.index("--go-no-go-summary") + 1])
            self.assertEqual(legacy_dashboard, read_json(extracted))

    def test_every_v2_component_input_requires_its_mapped_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in legacy.V2_KIND_BY_INPUT:
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(
                    path,
                    EvidenceEnvelope(
                        kind="wrong-kind",
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "self-test",
                            "profile": "pr",
                            "component": "wrong",
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": None,
                            "exitCode": 0,
                        },
                        counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {}},
                    ).to_json(),
                )
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "kind-validation")

            for key, expected_kind in legacy.V2_KIND_BY_INPUT.items():
                with self.subTest(key=key):
                    with self.assertRaisesRegex(ValueError, f"expected evidence kind {expected_kind}"):
                        legacy._legacy_input_path(context, key)

    def test_v2_component_inputs_reject_raw_v1_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in legacy.V2_KIND_BY_INPUT:
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(path, {"schemaVersion": 1, "status": "pass"})
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "v1-rejection")

            for key, expected_kind in legacy.V2_KIND_BY_INPUT.items():
                with self.subTest(key=key):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"inputs\.{key} must be a v2 {expected_kind} evidence envelope",
                    ):
                        legacy._legacy_input_path(context, key)

    def test_explicit_external_and_non_envelope_inputs_retain_v1_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in (
                "ecosystemMatrix",
                "interopSmoke",
                "interopExtended",
                "performanceSmoke",
                "thirdPartyIntake",
            ):
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(path, {"schemaVersion": 1, "status": "success"})
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "external-v1-inputs")

            for key, relative_path in inputs.items():
                with self.subTest(key=key):
                    self.assertEqual(
                        (root / relative_path).resolve(),
                        legacy._legacy_input_path(context, key),
                    )

    def test_production_adapter_propagates_structured_manifest_fields(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    output,
                    release={"id": "candidate-id", "version": None, "profile": "developer-dry-run"},
                    policies={
                        "artifactBaseUri": "https://downloads.crypta.invalid/candidate/",
                        "catalogChannel": "beta",
                    },
                    requirements={"liveNetwork": True, "sandboxProviderTests": True},
                    execution={
                        "fixtureEvidence": True,
                        "skipGradle": True,
                        "skipFullBuild": True,
                        "timeoutSeconds": 75,
                    },
                    commands={
                        "production-beta": {
                            "args": [
                                "--previous-summary",
                                "unsafe-v1.json",
                                "--multi-node-mode",
                                "simulated",
                            ]
                        }
                    },
                ),
                root,
                output,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                return 0

            with mock.patch.object(production_beta_release, "main", side_effect=run):
                legacy._run_production_beta(context)

            self.assertEqual("candidate-id", captured[captured.index("--release-id") + 1])
            self.assertEqual("beta", captured[captured.index("--catalog-channel") + 1])
            self.assertEqual(
                "https://downloads.crypta.invalid/candidate/",
                captured[captured.index("--artifact-base-uri") + 1],
            )
            for option in (
                "--require-live-network",
                "--require-sandbox-provider-tests",
                "--use-fixture-evidence",
                "--skip-gradle",
                "--skip-full-build",
            ):
                self.assertIn(option, captured)
            self.assertEqual("75", captured[captured.index("--timeout-seconds") + 1])
            self.assertNotIn("unsafe-v1.json", captured)
            self.assertEqual("simulated", captured[captured.index("--multi-node-mode") + 1])

    def test_dashboard_and_stable_adapters_propagate_summary_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_kinds = {
                "production.json": "production-beta-release",
                "dashboard.json": "production-beta-go-no-go",
                "certification.json": "release-certification",
            }
            for name, kind in input_kinds.items():
                write_json(
                    root / name,
                    EvidenceEnvelope(
                        kind=kind,
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "self-test",
                            "profile": "pr",
                            "component": kind,
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": None,
                            "exitCode": 0,
                        },
                        counts={
                            "evidence": 0,
                            "blockers": 0,
                            "warnings": 0,
                            "waivers": 0,
                        },
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
                    ).to_json(),
                )
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={
                        "productionBeta": "production.json",
                        "goNoGo": "dashboard.json",
                        "releaseCertification": "certification.json",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            dashboard_context = prepare_context(root, manifest, "go-no-go")
            stable_context = prepare_context(root, manifest, "stable-readiness")
            dashboard_args: list[str] = []
            stable_args: list[str] = []
            with mock.patch.object(
                production_beta_go_no_go_dashboard,
                "main",
                side_effect=lambda args: dashboard_args.extend(args) or 0,
            ):
                legacy._run_go_no_go(dashboard_context)
            with mock.patch.object(
                stable_1_0_readiness,
                "main",
                side_effect=lambda args: stable_args.extend(args) or 0,
            ):
                legacy._run_stable_readiness(stable_context)
            self.assertIn("--production-beta-summary", dashboard_args)
            self.assertIn("--release-certification-summary", dashboard_args)
            self.assertIn("--production-beta-summary", stable_args)
            self.assertIn("--go-no-go-summary", stable_args)
            self.assertIn("--release-certification-summary", stable_args)


class WorkflowIntegrationTest(unittest.TestCase):
    def test_workflows_delimit_jq_arguments_and_publish_dashboard_artifacts(self) -> None:
        root = workspace_root()
        production = (root / ".github/workflows/production-beta-release.yml").read_text(
            encoding="utf-8"
        )
        release = (root / ".github/workflows/release-certification.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(2, production.count('-- "${args[@]}" > "$manifest"'))
        self.assertNotIn("$ARGS.positional", release)
        self.assertIn("releaseHistory: $release_history", release)
        self.assertIn('if [[ -f "build/interop-smoke/summary.json" ]]', release)
        self.assertIn('if [[ -f "build/interop-extended/summary.json" ]]', release)
        self.assertIn('if [[ -f "build/perf-smoke/summary.json" ]]', release)
        self.assertIn("interopSmoke: $interop_smoke", release)
        self.assertIn("interopExtended: $interop_extended", release)
        self.assertIn("performanceSmoke: $performance_smoke", release)
        self.assertNotIn(
            'interopSmoke: "build/interop-smoke/summary.json"',
            release,
        )
        self.assertNotIn(
            'performanceSmoke: "build/perf-smoke/summary.json"',
            release,
        )
        self.assertIn(
            'if [[ -n "$PREVIOUS_SUMMARY_PATH" && -z "$CANDIDATE_RELEASE_ID" ]]',
            release,
        )
        self.assertIn(
            "candidate-release-id is required when previous-summary-path is supplied.",
            release,
        )
        self.assertIn(
            'if [[ -n "$STABLE_READINESS_SUMMARY_PATH" && -z "$CANDIDATE_RELEASE_ID" ]]',
            release,
        )
        self.assertIn(
            "candidate-release-id is required when stable-readiness-summary-path is supplied.",
            release,
        )
        self.assertLess(
            release.index("candidate-release-id is required when previous-summary-path is supplied."),
            release.index('release_id="${CANDIDATE_RELEASE_ID:-ci-${GITHUB_RUN_ID}'),
        )
        self.assertLess(
            release.index(
                "candidate-release-id is required when stable-readiness-summary-path is supplied."
            ),
            release.index('release_id="${CANDIDATE_RELEASE_ID:-ci-${GITHUB_RUN_ID}'),
        )
        dashboard_redaction = (
            "*/production-beta/artifacts/legacy/reports/go-no-go-redaction-report.json"
        )
        dashboard_report = "*/production-beta/artifacts/legacy/reports/go-no-go-dashboard.md"
        self.assertEqual(2, production.count(dashboard_redaction))
        self.assertEqual(2, production.count(dashboard_report))
        self.assertNotIn('glob("*/production-beta/redaction-report.json")', production)
        self.assertNotIn("-path '*/production-beta/report.md'", production)
        self.assertIn("candidate_release_id:", production)
        self.assertEqual(
            2,
            production.count(
                "INPUT_CANDIDATE_RELEASE_ID: ${{ inputs.candidate_release_id || '' }}"
            ),
        )
        self.assertIn('release_id="$INPUT_CANDIDATE_RELEASE_ID"', production)
        self.assertNotIn('release_id="cryptad-beta-${GITHUB_RUN_ID}', production)
        self.assertIn('-n "$INPUT_MULTI_NODE_SOAK_SUMMARY"', production)
        self.assertIn('-n "$INPUT_SECURITY_DRILLS_SUMMARY"', production)
        self.assertIn(
            "candidate_release_id is required when previous_summary, previous_release_certification_summary, multi_node_soak_summary, or security_drills_summary is supplied.",
            production,
        )
        self.assertIn(
            'require_history="$([[ -n "$INPUT_PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" ]]',
            production,
        )
        self.assertNotIn(
            'require_history="$([[ "$mode" != "developer-dry-run"',
            production,
        )
        self.assertIn('if [[ -f "build/interop-smoke/summary.json" ]]', production)
        self.assertIn('if [[ -f "build/perf-smoke/summary.json" ]]', production)
        self.assertIn(
            'if $interop_smoke == "" then {} else {interopSmoke: $interop_smoke} end',
            production,
        )
        self.assertIn(
            'if $performance_smoke == "" then {} else {performanceSmoke: $performance_smoke} end',
            production,
        )
        self.assertNotIn(
            'inputs: ({interopSmoke: "build/interop-smoke/summary.json", performanceSmoke: "build/perf-smoke/summary.json"}',
            production,
        )

    def test_release_workflow_skill_uses_only_unified_cli_options(self) -> None:
        root = workspace_root()
        release_skill = (root / ".agents/skills/cryptad-release-workflow/SKILL.md").read_text(
            encoding="utf-8"
        )
        forbidden = (
            "--out-dir",
            "--mode release-candidate",
            "--mode production-beta",
            "--catalog-channel",
            "--artifact-base-uri",
            "--require-live-network",
            "--require-multi-node-soak",
            "--require-sandbox-provider-tests",
        )
        for option in forbidden:
            with self.subTest(option=option):
                self.assertNotIn(option, release_skill)

        self.assertIn(
            "build/release-certification/<release-id>/release-certification/summary.json",
            release_skill,
        )
        self.assertIn("multi-node-beta/run/summary.json", release_skill)
        self.assertNotIn(
            "build/release-certification/release-certification-summary.json",
            release_skill,
        )

        for command in ("release-certification", "production-beta"):
            with self.subTest(command=command):
                args = cli.build_parser().parse_args(
                    [
                        command,
                        "--manifest",
                        f"tools/release-certification/manifests/{'release-candidate' if command == 'release-certification' else 'production-beta'}.example.json",
                        "--workspace-root",
                        ".",
                    ]
                )
                self.assertEqual(command, args.command)


if __name__ == "__main__":
    unittest.main()
