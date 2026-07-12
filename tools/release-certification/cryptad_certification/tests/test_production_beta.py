"""Characterization suite for the production-beta pipeline."""

from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import legacy
from cryptad_certification.engines import production_beta_release
from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.legacy import execute as execute_engine
from cryptad_certification.manifest import load_manifest
from cryptad_certification.tests.support import workspace_root, write_manifest
from cryptad_certification.workspace import prepare_context, prepare_run_root


class ProductionBetaCharacterizationTest(unittest.TestCase):
    def test_existing_production_beta_scenarios(self) -> None:
        production_beta_release.run_self_test()

    def test_unified_adapter_uses_the_production_output_sentinel(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="certify-production-", dir=build_dir) as directory:
            output_root = Path(directory)
            manifest_path = write_manifest(
                output_root,
                release={
                    "id": "self-test-production",
                    "version": None,
                    "profile": "developer-dry-run",
                },
                policies={"catalogChannel": "stable"},
                execution={
                    "fixtureEvidence": True,
                    "skipGradle": True,
                    "skipFullBuild": True,
                },
            )
            manifest = load_manifest(manifest_path, root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")

            self.assertEqual(0, execute_engine(context, "production-beta"))

            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual(2, summary["schemaVersion"])
            self.assertEqual("production-beta-release", summary["kind"])
            self.assertEqual("self-test-production", summary["subject"]["releaseId"])
            self.assertEqual(
                "self-test-production",
                summary["payload"]["legacy"]["releaseId"],
            )
            self.assertEqual(
                summary["payload"]["legacy"]["version"],
                summary["subject"]["version"],
            )
            self.assertEqual("pass", summary["redaction"]["status"])
            self.assertEqual(
                summary["payload"]["legacy"]["goNoGo"]["decision"],
                summary["result"]["decision"],
            )
            self.assertTrue(
                (
                    context.component_dir
                    / "artifacts/legacy/.cryptad-production-beta-release-output"
                ).is_file()
            )

    def test_unified_adapter_stages_an_external_production_output_root(self) -> None:
        with (
            tempfile.TemporaryDirectory() as workspace_directory,
            tempfile.TemporaryDirectory() as output_directory,
        ):
            root = Path(workspace_directory)
            output_root = Path(output_directory)
            manifest = load_manifest(write_manifest(root), root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured_out: list[Path] = []

            def run(arguments: list[str]) -> int:
                engine_out = Path(arguments[arguments.index("--out-dir") + 1])
                captured_out.append(engine_out)
                write_json(
                    engine_out / "reports/production-beta-summary.json",
                    {
                        "generatedAt": "2026-01-01T00:00:00Z",
                        "releaseId": "self-test-release",
                        "version": "self-test",
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                write_text(
                    engine_out / "reports/production-beta-summary.md",
                    "# Production beta",
                )
                write_text(
                    engine_out / ".cryptad-production-beta-release-output",
                    "Crypta production beta release output directory.",
                )
                return 0

            with mock.patch.object(production_beta_release, "main", side_effect=run):
                self.assertEqual(0, execute_engine(context, "production-beta"))

            self.assertEqual(1, len(captured_out))
            self.assertTrue(captured_out[0].resolve().is_relative_to(root.resolve()))
            self.assertFalse(captured_out[0].exists())
            public_out = context.component_dir / "artifacts/legacy"
            self.assertFalse(public_out.resolve().is_relative_to(root.resolve()))
            self.assertTrue(
                (public_out / "reports/production-beta-summary.json").is_file()
            )
            self.assertTrue(
                (public_out / ".cryptad-production-beta-release-output").is_file()
            )

    def test_unified_adapter_rejects_a_symlinked_production_output(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with (
            tempfile.TemporaryDirectory(prefix="certify-production-", dir=build_dir) as output,
            tempfile.TemporaryDirectory(prefix="production-beta-target-", dir=build_dir) as target,
        ):
            output_root = Path(output)
            target_dir = Path(target)
            preserved = target_dir / "keep.json"
            write_json(preserved, {"preserved": True})
            manifest = load_manifest(write_manifest(output_root), root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            public_out = context.component_dir / "artifacts/legacy"
            try:
                public_out.symlink_to(target_dir, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(production_beta_release, "main") as engine:
                with self.assertRaisesRegex(
                    ValueError,
                    "production output path contains a symlink",
                ):
                    legacy._run_production_beta(context)

            engine.assert_not_called()
            self.assertEqual({"preserved": True}, read_json(preserved))

    def test_production_manifest_binds_required_third_party_intake(self) -> None:
        manifest = read_json(
            workspace_root()
            / "tools/release-certification/manifests/production-beta.example.json"
        )

        self.assertIsInstance(manifest, dict)
        self.assertIsInstance(manifest.get("requirements"), dict)
        self.assertIsInstance(manifest.get("inputs"), dict)
        self.assertIs(True, manifest["requirements"]["thirdPartyIntake"])
        self.assertEqual("REPLACE_ME.json", manifest["inputs"]["thirdPartyIntake"])

    def test_required_live_evidence_is_collected_and_bound_to_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                require_live_network=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            app_platform_args = captured["app-platform-smoke"]
            self.assertIn("--skip-gradle", app_platform_args)
            live_args = captured["live-network-beta-smoke"]
            self.assertIn("live-network-beta", live_args)
            self.assertIn("--require", live_args)
            certification_args = captured["release-certification"]
            self.assertNotIn("--require-history", certification_args)
            self.assertIn("--require-live-network-beta", certification_args)
            live_summary_index = certification_args.index("--live-network-summary")
            self.assertEqual(
                cert_out / "live-network-beta-smoke/summary.json",
                Path(certification_args[live_summary_index + 1]),
            )

    def test_attached_optional_live_evidence_is_enabled_without_becoming_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            attached_summary = workspace / "evidence/live-network-summary.json"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                live_network_summary=attached_summary,
                require_live_network=False,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(
                production_beta_release,
                "run_command",
                side_effect=run_command,
            ):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertNotIn("live-network-beta-smoke", captured)
            certification_args = captured["release-certification"]
            self.assertIn("--live-network-beta", certification_args)
            self.assertNotIn("--require-live-network-beta", certification_args)
            live_summary_index = certification_args.index("--live-network-summary")
            self.assertEqual(
                attached_summary,
                Path(certification_args[live_summary_index + 1]),
            )

    def test_strict_app_platform_collection_runs_gradle_sign_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            for mode in ("release-candidate", "production-beta"):
                with self.subTest(mode=mode):
                    settings = dataclasses.replace(
                        production_beta_release.cleanup_test_settings(workspace, out_dir),
                        mode=mode,
                        skip_gradle=False,
                        use_fixture_evidence=False,
                    )
                    state = production_beta_release.PipelineState(
                        settings,
                        "self-test",
                        production_beta_release.utc_now(),
                        [],
                        [],
                        [],
                    )
                    captured: dict[str, list[str]] = {}

                    def run_command(
                        pipeline_state: object,
                        name: str,
                        args: list[str],
                        **kwargs: object,
                    ) -> production_beta_release.CommandResult:
                        del pipeline_state, kwargs
                        captured[name] = list(args)
                        return production_beta_release.CommandResult(
                            name, list(args), 0, 1, "", ""
                        )

                    with mock.patch.object(
                        production_beta_release,
                        "run_command",
                        side_effect=run_command,
                    ):
                        production_beta_release.run_release_certification(
                            state, {}, cert_out
                        )

                    app_platform_args = captured["app-platform-smoke"]
                    self.assertEqual(
                        "release-candidate",
                        app_platform_args[app_platform_args.index("--mode") + 1],
                    )
                    self.assertNotIn("--skip-gradle", app_platform_args)

    def test_strict_app_platform_collection_honors_configured_gradle_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                skip_gradle=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertIn("--skip-gradle", captured["app-platform-smoke"])

    def test_release_candidate_requires_history_only_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                require_history=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(
                production_beta_release,
                "run_command",
                side_effect=run_command,
            ):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertIn("--require-history", captured["release-certification"])

    def test_generated_stable_multi_node_extract_uses_custom_release_id(self) -> None:
        custom_release_id = "cryptad-candidate-custom"
        summary = {
            "status": "pass",
            "currentCandidate": {"version": "3"},
        }

        stable_summary = production_beta_release.stable_readiness_soak_summary(
            summary,
            release_id=custom_release_id,
        )

        self.assertEqual(custom_release_id, stable_summary["releaseId"])
        self.assertEqual(
            [("releaseId", custom_release_id)],
            production_beta_release.stable_1_0_readiness.multi_node_candidate_release_ids(
                stable_summary
            ),
        )

    def test_release_candidate_collects_multi_node_soak_with_default_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                run_multi_node_soak=True,
                multi_node_soak_config=None,
                multi_node_soak_summary=None,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            multi_node_args = captured["multi-node-beta-soak"]
            self.assertIn("multi-node-beta", multi_node_args)
            self.assertIn("run", multi_node_args)
            self.assertNotIn("--config", multi_node_args)
            certification_args = captured["release-certification"]
            summary_index = certification_args.index("--multi-node-soak-summary")
            self.assertEqual(
                cert_out / "multi-node-beta-soak/summary.json",
                Path(certification_args[summary_index + 1]),
            )

    def test_required_live_multi_node_collection_requires_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            topology = workspace / "live-topology.json"
            config = production_beta_release.multi_node_beta_soak.load_config(None)
            config["mode"] = "live"
            write_json(topology, config)
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                run_multi_node_soak=True,
                require_multi_node_soak=True,
                multi_node_soak_config=topology,
                multi_node_soak_summary=None,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            multi_node_args = captured["multi-node-beta-soak"]
            self.assertIn("--require-all-scenarios", multi_node_args)
            self.assertIn("--require-live", multi_node_args)
