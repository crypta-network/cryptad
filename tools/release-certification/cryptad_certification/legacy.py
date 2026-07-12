"""Adapters from the established gate engines to the v2 command surface."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

from .envelope import from_legacy, validate_envelope, write_envelope
from .io import read_json, write_json
from .models import RunContext
from .workspace import _require_confined_directory, relative_to_run

KIND_BY_COMMAND = {
    "app-platform": "app-platform-smoke",
    "app-platform-docs": "app-platform-docs",
    "network-scale-soak": "network-scale-soak",
    "live-network-beta": "live-network-beta-smoke",
    "multi-node-beta": "multi-node-beta-soak",
    "security-response": "production-security-response",
    "release-certification": "release-certification",
    "production-beta": "production-beta-release",
    "go-no-go": "production-beta-go-no-go",
    "stable-readiness": "stable-1.0-readiness",
}
V2_KIND_BY_INPUT = {
    "appPlatform": "app-platform-smoke",
    "goNoGo": "production-beta-go-no-go",
    "liveNetwork": "live-network-beta-smoke",
    "multiNodeSoak": "multi-node-beta-soak",
    "networkScaleSoak": "network-scale-soak",
    "productionBeta": "production-beta-release",
    "releaseCertification": "release-certification",
    "securityDrills": "production-security-response",
    "stableReadiness": "stable-1.0-readiness",
}
COMMON_CONTROLLED_VALUE_OPTIONS = {"--workspace-root", "--out-dir", "--mode", "--release-id"}
STRUCTURED_VALUE_OPTIONS = {
    "multi-node-beta": {
        "--config",
        "--out",
        "--report",
    },
    "security-response": {
        "--out",
        "--release-notes-out",
        "--summary-out",
    },
    "release-certification": {
        "--app-platform-summary",
        "--history-dir",
        "--history-label",
        "--interop-extended-summary",
        "--interop-smoke-summary",
        "--live-network-summary",
        "--metadata",
        "--multi-node-soak-summary",
        "--network-scale-soak-summary",
        "--perf-smoke-summary",
        "--previous-summary",
        "--security-drills-summary",
        "--stable-readiness-summary",
        "--waiver-file",
    },
    "production-beta": {
        "--artifact-base-uri",
        "--catalog-channel",
        "--interop-extended-summary",
        "--interop-smoke-summary",
        "--live-network-summary",
        "--multi-node-soak-config",
        "--multi-node-soak-summary",
        "--network-scale-soak-summary",
        "--perf-smoke-summary",
        "--previous-release-certification-summary",
        "--previous-summary",
        "--security-drills-summary",
        "--stable-known-limitations",
        "--stable-readiness-policy",
        "--stable-readiness-waivers",
        "--third-party-intake-summary",
        "--timeout-seconds",
        "--waiver-file",
    },
    "go-no-go": {
        "--app-platform-summary",
        "--ecosystem-matrix",
        "--live-network-summary",
        "--multi-node-beta-soak-summary",
        "--network-scale-soak-summary",
        "--production-beta-summary",
        "--release-certification-summary",
        "--security-drills-summary",
        "--stable-readiness-summary",
        "--waivers",
    },
    "stable-readiness": {
        "--app-platform-summary",
        "--ecosystem-matrix",
        "--go-no-go-summary",
        "--multi-node-beta-soak-summary",
        "--network-scale-soak-summary",
        "--policy",
        "--production-beta-summary",
        "--public-beta-known-issues",
        "--release-certification-summary",
        "--security-drills-summary",
        "--stable-known-limitations",
        "--waivers",
    },
}
STRUCTURED_FLAG_OPTIONS = {
    "release-certification": {
        "--live-network-beta",
        "--require-history",
        "--require-live-network-beta",
        "--require-multi-node-soak",
        "--require-stable-readiness",
        "--skip-git-metadata",
        "--write-history",
    },
    "production-beta": {
        "--allow-dirty-workspace",
        "--allow-test-signing-in-production",
        "--emergency-skip-build",
        "--emergency-skip-live-network",
        "--generate-stable-readiness",
        "--require-history",
        "--require-live-network",
        "--require-multi-node-soak",
        "--require-sandbox-provider-tests",
        "--require-stable-readiness",
        "--require-third-party-intake",
        "--run-multi-node-soak",
        "--run-third-party-intake-sample-flow",
        "--skip-full-build",
        "--skip-gradle",
        "--use-fixture-evidence",
    },
    "go-no-go": {"--require-stable-readiness"},
}


def _config(context: RunContext, command: str) -> dict[str, Any]:
    value = context.manifest.commands.get(command, {})
    return value if isinstance(value, dict) else {}


def _args(context: RunContext, command: str) -> list[str]:
    value = _config(context, command).get("args", [])
    raw = list(value) if isinstance(value, list) else []
    controlled_values = COMMON_CONTROLLED_VALUE_OPTIONS | STRUCTURED_VALUE_OPTIONS.get(command, set())
    controlled_flags = STRUCTURED_FLAG_OPTIONS.get(command, set())
    controlled_options = controlled_values | controlled_flags
    filtered: list[str] = []
    skip_value = False
    for argument in raw:
        if skip_value:
            skip_value = False
            continue
        option = argument.partition("=")[0]
        if (
            option.startswith("--")
            and option not in controlled_options
            and any(controlled.startswith(option) for controlled in controlled_options)
        ):
            raise ValueError(
                f"commands.{command}.args contains an abbreviated controlled option: {option}"
            )
        if argument in controlled_values:
            skip_value = True
            continue
        if argument in controlled_flags:
            continue
        if any(argument.startswith(f"{option}=") for option in controlled_values):
            continue
        filtered.append(argument)
    return filtered


def _mode(context: RunContext, command: str) -> str:
    profile = context.manifest.release.profile
    if command in {"app-platform", "live-network-beta"}:
        expected = "nightly" if profile == "nightly" else "release-candidate" if profile in {
            "release-candidate", "production-beta", "stable-review"
        } else "pr"
    elif command == "release-certification":
        if profile == "nightly":
            expected = "nightly"
        else:
            expected = "release-candidate" if profile in {
                "release-candidate", "production-beta", "stable-review"
            } else "pr"
    elif command in {"production-beta", "go-no-go"}:
        expected = profile if profile in {
            "developer-dry-run", "release-candidate", "production-beta"
        } else "developer-dry-run"
    else:
        expected = profile
    configured = _config(context, command).get("mode")
    if isinstance(configured, str) and configured and configured != expected:
        raise ValueError(
            f"commands.{command}.mode cannot override release.profile {profile}; "
            f"expected {expected}"
        )
    return expected


def _legacy_dir(context: RunContext) -> Path:
    path = context.component_dir / "artifacts" / "legacy"
    _require_confined_directory(path, context.run_root, "legacy output")
    path.mkdir(parents=True, exist_ok=True)
    _require_confined_directory(path, context.run_root, "legacy output")
    return path


def _resolve_input_path(context: RunContext, key: str) -> Path | None:
    raw = context.manifest.inputs.get(key)
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = context.workspace_root / path
    return path.resolve()


def _legacy_input_path(
    context: RunContext,
    key: str,
    *,
    migrated_kind: str | None = None,
) -> Path | None:
    """Resolve an input and unwrap a candidate-bound v2 envelope for a legacy engine."""

    path = _resolve_input_path(context, key)
    if path is None:
        return None
    expected_kind = (
        f"migrated-v1-{migrated_kind}"
        if migrated_kind is not None
        else V2_KIND_BY_INPUT.get(key)
    )
    value = read_json(path)
    if not isinstance(value, dict):
        if migrated_kind is not None:
            raise ValueError(f"inputs.{key} must be a migrated v2 evidence envelope")
        if expected_kind is not None:
            raise ValueError(
                f"inputs.{key} must be a v2 {expected_kind} evidence envelope"
            )
        return path
    if value.get("schemaVersion") != 2:
        if migrated_kind is not None:
            raise ValueError(
                f"inputs.{key} must use migrate-v1 {migrated_kind} before normal consumption"
            )
        if expected_kind is not None:
            raise ValueError(
                f"inputs.{key} must be a v2 {expected_kind} evidence envelope"
            )
        return path
    if expected_kind is None:
        raise ValueError(f"inputs.{key} does not accept a v2 evidence envelope")
    validate_envelope(value, expected_kind, context.manifest.release.release_id)
    status = value["result"]["status"]
    if (
        value["result"]["exitCode"] != 0
        or value["redaction"]["status"] != "pass"
        or status == "fail"
    ):
        raise ValueError(f"inputs.{key} v2 envelope failed result or redaction validation")
    if migrated_kind is not None and status != "pass":
        raise ValueError(f"inputs.{key} migrated v2 envelope must have passing status")
    payload = value.get("payload")
    legacy = payload.get("legacy") if isinstance(payload, dict) else None
    if not isinstance(legacy, dict):
        raise ValueError(f"inputs.{key} v2 envelope is missing payload.legacy")
    extracted = context.component_dir / "artifacts" / "inputs" / f"{key}.json"
    write_json(extracted, legacy)
    if key == "securityDrills":
        _copy_security_drill_artifacts(path, legacy, extracted.parent)
    return extracted


def _copy_security_drill_artifacts(
    envelope_path: Path,
    legacy_summary: dict[str, Any],
    target_dir: Path,
) -> None:
    """Copy the public drill files referenced by a reusable security envelope."""

    artifacts = legacy_summary.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("inputs.securityDrills payload.legacy.artifacts must be an array")
    source_dir = envelope_path.parent / "artifacts"
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise ValueError("inputs.securityDrills v2 envelope artifact directory is missing or unsafe")
    resolved_source_dir = source_dir.resolve()
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            raise ValueError(
                f"inputs.securityDrills artifact entry {index} must be an object"
            )
        artifact_name = entry.get("artifact")
        if (
            not isinstance(artifact_name, str)
            or not artifact_name
            or Path(artifact_name).name != artifact_name
            or not artifact_name.endswith(".json")
        ):
            raise ValueError(
                f"inputs.securityDrills artifact entry {index} has an unsafe file name"
            )
        source = source_dir / artifact_name
        if source.is_symlink() or not source.is_file():
            raise ValueError(
                f"inputs.securityDrills referenced artifact is missing or unsafe: {artifact_name}"
            )
        try:
            source.resolve().relative_to(resolved_source_dir)
        except ValueError as exc:
            raise ValueError(
                f"inputs.securityDrills artifact escapes its envelope: {artifact_name}"
            ) from exc
        target = target_dir / artifact_name
        if target.is_symlink():
            raise ValueError(
                f"inputs.securityDrills extraction target is unsafe: {artifact_name}"
            )
        shutil.copy2(source, target)


def _option_path(args: list[str], option: str, path: Path | None) -> None:
    if path is not None:
        args.extend([option, str(path)])


def _flag(args: list[str], enabled: Any, option: str) -> None:
    if enabled is True:
        args.append(option)


def _missing_input(context: RunContext, name: str) -> Path:
    """Return a candidate-scoped path that is deliberately never created."""

    return context.component_dir / "artifacts" / "missing-inputs" / f"{name}.json"


def _run_app_platform(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import app_platform_smoke as engine

    out = _legacy_dir(context)
    mode = _mode(context, "app-platform")
    args = ["--workspace-root", str(context.workspace_root), "--out-dir", str(out), "--mode", mode]
    skip_gradle = (
        mode == "pr"
        or context.manifest.execution.get("skipGradle") is True
    )
    _flag(args, skip_gradle, "--skip-gradle")
    args.extend(_args(context, "app-platform"))
    code = int(engine.main(args))
    return code, out / "summary.json", out / "app-platform-smoke-report.md"


def _run_app_platform_docs(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import app_platform_docs_check as engine

    out = _legacy_dir(context) / "summary.json"
    value = engine.safe_summary_for_output(engine.run_check(context.workspace_root))
    write_json(out, value)
    return (0 if value.get("status") == "pass" else 1), out, None


def _run_network_scale(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import network_scale_soak as engine

    out = _legacy_dir(context) / "summary.json"
    value = engine.summary_for_release(context.manifest.release.release_id)
    write_json(out, value)
    return 0, out, None


def _run_live_network(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import live_network_beta_smoke as engine

    out = _legacy_dir(context)
    mode = _mode(context, "live-network-beta")
    args = [
        "--workspace-root",
        str(context.workspace_root),
        "--out-dir",
        str(out),
        "--mode",
        mode,
    ]
    _flag(args, context.manifest.requirements.get("liveNetwork"), "--require")
    args.extend(_args(context, "live-network-beta"))
    code = int(engine.main(args))
    return code, out / "summary.json", out / "live-network-beta-smoke-report.md"


def _run_release_certification(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import release_certification as engine

    out = _legacy_dir(context)
    args = ["--workspace-root", str(context.workspace_root), "--out-dir", str(out), "--mode", _mode(context, "release-certification")]
    candidates = {
        "interopSmoke": _missing_input(context, "interop-smoke"),
        "interopExtended": _missing_input(context, "interop-extended"),
        "performanceSmoke": _missing_input(context, "performance-smoke"),
        "appPlatform": context.run_root / "app-platform" / "artifacts" / "legacy-summary.json",
        "liveNetwork": context.run_root / "live-network-beta" / "artifacts" / "legacy-summary.json",
        "networkScaleSoak": context.run_root / "network-scale-soak" / "artifacts" / "legacy-summary.json",
        "multiNodeSoak": context.run_root / "multi-node-beta" / "run" / "artifacts" / "legacy-summary.json",
        "securityDrills": context.run_root / "security-response" / "drill-verify-all" / "artifacts" / "legacy-summary.json",
        "stableReadiness": context.run_root / "stable-readiness" / "artifacts" / "legacy-summary.json",
    }
    options = {
        "interopSmoke": "--interop-smoke-summary",
        "interopExtended": "--interop-extended-summary",
        "performanceSmoke": "--perf-smoke-summary",
        "appPlatform": "--app-platform-summary",
        "liveNetwork": "--live-network-summary",
        "networkScaleSoak": "--network-scale-soak-summary",
        "multiNodeSoak": "--multi-node-soak-summary",
        "securityDrills": "--security-drills-summary",
        "stableReadiness": "--stable-readiness-summary",
    }
    for key, option in options.items():
        supplied = _legacy_input_path(context, key)
        path = supplied or candidates[key]
        if key != "stableReadiness" or supplied is not None or context.manifest.requirements.get("stableReadiness") is True:
            args.extend([option, str(path)])

    history = _legacy_input_path(context, "releaseHistory", migrated_kind="release-history")
    if history is not None:
        history_value = read_json(history)
        history_error = engine.previous_summary_contract_error(history_value or {})
        if history_error:
            raise ValueError(f"inputs.releaseHistory is invalid: {history_error}")
        args.extend(["--previous-summary", str(history)])
    elif context.manifest.requirements.get("history") is True:
        args.extend(["--previous-summary", str(_missing_input(context, "release-history"))])

    history_dir = context.manifest.policies.get("historyDir")
    history_path = Path(history_dir) if isinstance(history_dir, str) else context.run_root / "history"
    if not history_path.is_absolute():
        history_path = context.workspace_root / history_path
    args.extend(["--history-dir", str(history_path.resolve())])
    if context.manifest.requirements.get("history") is True:
        args.append("--require-history")
    if context.manifest.requirements.get("liveNetwork") is True:
        args.append("--live-network-beta")
        args.append("--require-live-network-beta")
    elif _resolve_input_path(context, "liveNetwork") is not None or context.manifest.execution.get("collectLiveNetwork") is True:
        args.append("--live-network-beta")
    if context.manifest.requirements.get("multiNodeSoak") is True:
        args.append("--require-multi-node-soak")
    if context.manifest.requirements.get("stableReadiness") is True:
        args.append("--require-stable-readiness")
    _option_path(args, "--waiver-file", _resolve_input_path(context, "waiverFile"))
    _flag(args, context.manifest.execution.get("writeHistory"), "--write-history")
    _flag(args, context.manifest.execution.get("skipGitMetadata"), "--skip-git-metadata")
    history_label = context.manifest.policies.get("historyLabel")
    if isinstance(history_label, str):
        args.extend(["--history-label", history_label])
    metadata = context.manifest.policies.get("metadata")
    if isinstance(metadata, dict):
        for key, value in sorted(metadata.items()):
            args.extend(["--metadata", f"{key}={value}"])
    args.extend(_args(context, "release-certification"))
    code = int(engine.main(args))
    return code, out / "release-certification-summary.json", out / "release-certification-report.md"


def _run_production_beta(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import production_beta_release as engine

    # Unlike the other engines, the production pipeline owns creation of its output directory and
    # writes its cleanup sentinel there. Its legacy safety boundary requires that directory to be
    # inside the source workspace, so an external unified output root is staged under build/ and
    # copied into the already confined release workspace after the engine finishes.
    public_out = context.component_dir / "artifacts" / "legacy"
    args = [
        "--mode",
        _mode(context, "production-beta"),
        "--release-id",
        context.manifest.release.release_id,
    ]
    catalog_channel = context.manifest.policies.get("catalogChannel")
    if isinstance(catalog_channel, str):
        args.extend(["--catalog-channel", catalog_channel])
    artifact_base_uri = context.manifest.policies.get("artifactBaseUri")
    if isinstance(artifact_base_uri, str):
        args.extend(["--artifact-base-uri", artifact_base_uri])

    _flag(args, context.manifest.requirements.get("liveNetwork"), "--require-live-network")
    _flag(args, context.manifest.requirements.get("history"), "--require-history")
    _flag(args, context.manifest.requirements.get("multiNodeSoak"), "--require-multi-node-soak")
    _flag(
        args,
        context.manifest.requirements.get("sandboxProviderTests"),
        "--require-sandbox-provider-tests",
    )
    _flag(
        args,
        context.manifest.requirements.get("thirdPartyIntake"),
        "--require-third-party-intake",
    )
    _flag(args, context.manifest.requirements.get("stableReadiness"), "--require-stable-readiness")

    previous_candidate = _legacy_input_path(
        context,
        "previousCandidate",
        migrated_kind="previous-candidate",
    )
    release_history = _legacy_input_path(
        context,
        "releaseHistory",
        migrated_kind="release-history",
    )
    multi_node_summary = _legacy_input_path(context, "multiNodeSoak")
    _option_path(args, "--interop-smoke-summary", _legacy_input_path(context, "interopSmoke"))
    _option_path(args, "--interop-extended-summary", _legacy_input_path(context, "interopExtended"))
    _option_path(args, "--perf-smoke-summary", _legacy_input_path(context, "performanceSmoke"))
    _option_path(args, "--live-network-summary", _legacy_input_path(context, "liveNetwork"))
    _option_path(
        args,
        "--network-scale-soak-summary",
        _legacy_input_path(context, "networkScaleSoak"),
    )
    _option_path(args, "--previous-summary", previous_candidate)
    _option_path(args, "--previous-release-certification-summary", release_history)
    _option_path(args, "--multi-node-soak-summary", multi_node_summary)
    _option_path(args, "--multi-node-soak-config", _resolve_input_path(context, "multiNodeSoakConfig"))
    _option_path(args, "--third-party-intake-summary", _legacy_input_path(context, "thirdPartyIntake"))
    _option_path(args, "--security-drills-summary", _legacy_input_path(context, "securityDrills"))
    _option_path(args, "--waiver-file", _resolve_input_path(context, "waiverFile"))
    _option_path(args, "--stable-readiness-policy", _resolve_input_path(context, "stableReadinessPolicy"))
    _option_path(args, "--stable-known-limitations", _resolve_input_path(context, "stableKnownLimitations"))
    _option_path(args, "--stable-readiness-waivers", _resolve_input_path(context, "stableReadinessWaivers"))

    run_multi_node = context.manifest.execution.get("runMultiNodeSoak") is True or (
        context.manifest.requirements.get("multiNodeSoak") is True and multi_node_summary is None
    )
    _flag(args, run_multi_node, "--run-multi-node-soak")
    _flag(
        args,
        context.manifest.execution.get("runThirdPartyIntakeSampleFlow"),
        "--run-third-party-intake-sample-flow",
    )
    generate_stable = context.manifest.execution.get("generateStableReadiness") is True or (
        context.manifest.requirements.get("stableReadiness") is True
    )
    _flag(args, generate_stable, "--generate-stable-readiness")
    execution_flags = {
        "fixtureEvidence": "--use-fixture-evidence",
        "skipGradle": "--skip-gradle",
        "skipFullBuild": "--skip-full-build",
        "allowDirtyWorkspace": "--allow-dirty-workspace",
        "emergencySkipLiveNetwork": "--emergency-skip-live-network",
        "emergencySkipBuild": "--emergency-skip-build",
        "allowTestSigningInProduction": "--allow-test-signing-in-production",
    }
    for key, option in execution_flags.items():
        _flag(args, context.manifest.execution.get(key), option)
    timeout = context.manifest.execution.get("timeoutSeconds")
    if isinstance(timeout, int):
        args.extend(["--timeout-seconds", str(timeout)])
    args.extend(_args(context, "production-beta"))

    staging: tempfile.TemporaryDirectory[str] | None = None
    engine_out = public_out
    if not public_out.resolve().is_relative_to(context.workspace_root):
        staging_parent = context.workspace_root / "build"
        staging_parent.mkdir(parents=True, exist_ok=True)
        staging = tempfile.TemporaryDirectory(
            prefix="cryptad-production-beta-",
            dir=staging_parent,
        )
        engine_out = Path(staging.name) / "legacy"
    args[:0] = [
        "--workspace-root",
        str(context.workspace_root),
        "--out-dir",
        str(engine_out),
    ]
    try:
        code = int(engine.main(args))
        if staging is not None:
            shutil.copytree(engine_out, public_out, symlinks=True)
    finally:
        if staging is not None:
            staging.cleanup()
    return (
        code,
        public_out / "reports" / "production-beta-summary.json",
        public_out / "reports" / "production-beta-summary.md",
    )


def _run_go_no_go(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import production_beta_go_no_go_dashboard as engine

    out = _legacy_dir(context)
    args = ["build", "--workspace-root", str(context.workspace_root), "--out-dir", str(out), "--mode", _mode(context, "go-no-go"), "--release-id", context.manifest.release.release_id]
    input_options = {
        "productionBeta": "--production-beta-summary",
        "releaseCertification": "--release-certification-summary",
        "ecosystemMatrix": "--ecosystem-matrix",
        "appPlatform": "--app-platform-summary",
        "liveNetwork": "--live-network-summary",
        "networkScaleSoak": "--network-scale-soak-summary",
        "multiNodeSoak": "--multi-node-beta-soak-summary",
        "securityDrills": "--security-drills-summary",
        "stableReadiness": "--stable-readiness-summary",
    }
    for key, option in input_options.items():
        _option_path(args, option, _legacy_input_path(context, key))
    _option_path(args, "--waivers", _resolve_input_path(context, "waiverFile"))
    _flag(args, context.manifest.requirements.get("stableReadiness"), "--require-stable-readiness")
    args.extend(_args(context, "go-no-go"))
    code = int(engine.main(args))
    return code, out / "go-no-go-dashboard.json", out / "go-no-go-dashboard.md"


def _run_stable_readiness(context: RunContext) -> tuple[int, Path, Path | None]:
    from .engines import stable_1_0_readiness as engine

    out = _legacy_dir(context)
    args = ["--workspace-root", str(context.workspace_root), "--out-dir", str(out)]
    input_options = {
        "productionBeta": "--production-beta-summary",
        "goNoGo": "--go-no-go-summary",
        "releaseCertification": "--release-certification-summary",
        "ecosystemMatrix": "--ecosystem-matrix",
        "appPlatform": "--app-platform-summary",
        "multiNodeSoak": "--multi-node-beta-soak-summary",
        "networkScaleSoak": "--network-scale-soak-summary",
        "securityDrills": "--security-drills-summary",
        "publicBetaKnownIssues": "--public-beta-known-issues",
        "stableReadinessPolicy": "--policy",
        "stableKnownLimitations": "--stable-known-limitations",
    }
    for key, option in input_options.items():
        path = (
            _resolve_input_path(context, key)
            if key in {"publicBetaKnownIssues", "stableReadinessPolicy", "stableKnownLimitations"}
            else _legacy_input_path(context, key)
        )
        _option_path(args, option, path)
    _option_path(args, "--waivers", _resolve_input_path(context, "stableReadinessWaivers"))
    args.extend(_args(context, "stable-readiness"))
    code = int(engine.main(args))
    return code, out / "stable-1.0-readiness-summary.json", out / "stable-1.0-readiness-report.md"


def _run_passthrough(context: RunContext, command: str, action: str | None) -> tuple[int, Path, Path | None]:
    engine: Any
    out = _legacy_dir(context)
    configured = _args(context, command)
    if command == "multi-node-beta":
        from .engines import multi_node_beta_soak as engine
        translated = "previous-summary-schema" if action == "schema" else str(action)
        args = [translated]
        configured_mode = _config(context, command).get("mode")
        topology_config = _resolve_input_path(context, "multiNodeSoakConfig")
        if action in {"plan", "run"}:
            _option_path(
                args,
                "--config",
                topology_config,
            )
            if isinstance(configured_mode, str):
                args.extend(["--mode", configured_mode])
        if action == "plan":
            args.extend(["--out", str(out / "plan.json")])
        elif action == "run":
            args.extend(["--out-dir", str(out)])
            if (
                context.manifest.release.profile in {"release-candidate", "production-beta", "stable-review"}
                or context.manifest.requirements.get("multiNodeSoak") is True
            ) and "--require-all-scenarios" not in configured:
                args.append("--require-all-scenarios")
            required = context.manifest.requirements.get("multiNodeSoak") is True
            topology = (
                read_json(topology_config)
                if topology_config is not None
                else engine.DEFAULT_CONFIG
            )
            topology_mode = configured_mode
            if not isinstance(topology_mode, str) and isinstance(topology, dict):
                topology_mode = topology.get("mode")
            if required and topology_mode == "live" and "--require-live" not in configured:
                args.append("--require-live")
        elif action == "previous-summary":
            args.extend(["--out", str(out / "previous-summary.json")])
            args.extend(["--report", str(out / "previous-summary.md")])
        elif action == "verify-previous-summary":
            args.extend(
                ["--report", str(out / "previous-summary-verification.md")]
            )
        elif action == "schema":
            args.extend(["--out", str(out / "previous-summary-schema.json")])
    else:
        from .engines import security_response_runbook as engine
        prefixes = {
            "verify": ["verify"],
            "drill-create": ["drill", "create"],
            "drill-verify": ["drill", "verify"],
            "drill-run-all": ["drill", "run-all"],
            "drill-verify-all": ["drill", "verify-all"],
            "advisory-template": ["advisory", "template"],
        }
        args = list(prefixes[str(action)])
        drill_mode = context.manifest.release.profile
        if drill_mode not in engine.DRILL_MODES:
            drill_mode = "release-candidate"
        if action in {"drill-create", "drill-run-all", "drill-verify-all"}:
            args.extend(
                [
                    "--release-id",
                    context.manifest.release.release_id,
                    "--mode",
                    drill_mode,
                ]
            )
        if action == "drill-create":
            args.extend(["--out", str(out / "drill.json")])
        elif action == "drill-run-all":
            args.extend(["--out-dir", str(out / "drills")])
            args.extend(["--summary-out", str(out / "summary.json")])
            args.extend(
                [
                    "--release-notes-out",
                    str(out / "security-release-notes-draft.md"),
                ]
            )
        elif action == "drill-verify-all":
            if "--input-dir" not in configured:
                args.extend(
                    [
                        "--input-dir",
                        str(
                            context.run_root
                            / "security-response/drill-run-all/artifacts/legacy/drills"
                        ),
                    ]
                )
            args.extend(["--summary-out", str(out / "summary.json")])
        elif action == "advisory-template":
            args.extend(["--out", str(out / "advisory.md")])
    args.extend(configured)
    code = int(engine.main(args))
    candidates = sorted(out.rglob("*.json"))
    if not candidates:
        value = {
            "schemaVersion": 1,
            "tool": command,
            "generatedAt": None,
            "status": "pass" if code == 0 else "fail",
            "redaction": {"status": "pass", "findings": []},
        }
        summary = _legacy_dir(context) / "summary.json"
        write_json(summary, value)
        return code, summary, None
    return code, candidates[-1], None


RUNNERS: dict[str, Callable[[RunContext], tuple[int, Path, Path | None]]] = {
    "app-platform": _run_app_platform,
    "app-platform-docs": _run_app_platform_docs,
    "network-scale-soak": _run_network_scale,
    "live-network-beta": _run_live_network,
    "release-certification": _run_release_certification,
    "production-beta": _run_production_beta,
    "go-no-go": _run_go_no_go,
    "stable-readiness": _run_stable_readiness,
}


def execute(context: RunContext, command: str, action: str | None = None) -> int:
    """Run one established engine and publish its result as a v2 envelope."""

    component_summary = context.component_dir / "summary.json"
    if component_summary.is_symlink() or component_summary.exists():
        raise ValueError(f"component already has a summary; reset the run before rerunning: {context.component}")
    if command in RUNNERS:
        code, legacy_summary_path, legacy_report_path = RUNNERS[command](context)
    elif command in {"multi-node-beta", "security-response"}:
        code, legacy_summary_path, legacy_report_path = _run_passthrough(context, command, action)
    else:
        raise ValueError(f"unsupported certification command: {command}")
    if not legacy_summary_path.is_file():
        raise ValueError(f"{command} did not write its expected summary: {legacy_summary_path}")
    legacy = read_json(legacy_summary_path)
    if not isinstance(legacy, dict):
        raise ValueError(f"{command} summary must be a JSON object")
    artifact_summary = context.component_dir / "artifacts" / "legacy-summary.json"
    write_json(artifact_summary, legacy)
    if command == "security-response" and action == "drill-verify-all":
        drill_dir = (
            context.run_root
            / "security-response/drill-run-all/artifacts/legacy/drills"
        )
        for drill in sorted(drill_dir.glob("*.json")):
            shutil.copy2(drill, artifact_summary.parent / drill.name)
    report = f"# {command}\n\nThe command completed with legacy exit code `{code}`."
    if legacy_report_path is not None and legacy_report_path.is_file():
        report = legacy_report_path.read_text(encoding="utf-8")
    artifacts = {"legacySummary": relative_to_run(artifact_summary, context)}
    result_status = None
    if command == "multi-node-beta" and action in {"plan", "schema"}:
        result_status = "pass" if code == 0 else "fail"
    envelope = from_legacy(
        context,
        KIND_BY_COMMAND[command],
        legacy,
        code,
        artifacts,
        result_status=result_status,
    )
    write_envelope(context, envelope, report)
    return int(envelope.result["exitCode"])
