"""Implementation segment for the selftest fixtures portion of ``production_beta_release.py``."""

from __future__ import annotations

def make_self_test_workspace(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns("._*", ".DS_Store", "__MACOSX", "__pycache__", "*.pyc")
    shutil.copytree(
        REPO_ROOT / "tools/release-certification",
        root / "tools/release-certification",
        ignore=ignore,
        copy_function=shutil.copy,
    )
    shutil.copytree(REPO_ROOT / "docs", root / "docs", ignore=ignore, copy_function=shutil.copy)
    shutil.copy(REPO_ROOT / "build.gradle.kts", root / "build.gradle.kts")
    write_text(root / "gradlew", "#!/usr/bin/env sh\nexit 0\n")
    (root / "gradlew").chmod(0o755)

def write_fake_crypta_app_cli(workspace: Path) -> Path:
    bin_dir = workspace / "platform-devtools/build/install/crypta-app/bin"
    cli = bin_dir / crypta_app_launcher_name()
    python_cli = bin_dir / "crypta-app.py"
    write_text(
        python_cli,
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import pathlib
            import sys


            def value(args, flag):
                return args[args.index(flag) + 1]


            args = sys.argv[1:]
            try:
                if args[:1] == ["pack"]:
                    pathlib.Path(value(args, "--output")).write_bytes(b"fixture bundle\\n")
                elif args[:2] == ["catalog", "entry"]:
                    entry_text = (
                        "entry=ok\\n"
                        + "bundle.uri=" + value(args, "--bundle-uri") + "\\n"
                        + "artifact=" + value(args, "--artifact") + "\\n"
                    )
                    for flag, key in (
                        ("--minimum-crypta-version", "minimumCryptaVersion"),
                        ("--maximum-crypta-version", "maximumCryptaVersion"),
                        ("--maintenance-owner", "maintenance.owner"),
                        ("--maintenance-owner-uri", "maintenance.ownerUri"),
                        ("--maintenance-support-level", "maintenance.supportLevel"),
                        ("--maintenance-data-schema-policy", "maintenance.dataSchemaPolicy"),
                        ("--maintenance-migration-policy", "maintenance.migrationPolicy"),
                        ("--maintenance-backup-restore", "maintenance.backupRestore"),
                        ("--maintenance-security-policy", "maintenance.securityPolicy"),
                        ("--maintenance-deprecation-policy", "maintenance.deprecationPolicy"),
                        ("--maintenance-support-uri", "maintenance.supportUri"),
                    ):
                        if flag in args:
                            entry_text += key + "=" + value(args, flag) + "\\n"
                    pathlib.Path(value(args, "--output")).write_text(
                        entry_text,
                        encoding="utf-8",
                    )
                elif args[:2] == ["review", "sign"]:
                    pathlib.Path(value(args, "--receipt-file")).write_text(
                        "reviewedAt=" + value(args, "--reviewed-at") + "\\n", encoding="utf-8"
                    )
                elif args[:2] == ["review", "verify"]:
                    pass
                elif args[:2] == ["catalog", "create"]:
                    catalog_text = "generatedAt=" + value(args, "--generated-at") + "\\n"
                    for index, arg in enumerate(args):
                        if arg == "--entry":
                            catalog_text += pathlib.Path(args[index + 1]).read_text(encoding="utf-8")
                    pathlib.Path(value(args, "--catalog-file")).write_text(catalog_text, encoding="utf-8")
                elif args[:2] == ["catalog", "sign"]:
                    catalog = pathlib.Path(value(args, "--catalog-file"))
                    catalog.with_name("{CANONICAL_CATALOG_SIGNATURE}").write_text("signature=ok\\n", encoding="utf-8")
                elif args[:2] == ["catalog", "verify"]:
                    catalog = pathlib.Path(value(args, "--catalog-file"))
                    if not catalog.with_name("{CANONICAL_CATALOG_SIGNATURE}").is_file():
                        raise SystemExit("missing canonical signature sidecar")
                else:
                    raise SystemExit("unsupported fake crypta-app command: " + " ".join(args))
            except Exception as exc:
                sys.stderr.write(str(exc) + "\\n")
                raise SystemExit(1)
            """
        ),
    )
    if platform.system() == "Windows":
        write_text(cli, f'@echo off\r\n"{sys.executable}" "%~dp0crypta-app.py" %*\r\n')
    else:
        shutil.copy(python_cli, cli)
        cli.chmod(0o755)
    return cli

def write_test_zip_archive(path: Path, entries: dict[str, str | bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            # These archives are generated only by the redaction self-test and may contain
            # intentionally unsafe payloads that must be detected by the scanner.
            archive.writestr(name, content)

def test_zip_archive_bytes(entries: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()

def test_tar_gz_archive_bytes(entries: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in entries.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()

def write_test_tar_gz_archive(path: Path, entries: dict[str, str | bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # This helper is redaction-self-test-only and may persist intentionally unsafe fixtures that
    # must be rejected by the scanner.
    write_bytes(path, test_tar_gz_archive_bytes(entries))

def assert_redaction_fails(kind: str, writer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix=f"cryptad-redaction-{kind}-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/redaction"
        out_dir.mkdir(parents=True)
        writer(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tree(out_dir, settings, include_dist=True)
        assert findings, f"{kind} did not fail redaction"

def assert_redaction_allows(kind: str, writer: Any) -> None:
    with tempfile.TemporaryDirectory(prefix=f"cryptad-redaction-allow-{kind}-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/redaction"
        out_dir.mkdir(parents=True)
        writer(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tree(out_dir, settings, include_dist=True)
        assert not findings, f"{kind} unexpectedly failed redaction: {findings}"

def assert_safe_copy_tree_rejects_symlink() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-symlink-") as temp_name:
        root = Path(temp_name)
        src = root / "src"
        dst = root / "dst"
        src.mkdir()
        write_text(src / "cryptad-app.properties", "app.id=fixture\n")
        outside = root / "outside-secret.txt"
        write_text(outside, "host-local-data\n")
        try:
            (src / "leaked-host-file").symlink_to(outside)
        except (NotImplementedError, OSError):
            return
        try:
            safe_copy_tree(src, dst, "self-test staged app")
        except ReleaseArtifactError as exc:
            assert "symlink" in str(exc), exc
            assert not (dst / "leaked-host-file").exists(), "symlink target was copied into the artifact tree"
        else:
            raise AssertionError("safe_copy_tree accepted a staged app symlink")

def assert_safe_copy_tree_rejects_symlinked_root() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-root-symlink-") as temp_name:
        root = Path(temp_name)
        target = root / "target"
        target.mkdir()
        write_text(target / "host-file.txt", "host-local-data\n")
        src = root / "src-link"
        dst = root / "dst"
        try:
            src.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError):
            return
        try:
            safe_copy_tree(src, dst, "self-test staged app")
        except ReleaseArtifactError as exc:
            assert "symlink" in str(exc), exc
            assert not (dst / "host-file.txt").exists(), "symlinked root target was copied into the artifact tree"
        else:
            raise AssertionError("safe_copy_tree accepted a symlinked copy root")

def assert_redaction_rejects_release_output_symlink() -> None:
    def writer(out_dir: Path) -> None:
        target = out_dir / "target.txt"
        write_text(target, "public artifact text\n")
        link = out_dir / "reports" / "target-link"
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            write_redaction_fixture_text(
                out_dir / "reports" / "fallback.txt", "CRYPTAD_APP_TOKEN=abc1234567890abcdef\n"
            )

    assert_redaction_fails("release-output-symlink", writer)

def assert_tarball_redaction_rejects_symlink_member() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-tar-symlink-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        tar_path = Path(temp_name) / "candidate.tar.gz"
        with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("reports/host-workspace-link")
            info.type = tarfile.SYMTYPE
            info.linkname = str(workspace)
            archive.addfile(info)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=False,
        )
        findings = scan_tarball(tar_path, settings)
        assert any(finding["kind"] == "forbidden-tar-entry" for finding in findings), findings

def assert_blank_review_policy_env_uses_defaults() -> None:
    env_keys = (
        "CRYPTAD_APP_SIGNING_KEY_ID",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_KEY_ID",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEW_POLICY_ID",
        "CRYPTAD_APP_REVIEW_POLICY_VERSION",
    )
    saved = {key: os.environ.get(key) for key in env_keys}
    try:
        for key in env_keys:
            os.environ.pop(key, None)
        os.environ["CRYPTAD_APP_REVIEW_POLICY_ID"] = ""
        os.environ["CRYPTAD_APP_REVIEW_POLICY_VERSION"] = "  "
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-review-policy-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / "build/production-beta",
                mode="developer-dry-run",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.invalid/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=True,
                allow_dirty_workspace=True,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            assert profile.review_policy_id == "crypta-app-review-v1", profile
            assert profile.review_policy_version == "1", profile
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

def assert_fixture_signing_profile_ignores_ambient_env() -> None:
    saved = {key: os.environ.get(key) for key in SIGNING_PROFILE_ENV_KEYS}
    try:
        os.environ.update(
            {
                "CRYPTAD_APP_SIGNING_KEY_ID": "ambient-production-app-key",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64": "YW1iaWVudC1hcHAtcHJpdmF0ZQ==",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "YW1iaWVudC1hcHAtcHVibGlj",
                "CRYPTAD_APP_REVIEWER_KEY_ID": "ambient-production-reviewer-key",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64": "YW1iaWVudC1yZXZpZXdlci1wcml2YXRl",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "YW1iaWVudC1yZXZpZXdlci1wdWJsaWM=",
                "CRYPTAD_APP_REVIEW_POLICY_ID": "ambient-review-policy",
                "CRYPTAD_APP_REVIEW_POLICY_VERSION": "99",
            }
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-fixture-profile-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            settings = Settings(
                workspace_root=workspace,
                out_dir=workspace / "build/production-beta",
                mode="developer-dry-run",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.invalid/self-test",
                require_live_network=False,
                require_sandbox_provider_tests=False,
                skip_gradle=True,
                skip_full_build=True,
                use_fixture_evidence=True,
                allow_dirty_workspace=True,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=False,
                previous_summary=None,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            assert profile.kind == "test-fixture", profile
            assert profile.generated_test_keys is True, profile
            assert profile.app_key_id == FIXTURE_APP_SIGNING_KEY_ID, profile
            assert profile.reviewer_key_id == FIXTURE_REVIEWER_KEY_ID, profile
            assert profile.review_policy_id == DEFAULT_REVIEW_POLICY_ID, profile
            assert profile.review_policy_version == DEFAULT_REVIEW_POLICY_VERSION, profile
            assert profile.env["CRYPTAD_APP_SIGNING_KEY_ID"] == FIXTURE_APP_SIGNING_KEY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEWER_KEY_ID"] == FIXTURE_REVIEWER_KEY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEW_POLICY_ID"] == DEFAULT_REVIEW_POLICY_ID, profile.env
            assert profile.env["CRYPTAD_APP_REVIEW_POLICY_VERSION"] == DEFAULT_REVIEW_POLICY_VERSION, profile.env
            for key in (
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
            ):
                assert key not in profile.env, (key, profile.env)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

def assert_dirty_production_beta_is_non_promotable() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dirty-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=True,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [], dirty_workspace=True)
        state.signing_profile = SigningProfile(
            kind="production",
            generated_test_keys=False,
            env={},
            private_paths=[],
            app_key_id="app-key",
            reviewer_key_id="reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )
        promotion = evaluate_promotion(state, {})
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        assert "workspace.clean-production-beta" in failed_ids, failed_ids
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion

def write_minimal_promotion_artifacts(out_dir: Path) -> None:
    for app_id in APP_IDS:
        write_text(out_dir / "build/staged-apps" / app_id / "cryptad-app.signature", "signature=ok\n")
        write_text(out_dir / "reviews/review-receipts" / f"{app_id}-review-receipt.properties", "status=reviewed\n")
    write_text(out_dir / "catalog/first-party-catalog.properties", "catalog=ok\n")
    write_text(out_dir / "catalog" / CANONICAL_CATALOG_SIGNATURE, "signature=ok\n")

def previous_candidate_source_metadata(version: str) -> dict[str, Any]:
    fixture = read_json(multi_node_beta_soak.previous_candidate_fixture_path()) or {}
    metadata = {
        field: json.loads(json.dumps(fixture[field], sort_keys=True))
        for field in multi_node_beta_soak.PREVIOUS_CANDIDATE_SOURCE_METADATA_FIELDS
        if field in fixture
    }
    for app in metadata.get("firstPartyApps", []):
        if isinstance(app, dict):
            app["version"] = version
    return metadata

def write_valid_previous_candidate_summary(
    path: Path,
    *,
    release_certification_digest: str | None = None,
) -> None:
    write_json(
        path,
        multi_node_beta_soak.build_previous_candidate_summary(
            {
                "schemaVersion": 1,
                "tool": "release-certification",
                "version": "previous-beta",
                "status": "pass",
                "releaseCandidatePassed": True,
                "metadata": {"gitCommit": "self-test-previous-git"},
                "evidence": [{"id": "self-test.previous", "status": "pass"}],
            },
            {
                "schemaVersion": 1,
                "tool": "production-beta-release",
                "version": "previous-beta",
                "status": "pass",
                "promotionReady": True,
                "artifactBaseUri": "https://downloads.crypta.network/production-beta/previous-beta",
                **previous_candidate_source_metadata("previous-beta"),
            },
            release_certification_digest=release_certification_digest
            or multi_node_beta_soak.synthetic_full_digest("self-test-release-certification"),
            production_beta_digest=multi_node_beta_soak.synthetic_full_digest("self-test-production-beta"),
            generated_at=utc_now(),
        ),
    )

def write_valid_release_certification_history_summary(path: Path) -> None:
    write_json(
        path,
        {
            "schemaVersion": 1,
            "tool": release_certification.TOOL_NAME,
            "releaseId": "cryptad-beta-previous-beta",
            "version": "previous-beta",
            "status": "pass",
            "releaseCandidatePassed": True,
            "metadata": {"gitCommit": "self-test-previous-git"},
            "evidence": [
                {"id": "interop.smoke", "status": "pass"},
                {
                    "id": "platform-api.contract",
                    "status": "pass",
                    "summary": "Previous Platform API contract snapshot was generated.",
                    "details": previous_platform_api_contract_details(),
                },
            ],
        },
    )

def previous_platform_api_contract_details() -> dict[str, Any]:
    capabilities = ["queue.read"]
    endpoints = ["GET /queue"]
    return {
        "contractVersion": 23,
        "apiVersion": "v1",
        "stableBaseline": {
            "name": "1.0",
            "contractVersion": 19,
            "capabilityCount": len(capabilities),
            "endpointCount": len(endpoints),
            "capabilities": capabilities,
            "endpoints": endpoints,
        },
        "compatibilityWindow": {
            "schemaVersion": 1,
            "baselineName": "1.0",
            "baselineContractVersion": 19,
            "currentContractVersion": 23,
            "supportPhase": "beta",
            "supportWindowStartedRelease": "production-beta",
            "minimumDeprecationWindowContractVersions": 2,
            "minimumScheduledRemovalWindowContractVersions": 2,
            "stableRemovalRequiresNewBaseline": True,
            "stableRemovalRequiresPreviousSnapshot": True,
            "stableRemovalRequiresExplicitWaiver": True,
            "criticalStableRemovalWaiverAllowed": False,
            "experimentalGraduationRequiresReview": True,
            "experimentalGraduationRequiresStableReferenceUpdate": True,
            "previousSnapshotRequiredInProductionBeta": True,
            "policyDocument": "docs/platform-api-compatibility-support-window.md",
        },
        "stableBaselineCapabilities": capabilities,
        "stableBaselineEndpoints": endpoints,
        "stableBaselineCapabilityCount": len(capabilities),
        "stableBaselineEndpointCount": len(endpoints),
        "stableCapabilities": capabilities,
        "stableEndpoints": endpoints,
        "stableEndpointRequiredCapabilities": {"GET /queue": capabilities},
        "stableEndpointActionLabels": {"GET /queue": "queue.read"},
        "stableEndpointAppAccess": {
            "GET /queue": {
                "appProcessPrincipalsAllowed": True,
                "appBrowserPrincipalsAllowed": True,
            }
        },
    }

def write_valid_previous_candidate_history_pair(previous_summary: Path, history_summary: Path) -> None:
    write_valid_release_certification_history_summary(history_summary)
    write_valid_previous_candidate_summary(
        previous_summary,
        release_certification_digest=multi_node_beta_soak.sha256_path(history_summary),
    )

def passing_multi_node_beta_soak_summary(current_version: str = "self-test") -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-multi-node-summary-") as temp_name:
        base_dir = Path(temp_name)
        current_editions = catalog_channel_editions(current_version)
        write_json(
            base_dir / "previous-summary.json",
            multi_node_beta_soak.build_previous_candidate_summary(
                {
                    "schemaVersion": 1,
                    "tool": "release-certification",
                    "version": "previous-beta",
                    "status": "pass",
                    "releaseCandidatePassed": True,
                    "metadata": {"gitCommit": "self-test-previous-git"},
                    "evidence": [{"id": "self-test.previous", "status": "pass"}],
                },
                {
                    "schemaVersion": 1,
                    "tool": "production-beta-release",
                    "version": "previous-beta",
                    "status": "pass",
                    "promotionReady": True,
                    "artifactBaseUri": "https://downloads.crypta.network/production-beta/previous-beta",
                    **previous_candidate_source_metadata("previous-beta"),
                },
                release_certification_digest=multi_node_beta_soak.synthetic_full_digest(
                    "self-test-release-certification"
                ),
                production_beta_digest=multi_node_beta_soak.synthetic_full_digest(
                    "self-test-production-beta"
                ),
            ),
        )
        write_json(
            base_dir / "current-summary.json",
            {
                "schemaVersion": 1,
                "status": "pass",
                "promotionReady": True,
                "previousCandidateMetadata": {
                    "catalog": current_editions,
                },
            },
        )
        config = multi_node_beta_soak.validate_config(
            {
                "schemaVersion": 1,
                "kind": multi_node_beta_soak.CONFIG_KIND,
                "mode": "hybrid",
                "durationProfile": "ci-smoke",
                "previousCandidate": {
                    "version": "previous-beta",
                    "summaryPath": "previous-summary.json",
                    "catalogChannel": "stable",
                },
                "currentCandidate": {
                    "version": current_version,
                    "productionBetaSummaryPath": "current-summary.json",
                    "catalogChannel": "stable",
                },
                "nodes": [
                    {
                        "id": "node-a",
                        "role": "publisher",
                        "catalogChannels": ["stable"],
                        "apps": ["feed-reader", "profile-publisher", "trust-graph", "social-inbox"],
                    },
                    {
                        "id": "node-b",
                        "role": "subscriber",
                        "catalogChannels": ["stable", "beta"],
                        "apps": ["feed-reader", "social-inbox"],
                    },
                    {
                        "id": "node-c",
                        "role": "subscriber",
                        "catalogChannels": ["stable"],
                        "apps": ["feed-reader", "trust-graph"],
                    },
                ],
                "scenarios": {scenario: True for scenario in multi_node_beta_soak.REQUIRED_SCENARIOS},
                "redaction": {key: True for key in multi_node_beta_soak.REDACTION_KEYS},
                "strict": {
                    "requireAllScenarios": True,
                    "requirePreviousSummary": True,
                },
            },
            strict=True,
        )
        summary = multi_node_beta_soak.build_summary(config, strict=True, base_dir=base_dir)
    assert summary["status"] == "pass", summary
    assert summary["promotionReady"] is True, summary
    return summary

def passing_promotion_summaries() -> dict[str, Any]:
    cert_evidence = [
        {
            "id": evidence_id,
            "status": "pass",
            "summary": f"{evidence_id} passed.",
            "details": {},
        }
        for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS
    ]
    live_evidence = [
        {
            "id": evidence_id,
            "status": "pass",
            "summary": f"{evidence_id} passed.",
            "details": {},
        }
        for evidence_id in LIVE_NETWORK_REQUIRED_IDS
    ]
    return {
        "certification": {"releaseCandidatePassed": True, "evidence": cert_evidence},
        "liveNetwork": {"status": "pass", "evidence": live_evidence},
        "multiNodeBetaSoak": passing_multi_node_beta_soak_summary(),
        "matrix": {"status": "pass", "releaseBlockerCount": 0},
    }

def production_signing_profile() -> SigningProfile:
    return SigningProfile(
        kind="production",
        generated_test_keys=False,
        env={},
        private_paths=[],
        app_key_id="app-key",
        reviewer_key_id="reviewer-key",
        review_policy_id="crypta-app-review-v1",
        review_policy_version="1",
    )

def mark_required_pipeline_stages_passed(state: PipelineState) -> None:
    for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES:
        record_pipeline_stage(state, stage_id, "pass", f"{stage_id} passed in self-test.")

def write_previous_release_summary(path: Path) -> None:
    write_json(path, {"schemaVersion": 1, "status": "pass", "promotionReady": True})

def assert_emergency_build_skip_is_non_promotable() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-build-skip-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/production-beta"
        write_minimal_promotion_artifacts(out_dir)
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=True,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        assert release_config(state)["nonRelease"] is True
        promotion = evaluate_promotion(state, passing_promotion_summaries())
        failed_ids = {gate["id"] for gate in promotion["gates"] if gate["status"] == "fail"}
        assert "build.production-beta-complete" in failed_ids, promotion
        assert promotion["nonRelease"] is True, promotion
        assert promotion["promotionReady"] is False, promotion
        developer_beta = promotion["developerBetaProgram"]
        assert developer_beta["status"] == "pass", developer_beta
        assert developer_beta["sampleAppFlow"] == "pass", developer_beta
        assert developer_beta["submissionChecklist"] == "pass", developer_beta
        assert developer_beta["compatibilityWindow"] == "pass", developer_beta

def assert_allow_test_signing_env_profile_is_non_release() -> None:
    env_keys = (
        "CRYPTAD_APP_SIGNING_KEY_ID",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_KEY_ID",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_FILE",
        "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64",
        "CRYPTAD_APP_REVIEW_POLICY_ID",
        "CRYPTAD_APP_REVIEW_POLICY_VERSION",
    )
    saved = {key: os.environ.get(key) for key in env_keys}
    try:
        for key in env_keys:
            os.environ.pop(key, None)
        os.environ.update(
            {
                "CRYPTAD_APP_SIGNING_KEY_ID": "test-app-key",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64": "dGVzdC1hcHAtcHJpdmF0ZS1rZXk=",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "dGVzdC1hcHAtcHVibGljLWtleQ==",
                "CRYPTAD_APP_REVIEWER_KEY_ID": "test-reviewer-key",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wcml2YXRlLWtleQ==",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wdWJsaWMta2V5",
            }
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-test-signing-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            out_dir = workspace / "build/production-beta"
            previous_summary = workspace / "previous-summary.json"
            write_previous_release_summary(previous_summary)
            write_minimal_promotion_artifacts(out_dir)
            settings = Settings(
                workspace_root=workspace,
                out_dir=out_dir,
                mode="production-beta",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
                require_live_network=True,
                require_sandbox_provider_tests=True,
                skip_gradle=False,
                skip_full_build=False,
                use_fixture_evidence=False,
                allow_dirty_workspace=False,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=True,
                previous_summary=previous_summary,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            state.signing_profile = profile
            mark_required_pipeline_stages_passed(state)
            assert profile.kind == "configured", profile
            assert profile.generated_test_keys is False, profile
            assert release_config(state)["nonRelease"] is True
            promotion = evaluate_promotion(state, passing_promotion_summaries())
            assert promotion_gate_by_id(promotion, "signing.production-keys")["status"] == "pass", promotion
            assert promotion["status"] == "pass", promotion
            assert promotion["nonRelease"] is True, promotion
            assert promotion["promotionReady"] is False, promotion
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

def assert_test_key_ids_without_escape_hatch_are_rejected() -> None:
    saved = {key: os.environ.get(key) for key in SIGNING_PROFILE_ENV_KEYS}
    try:
        for key in SIGNING_PROFILE_ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update(
            {
                "CRYPTAD_APP_SIGNING_KEY_ID": "test-app-key",
                "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64": "dGVzdC1hcHAtcHJpdmF0ZS1rZXk=",
                "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64": "dGVzdC1hcHAtcHVibGljLWtleQ==",
                "CRYPTAD_APP_REVIEWER_KEY_ID": "fixture-reviewer-key",
                "CRYPTAD_APP_REVIEWER_PRIVATE_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wcml2YXRlLWtleQ==",
                "CRYPTAD_APP_REVIEWER_PUBLIC_KEY_BASE64": "dGVzdC1yZXZpZXdlci1wdWJsaWMta2V5",
            }
        )
        with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-test-key-policy-") as temp_name:
            workspace = Path(temp_name) / "repo"
            make_self_test_workspace(workspace)
            out_dir = workspace / "build/production-beta"
            previous_summary = workspace / "previous-summary.json"
            write_previous_release_summary(previous_summary)
            write_minimal_promotion_artifacts(out_dir)
            settings = Settings(
                workspace_root=workspace,
                out_dir=out_dir,
                mode="production-beta",
                catalog_channel="stable",
                artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
                require_live_network=True,
                require_sandbox_provider_tests=True,
                skip_gradle=False,
                skip_full_build=False,
                use_fixture_evidence=False,
                allow_dirty_workspace=False,
                emergency_skip_live_network=False,
                emergency_skip_build=False,
                allow_test_signing_in_production=False,
                previous_summary=previous_summary,
                waiver_file=None,
                timeout_seconds=60,
                clean_out_dir=True,
            )
            state = PipelineState(settings, "self-test", utc_now(), [], [], [])
            profile = prepare_signing_profile(state, workspace / "keys")
            state.signing_profile = profile
            mark_required_pipeline_stages_passed(state)
            promotion = evaluate_promotion(state, passing_promotion_summaries())
            assert profile.kind == "configured", profile
            assert any("key IDs must be production key IDs" in failure for failure in state.failures), state.failures
            assert promotion_gate_by_id(promotion, "signing.production-keys")["status"] == "fail", promotion
            assert promotion["nonRelease"] is True, promotion
            assert promotion["promotionReady"] is False, promotion
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

def assert_failed_final_summary_clears_promotion_ready() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-summary-ready-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="production-beta",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=True,
            require_sandbox_provider_tests=True,
            skip_gradle=False,
            skip_full_build=False,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        promotion = {
            "status": "pass",
            "promotionReady": True,
            "nonRelease": False,
            "failedGateCount": 0,
            "gates": [],
            "knownLimitations": [],
        }
        redaction_pass = {"schemaVersion": 1, "status": "pass", "scannedRoot": "<release-out>", "findingCount": 0, "findings": []}
        redaction_fail = {
            "schemaVersion": 1,
            "status": "fail",
            "scannedRoot": "<release-out>",
            "findingCount": 1,
            "findings": [{"kind": "app-token", "path": "reports/leak.txt"}],
        }

        command_failed_state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            ["gradle-stage-sign-verify-first-party-apps failed with exit code 1"],
            signing_profile=production_signing_profile(),
        )
        command_failed_summary = build_final_summary(command_failed_state, promotion, redaction_pass, None)
        assert command_failed_summary["status"] == "fail", command_failed_summary
        assert command_failed_summary["promotionReady"] is False, command_failed_summary
        assert command_failed_summary["promotion"]["promotionReady"] is False, command_failed_summary

        redaction_failed_state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            [],
            signing_profile=production_signing_profile(),
        )
        redaction_failed_summary = build_final_summary(redaction_failed_state, promotion, redaction_fail, None)
        assert redaction_failed_summary["status"] == "fail", redaction_failed_summary
        assert redaction_failed_summary["promotionReady"] is False, redaction_failed_summary
        assert redaction_failed_summary["promotion"]["promotionReady"] is False, redaction_failed_summary

def promotion_gate_by_id(promotion: dict[str, Any], gate_id: str) -> dict[str, Any]:
    for gate in promotion["gates"]:
        if gate["id"] == gate_id:
            return gate
    raise AssertionError(f"missing promotion gate {gate_id}")

def assert_required_third_party_intake_requires_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-intake-required-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            require_third_party_intake=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        promotion = evaluate_promotion(state, passing_promotion_summaries())
        assert promotion_gate_by_id(promotion, "third-party-intake.required-evidence")["status"] == "fail", promotion
        assert promotion_gate_by_id(promotion, "third-party-intake.redaction")["status"] == "fail", promotion

def assert_public_beta_support_feedback_evidence_is_critical() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-support-feedback-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        summaries = passing_promotion_summaries()
        summaries["certification"]["evidence"] = [
            item
            for item in summaries["certification"]["evidence"]
            if item.get("id") != "public-beta.support-feedback-loop"
        ]
        promotion = evaluate_promotion(state, summaries)
        assert promotion_gate_by_id(promotion, "evidence.public-beta.support-feedback-loop")[
            "status"
        ] == "fail", promotion
        assert promotion["publicBetaSupportFeedback"]["status"] == "missing", promotion
        redaction_summaries = passing_promotion_summaries()
        for item in redaction_summaries["certification"]["evidence"]:
            if item.get("id") == "public-beta.redaction-fixtures":
                item["status"] = "pass"
                item["details"] = {"redactionFindings": [{"path": "support-feedback", "issue": "token"}]}
        redaction_promotion = evaluate_promotion(state, redaction_summaries)
        assert promotion_gate_by_id(redaction_promotion, "evidence.public-beta.redaction-fixtures")[
            "status"
        ] == "fail", redaction_promotion
        assert redaction_promotion["publicBetaSupportFeedback"]["status"] == "fail", (
            redaction_promotion
        )
        assert redaction_promotion["publicBetaSupportFeedback"]["redactionFixtures"] == "fail", (
            redaction_promotion
        )
        assert "public-beta.redaction-fixtures evidence has redaction findings." in (
            redaction_promotion["publicBetaSupportFeedback"]["blockers"]
        ), redaction_promotion

def assert_required_third_party_intake_uses_attached_summary_rows() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-intake-attached-rows-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            require_third_party_intake=True,
        )
        source_evidence = [
            {
                "id": evidence_id,
                "status": "pass",
                "summary": f"{evidence_id} passed in source-level smoke evidence.",
                "details": {},
            }
            for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS
        ]
        attached_summary = third_party_intake_sample_summary()
        attached_summary["evidence"] = [
            item
            for item in attached_summary["evidence"]
            if item["id"] != "third-party-intake.catalog-candidate-staging"
        ]
        summaries = passing_promotion_summaries()
        summaries["appPlatform"] = {"status": "pass", "evidence": source_evidence}
        summaries["thirdPartyIntake"] = attached_summary
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])

        promotion = evaluate_promotion(state, summaries)

        assert promotion_gate_by_id(promotion, "third-party-intake.required-evidence")["status"] == "fail", promotion
        assert "third-party-intake.catalog-candidate-staging" in promotion["thirdPartyIntake"][
            "missingOrFailedEvidence"
        ], promotion

def assert_production_third_party_intake_rejects_non_release_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-intake-nonrelease-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            require_live_network=True,
            require_multi_node_soak=True,
            require_third_party_intake=True,
            skip_gradle=False,
            skip_full_build=False,
        )
        write_minimal_promotion_artifacts(out_dir)
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES:
            state.pipeline_stages[stage_id] = {"status": "pass"}
        summaries = passing_promotion_summaries()
        summaries["thirdPartyIntake"] = third_party_intake_sample_summary()
        promotion = evaluate_promotion(state, summaries)
        gate = promotion_gate_by_id(promotion, "third-party-intake.production-evidence")
        assert gate["status"] == "fail", promotion
        assert promotion["thirdPartyIntake"]["nonRelease"] is True, promotion

def assert_production_third_party_intake_rejects_optional_non_release_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-intake-optional-nonrelease-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="production-beta",
            require_live_network=True,
            require_multi_node_soak=True,
            require_third_party_intake=False,
            skip_gradle=False,
            skip_full_build=False,
        )
        write_minimal_promotion_artifacts(out_dir)
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = production_signing_profile()
        for stage_id in PRODUCTION_BETA_REQUIRED_PIPELINE_STAGES:
            state.pipeline_stages[stage_id] = {"status": "pass"}
        summaries = passing_promotion_summaries()
        summaries["thirdPartyIntake"] = third_party_intake_sample_summary()

        promotion = evaluate_promotion(state, summaries)

        gate = promotion_gate_by_id(promotion, "third-party-intake.production-evidence")
        assert gate["status"] == "fail", promotion
        assert promotion["thirdPartyIntake"]["required"] is False, promotion
        assert promotion["thirdPartyIntake"]["nonRelease"] is True, promotion

def assert_release_candidate_third_party_intake_rejects_non_release_summary() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-rc-intake-nonrelease-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="release-candidate",
            require_third_party_intake=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summaries = passing_promotion_summaries()
        summaries["thirdPartyIntake"] = third_party_intake_sample_summary()

        promotion = evaluate_promotion(state, summaries)

        gate = promotion_gate_by_id(promotion, "third-party-intake.production-evidence")
        assert gate["status"] == "fail", promotion
        assert promotion["thirdPartyIntake"]["nonRelease"] is True, promotion

def assert_waived_critical_evidence_is_accepted_without_redaction_findings() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-waived-evidence-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.network/production-beta/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=True,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=False,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        state.signing_profile = SigningProfile(
            kind="test-fixture",
            generated_test_keys=True,
            env={},
            private_paths=[],
            app_key_id="test-app-key",
            reviewer_key_id="test-reviewer-key",
            review_policy_id="crypta-app-review-v1",
            review_policy_version="1",
        )

        def summaries_for(details: dict[str, Any]) -> dict[str, Any]:
            evidence = [
                {
                    "id": evidence_id,
                    "status": "pass",
                    "summary": f"{evidence_id} passed.",
                    "details": {},
                }
                for evidence_id in CRITICAL_PRODUCTION_BETA_EVIDENCE_IDS
            ]
            for item in evidence:
                if item["id"] == "apphost.sandbox-provider":
                    item["status"] = "warn"
                    item["summary"] = "Sandbox provider evidence was waived."
                    item["details"] = details
            return {
                "certification": {"releaseCandidatePassed": True, "evidence": evidence},
                "matrix": {"status": "warn", "releaseBlockerCount": 0},
            }

        waived = evaluate_promotion(state, summaries_for({"waived": True, "waiverId": "sandbox-waiver"}))
        assert promotion_gate_by_id(waived, "evidence.apphost.sandbox-provider")["status"] == "pass", waived
        assert promotion_gate_by_id(waived, "evidence.required-sandbox-provider-tests")["status"] == "pass", waived

        redaction = evaluate_promotion(
            state,
            summaries_for(
                {
                    "waived": True,
                    "waiverId": "sandbox-waiver",
                    "redactionFindings": [{"kind": "raw-content-or-app-data"}],
                }
            ),
        )
        assert promotion_gate_by_id(redaction, "evidence.apphost.sandbox-provider")["status"] == "fail", redaction
        assert promotion_gate_by_id(redaction, "evidence.required-sandbox-provider-tests")["status"] == "fail", redaction

def assert_developer_dry_run_exit_code_fails_on_recorded_failures() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-dry-run-failure-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(
            settings,
            "self-test",
            utc_now(),
            [],
            [],
            ["gradle-stage-sign-verify-first-party-apps failed with exit code 1"],
        )
        summary = build_final_summary(
            state,
            {"status": "pass", "promotionReady": False, "nonRelease": True, "gates": [], "knownLimitations": []},
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )
        assert summary["status"] == "fail", summary
        assert release_exit_code(settings, summary) == 1, summary

def assert_security_release_notes_draft_artifact_requires_file() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-security-draft-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        promotion = {
            "status": "pass",
            "promotionReady": False,
            "nonRelease": True,
            "gates": [],
            "knownLimitations": [],
        }
        redaction_report = {
            "schemaVersion": 1,
            "status": "pass",
            "scannedRoot": "<release-out>",
            "findingCount": 0,
            "findings": [],
        }
        without_draft = build_final_summary(state, promotion, redaction_report, None)
        assert "securityReleaseNotesDraft" not in without_draft["artifacts"], without_draft["artifacts"]
        write_text(security_release_notes_draft_path(settings), "# Security Release Notes Draft\n")
        with_draft = build_final_summary(state, promotion, redaction_report, None)
        assert (
            with_draft["artifacts"]["securityReleaseNotesDraft"]
            == "security/security-release-notes-draft.md"
        ), with_draft["artifacts"]

def assert_security_response_summary_reads_combined_drill_details() -> None:
    counts = {
        "required": len(security_response_runbook.REQUIRED_DRILLS),
        "passed": len(security_response_runbook.REQUIRED_DRILLS),
        "failed": 0,
        "missing": 0,
        "stale": 0,
        "malformed": 0,
    }
    combined = {
        "production-security.response-runbook": {
            "id": "production-security.response-runbook",
            "status": "pass",
            "summary": "Production security response runbook and operational drills passed.",
            "details": {
                "appPlatformRunbook": {
                    "status": "pass",
                    "details": {
                        "checks": {
                            "runbookDocExists": True,
                            "advisoryLifecycleTestable": True,
                            "releaseNotesTemplate": True,
                            "supportRedactionDrill": True,
                        },
                        "drillIds": list(security_response_runbook.REQUIRED_DRILLS),
                    },
                },
                "securityDrills": {
                    "status": "pass",
                    "details": {
                        "promotionReady": True,
                        "nonRelease": False,
                        "fixtureOnly": False,
                        "counts": counts,
                        "requiredScenarios": list(security_response_runbook.REQUIRED_DRILLS),
                        "passedScenarios": list(security_response_runbook.REQUIRED_DRILLS),
                        "failedScenarios": [],
                        "missingScenarios": [],
                        "staleScenarios": [],
                        "malformedScenarios": [],
                        "redaction": {"status": "pass", "findings": []},
                        "releaseNotes": {"templateStatus": "pass"},
                        "validationErrors": [],
                    },
                },
                "componentStatuses": {
                    "appPlatformRunbook": "pass",
                    "securityDrills": "pass",
                },
            },
        }
    }

    summary = production_security_response_summary(combined)

    assert summary["counts"] == counts, summary
    assert summary["requiredScenarios"] == list(security_response_runbook.REQUIRED_DRILLS), summary
    assert summary["passedScenarios"] == sorted(security_response_runbook.REQUIRED_DRILLS), summary
    assert summary["runbookStatus"] == "pass", summary
    assert summary["advisoryLifecycleStatus"] == "pass", summary
    assert summary["reviewerCompromiseDrillStatus"] == "pass", summary
    assert summary["supportRedactionStatus"] == "pass", summary
    assert summary["redactionStatus"] == "pass", summary
    assert summary["securityReleaseNotesTemplateStatus"] == "pass", summary

    failed_runbook = json.loads(json.dumps(combined))
    failed_item = failed_runbook["production-security.response-runbook"]
    failed_item["status"] = "fail"
    failed_item["summary"] = "Production security response is not promotion-ready."
    failed_app = failed_item["details"]["appPlatformRunbook"]
    failed_app["status"] = "fail"
    failed_app["details"]["checks"]["runbookDocExists"] = False
    failed_app["details"]["checks"]["advisoryLifecycleTestable"] = False
    failed_item["details"]["componentStatuses"]["appPlatformRunbook"] = "fail"

    failed_summary = production_security_response_summary(failed_runbook)

    assert failed_summary["counts"] == counts, failed_summary
    assert failed_summary["runbookStatus"] == "fail", failed_summary
    assert failed_summary["advisoryLifecycleStatus"] == "fail", failed_summary
    assert failed_summary["reviewerCompromiseDrillStatus"] == "pass", failed_summary

def assert_attached_security_drills_summary_is_bound_to_release_id() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-security-drills-release-id-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        out_dir = workspace / "build/production-beta"
        attached_dir = workspace / "attached/security-drills"
        attached_summary = attached_dir / "security-drills-summary.json"
        started_at = "2026-07-04T00:00:00Z"
        security_response_runbook.drill_run_all(
            workspace / "tools/release-certification/production-security-response-runbook.json",
            attached_dir,
            attached_summary,
            release_id="cryptad-beta-other-candidate",
            generated_at=started_at,
            mode="release-candidate",
        )
        settings = Settings(
            workspace_root=workspace,
            out_dir=out_dir,
            mode="release-candidate",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=True,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=120,
            clean_out_dir=True,
            security_drills_summary=attached_summary,
        )
        state = PipelineState(settings, "current-candidate", started_at, [], [], [])

        run_security_response_drills(state)

        stage = state.pipeline_stages.get("security-response-drills", {})
        assert stage.get("status") == "fail", stage
        assert any("releaseId does not match" in failure for failure in state.failures), state.failures

def assert_invalid_attached_security_drills_summary_is_sanitized() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-security-drills-sanitized-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        started_at = "2026-07-04T00:00:00Z"
        version = "current-candidate"
        release_id = f"cryptad-beta-{version}"
        attached_dir = workspace / "attached/security-drills"
        attached_summary = attached_dir / "security-drills-summary.json"
        security_response_runbook.drill_run_all(
            workspace / "tools/release-certification/production-security-response-runbook.json",
            attached_dir,
            attached_summary,
            release_id=release_id,
            generated_at=started_at,
            mode="production-beta",
        )
        unsafe_summary = read_json(attached_summary)
        if unsafe_summary is None:
            raise AssertionError("security drills self-test did not create an attached summary")
        unsafe_summary["rawSupportBundleBody"] = "-----BEGIN PRIVATE KEY-----\nunsafe-fixture\n-----END PRIVATE KEY-----"
        unsafe_summary.setdefault("releaseNotes", {})["redactedSnippet"] = (
            "Unsafe attached summary mentions /home/alice/private/key.pem"
        )
        write_json(attached_summary, unsafe_summary)
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, workspace / "build/production-beta-unsafe-security-drills"),
            mode="production-beta",
            security_drills_summary=attached_summary,
        )
        state = PipelineState(settings, version, started_at, [], [], [])

        summary_path = run_security_response_drills(state)

        stage = state.pipeline_stages.get("security-response-drills", {})
        assert stage.get("status") == "fail", stage
        persisted = read_json(summary_path)
        assert isinstance(persisted, dict), persisted
        assert persisted.get("status") == "fail", persisted
        assert persisted.get("promotionReady") is False, persisted
        assert persisted.get("attachment", {}).get("sanitized") is True, persisted
        assert persisted.get("attachmentErrors"), persisted
        encoded = summary_path.read_text(encoding="utf-8") + json.dumps(state.failures, sort_keys=True)
        for forbidden in ("-----BEGIN PRIVATE KEY-----", "/home/alice/private/key.pem", "unsafe-fixture"):
            assert forbidden not in encoded, forbidden

def assert_attached_security_drills_summary_preserves_artifacts() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-security-drills-attached-") as temp_name:
        workspace = Path(temp_name) / "repo"
        make_self_test_workspace(workspace)
        started_at = "2026-07-04T00:00:00Z"
        version = "current-candidate"
        release_id = f"cryptad-beta-{version}"
        attached_dir = workspace / "attached/security-drills"
        attached_summary = attached_dir / "security-drills-summary.json"
        security_response_runbook.drill_run_all(
            workspace / "tools/release-certification/production-security-response-runbook.json",
            attached_dir,
            attached_summary,
            release_id=release_id,
            generated_at=started_at,
            mode="production-beta",
        )
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, workspace / "build/production-beta"),
            mode="production-beta",
            security_drills_summary=attached_summary,
        )
        state = PipelineState(settings, version, started_at, [], [], [])

        summary_path = run_security_response_drills(state)

        stage = state.pipeline_stages.get("security-response-drills", {})
        assert stage.get("status") == "pass", stage
        assert state.failures == [], state.failures
        assert read_json(summary_path)["status"] == "pass"
        for scenario, file_name in security_response_runbook.DRILL_OUTPUT_FILENAMES.items():
            copied = security_drills_dir(settings) / file_name
            assert copied.is_file(), scenario

        missing_dir = workspace / "attached-missing/security-drills"
        missing_summary = missing_dir / "security-drills-summary.json"
        security_response_runbook.drill_run_all(
            workspace / "tools/release-certification/production-security-response-runbook.json",
            missing_dir,
            missing_summary,
            release_id=release_id,
            generated_at=started_at,
            mode="production-beta",
        )
        (missing_dir / security_response_runbook.DRILL_OUTPUT_FILENAMES["reviewer-key-compromise"]).unlink()
        missing_settings = dataclasses.replace(
            cleanup_test_settings(workspace, workspace / "build/production-beta-missing"),
            mode="production-beta",
            security_drills_summary=missing_summary,
        )
        missing_state = PipelineState(missing_settings, version, started_at, [], [], [])

        missing_summary_path = run_security_response_drills(missing_state)

        missing_stage = missing_state.pipeline_stages.get("security-response-drills", {})
        assert missing_stage.get("status") == "fail", missing_stage
        assert any("artifacts are incomplete" in failure for failure in missing_state.failures), (
            missing_state.failures
        )
        failed_summary = read_json(missing_summary_path)
        assert failed_summary["status"] == "fail", failed_summary
        assert failed_summary["promotionReady"] is False, failed_summary
        assert failed_summary["attachmentErrors"], failed_summary

def assert_certification_failure_marks_dry_run_failed() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-cert-failure-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        settings = Settings(
            workspace_root=workspace,
            out_dir=workspace / "build/production-beta",
            mode="developer-dry-run",
            catalog_channel="stable",
            artifact_base_uri="https://downloads.crypta.invalid/self-test",
            require_live_network=False,
            require_sandbox_provider_tests=False,
            skip_gradle=True,
            skip_full_build=True,
            use_fixture_evidence=False,
            allow_dirty_workspace=True,
            emergency_skip_live_network=False,
            emergency_skip_build=False,
            allow_test_signing_in_production=False,
            previous_summary=None,
            waiver_file=None,
            timeout_seconds=60,
            clean_out_dir=True,
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        record_certification_result(
            state,
            CommandResult(
                name="release-certification",
                args=[],
                exit_code=17,
                duration_ms=1,
                stdout_tail="",
                stderr_tail="failed",
            ),
        )
        summary = build_final_summary(
            state,
            {"status": "fail", "promotionReady": False, "nonRelease": True, "gates": [], "knownLimitations": []},
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )
        assert state.certification_exit_code == 17, state.certification_exit_code
        assert "release-certification failed with exit code 17" in state.failures, state.failures
        assert summary["status"] == "fail", summary
        assert release_exit_code(settings, summary) == 1, summary

def assert_release_candidate_no_go_dashboard_preserves_summary_and_exit() -> None:
    with tempfile.TemporaryDirectory(prefix="cryptad-production-beta-rc-dashboard-no-go-") as temp_name:
        workspace = Path(temp_name) / "repo"
        workspace.mkdir(parents=True)
        out_dir = workspace / "build/production-beta"
        settings = dataclasses.replace(
            cleanup_test_settings(workspace, out_dir),
            mode="release-candidate",
        )
        state = PipelineState(settings, "self-test", utc_now(), [], [], [])
        summary = build_final_summary(
            state,
            {
                "status": "pass",
                "promotionReady": False,
                "nonRelease": True,
                "failedGateCount": 0,
                "gates": [],
                "knownLimitations": [],
            },
            {
                "schemaVersion": 1,
                "status": "pass",
                "scannedRoot": "<release-out>",
                "findingCount": 0,
                "findings": [],
            },
            None,
        )
        assert summary["status"] == "pass", summary

        def fake_run_command(
            state: PipelineState,
            name: str,
            args: list[str],
            env: dict[str, str] | None = None,
            timeout_seconds: int = 0,
            allow_failure: bool = False,
        ) -> CommandResult:
            del name, args, env, timeout_seconds, allow_failure
            write_json(
                state.settings.out_dir / GO_NO_GO_DASHBOARD_JSON,
                {
                    "decision": "no-go",
                    "promotionReady": False,
                    "summary": {"blockers": 1, "warnings": 0, "waiversUsed": 0, "criticalRedactionFindings": 0},
                    "blockers": [
                        {
                            "id": "waiver.file.invalid",
                            "evidenceId": "production-beta.waiver-validation",
                            "severity": "blocker",
                            "summary": "Waiver file is invalid.",
                        }
                    ],
                    "redaction": {"status": "pass", "findings": []},
                },
            )
            write_text(state.settings.out_dir / GO_NO_GO_DASHBOARD_MARKDOWN, "Decision: `NO-GO`\n")
            write_json(
                state.settings.out_dir / GO_NO_GO_REDACTION_REPORT,
                {
                    "schemaVersion": SCHEMA_VERSION,
                    "status": "pass",
                    "findingCount": 0,
                    "criticalFindingCount": 0,
                    "findings": [],
                },
            )
            return CommandResult("production-beta-go-no-go-dashboard", [], 1, 1, "", "")

        original_run_command = globals()["run_command"]
        try:
            globals()["run_command"] = fake_run_command
            attached = attach_go_no_go_dashboard(state, summary)
        finally:
            globals()["run_command"] = original_run_command

        assert attached["goNoGo"]["decision"] == "no-go", attached
        assert attached["status"] == "pass", attached
        assert attached["promotionReady"] is False, attached
        assert release_exit_code(settings, attached) == 0, attached
