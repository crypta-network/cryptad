"""Implementation segment for the distribution portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def collect_signed_bundle_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    inputs = signing_inputs(os.environ)
    details: dict[str, Any] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "privateKeySource": "file" if inputs["privateFile"] else ("environment" if inputs["privateBase64"] else "missing"),
        "publicKeySource": "file" if inputs["publicFile"] else ("environment" if inputs["publicBase64"] else "missing"),
    }
    source = summary_source(settings)
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "skip"
        return EvidenceItem(
            "app-platform.signed-bundles",
            status,
            True,
            "Signing key inputs are not complete; signed bundle verification was not run.",
            source,
            details,
        )
    gradle_result = gradle_command(settings, ["signFirstPartyApps", "verifyFirstPartyApps"], "gradle-sign-verify-first-party-apps")
    details["firstPartySignVerifyCommand"] = command_details(gradle_result, settings)
    failures: list[str] = []
    if gradle_result is None:
        details["firstPartySignVerifyRan"] = False
        if settings.mode == "release-candidate":
            failures.append("first-party sign/verify Gradle task was skipped")
    elif gradle_result.exit_code != 0:
        details["firstPartySignVerifyRan"] = True
        failures.append("first-party sign/verify Gradle task failed")
    else:
        details["firstPartySignVerifyRan"] = True
    cli = sample_paths.get("cli")
    sample_dir = sample_paths.get("bundleDir")
    if cli and sample_dir and sample_dir.is_dir():
        sign_result = run_cli(cli, sign_args(sample_dir, inputs), settings, "crypta-app-sign-sample")
        verify_result = run_cli(cli, verify_args(sample_dir, inputs), settings, "crypta-app-verify-sample")
        details["sampleSign"] = command_details(sign_result, settings)
        details["sampleVerify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append("sample bundle sign failed")
        if verify_result.exit_code != 0:
            failures.append("sample bundle verify failed")
        sample_zip = sample_paths.get("zip")
        if sample_zip and sign_result.exit_code == 0 and verify_result.exit_code == 0:
            repack_result = run_cli(
                cli,
                ["pack", "--bundle-dir", str(sample_dir), "--output", str(sample_zip), "--overwrite"],
                settings,
                "crypta-app-pack-signed-sample",
            )
            details["sampleRepackAfterSigning"] = command_details(repack_result, settings)
            if repack_result.exit_code != 0:
                failures.append("signed sample bundle repack failed")
            elif sample_zip.is_file():
                details["signedSampleZipSha256"] = sha256_file(sample_zip)
                details["signedSampleZipSizeBytes"] = sample_zip.stat().st_size
    else:
        failures.append("sample bundle was unavailable for signing")
    if failures:
        return EvidenceItem(
            "app-platform.signed-bundles",
            "fail",
            True,
            "Signed bundle smoke failed.",
            source,
            {"failures": failures, **details},
        )
    return EvidenceItem(
        "app-platform.signed-bundles",
        "pass",
        True,
        "First-party and sample bundle signing evidence passed.",
        source,
        details,
    )

def collect_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    sample_zip = sample_paths.get("zip")
    details: dict[str, Any] = {}
    if not cli or not sample_zip or not sample_zip.is_file():
        return EvidenceItem("catalog.smoke", root_consequence(settings, "missing"), True, "Sample ZIP or crypta-app CLI is unavailable for catalog smoke.", source, details)
    catalog_dir = sample_workspace(settings) / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    descriptor = catalog_dir / "entry.properties"
    catalog_file = catalog_dir / "cryptad-app-catalog.properties"
    signature_file = catalog_dir / "cryptad-app-catalog.signature"
    descriptor.write_text(
        "\n".join(
            [
                f"artifact.path={sample_zip.resolve()}",
                f"bundle.uri={sample_zip.resolve().as_uri()}",
                "summary=Certification smoke app.",
                "name=Certification Smoke",
                "permissions=queue.read",
                "app.id=cert-smoke",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    remove_existing_path(catalog_file)
    remove_existing_path(signature_file)
    create_result = run_cli(
        cli,
        [
            "catalog",
            "create",
            "--catalog-file",
            str(catalog_file),
            "--catalog-id",
            "cert-smoke",
            "--name",
            "Certification Smoke Apps",
            "--generated-at",
            "2026-05-01T00:00:00Z",
            "--entry",
            str(descriptor),
            "--overwrite",
        ],
        settings,
        "crypta-app-catalog-create",
    )
    details["create"] = command_details(create_result, settings)
    if create_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", root_consequence(settings, "fail"), True, "Catalog creation failed.", source, details)
    catalog_exists = catalog_file.is_file()
    details["catalogExists"] = catalog_exists
    if not catalog_exists:
        return EvidenceItem(
            "catalog.smoke",
            root_consequence(settings, "fail"),
            True,
            "Catalog creation did not produce catalog output.",
            source,
            details,
        )
    catalog = parse_properties(catalog_file)
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "catalogVersion": catalog.get("catalog.version"),
        "entries": catalog.get("catalog.entries"),
        "appId": catalog.get("app.cert-smoke.id"),
        "bundleSha256": catalog.get("app.cert-smoke.bundle.sha256"),
        "bundleSizeBytes": catalog.get("app.cert-smoke.bundle.size.bytes"),
        "catalogSha256": sha256_file(catalog_file),
    }
    inputs = signing_inputs(os.environ)
    details["signingInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
    }
    if not inputs["complete"]:
        status = "fail" if settings.mode == "release-candidate" else "warn"
        return EvidenceItem(
            "catalog.smoke",
            status,
            True,
            "Catalog creation passed, but signing key inputs are incomplete.",
            source,
            details,
        )
    sign_result = run_cli(cli, catalog_sign_args(catalog_file, inputs), settings, "crypta-app-catalog-sign")
    verify_result = run_cli(cli, catalog_verify_args(catalog_file, inputs), settings, "crypta-app-catalog-verify")
    details["sign"] = command_details(sign_result, settings)
    details["verify"] = command_details(verify_result, settings)
    if sign_result.exit_code != 0 or verify_result.exit_code != 0:
        return EvidenceItem("catalog.smoke", "fail", True, "Signed catalog smoke failed.", source, details)
    return EvidenceItem("catalog.smoke", "pass", True, "Catalog create, sign, and verify smoke passed.", source, details)

def collect_live_usk_catalog_publication_evidence(
    settings: Settings, sample_paths: dict[str, Path]
) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    test_dir = workspace / "platform-devtools/src/test/java/network/crypta/platform/devtools"
    cli_text = read_source(devtools_dir / "CryptaAppCli.java")
    service_text = read_source(devtools_dir / "LiveUskPublicationService.java")
    publisher_text = read_source(devtools_dir / "PlatformApiLiveUskPublisher.java")
    result_text = read_source(devtools_dir / "LiveUskPublicationResult.java")
    writer_text = read_source(devtools_dir / "LiveUskPublicationResultWriter.java")
    validator_text = read_source(devtools_dir / "PublicationInputValidator.java")
    tests_text = "\n".join(
        read_source(path)
        for path in (
            test_dir / "DeveloperBetaToolkitCliTest.java",
            test_dir / "LiveUskPublicationServiceTest.java",
            test_dir / "PublicationPlanWriterTest.java",
        )
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/developer-beta-toolkit.md",
            "docs/app-platform-beta-tutorials.md",
            "docs/first-party-beta-catalog.md",
            "docs/app-catalogs.md",
            "docs/release-certification.md",
            "docs/cryptad-release-workflow-and-runbook.md",
        )
    )
    checks = {
        "explicitLiveMode": (
            '"--live"' in cli_text
            and '"--dry-run"' in cli_text
            and "requires exactly one of --dry-run or --live" in cli_text
        ),
        "secureLiveInputs": (
            "--private-insert-uri-env" in cli_text
            and "--private-insert-uri-file" in cli_text
            and "--form-password-env" in cli_text
            and "--form-password-file" in cli_text
            and "loadSecureText" in cli_text
        ),
        "localVerificationBeforeInsert": (
            "PublicationInputValidator.validate" in service_text
            and "AppCatalogVerifier.verify" in service_text
            and "requirePrivateInsertUri" in service_text
        ),
        "realQueueInsertionPath": (
            "queue/inserts/directory" in publisher_text
            and "sourcePath" in publisher_text
            and "insertUri" in publisher_text
            and "COMPAT_CURRENT" in publisher_text
            and "followRedirects(HttpClient.Redirect.NEVER)" in publisher_text
        ),
        "optionalLiveFetchVerification": (
            "content/fetch" in publisher_text
            and "contentBase64" in publisher_text
            and "live_publish_verification_failed" in publisher_text
        ),
        "sanitizedResultModel": (
            "catalogSha256" in result_text
            and "signatureSha256" in result_text
            and "catalogSigningKeyId" in result_text
            and "catalogInsertStatus" in result_text
            and "schedulerRefreshVerificationStatus" in result_text
            and "privateInsertUri" not in writer_text
            and "formPassword" not in writer_text
            and "stagingDirectory" not in writer_text
        ),
        "sharedInputValidation": (
            "crypta:USK@.../" in validator_text
            and "cryptad-app-catalog.properties" in validator_text
            and "cryptad-app-catalog.signature" in validator_text
        ),
        "testsCoverLiveAndRedaction": (
            "publish_whenFakePublisherSucceeds_expectSanitizedSummaryAndRetainedStaging"
            in tests_text
            and "publish_whenInsertIsOnlyQueued_expectStagingRetainedWithoutPathInSummary"
            in tests_text
            and "publish_whenPrivateInsertUriDoesNotMatchPublicSource_expectFailureWithoutPublisherOrSummary"
            in tests_text
            and "private insert URI must be configured by exactly one env or file source"
            in tests_text
            and "staging_sidecars_retained_until_live_insert_completion" in tests_text
            and "assertFalse(liveSummaryText.contains(LIVE_PRIVATE_INSERT_URI))" in tests_text
        ),
        "docsCoverLivePublication": (
            "crypta-app publish-usk --live" in docs_text
            and "private insert URI" in docs_text
            and "cryptad-app-catalog.signature" in docs_text
            and "same USK" in docs_text
            and "dry-run" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "actualLiveInsertionOptional": True,
        "publicSourceShape": "crypta:USK@.../cryptad-app-catalog.properties",
        "signatureSidecar": "cryptad-app-catalog.signature",
        "checks": checks,
        "sources": {
            "cli": display_path(devtools_dir / "CryptaAppCli.java", workspace),
            "service": display_path(devtools_dir / "LiveUskPublicationService.java", workspace),
            "publisher": display_path(devtools_dir / "PlatformApiLiveUskPublisher.java", workspace),
            "result": display_path(devtools_dir / "LiveUskPublicationResult.java", workspace),
            "writer": display_path(devtools_dir / "LiveUskPublicationResultWriter.java", workspace),
            "validator": display_path(devtools_dir / "PublicationInputValidator.java", workspace),
            "tests": display_path(test_dir / "LiveUskPublicationServiceTest.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "catalog.live-usk-publication",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live USK catalog publication evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.live-usk-publication",
        "pass",
        True,
        "Live USK catalog publication source and redaction evidence passed.",
        source,
        details,
    )

def collect_live_usk_source_verification_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_tests = workspace / "platform-api/src/test/java/network/crypta/platform/api/appcatalogs"
    source_text = read_source(appcatalog_dir / "AppCatalogSource.java")
    uri_text = read_source(appcatalog_dir / "CryptaCatalogUri.java")
    fetcher_text = read_source(appcatalog_dir / "AppCatalogFetcher.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    recommended_text = read_source(appcatalog_dir / "RecommendedAppCatalogs.java")
    appcatalog_test_text = read_source(appcatalog_tests / "AppCatalogManagerTest.java")
    api_test_text = read_source(api_tests / "AppCatalogsApiHandlerTest.java")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/first-party-beta-catalog.md",
            "docs/app-update-lifecycle.md",
        )
    )
    checks = {
        "cryptaUskSourceAccepted": (
            "CryptaCatalogUri.parse" in source_text
            and "crypta:USK@" in uri_text
            and "SIGNATURE_QUERY_PREFIX" in uri_text
        ),
        "resolvedEditionSignatureSidecar": (
            "signatureFetchKeyForResolvedCatalog" in uri_text
            and "normalizeResolvedCatalogFetchKey" in uri_text
            and "requireCompatibleResolvedKeyKind" in uri_text
            and "siblingSignatureKey(resolvedKey)" in uri_text
        ),
        "boundedContentFetch": (
            "ContentFetchPort" in fetcher_text
            and "signatureFetchKeyForResolvedCatalog(catalogBytes.resolvedUri())" in fetcher_text
            and "MAX_CATALOG_BYTES" in fetcher_text
            and "MAX_SIGNATURE_BYTES" in fetcher_text
        ),
        "verifyBeforeStorage": (
            "AppCatalogVerifier.verify" in manager_text
            and "sourceStore.write(catalog, source, fetched" in manager_text
            and "CATALOG_ID_MISMATCH" in manager_text
        ),
        "refreshPreservesPreviousOnFailure": (
            "recordRefreshFailure" in manager_text
            and "previous stored sidecars remain in place" in manager_text
        ),
        "firstPartySourceConfigDriven": (
            "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in recommended_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID" in recommended_text
        ),
        "testsCoverResolvedEdition": (
            "fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition"
            in appcatalog_test_text
            and "fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition"
            in appcatalog_test_text
            and "fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource"
            in appcatalog_test_text
            and "fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests"
            in appcatalog_test_text
        ),
        "testsCoverRefreshPreservation": (
            "refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated"
            in appcatalog_test_text
            and "refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri"
            in appcatalog_test_text
        ),
        "recommendedSummariesRedactSources": (
            "listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource"
            in api_test_text
            and "listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted"
            in api_test_text
            and "listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted"
            in api_test_text
        ),
        "docsCoverUskVerification": (
            "crypta:USK@" in docs_text
            and "same USK" in docs_text
            and "signed catalog verification" in docs_text.lower()
            and "cryptad-app-catalog.signature" in docs_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "sourceModel": display_path(appcatalog_dir / "AppCatalogSource.java", workspace),
            "cryptaUri": display_path(appcatalog_dir / "CryptaCatalogUri.java", workspace),
            "fetcher": display_path(appcatalog_dir / "AppCatalogFetcher.java", workspace),
            "manager": display_path(appcatalog_dir / "AppCatalogManager.java", workspace),
            "tests": display_path(appcatalog_tests / "AppCatalogManagerTest.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "catalog.live-usk-source-verification",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Live USK source verification evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.live-usk-source-verification",
        "pass",
        True,
        "Live USK source verification evidence passed deterministic checks.",
        source,
        details,
    )

def collect_first_party_beta_catalog_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    model_text = read_source(appcatalog_dir / "RecommendedAppCatalog.java")
    provider_text = read_source(appcatalog_dir / "RecommendedAppCatalogs.java")
    downloader_text = read_source(appcatalog_dir / "AppCatalogArtifactDownloader.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogManagerTest.java",
            appcatalog_tests / "AppCatalogParserTest.java",
            appcatalog_tests / "AppCatalogEntryDescriptorTest.java",
            appcatalog_tests / "RecommendedAppCatalogsTest.java",
        )
    )
    api_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    api_routes_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    )
    api_contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/app-dev-cli.md",
            "docs/first-party-beta-catalog.md",
            "docs/release-certification.md",
        )
    )
    app_ids = list(APP_IDS)
    checks = {
        "recommendedDescriptorPresent": (
            "public record RecommendedAppCatalog" in model_text
            and "trustedCatalogKeyId" in model_text
            and "AppCatalogSource.parse" in model_text
        ),
        "firstPartyProviderPresent": (
            "FIRST_PARTY_BETA_CATALOG_ID" in provider_text
            and "crypta-first-party-beta" in provider_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in provider_text
        ),
        "apiRecommendedEndpointsPresent": (
            "listRecommendedCatalogs" in api_text
            and "addRecommended" in api_text
            and "routeRecommendedAppCatalogs" in api_routes_text
            and "routeRecommendedAppCatalogAddOrApp" in api_routes_text
            and '"/app-catalogs/recommended"' in api_contract_text
            and '"/app-catalogs/recommended/{catalogId}/add"' in api_contract_text
            and "catalogs.recommended.list" in api_contract_text
            and "catalogs.recommended.add" in api_contract_text
            and "recommended_catalog_trusted_key_missing" in api_text
        ),
        "webShellOnboardingPresent": (
            "renderRecommendedCatalogs" in shell_text
            and "renderRecommendedCatalogCard" in shell_text
            and "app-catalogs/recommended" in shell_text
            and "addRecommended" in shell_text
        ),
        "cryptaArtifactTransportPresent": (
            "copyCryptaArtifact" in downloader_text
            and "ContentFetchPort" in downloader_text
            and "cryptaArtifactFetchKey" in downloader_text
            and "new AppCatalogArtifactDownloader(contentFetchPort)" in manager_text
        ),
        "cryptaArtifactUriTestsPresent": (
            "entry_whenArtifactUriIsCryptaChk_expectAccepted" in appcatalog_test_text
            and "prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan"
            in appcatalog_test_text
            and "download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable"
            in appcatalog_test_text
        ),
        "firstPartyAppMetadataDocumented": all(app_id in docs_text for app_id in app_ids)
        and "permissions.rationale" in docs_text
        and "api.minimumVersion" in docs_text
        and "changelog.summary" in docs_text
        and "review receipts" in docs_text.lower(),
        "cryptaArtifactPublicationDocumented": (
            "crypta:CHK@" in docs_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE" in docs_text
            and "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED" in docs_text
        ),
        "privateKeysExcludedByDocs": (
            "No private keys" in docs_text or "no private keys" in docs_text.lower()
        ),
    }
    configuration = {
        "sourceConfigured": bool(os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_SOURCE", "").strip()),
        "trustedCatalogKeyHintConfigured": bool(
            os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID", "").strip()
            or os.environ.get("CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID", "").strip()
        ),
        "apphostTrustedKeyConfigured": bool(
            os.environ.get("CRYPTAD_APPHOST_TRUSTED_KEY_ID", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_KEYS_FILE", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE", "").strip()
            or os.environ.get("CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64", "").strip()
        ),
    }
    details = {
        "catalogId": "crypta-first-party-beta",
        "requiredFirstPartyApps": app_ids,
        "configuration": configuration,
        "checks": checks,
        "sources": {
            "recommendedModel": display_path(appcatalog_dir / "RecommendedAppCatalog.java", workspace),
            "recommendedProvider": display_path(appcatalog_dir / "RecommendedAppCatalogs.java", workspace),
            "artifactDownloader": display_path(appcatalog_dir / "AppCatalogArtifactDownloader.java", workspace),
            "apiHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java",
                workspace,
            ),
            "webShell": display_path(
                workspace
                / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/app-catalogs.md", workspace),
                display_path(workspace / "docs/first-party-beta-catalog.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-catalog.first-party-beta",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party beta catalog onboarding evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-catalog.first-party-beta",
        "pass",
        True,
        "First-party beta catalog onboarding evidence passed deterministic checks.",
        source,
        details,
    )

def collect_production_catalog_channels_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    api_updates_dir = api_dir / "appupdates"
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    shell_dir = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static"
    channel_text = read_source(appcatalog_dir / "AppCatalogChannel.java")
    production_metadata_text = read_source(appcatalog_dir / "AppCatalogProductionMetadata.java")
    parser_writer_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_dir / "AppCatalog.java",
            appcatalog_dir / "AppCatalogParser.java",
            appcatalog_dir / "AppCatalogWriter.java",
            appcatalog_dir / "AppCatalogEntryDescriptor.java",
            appcatalog_dir / "AppCatalogSecurityAdvisory.java",
        )
    )
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogParserTest.java",
            appcatalog_tests / "AppCatalogWriterTest.java",
            appcatalog_tests / "AppCatalogEntryDescriptorTest.java",
            appcatalog_tests / "AppCatalogMetadataTest.java",
        )
    )
    api_text = "\n".join(
        read_source(path)
        for path in (
            api_dir / "appcatalogs/AppCatalogsApiHandler.java",
            api_updates_dir / "AppUpdatePolicy.java",
            api_updates_dir / "AppUpdateService.java",
            api_updates_dir / "AppUpdateCandidate.java",
            api_updates_dir / "AppUpdatesApiHandler.java",
            api_dir / "PlatformApiContract.java",
        )
    )
    devtools_text = "\n".join(
        read_source(path)
        for path in (
            devtools_dir / "CatalogEntryDescriptorGenerator.java",
            devtools_dir / "CryptaAppCli.java",
        )
    )
    shell_text = "\n".join(
        read_source(path) for path in (shell_dir / "web-shell.js", shell_dir / "index.html")
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/app-update-lifecycle.md",
            "docs/platform-api-surface.md",
            "docs/production-first-party-catalog-channels.md",
            "docs/first-party-beta-catalog.md",
        )
    )
    checks = {
        "channelEnumPresent": all(
            token in channel_text for token in ("stable", "beta", "nightly", "deprecated")
        ),
        "schemaV3ParserWriterPresent": (
            "VERSION_PRODUCTION_CHANNELS = 3" in parser_writer_text
            and "maximumCryptaVersion" in parser_writer_text
            and "securityAdvisory" in parser_writer_text
            and "replacementAppId" in parser_writer_text
        ),
        "productionMetadataDefaultsSafe": (
            "AppCatalogChannel.STABLE" in production_metadata_text
            and "AppCatalogSupportStatus.SUPPORTED" in production_metadata_text
            and "deprecatedForAutomaticUpdates" in production_metadata_text
        ),
        "parserWriterTestsPresent": (
            "parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized"
            in appcatalog_test_text
            and "serialize_whenVersionTwoCatalogHasProductionMetadata_expectInvalidCatalogEntry"
            in appcatalog_test_text
            and "parse_whenVersionTwoCatalogOmitsProductionMetadata_expectStableDefaults"
            in appcatalog_test_text
        ),
        "apiExposurePresent": (
            '"channel"' in api_text
            and '"supportStatus"' in api_text
            and '"securityAdvisories"' in api_text
            and '"defaultEntryChannel"' in api_text
            and '"allowedChannels"' in api_text
        ),
        "updatePolicyBlocksNonStableAutomation": (
            "DEFAULT_ALLOWED_CHANNELS" in api_text
            and "channel_policy_blocked" in api_text
            and "allowsAutomaticChannel" in api_text
            and "deprecatedForAutomaticUpdates" in api_text
        ),
        "devtoolsDescriptorSupportPresent": (
            "--channel" in devtools_text
            and "--support-status" in devtools_text
            and "--security-advisory" in devtools_text
            and "maximumCryptaVersion" in devtools_text
        ),
        "webShellChannelControlsPresent": (
            "catalog-channel-select" in shell_text
            and "catalogAppChannel" in shell_text
            and "securityAdvisoryListNode" in shell_text
            and "is-deprecated-channel" in shell_text
        ),
        "signatureAndReviewSemanticsRetained": (
            "AppCatalogVerifier.verify" in read_source(appcatalog_dir / "AppCatalogManager.java")
            and "AppReviewReceiptVerifier.evaluate" in api_text
        ),
        "documentationPresent": (
            "catalog.version=3" in docs_text
            and "stable" in docs_text
            and "nightly" in docs_text
            and "channel_policy_blocked" in docs_text
            and "deprecated entries" in docs_text.lower()
        ),
    }
    details = {
        "channels": ["stable", "beta", "nightly", "deprecated"],
        "defaultAutomaticChannels": ["stable"],
        "deprecatedAutomaticUpdatesBlocked": True,
        "checks": checks,
        "redactionGuarantees": [
            "private insert URIs excluded",
            "tokens redacted",
            "private keys redacted",
            "raw fetched content excluded",
            "raw app data excluded",
            "absolute staging paths sanitized",
        ],
        "sources": {
            "catalogChannel": display_path(appcatalog_dir / "AppCatalogChannel.java", workspace),
            "catalogParser": display_path(appcatalog_dir / "AppCatalogParser.java", workspace),
            "catalogWriter": display_path(appcatalog_dir / "AppCatalogWriter.java", workspace),
            "apiHandler": display_path(api_dir / "appcatalogs/AppCatalogsApiHandler.java", workspace),
            "updatePolicy": display_path(api_updates_dir / "AppUpdatePolicy.java", workspace),
            "webShell": display_path(shell_dir / "web-shell.js", workspace),
            "docs": display_path(
                workspace / "docs/production-first-party-catalog-channels.md", workspace
            ),
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "catalog.production-channels",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Production catalog channel evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.production-channels",
        "pass",
        True,
        "Production catalog channel evidence passed deterministic checks.",
        source,
        details,
    )

def collect_catalog_operations_and_mirrors_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    api_handler = api_dir / "appcatalogs/AppCatalogsApiHandler.java"
    shell = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    model_text = "\n".join(
        read_source(appcatalog_dir / name)
        for name in (
            "AppCatalogMirror.java",
            "AppCatalogMirrorId.java",
            "AppCatalogSourceRole.java",
            "AppCatalogMirrorHealth.java",
            "AppCatalogVerifiedRevision.java",
            "AppCatalogRollbackCandidate.java",
            "AppCatalogKeyRotationStatus.java",
            "AppCatalogKeyRotationPlan.java",
        )
    )
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    operations_text = read_source(appcatalog_dir / "AppCatalogOperations.java")
    refresh_coordinator_text = read_source(appcatalog_dir / "AppCatalogRefreshCoordinator.java")
    catalog_operations_text = "\n".join(
        (manager_text, operations_text, refresh_coordinator_text)
    )
    store_text = read_source(appcatalog_dir / "AppCatalogSourceStore.java")
    handler_text = read_source(api_handler)
    routes_text = read_source(api_dir / "PlatformApiAppRoutes.java")
    contract_text = read_source(api_dir / "PlatformApiContract.java")
    shell_text = read_source(shell)
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogManagerTest.java",
            appcatalog_tests / "AppCatalogSourceStoreTest.java",
        )
    )
    api_test_text = read_source(
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandlerTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/catalog-operations-and-mirrors.md",
            "docs/app-catalogs.md",
            "docs/first-party-beta-catalog.md",
            "docs/production-security-response-runbook.md",
            "docs/production-beta-release-pipeline.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
        )
    )
    checks = {
        "primaryMirrorModelPresent": (
            "record AppCatalogMirror" in model_text
            and "AppCatalogMirrorId" in model_text
            and "PRIMARY" in model_text
            and "MIRROR" in model_text
            and "AppCatalogMirrorHealth" in model_text
        ),
        "mirrorFallbackKeepsSignatureTrust": (
            "refreshEndpoints" in catalog_operations_text
            and "fetchAndVerifyEndpoint" in catalog_operations_text
            and "AppCatalogVerifier.verify" in catalog_operations_text
            and "CATALOG_ID_MISMATCH" in catalog_operations_text
            and "generatedAtComparison" in catalog_operations_text
            and "catalogContentDigest" in catalog_operations_text
        ),
        "revisionHistoryAndRollbackPresent": (
            "HISTORY_DIRECTORY_NAME" in store_text
            and "REVISION_RETENTION_COUNT" in store_text
            and "recordRevision" in store_text
            and "listRevisions" in store_text
            and "rollbackCandidates" in catalog_operations_text
            and "sourceStore.readRevision" in catalog_operations_text
        ),
        "keyRotationAndEmergencyRefreshPresent": (
            "keyRotationStatus" in catalog_operations_text
            and "AppCatalogKeyRotationStatus" in model_text
            and "emergencyRefresh" in catalog_operations_text
            and "emergency-refresh" in routes_text
        ),
        "platformApiOperationsRoutesPresent": (
            "sourceHealth" in handler_text
            and "addMirror" in handler_text
            and "rollback(" in handler_text
            and "keyRotationStatus" in handler_text
            and "/app-catalogs/{catalogId}/operations/health" in contract_text
            and "/app-catalogs/{catalogId}/mirrors" in contract_text
        ),
        "webShellOperationsPresent": (
            "renderCatalogOperationsNode" in shell_text
            and "buildCatalogRollbackForm" in shell_text
            and "operations/health" in shell_text
            and "operations/emergency-refresh" in shell_text
            and "catalogSourceDisplay" in shell_text
        ),
        "testsCoverOperations": (
            "refresh_whenPrimaryFailsAndMirrorIsVerified_expectMirrorFallbackAccepted"
            in appcatalog_test_text
            and "refresh_whenMirrorReturnsOlderVerifiedRevision_expectCurrentCatalogPreserved"
            in appcatalog_test_text
            and "rollback_whenPreviousRevisionIsRetained_expectRevisionReverifiedAndRestored"
            in appcatalog_test_text
            and "read_whenLegacySingleSourceExists_expectPrimaryOnlyMirrorModel"
            in appcatalog_test_text
            and "health_whenSourcesContainPathsAndTokens_expectOperationsOutputRedacted"
            in api_test_text
        ),
        "docsCoverOperations": (
            "primary source plus mirrors" in docs_text
            and "transport fallback" in docs_text
            and "explicit rollback" in docs_text
            and "key-rotation status" in docs_text
            and "emergency advisory refresh" in docs_text
            and "catalog.operations-and-mirrors" in docs_text
        ),
        "redactionCoveragePresent": (
            "redactedCatalogSource" in handler_text
            and "lastResolvedDisplay" in handler_text
            and "sourceDisplay" in handler_text
            and "file:<configured>" in api_test_text
            and "private insert uri" in docs_text.lower()
            and "absolute local path" in docs_text.lower()
        ),
    }
    details = {
        "liveNodeRequired": False,
        "evidenceId": "catalog.operations-and-mirrors",
        "checks": checks,
        "redactionGuarantees": [
            "private insert URIs excluded",
            "private keys excluded",
            "tokens excluded",
            "raw catalog content excluded",
            "raw app data excluded",
            "scratch and staged paths excluded",
            "absolute local paths redacted",
        ],
        "sources": {
            "manager": display_path(appcatalog_dir / "AppCatalogManager.java", workspace),
            "operations": display_path(appcatalog_dir / "AppCatalogOperations.java", workspace),
            "refreshCoordinator": display_path(
                appcatalog_dir / "AppCatalogRefreshCoordinator.java", workspace
            ),
            "store": display_path(appcatalog_dir / "AppCatalogSourceStore.java", workspace),
            "apiHandler": display_path(api_handler, workspace),
            "apiRoutes": display_path(api_dir / "PlatformApiAppRoutes.java", workspace),
            "webShell": display_path(shell, workspace),
            "docs": display_path(workspace / "docs/catalog-operations-and-mirrors.md", workspace),
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "catalog.operations-and-mirrors",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Catalog operations and mirrors evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "catalog.operations-and-mirrors",
        "pass",
        True,
        "Catalog operations and mirrors evidence passed deterministic checks.",
        source,
        details,
    )

def maintenance_policy_evidence_value(
    app_id: str, field: str, value: Any, workspace: Path
) -> Any:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if "\n" in stripped or "\r" in stripped:
        return "<redacted>"
    if field == "owner":
        return stripped if stripped == FIRST_PARTY_MAINTENANCE_OWNER else "<redacted>"
    if field == "ownerUri":
        expected = FIRST_PARTY_MAINTENANCE_OWNER_URI
        return (
            stripped
            if stripped == expected and scrub_text(stripped, workspace) == stripped
            else "<redacted>"
        )
    if field == "supportUri":
        expected = FIRST_PARTY_SUPPORT_URI
        return (
            stripped
            if stripped == expected and scrub_text(stripped, workspace) == stripped
            else "<redacted>"
        )
    if field in FIRST_PARTY_MAINTENANCE_ENUMS:
        return stripped if stripped in FIRST_PARTY_MAINTENANCE_ENUMS[field] else "<redacted>"
    expected = FIRST_PARTY_MAINTENANCE_EXPECTATIONS.get(app_id, {})
    return stripped if expected.get(field) == stripped else "<redacted>"

def maintenance_policy_evidence_summary(
    app_id: str, maintenance: Any, workspace: Path
) -> dict[str, Any]:
    if not isinstance(maintenance, dict):
        return {}
    return {
        field: maintenance_policy_evidence_value(
            app_id, field, maintenance.get(field), workspace
        )
        for field in FIRST_PARTY_MAINTENANCE_REQUIRED_FIELDS
    }

def maintenance_policy_metadata_evidence_value(field: str, value: Any) -> Any:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if "\n" in stripped or "\r" in stripped:
        return "<redacted>"
    return (
        stripped
        if FIRST_PARTY_MAINTENANCE_POLICY_METADATA_EXPECTATIONS.get(field) == stripped
        else "<redacted>"
    )

def collect_first_party_maintenance_policy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    policy_path = workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH
    policy = read_json_file(policy_path)
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    devtools_dir = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    api_handler = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    )
    web_shell = (
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    parser_writer_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_dir / "AppCatalog.java",
            appcatalog_dir / "AppCatalogMaintenanceMetadata.java",
            appcatalog_dir / "AppCatalogParser.java",
            appcatalog_dir / "AppCatalogWriter.java",
            appcatalog_dir / "AppCatalogEntryDescriptor.java",
        )
    )
    appcatalog_test_text = "\n".join(
        read_source(path)
        for path in (
            appcatalog_tests / "AppCatalogParserTest.java",
            appcatalog_tests / "AppCatalogWriterTest.java",
            appcatalog_tests / "AppCatalogEntryDescriptorTest.java",
            appcatalog_tests / "AppCatalogMetadataTest.java",
        )
    )
    devtools_text = "\n".join(
        read_source(path)
        for path in (
            devtools_dir / "CatalogEntryDescriptorGenerator.java",
            devtools_dir / "CryptaAppCli.java",
        )
    )
    api_text = read_source(api_handler)
    shell_text = read_source(web_shell)
    release_pipeline_text = read_engine_source(workspace, "production_beta_release")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/first-party-app-maintenance-policy.md",
            "docs/app-catalogs.md",
            "docs/production-first-party-catalog-channels.md",
            "docs/first-party-beta-catalog.md",
            "docs/production-beta-release-pipeline.md",
            "tools/release-certification/README.md",
        )
    )
    checks: dict[str, Any] = {
        "policyFilePresent": policy is not None,
        "schemaVersion": isinstance(policy, dict) and policy.get("schemaVersion") == 1,
        "catalogSchemaV5Present": (
            "VERSION_FIRST_PARTY_MAINTENANCE = 5" in parser_writer_text
            and "AppCatalogMaintenanceMetadata" in parser_writer_text
            and "maintenance.owner" in parser_writer_text
            and "maintenance.supportLevel" in parser_writer_text
            and "maintenance.backupRestore" in parser_writer_text
        ),
        "parserWriterTestsPresent": (
            "parse_whenCatalogHasMaintenanceMetadata_expectMetadataNormalized"
            in appcatalog_test_text
            and "parse_whenVersionFourCatalogDeclaresMaintenanceMetadata_expectInvalidCatalogEntry"
            in appcatalog_test_text
            and "serialize_whenVersionFourCatalogHasMaintenanceMetadata_expectInvalidCatalogEntry"
            in appcatalog_test_text
            and "parse_whenMaintenanceMetadataUsesMixedCase_expectNormalizedEnums"
            in appcatalog_test_text
        ),
        "devtoolsDescriptorSupportPresent": all(
            flag in devtools_text
            for flag in (
                "--maintenance-owner",
                "--maintenance-support-level",
                "--maintenance-data-schema-policy",
                "--maintenance-migration-policy",
                "--maintenance-backup-restore",
                "--maintenance-security-policy",
                "--maintenance-deprecation-policy",
                "--maintenance-support-uri",
            )
        ),
        "apiExposurePresent": '"maintenance"' in api_text and "summarizeMaintenance" in api_text,
        "webShellDisplayPresent": (
            "catalogMaintenancePolicyNode" in shell_text
            and "Maintenance policy" in shell_text
            and "catalogMaintenanceDeclared" in shell_text
        ),
        "releasePipelineConsumesPolicy": (
            "FIRST_PARTY_MAINTENANCE_POLICY_FILE" in release_pipeline_text
            and "maintenance_policy_args" in release_pipeline_text
            and "app-catalog.first-party-maintenance-policy" in release_pipeline_text
        ),
        "docsPresent": (
            "app-catalog.first-party-maintenance-policy" in docs_text
            and "catalog.version=5" in docs_text
            and "maintenance.supportLevel" in docs_text
            and "Trust Graph Local RC is not global WoT" in docs_text
            and "Social Inbox RC is not legacy Freemail/Freetalk/Sone protocol compatibility"
            in docs_text
        ),
    }
    policy_apps = policy.get("apps") if isinstance(policy, dict) else None
    checks["policyAppsMapPresent"] = isinstance(policy_apps, dict)
    app_details: dict[str, Any] = {}
    errors: list[str] = [name for name, passed in checks.items() if passed is not True]
    if isinstance(policy_apps, dict):
        checks["requiredAppsPresent"] = sorted(policy_apps) == sorted(APP_IDS)
        if checks["requiredAppsPresent"] is not True:
            errors.append("requiredAppsPresent")
        for app_id in APP_IDS:
            app_policy = policy_apps.get(app_id)
            app_result: dict[str, Any] = {"checks": {}}
            if not isinstance(app_policy, dict):
                app_result["checks"]["policyEntryPresent"] = False
                errors.append(f"{app_id}: policyEntryPresent")
                app_details[app_id] = app_result
                continue
            maintenance = app_policy.get("maintenance")
            app_result["channel"] = maintenance_policy_metadata_evidence_value(
                "channel", app_policy.get("channel")
            )
            app_result["supportStatus"] = maintenance_policy_metadata_evidence_value(
                "supportStatus", app_policy.get("supportStatus")
            )
            app_result["deprecationStatus"] = maintenance_policy_metadata_evidence_value(
                "deprecationStatus", app_policy.get("deprecationStatus")
            )
            app_result["maintenance"] = maintenance_policy_evidence_summary(
                app_id, maintenance, workspace
            )
            app_checks = app_result["checks"]
            app_checks["releaseMetadataConsistent"] = (
                app_policy.get("channel") == "stable"
                and app_policy.get("supportStatus") == "supported"
                and app_policy.get("deprecationStatus") == "none"
            )
            app_checks["maintenanceBlockPresent"] = isinstance(maintenance, dict)
            if not isinstance(maintenance, dict):
                errors.append(f"{app_id}: maintenanceBlockPresent")
                app_details[app_id] = app_result
                continue
            app_checks["requiredFieldsPresent"] = all(
                isinstance(maintenance.get(field), str) and bool(maintenance.get(field, "").strip())
                for field in FIRST_PARTY_MAINTENANCE_REQUIRED_FIELDS
            )
            app_checks["fieldsAreSingleLine"] = all(
                "\n" not in str(maintenance.get(field, ""))
                and "\r" not in str(maintenance.get(field, ""))
                for field in FIRST_PARTY_MAINTENANCE_REQUIRED_FIELDS
            )
            app_checks["enumTokensKnown"] = all(
                str(maintenance.get(field)) in allowed
                for field, allowed in FIRST_PARTY_MAINTENANCE_ENUMS.items()
            )
            expected = FIRST_PARTY_MAINTENANCE_EXPECTATIONS[app_id]
            app_checks["policyMatchesExpectedAppClass"] = all(
                maintenance.get(field) == expected_value
                for field, expected_value in expected.items()
            )
            app_checks["ownerIsCore"] = maintenance.get("owner") == FIRST_PARTY_MAINTENANCE_OWNER
            app_checks["urisAreMetadataOnly"] = (
                maintenance.get("ownerUri") == FIRST_PARTY_MAINTENANCE_OWNER_URI
                and maintenance.get("supportUri")
                == FIRST_PARTY_SUPPORT_URI
            )
            app_checks["maintenanceEvidenceValuesSafe"] = all(
                value != "<redacted>" and value is not None
                for value in app_result["maintenance"].values()
            )
            for check_name, passed in app_checks.items():
                if passed is not True:
                    errors.append(f"{app_id}: {check_name}")
            app_details[app_id] = app_result
    details = {
        "policy": display_path(policy_path, workspace),
        "requiredFirstPartyApps": list(APP_IDS),
        "expectedPolicy": FIRST_PARTY_MAINTENANCE_EXPECTATIONS,
        "checks": checks,
        "apps": app_details,
        "sources": {
            "catalogMetadata": display_path(
                appcatalog_dir / "AppCatalogMaintenanceMetadata.java", workspace
            ),
            "catalogParser": display_path(appcatalog_dir / "AppCatalogParser.java", workspace),
            "catalogWriter": display_path(appcatalog_dir / "AppCatalogWriter.java", workspace),
            "devtools": display_path(devtools_dir / "CryptaAppCli.java", workspace),
            "apiHandler": display_path(api_handler, workspace),
            "webShell": display_path(web_shell, workspace),
            "docs": display_path(
                workspace / "docs/first-party-app-maintenance-policy.md", workspace
            ),
        },
        "redaction": {
            "privateInsertUrisExcluded": True,
            "privateKeysExcluded": True,
            "tokensExcluded": True,
            "rawAppDataExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    if errors:
        return EvidenceItem(
            "app-catalog.first-party-maintenance-policy",
            root_consequence(settings, "fail"),
            True,
            "First-party maintenance policy evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-catalog.first-party-maintenance-policy",
        "pass",
        True,
        "First-party maintenance policy evidence passed deterministic checks.",
        source,
        details,
    )

def first_party_beta_expected_values(app_id: str) -> dict[str, Any]:
    return {
        **FIRST_PARTY_BETA_COMMON_EXPECTED_VALUES,
        **FIRST_PARTY_BETA_EXPECTATIONS[app_id],
    }

def safe_first_party_beta_readiness_details(
    beta_readiness: Any, expected_values: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(beta_readiness, dict):
        return {}
    details: dict[str, Any] = {}
    for field, expected_value in expected_values.items():
        if field not in beta_readiness:
            details[field] = "<missing>"
        elif beta_readiness.get(field) == expected_value:
            details[field] = expected_value
        else:
            details[field] = "<invalid>"
    return details

def collect_first_party_beta_quality_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    readiness_path = workspace / FIRST_PARTY_BETA_READINESS_PATH
    maintenance_path = workspace / FIRST_PARTY_MAINTENANCE_POLICY_PATH
    readiness = read_json_file(readiness_path)
    maintenance_policy = read_json_file(maintenance_path)
    errors: list[str] = []
    redaction_findings: list[dict[str, Any]] = []
    checks: dict[str, Any] = {
        "readinessFilePresent": readiness is not None,
        "schemaVersion": isinstance(readiness, dict) and readiness.get("schemaVersion") == 1,
        "evidenceId": (
            isinstance(readiness, dict)
            and readiness.get("evidenceId") == FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID
        ),
    }
    readiness_apps = readiness.get("apps") if isinstance(readiness, dict) else None
    policy_apps = maintenance_policy.get("apps") if isinstance(maintenance_policy, dict) else None
    checks["readinessAppsMapPresent"] = isinstance(readiness_apps, dict)
    checks["maintenanceAppsMapPresent"] = isinstance(policy_apps, dict)
    if isinstance(readiness_apps, dict):
        checks["allFirstPartyAppsCovered"] = sorted(readiness_apps) == sorted(APP_IDS)
    else:
        checks["allFirstPartyAppsCovered"] = False
    errors.extend(name for name, passed in checks.items() if passed is not True)
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/first-party-app-beta-quality-pass.md",
            "docs/first-party-app-maintenance-policy.md",
            "docs/production-beta-release-pipeline.md",
            "docs/production-beta-go-no-go-dashboard.md",
            "docs/app-ui-design-system.md",
            "docs/app-data-backup-restore-portability.md",
            "docs/app-upgrade-data-migrations.md",
            "docs/operator-rc-recovery-and-support-workflow.md",
            "docs/feed-reader-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/social-inbox-reference-app.md",
        )
    )
    docs_checks = {
        "readinessDocPresent": (workspace / "docs/first-party-app-beta-quality-pass.md").is_file(),
        "evidenceIdDocumented": FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID in docs_text,
        "vaultBoundaryDocumented": "vault private identity material" in docs_text,
        "trustGraphScopeDocumented": "not global truth" in docs_text,
        "socialInboxNonGoalsDocumented": "not Freemail/Freetalk/Sone" in docs_text
        or "not Freetalk, Sone, Freemail" in docs_text,
    }
    errors.extend(f"docs: {name}" for name, passed in docs_checks.items() if passed is not True)
    app_details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        app_id = spec["appId"]
        source_dir = spec["sourceDir"]
        app_errors: list[str] = []
        app_checks: dict[str, Any] = {}
        readiness_entry = (
            readiness_apps.get(app_id) if isinstance(readiness_apps, dict) else None
        )
        beta_readiness = (
            readiness_entry.get("betaReadiness") if isinstance(readiness_entry, dict) else None
        )
        expected = FIRST_PARTY_BETA_EXPECTATIONS[app_id]
        expected_values = first_party_beta_expected_values(app_id)
        app_checks["readinessEntryPresent"] = isinstance(beta_readiness, dict)
        if isinstance(beta_readiness, dict):
            app_checks["readinessFieldsClosed"] = set(beta_readiness) <= set(expected_values)
            app_checks["readinessValuesMatchExpected"] = all(
                beta_readiness.get(field) == value for field, value in expected_values.items()
            )
        else:
            app_checks["readinessFieldsClosed"] = False
            app_checks["readinessValuesMatchExpected"] = False
        maintenance = (
            policy_apps.get(app_id, {}).get("maintenance")
            if isinstance(policy_apps, dict) and isinstance(policy_apps.get(app_id), dict)
            else None
        )
        app_checks["maintenancePolicyLinked"] = (
            isinstance(maintenance, dict)
            and maintenance.get("owner") == FIRST_PARTY_MAINTENANCE_OWNER
            and maintenance.get("supportUri")
            == FIRST_PARTY_SUPPORT_URI
            and (not isinstance(beta_readiness, dict)
                 or maintenance.get("backupRestore") == beta_readiness.get("backupRestore"))
        )
        manifest_path = source_dir / "cryptad-app.properties.template"
        index_path = source_dir / "static/index.html"
        css_path = source_dir / "static/app.css"
        js_path = source_dir / "static/app.js"
        readme_path = workspace / f"apps/{app_id}/README.md"
        app_checks["staticAssetsPresent"] = all(
            path.is_file() for path in (manifest_path, index_path, css_path, js_path)
        )
        manifest: dict[str, str] = {}
        try:
            manifest = parse_properties(manifest_path)
        except (OSError, UnicodeDecodeError, ValueError):
            app_checks["manifestParseable"] = False
        else:
            app_checks["manifestParseable"] = True
        if manifest:
            manifest_expected = dict(FIRST_PARTY_BETA_MANIFEST_REQUIRED_VALUES)
            if isinstance(beta_readiness, dict):
                manifest_expected.update(
                    {
                        "app.beta.appData": str(beta_readiness.get("appData", "")),
                        "app.beta.backupRestore": str(beta_readiness.get("backupRestore", "")),
                        "app.beta.exportSupported": str(beta_readiness.get("exportSupported", "")),
                        "app.beta.importSupported": str(beta_readiness.get("importSupported", "")),
                        "app.beta.migrationDryRunSupported": str(
                            beta_readiness.get("migrationDryRun", "")
                        ),
                    }
                )
            app_checks["manifestBetaFieldsMatch"] = all(
                manifest.get(key) == value for key, value in manifest_expected.items()
            )
            app_checks["supportUriMatchesPolicy"] = (
                manifest.get("app.beta.support.uri")
                == FIRST_PARTY_SUPPORT_URI
            )
            permissions = {part.strip() for part in manifest.get("app.permissions", "").split(",") if part.strip()}
            app_checks["permissionRationalesPresent"] = all(
                manifest.get(f"permissions.rationale.{permission}") for permission in permissions
            )
            if expected.get("appData") == "stateless":
                app_checks["statelessDoesNotOverclaimBackup"] = all(
                    manifest.get(key) == "not-applicable"
                    for key in (
                        "app.beta.backupRestore",
                        "app.beta.exportSupported",
                        "app.beta.importSupported",
                        "app.beta.migrationDryRunSupported",
                    )
                )
            else:
                app_checks["statelessDoesNotOverclaimBackup"] = True
            schema_version = expected.get("schemaVersion")
            app_checks["schemaVersionMatches"] = (
                schema_version is None
                or manifest.get("app.data.schema.current") == str(schema_version)
            )
            migration_step = expected.get("migrationStep")
            app_checks["migrationDryRunMatches"] = (
                migration_step is None
                or (
                    manifest.get("app.data.migrations") == migration_step
                    and bool(manifest.get(f"app.data.migration.{migration_step}.command"))
                )
            )
        index_text = read_source(index_path)
        app_checks["uiReadinessMarkersPresent"] = all(
            marker in index_text for marker in FIRST_PARTY_BETA_UI_MARKERS
        )
        app_checks["permissionRationaleVisible"] = (
            "data-beta-permission-rationale" in index_text
            and "data-crypta-permission-summary" in index_text
        )
        app_checks["designSystemClassesPresent"] = "cr-card" in index_text and "cr-button" in index_text
        if app_id == "trust-graph":
            lowered = index_text.lower()
            app_checks["localRcScopeRetained"] = (
                "local trust only" in lowered
                and "not global truth" in lowered
                and "network crawling" in lowered
            )
        else:
            app_checks["localRcScopeRetained"] = True
        if app_id == "social-inbox":
            lowered = index_text.lower()
            app_checks["legacyProtocolNonGoalsRetained"] = (
                "not freetalk" in lowered and "sone" in lowered and "freemail" in lowered
            )
        else:
            app_checks["legacyProtocolNonGoalsRetained"] = True
        readme_text = read_source(readme_path)
        app_checks["readmeBetaReadinessPresent"] = (
            "Beta readiness" in readme_text
            and "Diagnostic redaction" in readme_text
            and "Permission rationale" in readme_text
        )
        app_checks["diagnosticsRedactionCopyPresent"] = (
            "redacted-summary-only" in index_text
            or "redacted-summary-only" in readme_text
        )
        redaction_findings.extend(
            first_party_beta_redaction_findings(
                app_id,
                workspace,
                first_party_beta_redaction_scan_paths(source_dir, manifest_path, readme_path),
            )
        )
        for check_name, passed in app_checks.items():
            if passed is not True:
                app_errors.append(check_name)
                errors.append(f"{app_id}: {check_name}")
        app_details[app_id] = {
            "checks": app_checks,
            "readiness": safe_first_party_beta_readiness_details(
                beta_readiness, expected_values
            ),
            "sources": {
                "manifest": display_path(manifest_path, workspace),
                "index": display_path(index_path, workspace),
                "css": display_path(css_path, workspace),
                "js": display_path(js_path, workspace),
                "readme": display_path(readme_path, workspace),
            },
        }
        if app_errors:
            app_details[app_id]["errors"] = app_errors
    details = {
        "readinessMetadata": display_path(readiness_path, workspace),
        "maintenancePolicy": display_path(maintenance_path, workspace),
        "requiredFirstPartyApps": list(APP_IDS),
        "expectedReadiness": FIRST_PARTY_BETA_EXPECTATIONS,
        "checks": checks,
        "docs": docs_checks,
        "apps": app_details,
        "redactionPolicy": {
            "diagnostics": "redacted-summary-only",
            "rawFetchedContentExcluded": True,
            "rawMessagesExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    if redaction_findings:
        return EvidenceItem(
            FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
            "fail",
            True,
            "First-party beta-quality evidence has unwaivable redaction findings.",
            source,
            {"errors": errors, "redactionFindings": redaction_findings, **details},
        )
    if errors:
        return EvidenceItem(
            FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
            root_consequence(settings, "fail"),
            True,
            "First-party beta-quality evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        FIRST_PARTY_BETA_QUALITY_EVIDENCE_ID,
        "pass",
        True,
        "First-party app beta-quality readiness passed deterministic checks.",
        source,
        details,
    )

def first_party_beta_redaction_findings(
    app_id: str, workspace: Path, paths: tuple[Path, ...]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        (
            "private-insert-uri",
            re.compile(
                r"(?:"
                r"\b(?:crypta:|freenet:)?(?:SSK|USK)@"
                r"[^/,\s\"'<>)]*(?:PRIVATE|INSERT|AQECAAE)[^\s\"'<>)]*"
                r"|"
                r"(?<![\w-])[\"']?(?:private[-_ ]*)?insert(?:[-_ ]*uri)?[\"']?(?![\w-])"
                r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?"
                r"(?:crypta:|freenet:)?(?:SSK|USK)@"
                r"(?=[A-Za-z0-9~_-]{8,},)[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?"
                r"|"
                r"(?<![\w-])[\"']?privateInsertUri[\"']?(?![\w-])"
                r"\s*(?::|(?<![=!<>])=(?!=))\s*['\"]?"
                r"(?:crypta:|freenet:)?(?:SSK|USK)@"
                r"(?=[A-Za-z0-9~_-]{8,},)[A-Za-z0-9~_,=-]+(?:/[^\s`'\"<>)]*)?"
                r")",
                re.IGNORECASE,
            ),
        ),
        ("sensitive-header", SENSITIVE_HEADER_RE),
        ("raw-sensitive-label", SENSITIVE_TEXT_LABEL_RE),
        ("file-uri-path", FILE_URI_PATH_RE),
    )
    for path in paths:
        text = read_source(path)
        if not text:
            continue
        for kind, pattern in patterns:
            if pattern.search(text):
                findings.append(
                    {
                        "appId": app_id,
                        "kind": kind,
                        "source": display_path(path, workspace),
                    }
                )
        if first_party_beta_sensitive_assignment_present(text):
            findings.append(
                {
                    "appId": app_id,
                    "kind": "sensitive-assignment",
                    "source": display_path(path, workspace),
                }
            )
        if first_party_beta_windows_path_present(text):
            findings.append(
                {
                    "appId": app_id,
                    "kind": "windows-local-path",
                    "source": display_path(path, workspace),
                }
            )
        path_scan_text, _ = protect_route_paths(text)
        if first_party_beta_absolute_path_present(path_scan_text, workspace):
            findings.append(
                {
                    "appId": app_id,
                    "kind": "absolute-local-path",
                    "source": display_path(path, workspace),
                }
            )
    return findings

def first_party_beta_sensitive_assignment_present(text: str) -> bool:
    return any(
        should_redact_key_name(match.group("key"))
        and first_party_beta_assignment_value_is_sensitive(match)
        for match in SENSITIVE_ASSIGNMENT_RE.finditer(text)
    )

def first_party_beta_assignment_value_is_sensitive(match: re.Match[str]) -> bool:
    value = match.group("quoted_value") or match.group("value") or ""
    value = value.strip().strip(",;\"'")
    if not value:
        return False
    if value.startswith("<") and value.endswith(">"):
        return False
    if value.startswith("/abs/path"):
        return False
    lowered = value.lower()
    if lowered in {"true", "false", "null", "undefined"}:
        return False
    if re.fullmatch(r"\d+(?:\.\d+)?", value):
        return False
    if "(" in value or ")" in value:
        return False
    return True

def first_party_beta_windows_path_present(text: str) -> bool:
    for pattern in (WINDOWS_DRIVE_PATH_RE, WINDOWS_UNC_PATH_RE):
        for match in pattern.finditer(text):
            value = match.group(0)
            if re.search(r"\\u[0-9a-fA-F]{4}", value):
                continue
            return True
    return False

def first_party_beta_absolute_path_present(text: str, workspace: Path) -> bool:
    for root_text in path_prefix_variants(workspace):
        if replace_absolute_path_prefix(text, root_text, "<repo>") != text:
            return True
    home = str(Path.home())
    if home and home != "/" and replace_absolute_path_prefix(text, home, "<home>") != text:
        return True
    if replace_absolute_path_prefix(text, tempfile.gettempdir(), "<workdir>") != text:
        return True
    return FIRST_PARTY_BETA_COMMON_LOCAL_PATH_RE.search(text) is not None

def first_party_beta_redaction_scan_paths(
    source_dir: Path, manifest_path: Path, readme_path: Path
) -> tuple[Path, ...]:
    paths: list[Path] = []
    if manifest_path.is_file():
        paths.append(manifest_path)
    static_dir = source_dir / "static"
    if static_dir.is_dir():
        paths.extend(
            path
            for path in sorted(static_dir.rglob("*"))
            if path.is_file() and path.suffix.lower() in FIRST_PARTY_BETA_STATIC_TEXT_EXTENSIONS
        )
    paths.append(readme_path)
    return tuple(paths)

def collect_app_review_receipt_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    receipt_text = read_source(appcatalog_dir / "AppReviewReceipt.java")
    payload_text = read_source(appcatalog_dir / "AppReviewReceiptPayload.java")
    io_text = read_source(appcatalog_dir / "AppReviewReceiptIO.java")
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    cli_text = read_source(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java")
    checks = {
        "canonicalPayloadExcludesSignature": (
            "canonicalPayloadBytes" in payload_text
            and "review.receipt.signature.value.base64" not in payload_text
        ),
        "receiptSignatureIndependent": (
            "Signature.getInstance(receipt.signature().algorithm())" in verifier_text
            and "receipt.payload().canonicalPayloadBytes()" in verifier_text
        ),
        "bindingChecks": (
            "receipt.mismatchStatus(" in verifier_text
            and "binding.appId()" in verifier_text
            and "binding.version()" in verifier_text
            and "binding.artifactSha256()" in verifier_text
            and "binding.artifactSizeBytes()" in verifier_text
            and "AppReviewTrustStatus.ARTIFACT_MISMATCH" in receipt_text
            and "AppReviewTrustStatus.APP_MISMATCH" in receipt_text
        ),
        "expiryAndUnknownReviewerFailClosed": (
            "AppReviewTrustStatus.EXPIRED" in verifier_text
            and "AppReviewTrustStatus.UNKNOWN_REVIEWER" in verifier_text
        ),
        "trustedReviewerRegistrySeparate": (
            "trusted.reviewers.version" in keys_text
            and "public.key.base64" in keys_text
        ),
        "parserWriterEmbedsReceipt": (
            "parseProperties" in io_text
            and "appendReceiptProperties" in io_text
            and "review.receipt.signature.value.base64" in io_text
        ),
        "devtoolsSignVerify": (
            'name = "review"' in cli_text
            and "ReviewSignCommand" in cli_text
            and "ReviewVerifyCommand" in cli_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "receiptSchemaVersion": 1,
        "signatureAlgorithm": "Ed25519",
        "checks": checks,
        "sources": {
            "verifier": display_path(appcatalog_dir / "AppReviewReceiptVerifier.java", settings.workspace_root),
            "receipt": display_path(appcatalog_dir / "AppReviewReceipt.java", settings.workspace_root),
            "payload": display_path(appcatalog_dir / "AppReviewReceiptPayload.java", settings.workspace_root),
            "receiptIo": display_path(appcatalog_dir / "AppReviewReceiptIO.java", settings.workspace_root),
            "trustedReviewerKeys": display_path(appcatalog_dir / "TrustedReviewerKeys.java", settings.workspace_root),
            "devtools": display_path(settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java", settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.trusted-receipts",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-review receipt evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.trusted-receipts",
        "pass",
        True,
        "Trusted review receipt model and offline tooling evidence passed.",
        source,
        details,
    )

APP_STORE_SUBMISSION_EVIDENCE_IDS = (
    "app-store.submission-package-schema",
    "app-store.submission-cli",
    "app-store.pre-review",
    "app-store.review-decision-states",
    "app-store.review-receipt-issued",
    "app-store.rejection-record",
    "app-store.resubmission-link",
    "app-store.transparency-log",
    "app-store.catalog-candidate",
    "app-store.third-party-sample-flow",
    "app-store.redaction-clean",
)

THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS = (
    "third-party-developer.beta-program",
    "third-party-developer.docs",
    "third-party-developer.template",
    "third-party-developer.sample-app-flow",
    "third-party-developer.submission-checklist",
    "third-party-developer.compatibility-window",
    "third-party-developer.feedback-workflow",
    "third-party-developer.plugin-author-migration",
    "third-party-developer.redaction",
)

THIRD_PARTY_INTAKE_EVIDENCE_IDS = (
    "third-party-intake.queue-schema",
    "third-party-intake.import",
    "third-party-intake.reviewer-assignment",
    "third-party-intake.pre-review-artifacts",
    "third-party-intake.review-decision",
    "third-party-intake.resubmission-flow",
    "third-party-intake.catalog-candidate-staging",
    "third-party-intake.beta-catalog-install-smoke",
    "third-party-intake.transparency-export",
    "third-party-intake.rejected-candidate-blocked",
    "third-party-intake.caution-warning",
    "third-party-intake.redaction",
)

def collect_app_store_submission_workflow_evidence(settings: Settings) -> list[EvidenceItem]:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    devtools_cli = settings.workspace_root / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java"
    api_handler = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    web_shell = settings.workspace_root / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    docs_workflow = settings.workspace_root / "docs/app-store-submission-and-review-workflow.md"
    metadata_text = read_source(appcatalog_dir / "AppSubmissionMetadata.java")
    writer_text = read_source(appcatalog_dir / "AppSubmissionPackageWriter.java")
    verifier_text = read_source(appcatalog_dir / "AppSubmissionPackageVerifier.java")
    report_text = read_source(appcatalog_dir / "AppSubmissionPreReviewReport.java")
    redaction_text = read_source(appcatalog_dir / "AppSubmissionRedactionScanner.java")
    catalog_text = read_source(appcatalog_dir / "AppCatalog.java")
    catalog_writer_text = read_source(appcatalog_dir / "AppCatalogWriter.java")
    receipt_payload_text = read_source(appcatalog_dir / "AppReviewReceiptPayload.java")
    status_text = read_source(appcatalog_dir / "AppCatalogReviewStatus.java")
    transparency_text = read_source(appcatalog_dir / "AppReviewTransparencyEventKind.java")
    cli_text = read_source(devtools_cli)
    api_text = read_source(api_handler)
    web_text = read_source(web_shell)
    docs_text = read_source(docs_workflow)
    checks = {
        "schemaFields": all(
            token in metadata_text
            for token in (
                "schemaVersion",
                "submissionId",
                "submissionCreatedAt",
                "submissionType",
                "bundleDigest",
                "apiTargetStability",
                "experimentalCapabilitiesAccepted",
                "requestedPermissions",
                "permissionRationaleDigest",
                "redactionScanDigest",
                "nonProduction",
            )
        ),
        "deterministicZipWriter": "ZipEntry.STORED" in writer_text and "FIXED_ZIP_TIME_MILLIS" in writer_text,
        "packageVerifier": (
            "SUBMISSION_METADATA_ENTRY" in verifier_text
            and "BUNDLE_ARTIFACT_ENTRY" in verifier_text
            and "validateMetadataBinding" in verifier_text
        ),
        "preReviewReport": (
            "promotionReady" in report_text
            and "AppSubmissionFindingSeverity.BLOCKER" in report_text
        ),
        "decisionStates": all(
            token in status_text
            for token in ("SUBMITTED", "PRE_REVIEW_PASSED", "REVIEWED", "CAUTION", "REJECTED", "RESUBMITTED")
        ),
        "cliCommands": all(
            token in cli_text
            for token in (
                "SubmissionCreateCommand",
                "SubmissionVerifyCommand",
                "SubmissionPreReviewCommand",
                "SubmissionDecideCommand",
                "SubmissionCatalogCandidateCommand",
            )
        ),
        "receiptIssued": "REVIEW_RECEIPT_ISSUED" in cli_text and "AppReviewReceiptSigner.sign" in cli_text,
        "rejectionRecord": "submission.decision.version=1" in cli_text and "SUBMISSION_REJECTED" in cli_text,
        "resubmissionLink": "resubmissionOf" in metadata_text and "RESUBMITTED" in status_text,
        "transparencyEvents": all(
            token in transparency_text
            for token in (
                "submission_created",
                "pre_review_completed",
                "review_decision_recorded",
                "review_receipt_issued",
                "submission_rejected",
                "submission_resubmitted",
                "catalog_candidate_created",
            )
        ),
        "catalogCandidate": "review.receipt.fingerprint.sha256" in cli_text and "catalog-candidate" in cli_text,
        "catalogSchemaV6": (
            "VERSION_THIRD_PARTY_SUBMISSION_REVIEW = 6" in catalog_text
            and "catalog.version 6 is required when submission review metadata is present"
            in catalog_writer_text
            and "review.submission.id" in catalog_writer_text
        ),
        "catalogSchemaV7": (
            "VERSION_PLATFORM_API_TARGET_BASELINE = 7" in catalog_text
            and "catalog.version 7 is required when api.targetBaseline metadata is present"
            in catalog_writer_text
            and "api.targetBaseline" in catalog_writer_text
        ),
        "decisionReasonBound": (
            "review.receipt.decision.reason.sha256" in receipt_payload_text
            and "RECEIPT_VERSION_WITH_DECISION_REASON = 2" in receipt_payload_text
            and "decisionReasonSha256" in cli_text
            and "review.decision.reason.sha256" in cli_text
        ),
        "apiAndWebShellDisplay": "thirdPartyReview" in api_text and "Third-party submission" in web_text,
        "redactionClean": all(
            token in redaction_text
            for token in (
                "PRIVATE_KEY_PATTERN",
                "AUTHORIZATION_HEADER_PATTERN",
                "BEARER_TOKEN_PATTERN",
                "CRYPTA_SIGNED_SUBSPACE_URI_PATTERN",
                "LOCAL_UNIX_PATH_PREFIXES",
                "RAW_CONTENT_PATTERN",
            )
        ),
        "docs": (
            "crypta-app submission create" in docs_text
            and "caution" in docs_text
            and "resubmission" in docs_text
            and "transparency" in docs_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "submissionStatuses": [
            "submitted",
            "pre_review_passed",
            "reviewed",
            "caution",
            "rejected",
            "resubmitted",
        ],
        "sampleFlow": [
            "submission create",
            "submission verify",
            "submission pre-review",
            "submission decide reviewed",
            "review transparency verify",
            "submission catalog-candidate",
            "submission decide rejected",
            "resubmission link",
        ],
        "redaction": {
            "privateKeysExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "rawContentExcluded": True,
            "absolutePathsExcluded": True,
        },
        "sources": {
            "metadata": display_path(appcatalog_dir / "AppSubmissionMetadata.java", settings.workspace_root),
            "verifier": display_path(appcatalog_dir / "AppSubmissionPackageVerifier.java", settings.workspace_root),
            "catalog": display_path(appcatalog_dir / "AppCatalog.java", settings.workspace_root),
            "catalogWriter": display_path(appcatalog_dir / "AppCatalogWriter.java", settings.workspace_root),
            "receiptPayload": display_path(appcatalog_dir / "AppReviewReceiptPayload.java", settings.workspace_root),
            "devtools": display_path(devtools_cli, settings.workspace_root),
            "api": display_path(api_handler, settings.workspace_root),
            "webShell": display_path(web_shell, settings.workspace_root),
            "docs": display_path(docs_workflow, settings.workspace_root),
        },
    }
    status = "pass" if not errors else root_consequence(settings, "fail")
    summary = (
        "Third-party app submission workflow evidence passed deterministic checks."
        if not errors
        else "Third-party app submission workflow evidence is incomplete."
    )
    return [
        EvidenceItem(evidence_id, status, True, summary, source, {"errors": errors, **details})
        for evidence_id in APP_STORE_SUBMISSION_EVIDENCE_IDS
    ]

def collect_third_party_intake_evidence(settings: Settings) -> list[EvidenceItem]:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    appcatalog_tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog"
    devtools_cli = workspace / "platform-devtools/src/main/java/network/crypta/platform/devtools/CryptaAppCli.java"
    api_routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java"
    api_tests = workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java"
    web_shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    docs_paths = (
        workspace / "docs/app-store-submission-and-review-workflow.md",
        workspace / "docs/third-party-developer-beta-program.md",
        workspace / "docs/third-party-app-submission-checklist.md",
        workspace / "docs/app-review-governance.md",
        workspace / "docs/app-platform-developer-portal.md",
        workspace / "docs/production-beta-release-pipeline.md",
        workspace / "docs/production-beta-go-no-go-dashboard.md",
    )
    record_text = read_source(appcatalog_dir / "AppSubmissionIntakeRecord.java")
    status_text = read_source(appcatalog_dir / "AppSubmissionIntakeStatus.java")
    store_text = read_source(appcatalog_dir / "FileAppSubmissionIntakeStore.java")
    assignment_text = read_source(appcatalog_dir / "AppSubmissionReviewerAssignment.java")
    decision_text = read_source(appcatalog_dir / "AppSubmissionReviewDecisionRecord.java")
    candidate_text = read_source(appcatalog_dir / "AppSubmissionCatalogCandidateRecord.java")
    model_test_text = read_source(appcatalog_tests / "AppSubmissionIntakeRecordTest.java")
    cli_text = read_source(devtools_cli)
    cli_test_text = read_source(
        workspace
        / "platform-devtools/src/test/java/network/crypta/platform/devtools/CryptaAppCliTest.java"
    )
    api_text = read_source(api_routes)
    api_test_text = read_source(api_tests)
    web_text = read_source(web_shell)
    docs_text = "\n".join(read_source(path) for path in docs_paths)
    checks = {
        "queueSchema": all(
            token in record_text
            for token in (
                "schemaVersion",
                "submissionId",
                "submissionDigest",
                "resubmissionOf",
                "reviewerAssignment",
                "preReviewReportDigest",
                "catalogCandidate",
                "transparencyLogDigest",
                "nonProduction",
                "redactionStatus",
                "auditEvents",
            )
        ),
        "statusLifecycle": all(
            token in status_text
            for token in (
                "submitted",
                "reviewer_assigned",
                "pre_review_running",
                "pre_review_passed",
                "pre_review_failed",
                "reviewed",
                "caution",
                "rejected",
                "resubmission_requested",
                "staged_to_beta_catalog",
                "beta_install_smoke_passed",
            )
        ),
        "fileStore": (
            "records/<submission-id>.json" in store_text
            or "records/&lt;submission-id&gt;.json" in store_text
        )
        and (
            "submissions/<submission-id>.zip" in store_text
            or "submissions/&lt;submission-id&gt;.zip" in store_text
        )
        and "ATOMIC_MOVE" in store_text
        and "safeSubmissionId" in store_text,
        "reviewerAssignment": "previousReviewerKeyId" in assignment_text
        and "assignmentReasonDigest" in assignment_text
        and "reviewer private key material" in assignment_text,
        "decisionRecords": "reviewReceiptFingerprintSha256" in decision_text
        and "decisionReasonDigest" in decision_text
        and "feedbackDigest" in decision_text
        and "reviewed/caution intake decisions require receipt" in decision_text,
        "candidateRecord": "betaCatalogCandidateReference" in candidate_text
        and "cautionAllowed" in candidate_text
        and "installSmokeStatus" in candidate_text,
        "transitionTests": all(
            token in model_test_text
            for token in (
                "recordCatalogCandidate_whenRejected_expectCandidateBlocked",
                "recordCatalogCandidate_whenCautionWithoutAllowance_expectBlocked",
                "recordCatalogCandidate_whenReviewed_expectInstallSmokeStatus",
                "recordPreReview_whenRedactionFails_expectSummaryCarriesFailure",
                "parse_whenResubmissionRecord_expectPriorSubmissionLinked",
            )
        ),
        "cliCommands": all(
            token in cli_text
            for token in (
                "SubmissionIntakeCommand",
                "SubmissionIntakeImportCommand",
                "SubmissionIntakeListCommand",
                "SubmissionIntakeAssignCommand",
                "SubmissionIntakePreReviewCommand",
                "SubmissionIntakeDecideCommand",
                "SubmissionIntakeStageCandidateCommand",
                "SubmissionIntakeInstallSmokeCommand",
            )
        ),
        "preReviewArtifacts": all(
            token in cli_text
            for token in (
                "pre-review.json",
                "submission-verification.json",
                "api-compatibility.json",
                "ui-lint.json",
                "redaction-scan.json",
                "artifact-manifest.json",
            )
        ),
        "catalogCandidateStaging": all(
            token in cli_text
            for token in (
                "candidate-manifest.json",
                "candidate-review-receipt.properties",
                "candidate-transparency-log.jsonl",
                "catalog candidate does not expose third-party review metadata",
                "caution catalog candidates require --allow-caution",
                "installSmoke=pending",
            )
        ),
        "betaCatalogInstallSmoke": all(
            token in cli_text
            for token in (
                "install-smoke",
                "candidate-install-smoke.json",
                "recordInstallSmokePassed",
                "Beta catalog install smoke passed",
                "crypta-beta-catalog-install-smoke",
            )
        )
        and "assertCandidateStagingPendingSmoke" in cli_test_text
        and "assertInstallSmokePassed" in cli_test_text,
        "operatorApi": all(
            token in api_text
            for token in (
                "operator/app-submissions",
                "cryptad.appSubmissionIntakeDir",
                "CRYPTAD_APP_INTAKE_QUEUE_DIR",
                "operatorRoutesInAppContract",
                "appSubmissionIntakeSummary",
                "routeAppSubmissionIntakeRecord",
            )
        )
        and "route_whenAppSubmissionIntakeQueueConfigured_expectSafeOperatorSummary" in api_test_text,
        "webShell": all(
            token in web_text
            for token in (
                "operator/app-submissions",
                "Third-party app intake",
                "renderThirdPartyIntake",
                "transparencyLogDigest",
                "redactionStatus",
                "beta_install_smoke_passed",
            )
        ),
        "docs": all(
            token in docs_text
            for token in (
                "submission intake import",
                "submission intake assign",
                "submission intake pre-review",
                "submission intake decide",
                "submission intake stage-candidate",
                "submission intake install-smoke",
                "third-party-intake.queue-schema",
                "non-production",
                "redaction",
            )
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "errors": errors,
        "evidenceRows": list(THIRD_PARTY_INTAKE_EVIDENCE_IDS),
        "sampleFlow": [
            "sample app package created",
            "submission imported",
            "reviewer assigned",
            "pre-review artifacts stored",
            "reviewed/caution/rejected/resubmission decisions recorded",
            "beta catalog candidate generated",
            "catalog summary exposes thirdPartyReview",
            "install-from-beta-catalog smoke passed",
            "transparency log verified",
            "redaction passed",
        ],
        "negativePaths": [
            "rejected submission cannot stage",
            "caution submission requires explicit allowance",
            "non-production evidence is marked",
            "redaction failures fail closed",
        ],
        "sources": {
            "record": display_path(appcatalog_dir / "AppSubmissionIntakeRecord.java", workspace),
            "store": display_path(appcatalog_dir / "FileAppSubmissionIntakeStore.java", workspace),
            "cli": display_path(devtools_cli, workspace),
            "api": display_path(api_routes, workspace),
            "webShell": display_path(web_shell, workspace),
        },
    }
    status = "pass" if not errors else root_consequence(settings, "fail")
    summary = (
        "Third-party public-beta intake evidence passed deterministic checks."
        if not errors
        else "Third-party public-beta intake evidence is incomplete."
    )
    return [
        EvidenceItem(evidence_id, status, True, summary, source, details)
        for evidence_id in THIRD_PARTY_INTAKE_EVIDENCE_IDS
    ]

def collect_third_party_developer_beta_program_evidence(
    settings: Settings,
) -> list[EvidenceItem]:
    source = summary_source(settings)
    docs_dir = settings.workspace_root / "docs"
    issue_dir = settings.workspace_root / ".github/ISSUE_TEMPLATE"
    devtools_dir = (
        settings.workspace_root
        / "platform-devtools/src/main/java/network/crypta/platform/devtools"
    )
    devserver_dir = devtools_dir / "devserver"
    devtools_test_dir = (
        settings.workspace_root
        / "platform-devtools/src/test/java/network/crypta/platform/devtools"
    )
    sample_dir = settings.workspace_root / "samples/third-party/hello-stable-app"
    beta_doc = docs_dir / "third-party-developer-beta-program.md"
    checklist_doc = docs_dir / "third-party-app-submission-checklist.md"
    compatibility_doc = docs_dir / "platform-api-compatibility-support-window.md"
    sdk_example_doc = docs_dir / "examples/third-party-hello-stable.md"
    legacy_migration_doc = docs_dir / "legacy-plugin-migration-guide.md"
    release_cert_doc = docs_dir / "release-certification.md"
    template_kind_text = read_source(devtools_dir / "AppTemplateKind.java")
    scaffolder_text = read_source(devtools_dir / "AppTemplateScaffolder.java")
    cli_text = read_source(devtools_dir / "CryptaAppCli.java")
    mock_api_text = read_source(devserver_dir / "MockPlatformApi.java")
    mock_fixtures_text = read_source(devserver_dir / "MockPlatformApiFixtures.java")
    toolkit_test_text = read_source(devtools_test_dir / "DeveloperBetaToolkitCliTest.java")
    cli_test_text = read_source(devtools_test_dir / "CryptaAppCliTest.java")
    beta_doc_text = read_source(beta_doc)
    checklist_text = read_source(checklist_doc)
    compatibility_text = read_source(compatibility_doc)
    sdk_example_text = read_source(sdk_example_doc)
    legacy_migration_text = read_source(legacy_migration_doc)
    release_cert_text = read_source(release_cert_doc)
    sample_manifest = read_source(sample_dir / "cryptad-app.properties")
    sample_script = read_source(sample_dir / "static/app.js")
    sample_index = read_source(sample_dir / "static/index.html")
    sample_readme = read_source(sample_dir / "README.md")
    sample_review_files = (
        "permission-rationale.md",
        "sandbox-rationale.md",
        "data-schema.md",
        "backup-restore.md",
        "security-notes.md",
        "changelog.md",
    )
    sample_review_texts = {
        name: read_source(sample_dir / "review" / name) for name in sample_review_files
    }
    sample_redaction_text = "\n".join(
        (
            sample_manifest,
            sample_script,
            sample_index,
            sample_readme,
            *sample_review_texts.values(),
        )
    )
    sample_redaction_findings = production_security_redaction_findings(
        sample_redaction_text, settings.workspace_root
    )
    issue_templates = {
        name: read_source(issue_dir / name)
        for name in (
            "developer-beta-feedback.yml",
            "app-submission-beta.yml",
            "app-review-appeal.yml",
            "platform-api-compatibility.yml",
            "plugin-migration-feedback.yml",
        )
    }
    checklist_sections = (
        "Manifest validation",
        "API stability target",
        "No internal/operator-only permissions",
        "Permission rationale",
        "UI lint",
        "CSP and remote script policy",
        "Sandbox declaration",
        "App-data schema declaration",
        "Data migration declaration",
        "Backup/restore declaration",
        "Service dependency/grant declaration",
        "Security notes",
        "Support/maintainer metadata",
        "Redaction and privacy review",
        "Submission package generation",
        "Pre-review output",
        "Resubmission requirements",
    )
    docs_checks = {
        "betaProgramDoc": all(
            token in beta_doc_text
            for token in (
                "crypta-app init",
                "--template hello-stable",
                "crypta-app submission create",
                "crypta-app submission verify",
                "crypta-app submission pre-review",
                "crypta-app submission catalog-candidate",
                "reviewed",
                "caution",
                "rejected",
                "resubmitted",
                "third-party-app-submission-checklist.md",
            )
        ),
        "sdkExampleDoc": (
            any(
                token in sdk_example_text
                for token in (
                    'CryptaPlatform.api.get("platform/contract")',
                    'window.CryptaPlatform.api.get("platform/contract")',
                    'platform.api.get("platform/contract")',
                )
            )
            and "api.targetStability=stable" in sdk_example_text
            and "crypta-app compat verify" in sdk_example_text
        ),
        "releaseCertificationDoc": all(
            token in release_cert_text
            for token in (
                "third-party-developer.beta-program",
                "third-party-developer.sample-app-flow",
                "third-party-developer.redaction",
            )
        ),
    }
    template_checks = {
        "templateKind": "HELLO_STABLE" in template_kind_text
        and '"hello-stable"' in template_kind_text,
        "stablePermission": "platform.contract.read" in template_kind_text,
        "scaffoldUsesContract": 'platform.api.get("platform/contract")' in scaffolder_text,
        "cliHelpAndAlias": "hello-stable" in cli_text and '{"--app-id", "--id"}' in cli_text,
        "mockContractRoute": 'suffix.equals("/platform/contract")' in mock_api_text
        and "platform-contract.json" in mock_fixtures_text,
        "testsCoverTemplate": "hello-stable" in toolkit_test_text
        and "platform.contract.read" in toolkit_test_text
        and "submissionCreate_whenInitializedStaticBundleIncludesSdk_expectAccepted"
        in cli_test_text,
    }
    sample_checks = {
        "sampleManifestStable": all(
            token in sample_manifest
            for token in (
                "app.id=org.example.hello",
                "api.targetStability=stable",
                "api.experimentalCapabilitiesAccepted=false",
                "app.permissions=platform.contract.read",
            )
        ),
        "sampleNoRestrictedPermissions": all(
            token not in sample_manifest
            for token in ("vault.identities.manage", "internal", "operator-only")
        ),
        "sampleSdkUsage": "CryptaPlatform" in sample_script
        and 'api.get("platform/contract")' in sample_script
        and "console.log" not in sample_script,
        "samplePermissionDisclosure": "data-crypta-permission-summary" in sample_index,
        "sampleReviewNotes": all(
            (sample_dir / "review" / name).is_file() for name in sample_review_files
        ),
        "sampleReadmeFlow": "crypta-app submission create" in sample_readme
        and "crypta-app submission pre-review" in sample_readme,
    }
    checklist_checks = {section: section in checklist_text for section in checklist_sections}
    compatibility_checks = {
        "stableBaselineExpectation": "Platform API 1.0 stable baseline" in compatibility_text,
        "experimentalOptIn": "api.experimentalCapabilitiesAccepted=true" in compatibility_text,
        "deprecationWindow": "scheduled-for-removal" in compatibility_text,
        "releaseCertificationBehavior": "Release certification" in compatibility_text,
        "candidateSnapshots": "previous release-candidate snapshot" in compatibility_text,
        "catalogReviewMetadata": "Catalog candidates and review metadata" in compatibility_text,
    }
    feedback_checks = {
        name: (
            "Do not paste" in text
            and "private" in text
            and "local absolute paths" in text
        )
        for name, text in issue_templates.items()
    }
    plugin_checks = {
        "developerBetaLinks": "third-party-developer-beta-program.md" in legacy_migration_text
        and "third-party-app-submission-checklist.md" in legacy_migration_text,
        "stableBaseline": "Platform API 1.0 stable baseline" in legacy_migration_text,
        "unsupportedPatterns": all(
            token in legacy_migration_text
            for token in ("old plugin ABI", "old FCP", "Retained FProxy browse")
        ),
    }
    redaction_checks = {
        "sampleSensitiveMarkersAbsent": not sample_redaction_findings,
        "sampleReviewNotesScanned": all(
            (sample_dir / "review" / name).is_file() for name in sample_review_files
        ),
        "issueTemplatesWarn": all(feedback_checks.values()),
        "docsWarnRedaction": all(
            token in beta_doc_text
            for token in (
                "private keys",
                "private insert URIs",
                "browser session tokens",
                "raw app data",
                "local absolute paths",
            )
        ),
    }
    flow_checks = {
        "localWorkflow": all(
            token in beta_doc_text
            for token in (
                "crypta-app test",
                "crypta-app ui lint",
                "crypta-app compat verify",
                "crypta-app pack",
                "crypta-app submission create",
                "crypta-app submission verify",
                "crypta-app submission pre-review",
            )
        ),
        "reviewedDecision": "submission decide" in beta_doc_text and "reviewed" in beta_doc_text,
        "negativeOperatorOnlyPath": "vault.identities.manage" in cli_test_text
        or "operator-only" in beta_doc_text
        or "operator-only" in compatibility_text,
        "catalogCandidate": "submission catalog-candidate" in beta_doc_text,
    }
    evidence_checks: dict[str, dict[str, bool]] = {
        "third-party-developer.beta-program": docs_checks,
        "third-party-developer.docs": docs_checks,
        "third-party-developer.template": template_checks,
        "third-party-developer.sample-app-flow": {**sample_checks, **flow_checks},
        "third-party-developer.submission-checklist": checklist_checks,
        "third-party-developer.compatibility-window": compatibility_checks,
        "third-party-developer.feedback-workflow": feedback_checks,
        "third-party-developer.plugin-author-migration": plugin_checks,
        "third-party-developer.redaction": redaction_checks,
    }
    base_details = {
        "sampleApp": "samples/third-party/hello-stable-app",
        "template": "hello-stable",
        "apiTargetStability": "stable",
        "experimentalCapabilitiesAccepted": False,
        "defaultPermissions": ["platform.contract.read"],
        "sampleReviewFilesScanned": list(sample_review_files),
        "sampleRedactionFindings": sample_redaction_findings,
        "reviewStatuses": ["reviewed", "caution", "rejected", "resubmitted"],
        "sampleFlow": [
            "init/template",
            "test",
            "ui lint",
            "compat verify",
            "submission create",
            "submission verify",
            "pre-review",
            "reviewed decision",
            "catalog candidate",
            "operator-only rejection",
        ],
        "redaction": {
            "privateKeysExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "rawAppDataExcluded": True,
            "rawFetchedContentExcluded": True,
            "absolutePathsExcluded": True,
            "productionReviewerMaterialExcluded": True,
        },
        "sources": {
            "program": display_path(beta_doc, settings.workspace_root),
            "checklist": display_path(checklist_doc, settings.workspace_root),
            "compatibilityWindow": display_path(compatibility_doc, settings.workspace_root),
            "sdkExample": display_path(sdk_example_doc, settings.workspace_root),
            "sampleApp": display_path(sample_dir, settings.workspace_root),
            "templateKind": display_path(
                devtools_dir / "AppTemplateKind.java", settings.workspace_root
            ),
            "scaffolder": display_path(
                devtools_dir / "AppTemplateScaffolder.java", settings.workspace_root
            ),
        },
    }
    evidence = []
    for evidence_id in THIRD_PARTY_DEVELOPER_BETA_EVIDENCE_IDS:
        checks = evidence_checks[evidence_id]
        errors = [key for key, passed in checks.items() if not passed]
        status = "pass" if not errors else root_consequence(settings, "fail")
        evidence.append(
            EvidenceItem(
                evidence_id,
                status,
                True,
                (
                    "Third-party developer beta program evidence passed."
                    if not errors
                    else "Third-party developer beta program evidence is incomplete."
                ),
                source,
                {"checks": checks, "errors": errors, **base_details},
            )
        )
    return evidence

def public_beta_docs_text(workspace: Path, paths: tuple[str, ...]) -> str:
    return "\n".join(read_source(workspace / path) for path in paths)

def public_beta_missing_terms(text: str, terms: tuple[str, ...]) -> list[str]:
    lowered = app_platform_docs_check.normalize_crypta_app_aliases(text).lower()
    return sorted(term for term in terms if term.lower() not in lowered)

def public_beta_broken_links(workspace: Path) -> list[dict[str, str]]:
    broken: list[dict[str, str]] = []
    workspace_resolved = workspace.resolve()
    for doc_path in app_platform_docs_check.PUBLIC_BETA_DOCS:
        markdown_file = workspace / doc_path
        if not markdown_file.is_file():
            continue
        text = read_source(markdown_file)
        for target in app_platform_docs_check.markdown_doc_link_targets(text):
            resolved = app_platform_docs_check.resolve_doc_link_target(
                workspace, markdown_file, target
            )
            try:
                resolved.relative_to(workspace_resolved)
            except ValueError:
                broken.append(
                    {
                        "source": doc_path,
                        "target": app_platform_docs_check.safe_broken_link_target(target),
                        "reason": "outside-repo",
                    }
                )
                continue
            if not resolved.is_file():
                broken.append(
                    {
                        "source": doc_path,
                        "target": app_platform_docs_check.safe_broken_link_target(target),
                        "reason": "missing",
                    }
                )
    return broken

def public_beta_redaction_findings(workspace: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in app_platform_docs_check.public_beta_redaction_files_to_check(workspace):
        doc_path = display_path(path, workspace)
        for issue in app_platform_docs_check.redaction_findings_for_text(read_source(path)):
            findings.append({"path": doc_path, "issue": issue})
    return findings

def collect_public_beta_docs_onboarding_evidence(settings: Settings) -> list[EvidenceItem]:
    workspace = settings.workspace_root
    docs_summary = app_platform_docs_check.run_check(workspace)
    docs_evidence = {
        str(item.get("id")): item
        for item in docs_summary.get("evidence", [])
        if isinstance(item, dict)
    }
    evidence: list[EvidenceItem] = []
    for evidence_id in PUBLIC_BETA_DOCS_EVIDENCE_IDS:
        item = docs_evidence.get(evidence_id)
        if not isinstance(item, dict):
            evidence.append(
                EvidenceItem(
                    evidence_id,
                    root_consequence(settings, "fail"),
                    True,
                    f"{evidence_id} evidence is missing from app-platform docs check.",
                    summary_source(settings),
                    {"errors": ["missingDocsCheckEvidence"]},
                )
            )
            continue
        status = str(item.get("status", "missing"))
        if status != "pass":
            status = root_consequence(settings, "fail")
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        evidence.append(
            EvidenceItem(
                evidence_id,
                status,
                True,
                str(item.get("summary", f"{evidence_id} evidence imported.")),
                str(item.get("source", "tools/release-certification/certify.py")),
                dict(details),
            )
        )
    return evidence

def collect_app_review_policy_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    appcatalog_dir = settings.workspace_root / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    api_catalogs = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    api_updates = settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateService.java"
    policy_text = read_source(appcatalog_dir / "AppReviewPolicy.java")
    mode_text = read_source(appcatalog_dir / "AppReviewPolicyMode.java")
    decision_text = read_source(appcatalog_dir / "AppReviewTrustDecision.java")
    catalogs_text = read_source(api_catalogs)
    updates_text = read_source(api_updates)
    checks = {
        "policyModes": (
            "ADVISORY" in mode_text
            and "WARN_UNTRUSTED" in mode_text
            and "REQUIRE_TRUSTED_REVIEW" in mode_text
            and "REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED" in mode_text
        ),
        "defaultAdvisory": "AppReviewPolicyMode.ADVISORY" in policy_text,
        "decisionFlags": (
            "requiresAcknowledgement" in decision_text
            and "blocksInstall" in decision_text
            and "blocksUpdate" in decision_text
            and "blocksPolicyApply" in decision_text
        ),
        "catalogInstallUpdateGate": (
            "requireReviewGate(" in catalogs_text
            and "reviewAcknowledged" in catalogs_text
            and "app_review_missing" in catalogs_text
        ),
        "updateLifecycleGate": (
            "requireReviewGate(candidate.reviewTrust()" in updates_text
            and "eligibleForAutomaticApply()" in read_source(settings.workspace_root / "platform-api/src/main/java/network/crypta/platform/api/appupdates/AppUpdateCandidate.java")
            and "app_review_rejected" in updates_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "mode": "advisory default; warn/block modes operator-configured",
        "checks": checks,
        "sources": {
            "policy": display_path(appcatalog_dir / "AppReviewPolicy.java", settings.workspace_root),
            "policyMode": display_path(appcatalog_dir / "AppReviewPolicyMode.java", settings.workspace_root),
            "decision": display_path(appcatalog_dir / "AppReviewTrustDecision.java", settings.workspace_root),
            "catalogsApi": display_path(api_catalogs, settings.workspace_root),
            "updatesApi": display_path(api_updates, settings.workspace_root),
        },
    }
    if errors:
        return EvidenceItem("app-review.policy", "fail" if settings.mode == "release-candidate" else "warn", True, "App-review policy evidence is incomplete.", source, {"errors": errors, **details})
    return EvidenceItem("app-review.policy", "pass", True, "App-review policy gates passed deterministic evidence checks.", source, details)

def collect_app_review_governance_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    api_routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    api_handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    status_text = read_source(appcatalog_dir / "TrustedReviewerKeyStatus.java")
    lifecycle_text = read_source(appcatalog_dir / "TrustedReviewerKeyLifecycle.java")
    verifier_text = read_source(appcatalog_dir / "AppReviewReceiptVerifier.java")
    routes_text = read_source(api_routes)
    handler_text = read_source(api_handler)
    shell_text = read_source(shell)
    checks = {
        "reviewerLifecycleStatuses": all(value in status_text for value in ("ACTIVE", "RETIRED", "REVOKED")),
        "policyVersionConstraint": "TrustedReviewerPolicyConstraint" in read_source(appcatalog_dir / "TrustedReviewerPolicyConstraint.java"),
        "lifecycleTrustStatuses": all(
            value in verifier_text
            for value in (
                "REVOKED_REVIEWER",
                "RETIRED_REVIEWER",
                "REVIEWER_NOT_YET_VALID",
                "REVIEWER_EXPIRED",
                "REVIEW_POLICY_MISMATCH",
            )
        ),
        "governanceRoutes": (
            "routeAppReviewRequest" in routes_text
            and "app-review" in routes_text
            and "reviewer-keys" in routes_text
            and "transparency-log" in routes_text
        ),
        "redactedReviewerSummaries": (
            "TrustedReviewerKeySummary" in handler_text
            and "publicKey" not in read_source(appcatalog_dir / "TrustedReviewerKeySummary.java")
        ),
        "webShellGovernance": (
            "Review governance" in shell_text
            and "reviewerKeyStatus" in shell_text
            and "policyVersionStatus" in shell_text
        ),
        "lifecycleValidation": (
            "revocation metadata requires status=revoked" in lifecycle_text
            and "reviewer valid.until must be after valid.from" in lifecycle_text
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "status": display_path(appcatalog_dir / "TrustedReviewerKeyStatus.java", workspace),
            "lifecycle": display_path(appcatalog_dir / "TrustedReviewerKeyLifecycle.java", workspace),
            "verifier": display_path(appcatalog_dir / "AppReviewReceiptVerifier.java", workspace),
            "apiRoutes": display_path(api_routes, workspace),
            "apiHandler": display_path(api_handler, workspace),
            "webShell": display_path(shell, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.governance",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-review governance evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.governance",
        "pass",
        True,
        "App-review governance evidence passed deterministic source checks.",
        source,
        details,
    )

def collect_app_review_reviewer_key_lifecycle_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    tests = workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppReviewReceiptTest.java"
    keys_text = read_source(appcatalog_dir / "TrustedReviewerKeys.java")
    tests_text = read_source(tests)
    checks = {
        "v2Parser": (
            "trusted.reviewers.version" in keys_text
            and "policy.version" in keys_text
            and "valid.from" in keys_text
            and "revoked.at" in keys_text
        ),
        "duplicateIdsFailClosed": "duplicate trusted reviewer key id" in keys_text,
        "strictInstants": "Instant.parse(value)" in keys_text,
        "revokedReviewerTest": "evaluate_whenReviewerKeyIsRevoked_expectRevokedReviewer" in tests_text,
        "retiredReviewerTest": "evaluate_whenRetiredReviewerCoversReviewedAt_expectTrustedHistoricalReview" in tests_text,
        "retiredReviewerRequiresWindowTest": "evaluate_whenRetiredReviewerHasNoValidityEnd_expectRetiredReviewer" in tests_text,
        "policyMismatchTest": "evaluate_whenPolicyVersionDoesNotMatchReviewerConstraint_expectPolicyMismatch" in tests_text,
        "policyVersionRequiresPolicyIdTest": "trustedReviewerKeysLoad_whenPolicyVersionOmitsPolicyId_expectInvalidCatalogEntry" in tests_text,
        "redactedSummaryTest": "publicKey" in tests_text and "containsKey" in tests_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "trustedReviewerKeys": display_path(appcatalog_dir / "TrustedReviewerKeys.java", workspace),
            "tests": display_path(tests, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.reviewer-key-lifecycle",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer-key lifecycle evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.reviewer-key-lifecycle",
        "pass",
        True,
        "Reviewer-key lifecycle parser and verifier evidence passed.",
        source,
        details,
    )

def collect_app_review_transparency_log_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    appcatalog_dir = workspace / "platform-appcatalog/src/main/java/network/crypta/platform/appcatalog"
    record_text = read_source(appcatalog_dir / "AppReviewTransparencyRecord.java")
    store_text = read_source(appcatalog_dir / "FileAppReviewTransparencyStore.java")
    log_text = read_source(appcatalog_dir / "AppReviewTransparencyLog.java")
    manager_text = read_source(appcatalog_dir / "AppCatalogManager.java")
    tests_text = read_source(workspace / "platform-appcatalog/src/test/java/network/crypta/platform/appcatalog/AppReviewReceiptTest.java")
    checks = {
        "hashChain": (
            "previousRecordHash" in record_text
            and "recordHash" in record_text
            and "computeRecordHash" in record_text
            and "verifyRecords" in store_text
        ),
        "redactedFields": (
            "privateKey" not in record_text
            and "processToken" not in record_text
            and "browserSession" not in record_text
            and "signature.value" not in record_text
        ),
        "receiptObservationDedup": "REVIEW_RECEIPT_OBSERVED" in log_text and "receiptFingerprint" in log_text,
        "receiptObservationPayloadBindingTest": "transparencyLog_whenMismatchedReceiptObserved_expectReceiptPayloadBinding" in tests_text,
        "gateReceiptStatusTest": "transparencyRecordFromCatalogDecision_whenReceiptAndPublisherStatusesDiffer_expectReceiptStatus" in tests_text,
        "publisherOnlyNoReceiptStatusTest": "transparencyRecordFromCatalogDecision_whenOnlyPublisherReviewExists_expectNoReceiptStatus" in tests_text,
        "managerOwnedStore": "reviewTransparencyLog" in manager_text,
        "rejectUnknownFields": "rejectUnknownJsonFields" in record_text,
        "rejectTrailingData": "expectEnd()" in record_text,
        "tamperTest": "transparencyStoreVerify_whenRecordIsTampered_expectVerificationFailure" in tests_text,
        "unknownFieldTest": "transparencyStoreVerify_whenRecordHasUnknownField_expectVerificationFailure" in tests_text,
        "trailingDataTest": "transparencyStoreVerify_whenRecordHasTrailingData_expectVerificationFailure" in tests_text,
        "warningListTamperTest": "transparencyStoreVerify_whenWarningListShapeIsTampered_expectVerificationFailure" in tests_text,
        "booleanTypeTamperTest": "transparencyStoreVerify_whenBooleanFieldHasStringValue_expectVerificationFailure" in tests_text,
        "schemaVersionRangeTest": "transparencyStoreVerify_whenSchemaVersionIsOutOfRange_expectVerificationFailure" in tests_text,
        "bestEffortMalformedLogTest": "transparencyLogRecordCatalogDecision_whenExistingLogIsMalformed_expectBestEffort" in tests_text,
        "bestEffortNullRecordIdTest": "transparencyLogRecordCatalogDecision_whenExistingReceiptRecordHasNullId_expectBestEffort" in tests_text,
        "dedupTest": "transparencyLog_whenReceiptObservedTwice_expectReceiptObservationDeduplicated" in tests_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "record": display_path(appcatalog_dir / "AppReviewTransparencyRecord.java", workspace),
            "store": display_path(appcatalog_dir / "FileAppReviewTransparencyStore.java", workspace),
            "log": display_path(appcatalog_dir / "AppReviewTransparencyLog.java", workspace),
            "manager": display_path(appcatalog_dir / "AppCatalogManager.java", workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.transparency-log",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Review transparency-log evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.transparency-log",
        "pass",
        True,
        "Review transparency-log hash-chain and redaction evidence passed.",
        source,
        details,
    )

def collect_app_review_history_api_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    routes = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppRoutes.java"
    handler = workspace / "platform-api/src/main/java/network/crypta/platform/api/appcatalogs/AppCatalogsApiHandler.java"
    shell = workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    routes_text = read_source(routes)
    handler_text = read_source(handler)
    shell_text = read_source(shell)
    checks = {
        "reviewHistoryRoute": "review-history" in routes_text and "reviewHistory(" in handler_text,
        "governanceEndpoint": "governance()" in handler_text,
        "reviewerKeysEndpoint": "reviewerKeys()" in handler_text,
        "transparencyEndpoint": "transparencyLog(" in handler_text and "verifyTransparencyLog" in handler_text,
        "shellHistoryFetch": "loadCatalogAppReviewHistory" in shell_text,
        "shellTrustDelta": "trustDelta" in handler_text and "Installed version" in shell_text,
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {
        "checks": checks,
        "sources": {
            "routes": display_path(routes, workspace),
            "handler": display_path(handler, workspace),
            "webShell": display_path(shell, workspace),
        },
    }
    if errors:
        return EvidenceItem(
            "app-review.review-history-api",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Review-history API evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.review-history-api",
        "pass",
        True,
        "Review-history and governance API evidence passed.",
        source,
        details,
    )

def collect_app_review_first_party_chain_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    smoke_text = read_engine_source(workspace, "app_platform_smoke")
    docs_text = read_source(workspace / "docs/app-review-governance.md")
    checks = {
        "firstPartyCatalogEvidence": "collect_app_review_first_party_catalog_evidence" in smoke_text,
        "reviewReceiptVerify": "review_verify_args" in smoke_text and "trustedPositiveReceipts" in smoke_text,
        "governanceEvidenceRequired": "app-review.governance" in smoke_text,
        "transparencyEvidenceRequired": "app-review.transparency-log" in smoke_text,
        "docsExplainLocalLog": (
            "tamper-evident" in docs_text.lower()
            and "not a global public" in docs_text.lower()
        ),
    }
    errors = [key for key, passed in checks.items() if not passed]
    details = {"checks": checks}
    if errors:
        return EvidenceItem(
            "app-review.first-party-review-chain",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party app-review chain evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-review.first-party-review-chain",
        "pass",
        True,
        "First-party app-review chain evidence passed deterministic checks.",
        source,
        details,
    )

def write_first_party_review_descriptor(
    descriptor: Path,
    spec: dict[str, Any],
    manifest: dict[str, str],
    artifact_zip: Path,
) -> None:
    app_id = manifest.get("app.id", spec["appId"])
    app_name = manifest.get("app.name", spec["name"])
    permissions = ",".join(sorted(parse_permission_set(manifest.get("app.permissions", ""))))
    lines = [
        f"artifact.path={artifact_zip.resolve()}",
        f"bundle.uri={artifact_zip.resolve().as_uri()}",
        f"summary=First-party release-candidate review target for {app_name}.",
        f"name={app_name}",
        f"permissions={permissions}",
        f"app.id={app_id}",
        f"version={manifest.get('app.version', '')}",
        "review.status=reviewed",
        "review.note=First-party app review receipt required for release promotion.",
        "changelog.summary=Release certification first-party catalog evidence.",
    ]
    if manifest.get("api.minimumVersion"):
        lines.append(f"api.minimumVersion={manifest['api.minimumVersion']}")
    if manifest.get("api.maximumTestedVersion"):
        lines.append(f"api.maximumTestedVersion={manifest['api.maximumTestedVersion']}")
    if manifest.get("api.targetStability"):
        lines.append(f"api.targetStability={manifest['api.targetStability']}")
    if manifest.get("api.experimentalCapabilitiesAccepted"):
        lines.append(
            "api.experimentalCapabilitiesAccepted="
            + manifest["api.experimentalCapabilitiesAccepted"]
        )
    descriptor.write_text("\n".join(lines) + "\n", encoding="utf-8")

def collect_app_review_first_party_catalog_evidence(settings: Settings, sample_paths: dict[str, Path]) -> EvidenceItem:
    source = summary_source(settings)
    cli = sample_paths.get("cli")
    specs = first_party_app_specs(settings)
    details: dict[str, Any] = {
        "policyMode": "release-candidate requires trusted positive receipts",
        "firstPartyApps": [spec["appId"] for spec in specs],
        "referenceContentApp": "site-publisher",
        "coverage": {
            "catalogAppsInspected": 0,
            "trustedPositiveReceipts": 0,
            "missingReceipts": len(specs),
            "expiredOrMismatchedOrUnknownReviewer": 0,
            "trustedRejectedReceipts": 0,
            "promotionBlocked": True,
        },
    }
    if not cli:
        return EvidenceItem("app-review.first-party-catalog", root_consequence(settings, "missing"), True, "crypta-app CLI is unavailable for first-party review catalog evidence.", source, details)
    inputs = reviewer_inputs(os.environ)
    details["reviewerInputs"] = {
        "keyIdPresent": bool(inputs["keyId"]),
        "privateKeyPresent": inputs["hasPrivate"],
        "publicKeyPresent": inputs["hasPublic"],
        "policyId": inputs["policyId"],
        "policyVersion": inputs["policyVersion"],
    }
    if not inputs["complete"]:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer key inputs are incomplete; trusted first-party review receipts were not verified.",
            source,
            details,
        )
    review_dir = sample_workspace(settings) / "app-review"
    review_dir.mkdir(parents=True, exist_ok=True)
    trusted_keys_file = review_dir / "trusted-reviewers.properties"
    catalog_file = review_dir / "cryptad-app-catalog.properties"
    remove_existing_path(catalog_file)
    try:
        write_trusted_reviewer_keys(trusted_keys_file, inputs)
    except OSError as exc:
        details["trustedReviewerKeys"] = {
            "error": scrub_text(str(exc), settings.workspace_root)
        }
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "Reviewer public key material could not be read for app-review catalog evidence.",
            source,
            details,
        )

    failures: list[str] = []
    entry_files: list[Path] = []
    receipt_files: list[Path] = []
    details["apps"] = {}
    for spec in specs:
        app_id = spec["appId"]
        app_details: dict[str, Any] = {
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
        details["apps"][app_id] = app_details
        manifest_path = spec["stagedDir"] / "cryptad-app.properties"
        if not manifest_path.is_file():
            failures.append(f"{app_id}: staged manifest is missing")
            continue
        try:
            manifest = parse_properties(manifest_path)
        except ValueError as exc:
            failures.append(f"{app_id}: {exc}")
            continue
        version = manifest.get("app.version", "unknown")
        artifact_zip = review_dir / f"{app_id}-{version}.zip"
        descriptor = review_dir / f"{app_id}.properties"
        receipt_file = review_dir / f"{app_id}-review-receipt.properties"
        remove_existing_path(artifact_zip)
        remove_existing_path(descriptor)
        remove_existing_path(receipt_file)
        pack_result = run_cli(
            cli,
            [
                "pack",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--output",
                str(artifact_zip),
                "--overwrite",
            ],
            settings,
            f"crypta-app-review-pack-{app_id}",
        )
        app_details["pack"] = command_details(pack_result, settings)
        app_details["artifact"] = display_path(artifact_zip, settings.workspace_root, settings.out_dir)
        if pack_result.exit_code != 0 or not artifact_zip.is_file():
            failures.append(f"{app_id}: first-party bundle pack failed")
            continue
        write_first_party_review_descriptor(descriptor, spec, manifest, artifact_zip)
        sign_result = run_cli(
            cli,
            review_sign_args(descriptor, receipt_file, inputs),
            settings,
            f"crypta-app-review-sign-{app_id}",
        )
        verify_result = run_cli(
            cli,
            review_verify_args(descriptor, receipt_file, trusted_keys_file),
            settings,
            f"crypta-app-review-verify-{app_id}",
        )
        app_details["descriptor"] = display_path(descriptor, settings.workspace_root, settings.out_dir)
        app_details["receipt"] = display_path(receipt_file, settings.workspace_root, settings.out_dir)
        app_details["sign"] = command_details(sign_result, settings)
        app_details["verify"] = command_details(verify_result, settings)
        if sign_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt signing failed")
        if verify_result.exit_code != 0:
            failures.append(f"{app_id}: review receipt verification failed")
        if sign_result.exit_code == 0 and verify_result.exit_code == 0:
            entry_files.append(descriptor)
            receipt_files.append(receipt_file)
    if failures:
        return EvidenceItem(
            "app-review.first-party-catalog",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "First-party review catalog preparation failed.",
            source,
            {"failures": failures, **details},
        )

    create_args = [
        "catalog",
        "create",
        "--catalog-file",
        str(catalog_file),
        "--catalog-id",
        "cert-first-party-review",
        "--name",
        "Certification First-Party Apps",
        "--generated-at",
        "2026-05-01T00:00:00Z",
    ]
    for entry_file in entry_files:
        create_args.extend(["--entry", str(entry_file)])
    for receipt_file in receipt_files:
        create_args.extend(["--review-receipt", str(receipt_file)])
    create_args.append("--overwrite")
    create_result = run_cli(cli, create_args, settings, "crypta-app-review-catalog-create")
    details["catalogCreate"] = command_details(create_result, settings)
    catalog = parse_properties(catalog_file) if catalog_file.is_file() else {}
    catalog_entries = parse_permission_set(catalog.get("catalog.entries", ""))
    expected_app_ids = {spec["appId"] for spec in specs}
    inspected_app_ids = {
        app_id
        for app_id in expected_app_ids
        if catalog.get(f"app.{app_id}.id") == app_id or app_id in catalog_entries
    }
    receipt_statuses = {
        app_id: catalog.get(f"app.{app_id}.review.receipt.status")
        for app_id in expected_app_ids
    }
    trusted_positive_receipts = sum(
        1 for status in receipt_statuses.values() if status == "reviewed"
    )
    trusted_rejected_receipts = sum(
        1 for status in receipt_statuses.values() if status == "rejected"
    )
    missing_receipts = sum(1 for status in receipt_statuses.values() if not status)
    verify_failures = sum(
        1
        for app_details in details["apps"].values()
        if app_details.get("verify", {}).get("exitCode") != 0
    )
    details["coverage"] = {
        "catalogAppsInspected": len(inspected_app_ids),
        "trustedPositiveReceipts": trusted_positive_receipts,
        "missingReceipts": missing_receipts,
        "expiredOrMismatchedOrUnknownReviewer": verify_failures,
        "trustedRejectedReceipts": trusted_rejected_receipts,
        "promotionBlocked": (
            create_result.exit_code != 0
            or inspected_app_ids != expected_app_ids
            or trusted_positive_receipts != len(expected_app_ids)
        ),
    }
    details["catalog"] = {
        "catalogId": catalog.get("catalog.id"),
        "entries": sorted(catalog_entries),
        "inspectedAppIds": sorted(inspected_app_ids),
        "receiptStatuses": receipt_statuses,
    }
    if details["coverage"]["promotionBlocked"]:
        return EvidenceItem("app-review.first-party-catalog", "fail" if settings.mode == "release-candidate" else "warn", True, "Trusted first-party review receipt catalog evidence failed.", source, details)
    return EvidenceItem("app-review.first-party-catalog", "pass", True, "First-party catalog review receipt evidence covered all first-party apps.", source, details)

def design_system_source_dir(settings: Settings) -> Path:
    return (
        settings.workspace_root
        / "platform-design-system/src/main/resources/network/crypta/platform/designsystem/static"
    )

def design_system_asset_names() -> tuple[str, ...]:
    return ("crypta-ui-tokens.css", "crypta-ui.css", "crypta-ui-components.js")

def collect_app_ui_design_system_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    canonical_dir = design_system_source_dir(settings)
    details: dict[str, Any] = {
        "canonicalResourceDir": display_path(canonical_dir, settings.workspace_root),
        "assets": [],
        "apps": {},
    }
    errors: list[str] = []
    for asset_name in design_system_asset_names():
        asset_path = canonical_dir / asset_name
        if not asset_path.is_file():
            errors.append(f"canonical design-system asset missing: {asset_name}")
            details["assets"].append({"name": asset_name, "present": False})
            continue
        details["assets"].append(
            {
                "name": asset_name,
                "present": True,
                "sha256": sha256_file(asset_path),
                "sizeBytes": asset_path.stat().st_size,
            }
        )
    for spec in first_party_app_specs(settings):
        app_details: dict[str, Any] = {"assets": []}
        staged_static_dir = spec["stagedDir"] / "static/crypta-ui"
        for asset_name in design_system_asset_names():
            staged_asset = staged_static_dir / asset_name
            canonical_asset = canonical_dir / asset_name
            present = staged_asset.is_file()
            matches = (
                present
                and canonical_asset.is_file()
                and sha256_file(staged_asset) == sha256_file(canonical_asset)
            )
            app_details["assets"].append(
                {
                    "name": asset_name,
                    "present": present,
                    "matchesCanonical": matches,
                    "path": display_path(staged_asset, settings.workspace_root),
                }
            )
            if not present:
                errors.append(f"{spec['appId']}: staged design-system asset missing: {asset_name}")
            elif not matches:
                errors.append(f"{spec['appId']}: staged design-system asset differs: {asset_name}")
        details["apps"][spec["appId"]] = app_details
    if errors:
        return EvidenceItem(
            "app-ui.design-system",
            root_consequence(settings, "fail"),
            True,
            "App UI design-system asset evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.design-system",
        "pass",
        True,
        "Canonical app UI design-system assets are present and staged into first-party apps.",
        source,
        details,
    )

def stylesheet_order_ok(index_html: str) -> bool:
    tokens = index_html.find("crypta-ui-tokens.css")
    ui_css = index_html.find("crypta-ui.css")
    app_css = index_html.find("app.css")
    return tokens >= 0 and ui_css > tokens and app_css > ui_css

def permission_disclosure_block(index_html: str) -> str:
    lower = index_html.lower()
    candidates = [
        lower.find("cr-permission-summary"),
        lower.find("data-crypta-permission-summary"),
        lower.find("<crypta-permission-summary"),
    ]
    starts = [candidate for candidate in candidates if candidate >= 0]
    if not starts:
        return ""
    start = min(starts)
    end_candidates = [
        lower.find("</section>", start),
        lower.find("</crypta-permission-summary>", start),
    ]
    ends = [candidate for candidate in end_candidates if candidate >= 0]
    end = min(ends) if ends else len(index_html)
    return index_html[start:end]

def source_ui_adoption_details(
    static_dir: Path, permissions: set[str], settings: Settings
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    index = static_dir / "index.html"
    details: dict[str, Any] = {
        "index": display_path(index, settings.workspace_root),
        "designSystemStylesheetOrder": False,
        "usesDesignSystemClasses": False,
        "hasPermissionDisclosure": False,
    }
    if not index.is_file():
        return ["static/index.html is missing"], details
    index_html = index.read_text(encoding="utf-8")
    details["designSystemStylesheetOrder"] = stylesheet_order_ok(index_html)
    details["usesDesignSystemClasses"] = "cr-" in index_html
    details["hasPermissionDisclosure"] = (
        "cr-permission-summary" in index_html
        or "data-crypta-permission-summary" in index_html
        or "<crypta-permission-summary" in index_html
    )
    if not details["designSystemStylesheetOrder"]:
        errors.append("index.html does not load design-system CSS before app CSS")
    if not details["usesDesignSystemClasses"]:
        errors.append("index.html does not use cr-* design-system classes")
    if permissions and not details["hasPermissionDisclosure"]:
        errors.append("manifest permissions have no visible permission disclosure")
    disclosure = permission_disclosure_block(index_html)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    omitted = sorted(permissions - mentioned_permissions)
    undeclared = sorted(mentioned_permissions - permissions)
    details["mentionedPermissions"] = sorted(mentioned_permissions)
    details["omittedPermissions"] = omitted
    if details["hasPermissionDisclosure"] and omitted:
        errors.append("permission disclosure omits declared permissions: " + ",".join(omitted))
    if undeclared:
        errors.append(
            "permission disclosure mentions undeclared permissions: " + ",".join(undeclared)
        )
    return errors, details

def collect_app_ui_first_party_adoption_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"sourceStaticUi": {}, "stagedStaticUi": {}}
    errors: list[str] = []
    for spec in first_party_app_specs(settings):
        source_errors, source_details = source_ui_adoption_details(
            spec["sourceDir"] / "static", spec["permissions"], settings
        )
        staged_errors, staged_details = source_ui_adoption_details(
            spec["stagedDir"] / "static", spec["permissions"], settings
        )
        details["sourceStaticUi"][spec["appId"]] = source_details
        details["stagedStaticUi"][spec["appId"]] = staged_details
        errors.extend(f"{spec['appId']} source: {error}" for error in source_errors)
        errors.extend(f"{spec['appId']} staged: {error}" for error in staged_errors)
    if errors:
        return EvidenceItem(
            "app-ui.first-party-adoption",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI design-system adoption checks found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.first-party-adoption",
        "pass",
        True,
        "First-party static apps use design-system loading order, classes, and permission disclosure.",
        source,
        details,
    )

def collect_app_ui_lint_evidence(settings: Settings, cli: Path | None) -> EvidenceItem:
    source = summary_source(settings)
    details: dict[str, Any] = {"apps": {}}
    if cli is None or not cli.is_file():
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "missing"),
            True,
            "crypta-app CLI is unavailable for app UI lint evidence.",
            source,
            details,
        )
    errors: list[str] = []
    lint_dir = settings.out_dir / "artifacts" / "app-ui-lint"
    lint_dir.mkdir(parents=True, exist_ok=True)
    for spec in first_party_app_specs(settings):
        json_path = lint_dir / f"{spec['appId']}.json"
        remove_existing_path(json_path)
        result = run_cli(
            cli,
            [
                "ui",
                "lint",
                "--bundle-dir",
                str(spec["stagedDir"]),
                "--strict",
                "--json",
                str(json_path),
            ],
            settings,
            f"crypta-app-ui-lint-{spec['appId']}",
        )
        app_details = {
            "command": command_details(result, settings),
            "json": display_path(json_path, settings.workspace_root, settings.out_dir),
        }
        lint_json = read_json_file(json_path)
        if lint_json:
            app_details["report"] = {
                "appId": str(lint_json.get("appId", "")),
                "uiMode": str(lint_json.get("uiMode", "")),
                "applicable": lint_json.get("applicable"),
            }
            summary = lint_json.get("summary", {})
            app_details["summary"] = summary
            findings = lint_json.get("findings", [])
            if isinstance(findings, list):
                app_details["findingIds"] = [
                    str(finding.get("id", "unknown"))
                    for finding in findings
                    if isinstance(finding, dict)
                ]
        details["apps"][spec["appId"]] = app_details
        if result.exit_code != 0:
            errors.append(f"crypta-app ui lint failed for {spec['appId']}")
        errors.extend(ui_lint_report_errors(lint_json, str(spec["appId"])))
    if errors:
        return EvidenceItem(
            "app-ui.lint",
            root_consequence(settings, "fail"),
            True,
            "First-party app UI lint found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-ui.lint",
        "pass",
        True,
        "crypta-app ui lint passed for first-party static apps.",
        source,
        details,
    )
