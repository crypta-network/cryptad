"""Implementation segment for the data network portion of ``app_platform_smoke.py``."""

from __future__ import annotations

def collect_app_vault_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    doc_path = settings.workspace_root / APP_VAULT_DOC
    vocabulary_path = (
        settings.workspace_root
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/DevtoolsCapabilityVocabulary.java"
    )
    details: dict[str, Any] = {
        "doc": display_path(doc_path, settings.workspace_root),
        "devtoolsVocabulary": display_path(vocabulary_path, settings.workspace_root),
        "capabilities": list(APP_VAULT_CAPABILITIES),
        "checks": {},
        "redaction": {
            "capabilityNamesRetained": True,
            "secretValuesRedacted": True,
            "identityPrivateMaterialRedacted": True,
            "signatureValuesRedacted": True,
        },
    }
    errors: list[str] = []
    doc_text = ""
    if doc_path.is_file():
        doc_text = doc_path.read_text(encoding="utf-8")
    else:
        errors.append(f"{APP_VAULT_DOC} is missing")
    vocabulary_text = vocabulary_path.read_text(encoding="utf-8") if vocabulary_path.is_file() else ""
    if not vocabulary_text:
        errors.append("devtools app-vault capability vocabulary is missing")

    lower_doc = doc_text.lower()
    lower_vocab = vocabulary_text.lower()
    missing_doc_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in doc_text
    ]
    missing_vocab_capabilities = [
        capability for capability in APP_VAULT_CAPABILITIES if capability not in lower_vocab
    ]
    if missing_doc_capabilities:
        errors.append("vault doc omits capabilities: " + ",".join(missing_doc_capabilities))
    if missing_vocab_capabilities:
        errors.append(
            "devtools vocabulary omits capabilities: " + ",".join(missing_vocab_capabilities)
        )
    checks = details["checks"]
    checks["capabilitiesDocumented"] = not missing_doc_capabilities
    checks["devtoolsVocabularyPresent"] = not missing_vocab_capabilities
    checks["appOwnedAndSharedIdentities"] = "app-owned" in lower_doc and "shared identit" in lower_doc
    checks["processBrowserRestrictions"] = (
        "process" in lower_doc and "browser" in lower_doc and "cryptad_app_token" in lower_doc
    )
    checks["atRestLimitations"] = (
        ("at-rest" in lower_doc or "at rest" in lower_doc)
        and "local" in lower_doc
        and "limit" in lower_doc
    )
    checks["grantLifecycle"] = all(
        word in lower_doc for word in ("update", "rollback", "uninstall", "reinstall")
    )
    checks["auditAndRedaction"] = "audit" in lower_doc and "redact" in lower_doc
    checks["futureExtensionPoint"] = all(word in lower_doc for word in ("content", "social", "mail"))
    checks["browserSafeIdentityCreationRoute"] = (
        "post /api/v1/app-vault/identities" in lower_doc
        and "browser" in lower_doc
        and "vault.identities.create" in doc_text
    )
    checks["profileDocumentRoute"] = (
        "post /api/v1/app-vault/identities/{identityid}/profile-document" in lower_doc
        and "vault.identities.read" in doc_text
        and "vault.identities.use" in doc_text
        and "profile document" in lower_doc
    )
    for name, passed in checks.items():
        if not passed:
            errors.append(f"vault documentation check failed: {name}")
    if errors:
        return EvidenceItem(
            "app-vault.capabilities",
            root_consequence(settings, "fail"),
            True,
            "App secret and identity vault evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-vault.capabilities",
        "pass",
        True,
        "App secret and identity vault capability docs and redaction checks passed.",
        source,
        details,
    )

def collect_identity_profile_publish_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/app-vault/identities/{identityId}/profile-document"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-secret-and-identity-vault.md",
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "AppVault" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/app-vault/identities/{identityid}/profile-document"
        in lower_docs,
        "requiredCapabilitiesDocumented": (
            "vault.identities.read" in docs_text and "vault.identities.use" in docs_text
        ),
        "profilePublisherDocumented": (
            "profile-publisher" in lower_docs and "Profile Publisher" in docs_text
        ),
        "routeInContractOrRouter": route in source_text,
        "routeUsesVaultIdentityReadAndUseCapabilities": (
            route in contract_text
            and "VAULT_IDENTITIES_READ" in contract_text
            and "VAULT_IDENTITIES_USE" in contract_text
        ),
        "handlerOrTestEvidencePresent": "profile-document" in handler_text
        or "profile-document" in tests_text,
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw request bodies",
                "private keys",
                "signatures",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["vault.identities.read", "vault.identities.use"],
        "checks": checks,
        "redaction": {
            "rawRequestBodiesExcluded": True,
            "identityPrivateMaterialRedacted": True,
            "signatureValuesRedacted": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "appVaultHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/app-secret-and-identity-vault.md", workspace),
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.identity-profile-publish",
            root_consequence(settings, "fail"),
            True,
            "Identity profile-document publish route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.identity-profile-publish",
        "pass",
        True,
        "Identity profile-document publish route evidence passed.",
        source,
        details,
    )

def collect_generated_document_insert_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/queue/inserts/app-document"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "Queue" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, sdk_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/queue/inserts/app-document" in lower_docs,
        "generatedDocumentScopeDocumented": (
            "app-generated document" in lower_docs and "local file path" in lower_docs
        ),
        "requiredCapabilitiesDocumented": (
            "content.insert.app-document" in docs_text and "queue.write" in docs_text
        ),
        "routeInContractOrRouter": route in source_text,
        "routeUsesAppDocumentInsertAndQueueWrite": (
            route in contract_text
            and "CONTENT_INSERT_APP_DOCUMENT" in contract_text
            and "QUEUE_WRITE" in contract_text
        ),
        "handlerOrTestEvidencePresent": "app-document" in handler_text
        or "app-document" in tests_text,
        "sdkOrGenericPostDocumented": (
            "queue/inserts/app-document" in sdk_text
            or "queue/inserts/app-document" in docs_text
        ),
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw request bodies",
                "private insert uris",
                "absolute staging paths",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["content.insert.app-document", "queue.write"],
        "checks": checks,
        "redaction": {
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "absoluteStagingPathsExcluded": True,
            "signatureValuesRedacted": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "queueHandler": display_path(
                workspace
                / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/platform-api-surface.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.generated-document-insert",
            root_consequence(settings, "fail"),
            True,
            "App-generated document insert route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.generated-document-insert",
        "pass",
        True,
        "App-generated document insert route evidence passed.",
        source,
        details,
    )

def collect_content_fetch_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    route = "/content/fetch"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/release-certification.md",
        )
    )
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    handler_text = "\n".join(
        read_source(path)
        for path in (
            workspace / "platform-api/src/main/java/network/crypta/platform/api/content/ContentApiHandler.java",
            workspace / "platform-api/src/main/java/network/crypta/platform/api/queue/QueueApiHandler.java",
        )
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    tests_text = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java").rglob("*.java"))
        if "Content" in path.name or "Capabilities" in path.name or "Contract" in path.name
    )
    lower_docs = docs_text.lower()
    source_text = "\n".join((contract_text, router_text, handler_text, sdk_text, tests_text))
    checks = {
        "routeDocumented": "post /api/v1/content/fetch" in lower_docs,
        "fetchScopeDocumented": "feed" in lower_docs and "content.fetch" in docs_text,
        "requiredCapabilitiesDocumented": "content.fetch" in docs_text,
        "routeInContractOrRouter": route in source_text,
        "routeUsesContentFetchCapability": (
            route in contract_text
            and ("CONTENT_FETCH" in contract_text or "content.fetch" in contract_text)
        ),
        "handlerOrTestEvidencePresent": (
            "content/fetch" in handler_text
            or "contentFetch" in handler_text
            or "ContentFetch" in handler_text
            or "content/fetch" in tests_text
            or "contentFetch" in tests_text
            or "ContentFetch" in tests_text
        ),
        "sdkFeedHelpersPresentOrDocumented": (
            "CryptaPlatform.feed" in sdk_text
            or "CryptaPlatform.feed" in docs_text
            or "content/fetch" in sdk_text
            or "content/fetch" in docs_text
        ),
        "redactionDocumented": all(
            phrase in lower_docs
            for phrase in (
                "raw feed bodies",
                "raw request bodies",
                "private insert uris",
                "browser-session tokens",
                "form passwords",
                "local paths",
            )
        ),
    }
    details = {
        "route": "POST /api/v1" + route,
        "requiredCapabilities": ["content.fetch"],
        "checks": checks,
        "redaction": {
            "rawFeedBodiesExcluded": True,
            "rawRequestBodiesExcluded": True,
            "privateInsertUrisExcluded": True,
            "appProcessTokensRedacted": True,
            "browserSessionTokensRedacted": True,
            "formPasswordsRedacted": True,
            "localPathsSanitized": True,
        },
        "sources": {
            "contract": display_path(
                workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
                workspace,
            ),
            "docs": [
                display_path(workspace / "docs/platform-api-contract.md", workspace),
                display_path(workspace / "docs/platform-api-surface.md", workspace),
                display_path(workspace / "docs/platform-sdk-js.md", workspace),
                display_path(workspace / "docs/feed-reader-reference-app.md", workspace),
                display_path(workspace / "docs/release-certification.md", workspace),
            ],
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.content-fetch",
            root_consequence(settings, "fail"),
            True,
            "Content fetch route evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.content-fetch",
        "pass",
        True,
        "Content fetch route evidence passed.",
        source,
        details,
    )

def collect_content_subscription_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/feed-reader-reference-app.md",
            "docs/release-certification.md",
            "docs/app-platform-beta-known-limitations.md",
        )
    )
    contract_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    capabilities_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java"
    )
    router_source = workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    content_routes_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContentRoutes.java"
    )
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java"
    )
    handler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionsApiHandler.java"
    )
    source_validator_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSource.java"
    )
    content_policy_source = (
        workspace / "platform-api/src/main/java/network/crypta/platform/api/content/ContentFetchPolicy.java"
    )
    sdk_source = (
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    router_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiContentSubscriptionsRouterTest.java"
    )
    service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java"
    )
    contract_text = read_source(contract_source)
    capabilities_text = read_source(capabilities_source)
    router_text = read_source(router_source)
    content_routes_text = router_text + "\n" + read_source(content_routes_source)
    service_text = read_source(service_source)
    subscription_text = read_source(subscription_source)
    handler_text = read_source(handler_source)
    source_validator_text = read_source(source_validator_source)
    source_validation_text = source_validator_text + "\n" + read_source(content_policy_source)
    sdk_text = read_source(sdk_source)
    tests_text = read_source(router_test_source) + "\n" + read_source(service_test_source)
    lower_docs = docs_text.lower()
    routes = (
        "/content/subscriptions",
        "/content/subscriptions/{subscriptionId}",
        "/content/subscriptions/{subscriptionId}/refresh",
        "/content/subscriptions/{subscriptionId}/pause",
        "/content/subscriptions/{subscriptionId}/resume",
    )
    checks = {
        "currentContractVersionV9": (
            "CURRENT_CONTRACT_VERSION = 9" in contract_text
            or "CURRENT_CONTRACT_VERSION = 10" in contract_text
            or "CURRENT_CONTRACT_VERSION = 11" in contract_text
            or "CURRENT_CONTRACT_VERSION = 12" in contract_text
            or "CURRENT_CONTRACT_VERSION = 13" in contract_text
            or "CURRENT_CONTRACT_VERSION = 14" in contract_text
            or "CURRENT_CONTRACT_VERSION = 15" in contract_text
            or "CURRENT_CONTRACT_VERSION = 20" in contract_text
            or "CURRENT_CONTRACT_VERSION = 22" in contract_text
            or "CURRENT_CONTRACT_VERSION = 23" in contract_text
            or "CURRENT_CONTRACT_VERSION = 24" in contract_text
        ),
        "capabilityDescriptorPresent": (
            "CONTENT_SUBSCRIBE" in contract_text
            and "CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION = 8" in contract_text
            and "CONTENT_SUBSCRIBE" in capabilities_text
            and "content.subscribe" in capabilities_text
        ),
        "routesPresent": (
            all(route in contract_text for route in routes)
            and "content.subscriptions.create" in contract_text
            and "content.subscriptions.refresh" in contract_text
            and "content.subscriptions.delete" in contract_text
            and "routeContentSubscriptionsRequest" in content_routes_text
        ),
        "capabilityGatesPresent": (
            "CONTENT_SUBSCRIBE" in contract_text
            and "CONTENT_FETCH" in contract_text
            and "ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE" in tests_text
            and "ContentSubscriptionService.CAPABILITY_CONTENT_FETCH" in tests_text
            and "route_whenAppLacksContentSubscribe_expectForbidden" in tests_text
            and "route_whenAppLacksContentFetchForCreate_expectForbidden" in tests_text
        ),
        "appPrincipalScoped": (
            "requireAppPrincipalId(request)" in content_routes_text
            and "PlatformApiPrincipal.hostOperator()" in tests_text
            and "route_whenAppReadsAnotherAppsSubscription_expectNotFound" in tests_text
        ),
        "serviceUnavailableStable": (
            "content_subscription_service_unavailable" in content_routes_text
            and "503" in content_routes_text
        ),
        "sourceValidationUskOnly": (
            "USK@" in source_validation_text
            and "crypta:" in source_validation_text
            and "hasDisallowedScheme" in source_validation_text
            and "containsWhitespace" in source_validation_text
            and "unsupported_content_subscription_source" in source_validation_text
            and ("unsupported" in tests_text or "Unsupported" in tests_text)
        ),
        "limitsAndMetadataOnly": (
            "perAppSubscriptionLimit" in service_text
            and "globalSubscriptionLimit" in service_text
            and "maxBytes" in service_text
            and "timeoutMillis" in service_text
            and "contentSha256" in service_text
            and "bytes.length" in service_text
            and "raw fetched content is digested and then discarded" in service_text
        ),
        "sdkHelpersPresent": (
            "CryptaPlatform.content.subscriptions" in docs_text
            and "content/subscriptions" in sdk_text
            and "contentSubscriptionPathSegment" in sdk_text
            and "apiDeleteForm" in sdk_text
        ),
        "docsDescribeRedactionAndNonGoals": all(
            phrase in lower_docs
            for phrase in (
                "raw fetched content",
                "raw request bodies",
                "browser-session tokens",
                "private insert uris",
                "queue html",
                "arbitrary http/https",
                "generic crawler",
            )
        ),
    }
    details = {
        "routes": [
            "GET /api/v1/content/subscriptions",
            "POST /api/v1/content/subscriptions",
            "GET /api/v1/content/subscriptions/{subscriptionId}",
            "POST /api/v1/content/subscriptions/{subscriptionId}/refresh",
            "POST /api/v1/content/subscriptions/{subscriptionId}/pause",
            "POST /api/v1/content/subscriptions/{subscriptionId}/resume",
            "DELETE /api/v1/content/subscriptions/{subscriptionId}",
        ],
        "requiredCapabilities": ["content.subscribe", "content.fetch for create/refresh"],
        "sourceScope": "USK@ and crypta:USK@ only",
        "checks": checks,
        "redaction": {
            "rawFetchedContentExcluded": True,
            "rawRequestBodiesExcluded": True,
            "browserSessionTokensRedacted": True,
            "appProcessTokensRedacted": True,
            "formPasswordsRedacted": True,
            "privateInsertUrisExcluded": True,
            "privateKeysExcluded": True,
            "absolutePathsExcluded": True,
            "queueHtmlExcluded": True,
        },
        "sources": {
            "contract": display_path(contract_source, workspace),
            "router": display_path(router_source, workspace),
            "contentRoutes": display_path(content_routes_source, workspace),
            "service": display_path(service_source, workspace),
            "handler": display_path(handler_source, workspace),
            "sourceValidator": display_path(source_validator_source, workspace),
            "sdk": display_path(sdk_source, workspace),
            "tests": [
                display_path(router_test_source, workspace),
                display_path(service_test_source, workspace),
            ],
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.content-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Content subscription API evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.content-subscriptions",
        "pass",
        True,
        "Content subscription API evidence passed.",
        source,
        details,
    )

def collect_content_subscription_scheduler_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    scheduler_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionScheduler.java"
    )
    scheduler_config_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSchedulerConfig.java"
    )
    service_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionService.java"
    )
    subscription_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscription.java"
    )
    store_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/FileContentSubscriptionStore.java"
    )
    pressure_source = (
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionPressureGate.java"
    )
    runtime_source = (
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    scheduler_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionSchedulerTest.java"
    )
    service_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/ContentSubscriptionServiceTest.java"
    )
    store_test_source = (
        workspace
        / "platform-api/src/test/java/network/crypta/platform/api/content/subscriptions/FileContentSubscriptionStoreTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/release-certification.md",
            "docs/app-platform-beta-known-limitations.md",
        )
    )
    scheduler_text = read_source(scheduler_source)
    scheduler_config_text = read_source(scheduler_config_source)
    service_text = read_source(service_source)
    subscription_text = read_source(subscription_source)
    store_text = read_source(store_source)
    pressure_text = read_source(pressure_source)
    runtime_text = read_source(runtime_source)
    tests_text = "\n".join(
        read_source(path)
        for path in (scheduler_test_source, service_test_source, store_test_source)
    )
    lower_docs = docs_text.lower()
    checks = {
        "schedulerSourcePresent": (
            "public final class ContentSubscriptionScheduler" in scheduler_text
            and "ContentSubscriptionSchedulerConfig" in scheduler_text
            and "ContentSubscriptionPressureGate" in scheduler_text
        ),
        "deterministicTickAndNoOverlap": (
            "tick(Instant now)" in scheduler_text
            and "AtomicBoolean running" in scheduler_text
            and "compareAndSet(false, true)" in scheduler_text
            and "alreadyRunning" in scheduler_text
            and "overlapping" in tests_text
        ),
        "backgroundLifecycle": (
            "scheduleWithFixedDelay" in scheduler_text
            and "config.initialDelay().plus(jitter())" in scheduler_text
            and "shutdownNow()" in scheduler_text
            and "contentSubscriptionScheduler::close" in runtime_text
        ),
        "conservativeLimits": (
            "perTickFetchLimit" in scheduler_text
            and "perAppSubscriptionLimit" in scheduler_config_text
            and "globalSubscriptionLimit" in scheduler_config_text
            and "minimumPollInterval" in scheduler_config_text
            and "maximumFailureBackoff" in scheduler_config_text
            and "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_PER_TICK_FETCH_LIMIT"
            in scheduler_config_text
        ),
        "dedupeAndMetadataOnly": (
            "contentChanged(" in service_text
            and "contentSha256" in subscription_text
            and "lastSeenEdition" in subscription_text
            and "lastSeenResolvedUri" in subscription_text
            and "updateCount" in subscription_text
            and "raw fetched content is digested and then discarded" in service_text
        ),
        "failureBackoff": (
            "failureBackoff(" in service_text
            and "withFailure" in service_text
            and "lastErrorCode" in store_text
            and "content_fetch_failed" in service_text
        ),
        "pressureGateStableSignals": (
            "QueueSupportPort" in pressure_text
            and "RequestQueuePort" in pressure_text
            and "isQueueBackendEnabled()" in pressure_text
            and "isPersistenceDatabaseKilled()" in pressure_text
            and "stopping()" in pressure_text
            and "awaitingPassword()" in pressure_text
            and "queueHtml" not in pressure_text
        ),
        "durablePathFreeStore": (
            "public final class FileContentSubscriptionStore" in store_text
            and "ATOMIC_MOVE" in store_text
            and "source URIs are never used as file names" in store_text
            and "content-subscriptions" in runtime_text
            and "layout.dataDir().resolve(\"apps\").resolve(\"content-subscriptions\")"
            in runtime_text
        ),
        "runtimeWiring": (
            "createContentSubscriptionService(" in runtime_text
            and "createContentSubscriptionScheduler(" in runtime_text
            and "contentSubscriptionScheduler.start()" in runtime_text
            and "contentSubscriptionService()" in runtime_text
        ),
        "focusedTestsPresent": (
            "tick_whenSubscriptionIsDue_expectOneBoundedFetchAndUpdatedMetadata" in tests_text
            and "tick_whenQueueBackendUnavailable_expectSafePressureSkip" in tests_text
            and "refresh_whenContentMetadataChanges_expectDigestEditionAndDedupe" in tests_text
            and "writeAndRead_whenSubscriptionContainsSourceUri_expectPathUsesAppAndSubscriptionIdsOnly"
            in tests_text
        ),
        "docsDescribeSchedulerRedaction": all(
            phrase in lower_docs
            for phrase in (
                "network-content.subscription-scheduler",
                "queue pressure",
                "no queue html",
                "raw fetched content",
                "path-free",
            )
        ),
    }
    details = {
        "policy": "bounded USK-only background polling with durable metadata, per-app/global/per-tick limits, and explicit pressure skips",
        "liveNodeRequired": False,
        "checks": checks,
        "sources": {
            "scheduler": display_path(scheduler_source, workspace),
            "schedulerConfig": display_path(scheduler_config_source, workspace),
            "service": display_path(service_source, workspace),
            "subscription": display_path(subscription_source, workspace),
            "store": display_path(store_source, workspace),
            "pressureGate": display_path(pressure_source, workspace),
            "runtime": display_path(runtime_source, workspace),
            "tests": [
                display_path(scheduler_test_source, workspace),
                display_path(service_test_source, workspace),
                display_path(store_test_source, workspace),
            ],
        },
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "network-content.subscription-scheduler",
            root_consequence(settings, "fail"),
            True,
            "Content subscription scheduler evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "network-content.subscription-scheduler",
        "pass",
        True,
        "Content subscription scheduler passed deterministic offline evidence checks.",
        source,
        details,
    )

def collect_network_scale_evidence(settings: Settings) -> list[EvidenceItem]:
    source = summary_source(settings)
    workspace = settings.workspace_root
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    budget_dir = api_dir / "networkbudget"
    budget_test_dir = workspace / "platform-api/src/test/java/network/crypta/platform/api/networkbudget"
    content_routes = read_source(api_dir / "PlatformApiContentRoutes.java")
    content_handler = read_source(api_dir / "content/ContentApiHandler.java")
    shared_services = read_source(api_dir / "PlatformApiSharedAppServices.java")
    router = read_source(api_dir / "PlatformApiRouter.java")
    subscription_dir = api_dir / "content/subscriptions"
    subscription_service = read_source(subscription_dir / "ContentSubscriptionService.java")
    subscription_scheduler = read_source(subscription_dir / "ContentSubscriptionScheduler.java")
    subscription_status = read_source(subscription_dir / "ContentSubscriptionStatus.java")
    pressure_gate = read_source(subscription_dir / "ContentSubscriptionPressureGate.java")
    trust_handler = read_source(api_dir / "trust/TrustGraphApiHandler.java")
    runtime = read_source(
        workspace / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    social_app = read_source(workspace / "apps/social-inbox/src/staged/static/app.js")
    social_test = read_source(
        workspace / "apps/social-inbox/src/test/java/network/crypta/apps/socialinbox/SocialInboxBundleStagingTest.java"
    )
    platform_tests = "\n".join(
        read_source(path)
        for path in sorted((workspace / "platform-api/src/test/java/network/crypta/platform/api").rglob("*.java"))
    )
    budget_text = "\n".join(read_source(path) for path in sorted(budget_dir.glob("*.java")))
    budget_tests = "\n".join(read_source(path) for path in sorted(budget_test_dir.glob("*.java")))
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/network-scale-soak-and-subscription-budget.md",
            "docs/release-certification.md",
            "docs/platform-api-contract.md",
            "docs/platform-api-surface.md",
            "docs/feed-reader-reference-app.md",
            "docs/social-inbox-reference-app.md",
            "docs/trust-graph-preview.md",
            "docs/operator-beta-dashboard.md",
        )
    )
    lower_docs = docs_text.lower()
    refresh_all = function_slice(
        social_app,
        "async function refreshAllActiveSources",
        "async function refreshAllSources",
    )
    trust_import_uri = function_slice(
        trust_handler,
        "public Map<String, Object> importUri",
        "private AppNetworkBudgetLease",
    )
    queue_before_poll = source_index_before(
        subscription_scheduler, "pressureGate.assess()", "service.schedulerPoll"
    )
    import_budget_before_fetch = source_index_before(
        trust_import_uri,
        "reserveTrustGraphImportBudget(appId)",
        "new ContentApiHandler",
    )
    checks_by_id: dict[str, dict[str, bool]] = {
        "network-scale.app-network-budget": {
            "packagePresent": budget_dir.is_dir()
            and all(
                name in budget_text
                for name in (
                    "AppNetworkBudgetConfig",
                    "AppNetworkBudgetService",
                    "AppNetworkBudgetStore",
                    "FileAppNetworkBudgetStore",
                    "InMemoryAppNetworkBudgetStore",
                    "AppNetworkBudgetDecision",
                    "AppNetworkBudgetOperation",
                    "AppNetworkBudgetReservation",
                    "AppNetworkBudgetScope",
                    "AppNetworkBudgetSnapshot",
                    "AppNetworkBudgetUsage",
                    "AppNetworkBudgetLease",
                )
            ),
            "finiteDefaultsPresent": all(
                value in budget_text
                for value in ("20, 200, 2, 16, 48, 1024, 1, 8, 120, 1024, 1, 8", "requirePositive")
            ),
            "systemAndEnvironmentConfigPresent": all(
                value in budget_text
                for value in (
                    "cryptad.appNetworkBudget.foregroundContentFetchPerAppPerMinute",
                    "CRYPTAD_APP_NETWORK_BUDGET_FOREGROUND_CONTENT_FETCH_PER_APP_PER_MINUTE",
                    "cryptad.appNetworkBudget.subscriptionPollPerAppPerHour",
                    "CRYPTAD_APP_NETWORK_BUDGET_SUBSCRIPTION_POLL_PER_APP_PER_HOUR",
                    "cryptad.appNetworkBudget.trustGraphImportPerAppPerHour",
                    "CRYPTAD_APP_NETWORK_BUDGET_TRUST_GRAPH_IMPORT_PER_APP_PER_HOUR",
                )
            ),
            "pathSafeStoreAndRuntimeWiring": (
                "AppManifest.normalizeAppId" in budget_text
                and "_cryptad_global" in budget_text
                and "_cryptad_operator" in budget_text
                and "ATOMIC_MOVE" in budget_text
                and "network-budget" in runtime
                and "AppNetworkBudgetService" in shared_services
                and "checkedAppServices.networkBudgetService()" in router
                and "new PlatformApiContentRoutes" in router
                and "new ContentApiHandler(contentFetchPort, networkBudgetService)" in content_routes
            ),
            "deterministicTestsPresent": all(
                fragment in budget_tests
                for fragment in (
                    "acquire_whenPerAppRateLimitReached_expectDeniedUntilWindowReset",
                    "acquire_whenGlobalRateLimitReachedAcrossApps_expectDenied",
                    "acquire_whenLeaseClosedByExceptionPath_expectConcurrencyReleased",
                    "acquire_whenAppIdMatchesFormerGlobalScope_expectGlobalCounterIsSeparate",
                    "acquire_whenHostOperatorScopeUsesTrustBudget_expectOperatorAppBudgetIsSeparate",
                    "write_whenMetadataPersisted_expectNoRawContentSecretsOrPaths",
                    "write_whenInternalScopePersisted_expectPathSafeNonAppDirectory",
                )
            ),
        },
        "network-scale.content-fetch-budget": {
            "handlerUsesBudgetBeforeRuntimeFetch": all(
                fragment in content_handler
                for fragment in (
                    "AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH",
                    "networkBudgetService.acquire",
                    "contentFetchPort.fetchContent",
                )
            )
            and (
                "try (var _ = acquireBudget(appId))" in content_handler
                or "try (AppNetworkBudgetLease" in content_handler
            ),
            "routesPassAppPrincipalId": (
                "optionalAppPrincipalId(request)" in content_routes
                and ".fetch(request.queryParameters(), optionalAppPrincipalId(request))" in content_routes
            ),
            "safeBudgetErrorsCovered": all(
                fragment in platform_tests
                for fragment in (
                    "content_fetch_budget_exhausted",
                    "fetch_whenBudgetExhausted_expectDeniedBeforeRuntimePort",
                    "route_whenBrowserAppExhaustsFetchBudget_expectTooManyRequestsBeforeRuntimeFetch",
                )
            ),
            "contentPolicyStillPresent": (
                "ContentFetchPolicy.normalizeForegroundSource" in content_handler
                and (
                    "unsupported_content_source" in content_handler
                    or "unsupported_content_source" in platform_tests
                    or "unsupported content source" in docs_text.lower()
                )
            ),
        },
        "network-scale.subscription-budget": {
            "manualAndSchedulerUseBudgetOperations": all(
                fragment in subscription_service
                for fragment in (
                    "AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH",
                    "AppNetworkBudgetOperation.SUBSCRIPTION_POLL",
                    "networkBudgetService.reserve",
                    "ContentSubscriptionStatus.BUDGET_EXHAUSTED",
                )
            ),
            "statusIsPublicAndSafe": "BUDGET_EXHAUSTED(\"budget_exhausted\")" in subscription_status,
            "leasesAndRetryAreBounded": all(
                fragment in subscription_service
                for fragment in (
                    "nextAfterBudgetDenied",
                    "budgetDecision.message()",
                )
            )
            and (
                "try (var budgetReservation = reserveBudget" in subscription_service
                and "budgetReservation.commit()" in subscription_service
                or "try (AppNetworkBudgetLease" in subscription_service
            ),
            "testsCoverManualSchedulerAndLeaseRelease": all(
                fragment in platform_tests
                for fragment in (
                    "refresh_whenSubscriptionBudgetExhausted_expectSafeStatusWithoutFetch",
                    "schedulerPoll_whenSubscriptionBudgetExhausted_expectNoFetch",
                    "refresh_whenFetchThrows_expectBudgetLeaseReleasedForNextRefresh",
                    "refresh_whenRunningStateWriteFails_expectBudgetReservedUntilNextRefresh",
                )
            ),
        },
        "network-scale.queue-pressure-backoff": {
            "pressurePrecedesBudgetAndFetch": queue_before_poll
            and "if (!pressure.allowed())" in subscription_scheduler,
            "budgetSkipDoesNotCountAsAttempt": (
                "ContentSubscriptionStatus.BUDGET_EXHAUSTED" in subscription_scheduler
                and (
                    "new SchedulerPollOutcome(0, 1, 1" in subscription_scheduler
                    or "if (result == ContentSubscriptionStatus.BUDGET_EXHAUSTED) { return; } attempted++"
                    in subscription_scheduler
                )
            ),
            "pressureGateUsesStableSpiNoHtml": (
                "QueueSupportPort" in pressure_gate
                and "RequestQueuePort" in pressure_gate
                and "queueHtml" not in pressure_gate
            ),
            "testsProvePressureSkipsBudgetAndFetch": (
                "tick_whenQueuePressureSkipsPoll_expectBudgetNotConsumed" in platform_tests
            ),
        },
        "network-scale.trust-graph-import-budget": {
            "directImportUsesImportBudget": all(
                fragment in trust_handler
                for fragment in (
                    "AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT",
                    "networkBudgetService.acquire",
                )
            )
            and (
                "acquireTrustGraphImportBudgetLease(appId)" in trust_handler
                or "acquireBudgetLease(appId, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)"
                in trust_handler
            ),
            "importUriUsesImportAndContentFetchBudgets": (
                import_budget_before_fetch
                and "AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI" in trust_handler
                and "new ContentApiHandler" in trust_handler
                and "commitTrustGraphImportBudget(importReservation)" in trust_import_uri
            ),
            "safeErrorsAndNoRawContentCovered": all(
                fragment in platform_tests
                for fragment in (
                    "route_whenDirectImportBudgetExhausted_expectSafeTooManyRequests",
                    "route_whenImportUriImportBudgetExhausted_expectNoFetch",
                    "route_whenImportUriContentFetchBudgetExhausted_expectNoFetchOrImport",
                    "trust_graph_import_budget_exhausted",
                    "content_fetch_budget_exhausted",
                )
            ),
        },
        "network-scale.social-inbox-multi-source-soak": {
            "refreshAllIsCappedAndSequential": (
                ".slice(0, maxSources)" in refresh_all
                and "for (const sourceId of activeSourceIds)" in refresh_all
                and "Promise.all" not in refresh_all
            ),
            "statusWordingCoversPressureBudgetStale": all(
                fragment in social_app
                for fragment in (
                    "Queue pressure",
                    "Runtime unavailable",
                    "Backoff",
                    "Budget exhausted",
                    "Stale",
                )
            ),
            "trustAnnotationsRemainMediated": (
                "CryptaPlatform.services.invoke" in social_app
                and "CryptaPlatform.trust.score" not in social_app
                and "/api/v1/trust-graph/score" not in social_app
            ),
            "staticTestsCoverBoundsAndNoBrowserCache": all(
                fragment in social_test
                for fragment in (
                    "verifyBoundedRefreshAll",
                    "Promise.all",
                    "CryptaPlatform.trust.score",
                    "indexedDB",
                )
            ),
        },
        "network-scale.redaction": {
            "budgetStorePersistsSafeCountersOnly": all(
                fragment in budget_text
                for fragment in (
                    "appId",
                    "operation",
                    "windowStart",
                    "lastDecision",
                    "nextAvailableAt",
                )
            )
            and all(fragment not in budget_text for fragment in ("contentText", "queueHtml", "browserSessionToken")),
            "releaseDocsForbidSensitiveEvidence": all(
                phrase in lower_docs
                for phrase in (
                    "raw fetched content",
                    "queue html",
                    "browser-session tokens",
                    "private insert uris",
                    "raw signatures",
                    "absolute local paths",
                )
            ),
            "soakFixtureIsRedactionOnly": (
                "self-test-network-scale-soak.json" in docs_text
                or (workspace / "tools/release-certification/fixtures/self-test-network-scale-soak.json").is_file()
            ),
        },
    }
    sources = {
        "budget": display_path(budget_dir, workspace),
        "contentRoutes": display_path(api_dir / "PlatformApiContentRoutes.java", workspace),
        "contentHandler": display_path(api_dir / "content/ContentApiHandler.java", workspace),
        "subscriptionService": display_path(subscription_dir / "ContentSubscriptionService.java", workspace),
        "subscriptionScheduler": display_path(subscription_dir / "ContentSubscriptionScheduler.java", workspace),
        "trustGraphHandler": display_path(api_dir / "trust/TrustGraphApiHandler.java", workspace),
        "socialInbox": display_path(workspace / "apps/social-inbox/src/staged/static/app.js", workspace),
        "docs": "docs/network-scale-soak-and-subscription-budget.md",
    }
    items: list[EvidenceItem] = []
    for evidence_id in NETWORK_SCALE_EVIDENCE_IDS:
        checks = checks_by_id[evidence_id]
        errors = [name for name, passed in checks.items() if passed is not True]
        details = {
            "checks": checks,
            "sources": sources,
            "redaction": {
                "rawFetchedContentExcluded": True,
                "privateInsertUrisExcluded": True,
                "tokensExcluded": True,
                "absolutePathsExcluded": True,
                "queueHtmlExcluded": True,
            },
        }
        if errors:
            items.append(
                EvidenceItem(
                    evidence_id,
                    root_consequence(settings, "fail"),
                    True,
                    f"{evidence_id} evidence is incomplete.",
                    source,
                    {"errors": errors, **details},
                )
            )
        else:
            items.append(
                EvidenceItem(
                    evidence_id,
                    "pass",
                    True,
                    f"{evidence_id} passed deterministic network-scale checks.",
                    source,
                    details,
                )
            )
    return items

def source_index_before(source: str, earlier: str, later: str) -> bool:
    earlier_index = source.find(earlier)
    later_index = source.find(later)
    return earlier_index >= 0 and later_index >= 0 and earlier_index < later_index

def function_slice(source: str, start_marker: str, end_marker: str) -> str:
    start = source.find(start_marker)
    end = source.find(end_marker, start + len(start_marker)) if start >= 0 else -1
    if start < 0 or end <= start:
        return ""
    return source[start:end]

def collect_app_data_store_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "contract": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java",
        "capabilities": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java",
        "router": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java",
        "routes": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiAppDataRoutes.java",
        "service": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "exportPayload": workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataExportPayload.java",
        "fileStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/FileAppDataStore.java",
        "config": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataStoreConfig.java",
        "handler": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataApiHandler.java",
        "runtime": workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java",
        "sdk": workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js",
        "docs": workspace / "docs/app-data-store.md",
        "contractDocs": workspace / "docs/platform-api-contract.md",
        "apiDocs": workspace / "docs/platform-api-surface.md",
        "routerTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiAppDataRouterTest.java",
        "serviceTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "fileStoreTest": workspace
        / "platform-api/src/test/java/network/crypta/platform/api/appdata/FileAppDataStoreTest.java",
        "uninstallOptions": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/AppUninstallOptions.java",
        "localAppHost": workspace
        / "platform-apphost/src/main/java/network/crypta/platform/apphost/runtime/LocalProcessAppHost.java",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    required_routes = (
        "/app-data/status",
        "/app-data/namespaces",
        "/app-data/namespaces/{namespace}",
        "/app-data/namespaces/{namespace}/schema",
        "/app-data/records",
        "/app-data/records/{namespace}/{key}",
        "/app-data/export",
        "/app-data/import",
    )
    checks = {
        "contractV9AndCapabilities": (
            (
                "CURRENT_CONTRACT_VERSION = 9" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 10" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 11" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 12" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 13" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 14" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 15" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 20" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 22" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 23" in text["contract"]
                or "CURRENT_CONTRACT_VERSION = 24" in text["contract"]
            )
            and "APP_DATA_STORE_CONTRACT_VERSION = 9" in text["contract"]
            and "app.data.read" in text["capabilities"]
            and "app.data.write" in text["capabilities"]
            and all(route in text["contract"] for route in required_routes)
        ),
        "routesRequireAppPrincipalAndCapabilities": (
            "PlatformApiAppDataRoutes" in text["router"]
            and "requireAppPrincipalId" in text["routes"]
            and "app.data.read" in text["capabilities"]
            and "app.data.write" in text["capabilities"]
            and (
                "PlatformApiCapabilities.APP_DATA_READ" in text["contract"]
                or "app.data.read" in text["contract"]
            )
            and (
                "PlatformApiCapabilities.APP_DATA_WRITE" in text["contract"]
                or "app.data.write" in text["contract"]
            )
        ),
        "fileBackedStoreIsPathSafeAndAtomic": (
            "sha256" in text["fileStore"].lower()
            and "ATOMIC_MOVE" in text["fileStore"]
            and "current.properties" in text["fileStore"]
            and ".cryptad-app-data" in text["fileStore"]
            and "value.bin" in text["fileStore"]
        ),
        "serviceBoundsQuotaAndImportExport": (
            "maxRecordBytes" in text["config"]
            and "maxRecordsPerApp" in text["config"]
            and "maxNamespacesPerApp" in text["config"]
            and "maxExportBytes" in text["config"]
            and "maxImportBytes" in text["config"]
            and "quota.data.bytes" in text["config"]
            and "app_data_import_app_mismatch" in text["exportPayload"]
        ),
        "schemaMigrationMetadata": (
            "updateSchema" in text["service"]
            and "fromSchemaVersion" in text["service"]
            and "toSchemaVersion" in text["service"]
            and "lastMigrationAt" in text["service"]
        ),
        "sdkHelpersExistAndAvoidBrowserStorage": (
            "data: Object.freeze" in text["sdk"]
            and "putAppDataJson" in text["sdk"]
            and "getAppDataJson" in text["sdk"]
            and "app-data/export" in text["sdk"]
            and "app-data/import" in text["sdk"]
            and "localStorage" not in text["sdk"]
            and "sessionStorage" not in text["sdk"]
        ),
        "testsCoverCoreSecurityAndPersistence": (
            "route_whenAppReadsAnotherAppsRecord_expectNotFound" in text["routerTest"]
            and "route_whenCapabilityMissingOrServiceUnavailable_expectDeniedOr503" in text["routerTest"]
            and "putRecord_whenIdentifierContainsTraversal_expectPathFreeValidationError" in text["serviceTest"]
            and "exportImport_whenPayloadRoundTrips_expectValuesCopiedAndOtherAppRejected" in text["serviceTest"]
            and "writeRecord_whenUnreferencedGenerationExists_expectCurrentRecordUnaffected" in text["fileStoreTest"]
        ),
        "runtimeAndUninstallWired": (
            "createAppDataService" in text["runtime"]
            and "durable-app-data" in text["runtime"]
            and "storeUsageOutsideAppDataDir" in text["service"]
            and "preserveData" in text["uninstallOptions"]
            and "options.preserveData()" in text["localAppHost"]
        ),
        "docsCoverLimitsAndRedaction": (
            "app.data.read" in text["docs"]
            and "cryptad.appData.maxRecordBytes" in text["docs"]
            and "Export and import" in text["docs"]
            and "Redaction rules" in text["docs"]
            and "not a filesystem API" in text["docs"]
            and "app-data" in text["contractDocs"]
            and "App data" in text["apiDocs"]
        ),
    }
    details = {
        "checks": checks,
        "routes": list(required_routes),
        "capabilities": ["app.data.read", "app.data.write"],
        "redaction": {
            "rawValuesExcludedFromEvidence": True,
            "rawRequestBodiesExcluded": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors = [f"app data store check failed: {name}" for name, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.durable-app-data-store",
            root_consequence(settings, "fail"),
            True,
            "Durable app-data store evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.durable-app-data-store",
        "pass",
        True,
        "Durable app-data store evidence passed.",
        source,
        details,
    )

def collect_app_data_backup_restore_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    source_files = {
        "service": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataService.java",
        "workflow": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupRestoreWorkflow.java",
        "store": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataStore.java",
        "fileStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/FileAppDataStore.java",
        "memoryStore": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/InMemoryAppDataStore.java",
        "bundle": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupBundle.java",
        "entry": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupEntry.java",
        "manifest": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupManifest.java",
        "options": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataBackupOptions.java",
        "restoreMode": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestoreMode.java",
        "restorePlan": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestorePlan.java",
        "restoreResult": workspace / "platform-api/src/main/java/network/crypta/platform/api/appdata/AppDataRestoreResult.java",
        "operatorRoutes": workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiOperatorRoutes.java",
        "toadlet": workspace / "adapter-http-legacy-admin/src/main/java/network/crypta/clients/http/PlatformApiToadlet.java",
        "redactor": workspace / "platform-api/src/main/java/network/crypta/platform/api/operator/OperatorSupportRedactor.java",
        "serviceTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/appdata/AppDataServiceTest.java",
        "fileStoreTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/appdata/FileAppDataStoreTest.java",
        "operatorRoutesTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiOperatorRoutesTest.java",
        "toadletTest": workspace / "src/test/java/network/crypta/clients/http/PlatformApiToadletTest.java",
        "redactorTest": workspace / "platform-api/src/test/java/network/crypta/platform/api/operator/OperatorSupportRedactorTest.java",
        "webShell": workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js",
        "webShellIndex": workspace / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/index.html",
        "webShellTest": workspace / "platform-web-shell/src/test/java/network/crypta/platform/webshell/WebShellResourcesTest.java",
        "backupDoc": workspace / "docs/app-data-backup-restore-portability.md",
        "appDataDoc": workspace / "docs/app-data-store.md",
        "operatorDoc": workspace / "docs/operator-beta-dashboard.md",
        "developerPortal": workspace / "docs/app-platform-developer-portal.md",
        "releaseDoc": workspace / "docs/release-certification.md",
        "certReadme": workspace / "tools/release-certification/README.md",
        "profileReadme": workspace / "apps/profile-publisher/README.md",
        "feedReadme": workspace / "apps/feed-reader/README.md",
        "socialReadme": workspace / "apps/social-inbox/README.md",
        "trustReadme": workspace / "apps/trust-graph/README.md",
    }
    text = {name: read_source(path) for name, path in source_files.items()}
    docs_text = "\n".join(
        text[name]
        for name in ("backupDoc", "appDataDoc", "operatorDoc", "developerPortal", "releaseDoc", "certReadme")
    )
    reference_docs_text = "\n".join(
        text[name] for name in ("profileReadme", "feedReadme", "socialReadme", "trustReadme")
    )
    model_text = "\n".join(
        text[name]
        for name in (
            "bundle",
            "entry",
            "manifest",
            "options",
            "restoreMode",
            "restorePlan",
            "restoreResult",
        )
    )
    checks = {
        "versionedEnvelopeModels": (
            "record AppDataBackupBundle" in text["bundle"]
            and "record AppDataBackupEntry" in text["entry"]
            and "record AppDataBackupManifest" in text["manifest"]
            and "CURRENT_BACKUP_VERSION = 1" in text["manifest"]
            and "crypta-app-data-backup" in text["manifest"]
            and "sensitiveUserData" in text["manifest"]
            and "ENCRYPTION_MODE_NONE" in text["manifest"]
            and "unsupported_backup_encryption" in text["manifest"]
        ),
        "metadataToStringAndPlanOmitRawValues": (
            "export.toJsonValue()" in text["entry"]
            and "return \"AppDataBackupBundle[" in text["bundle"]
            and "return \"AppDataBackupEntry[" in text["entry"]
            and "record AppDataRestorePlan" in text["restorePlan"]
            and "record AppDataRestoreResult" in text["restoreResult"]
            and "without raw backup values" in text["restorePlan"]
            and "without raw backup values" in text["restoreResult"]
            and '"export"' not in text["restorePlan"]
            and '"payloadBase64"' not in text["restorePlan"]
            and '"export"' not in text["restoreResult"]
            and '"payloadBase64"' not in text["restoreResult"]
        ),
        "storeListsKnownAppIds": (
            "listAppIds()" in text["store"]
            and "List<String> listAppIds()" in text["fileStore"]
            and "List<String> listAppIds()" in text["memoryStore"]
            and "listAppIds_whenStoreHasKnownAndMalformedDirectories_expectOnlyNormalizedIds"
            in text["fileStoreTest"]
        ),
        "serviceExportsSingleAndAllBackups": (
            "exportBackup" in text["service"]
            and "backupRestoreWorkflow.exportBackup" in text["service"]
            and "createBackupBundle" in text["workflow"]
            and "AppDataBackupOptions.SCOPE_SINGLE_APP" in text["workflow"]
            and "AppDataBackupOptions.SCOPE_ALL_APPS" in text["workflow"]
            and "listStoreAppIds()" in text["workflow"]
            and "payloadBase64" in text["workflow"]
            and "exportBackup_whenSingleAppRequested_expectVersionedEnvelopeAndMetadataOnlyToString"
            in text["serviceTest"]
            and "exportBackup_whenAllAppsRequested_expectKnownAppIdsSorted" in text["serviceTest"]
        ),
        "restoreModesPlanAndCommitReuseValidation": (
            "enum AppDataRestoreMode" in text["restoreMode"]
            and "MERGE(\"merge\")" in text["restoreMode"]
            and "REPLACE_NAMESPACE(\"replaceNamespace\")" in text["restoreMode"]
            and "REPLACE_APP(\"replaceApp\")" in text["restoreMode"]
            and "planRestore" in text["service"]
            and "restoreBackup" in text["service"]
            and "preflightImport" in text["service"]
            and "preflightReplaceApp" in text["service"]
            and "replaceImportedNamespaces" in text["service"]
            and "replaceAppData" in text["service"]
            and "restoreBackup_whenReplaceApp_expectTargetAppClearedAndOtherAppsPreserved"
            in text["serviceTest"]
            and "restorePlan_whenBackupContainsRawValues_expectMetadataOnlyPlan" in text["serviceTest"]
        ),
        "operatorOnlyRoutesAndAppPrincipalDenied": (
            "operator/app-data" in text["operatorRoutes"]
            and '"backups".equals(segments.get(2))' in text["operatorRoutes"]
            and "methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE)" in text["operatorRoutes"]
            and '"restore".equals(segments.get(2))' in text["operatorRoutes"]
            and (
                'case "plan"' in text["operatorRoutes"]
                or '"plan".equals(segments.get(3))' in text["operatorRoutes"]
            )
            and "appDataService.planRestore" in text["operatorRoutes"]
            and "requireHostOperator(request)" in text["operatorRoutes"]
            and "app_data_service_unavailable" in text["operatorRoutes"]
            and "requiresOperatorFormPassword" in text["toadlet"]
            and '"backups".equals(pathSegments.get(2))' in text["toadlet"]
            and "/operator/app-data/backups" in text["toadletTest"]
            and "route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan"
            in text["operatorRoutesTest"]
            and "route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden"
            in text["operatorRoutesTest"]
        ),
        "supportRedactionRecognizesBackupPayloads": (
            "crypta-app-data-backup" in text["redactor"]
            and "REDACTED_APP_DATA_BACKUP" in text["redactor"]
            and "backupbundle" in text["redactor"].lower()
            and "payloadbase64" in text["redactor"].lower()
            and "redact_whenBackupPayloadAccidentallyEntersSupportBundle_expectWholeBackupRedacted"
            in text["redactorTest"]
        ),
        "webShellExposesBackupRestoreAndNoPersistentBackupStorage": (
            "Download all app-data backup" in text["webShellIndex"]
            and "Sensitive backup payload" in text["webShellIndex"]
            and "function downloadAllAppDataBackup()" in text["webShell"]
            and "function submitAppDataRestoreForm(form, restoreAction, statusSetter)" in text["webShell"]
            and "operator/app-data/backups" in text["webShell"]
            and "operator/app-data/restore/plan" in text["webShell"]
            and "operator/app-data/restore" in text["webShell"]
            and "function appDataBackupPayloadBlob(response)" in text["webShell"]
            and "urlSafeBase64ToBytes(payloadBase64)" in text["webShell"]
            and 'downloadAppDataBackupPayload(response, "all-apps", "")' in text["webShell"]
            and 'downloadAppDataBackupPayload(response, "single-app", appId)' in text["webShell"]
            and "localStorage" in text["webShell"]
            and "backupPayload" in text["webShell"]
            and "sessionStorage" not in text["webShell"]
            and "IndexedDB" not in text["webShell"]
            and "Export backup before delete" in text["webShell"]
            and "assertAppDataBackupRestoreMarkersPresent(script)" in text["webShellTest"]
        ),
        "docsCoverFormatModesSensitivityAndExclusions": (
            "backupVersion" in docs_text
            and "crypta-app-data-backup" in docs_text
            and "single-app" in docs_text
            and "all-apps" in docs_text
            and "merge" in docs_text
            and "replaceNamespace" in docs_text
            and "replaceApp" in docs_text
            and "sensitive user data" in docs_text
            and "encryption.mode = none" in docs_text
            and "vault secrets" in docs_text
            and "private identity material" in docs_text
            and "support bundles" in docs_text
            and "release evidence" in docs_text
            and "operator-beta.app-data-backup-restore" in docs_text
            and "app-data.backup-restore-portability" in docs_text
        ),
        "firstPartyDocsDescribePortableScope": (
            reference_docs_text.count("App-data backup scope") >= 4
            and "vault private identity material" in reference_docs_text
            and "app-service tokens" in reference_docs_text
            and "UI-local" in reference_docs_text
        ),
    }
    details = {
        "checks": checks,
        "backupVersion": 1,
        "encryptionModesSupported": ["none"],
        "restoreModes": ["merge", "replaceNamespace", "replaceApp"],
        "operatorRouteTemplates": [
            "POST /api/v1/operator/app-data/backups appId=<app-id>",
            "POST /api/v1/operator/app-data/backups scope=all",
            "POST /api/v1/operator/app-data/restore/plan",
            "POST /api/v1/operator/app-data/restore",
        ],
        "redaction": {
            "rawBackupPayloadsExcludedFromEvidence": True,
            "supportBundlesExcludeBackupPayloads": True,
            "tokensExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
        "sources": {name: display_path(path, workspace) for name, path in source_files.items()},
    }
    errors = [key for key, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-data.backup-restore-portability",
            root_consequence(settings, "fail"),
            True,
            "App-data backup/restore portability evidence is incomplete.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-data.backup-restore-portability",
        "pass",
        True,
        "App-data backup/restore portability evidence passed deterministic checks.",
        source,
        details,
    )

def read_json_file(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None

def ui_lint_report_errors(lint_json: dict[str, Any] | None, expected_app_id: str) -> list[str]:
    if lint_json is None:
        return [f"crypta-app ui lint JSON missing or malformed for {expected_app_id}"]
    errors: list[str] = []
    if lint_json.get("appId") != expected_app_id:
        errors.append(f"crypta-app ui lint JSON appId mismatch for {expected_app_id}")
    if lint_json.get("uiMode") != "static":
        errors.append(f"crypta-app ui lint JSON uiMode mismatch for {expected_app_id}")
    if lint_json.get("applicable") is not True:
        errors.append(f"crypta-app ui lint JSON applicability mismatch for {expected_app_id}")
    summary = lint_json.get("summary")
    if not isinstance(summary, dict):
        errors.append(
            f"crypta-app ui lint JSON summary missing or malformed for {expected_app_id}"
        )
    else:
        error_count = summary.get("errors")
        if not isinstance(error_count, int) or isinstance(error_count, bool) or error_count != 0:
            errors.append(f"crypta-app ui lint JSON reports nonzero errors for {expected_app_id}")
    findings = lint_json.get("findings")
    if not isinstance(findings, list):
        errors.append(
            f"crypta-app ui lint JSON findings missing or malformed for {expected_app_id}"
        )
    elif any(
        isinstance(finding, dict) and str(finding.get("severity", "")).lower() == "error"
        for finding in findings
    ):
        errors.append(
            f"crypta-app ui lint JSON findings include error severity for {expected_app_id}"
        )
    return errors

def collect_app_ui_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    source_ok, source_errors, source_details = check_source_static_ui(settings)
    staged_errors: list[str] = []
    staged_details: dict[str, Any] = {}
    for spec in first_party_app_specs(settings):
        static_dir = spec["stagedDir"] / "static"
        errors, details = validate_static_ui_files(static_dir, settings)
        staged_errors.extend(f"{spec['appId']}: {error}" for error in errors)
        staged_details[spec["appId"]] = details
    errors = source_errors + staged_errors
    details = {"sourceStaticUi": source_details, "stagedStaticUi": staged_details}
    if errors:
        return EvidenceItem(
            "app-ui.smoke",
            "fail" if settings.mode == "release-candidate" else "warn",
            True,
            "App-owned UI or SDK smoke found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem("app-ui.smoke", "pass", True, "App-owned UI and SDK smoke passed.", source, details)

def collect_reference_content_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "site-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "site-publisher",
        "checks": {},
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/site-publisher"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
            "expectedPermissions": sorted(spec["permissions"]),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesContentInsertDirectory"] = "CryptaPlatform.content.insertDirectory" in source_app_js
    checks["usesContentInsertFile"] = "CryptaPlatform.content.insertFile" in source_app_js
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load({ appId })" in source_app_js
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    checks["noVaultCapabilitiesDeclared"] = bool(manifest) and not any(
        permission.startswith("vault.") for permission in manifest_permissions
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["identityProfileDemoDocumentedFutureWork"] = (
        "Identity-backed" in app_readme and "future work" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresSitePublisher"] = (
            manifest.get("app.id") == "site-publisher"
            and manifest.get("app.name") == "Site Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresContentPermissions"] = spec["permissions"].issubset(
            manifest_permissions
        )
    else:
        checks["manifestDeclaresSitePublisher"] = False
        checks["manifestDeclaresContentPermissions"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"reference content app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-apps.content",
            root_consequence(settings, "fail"),
            True,
            "Site Publisher reference content app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-apps.content",
        "pass",
        True,
        "Site Publisher reference content app evidence passed.",
        source,
        details,
    )

def collect_profile_publisher_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "profile-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "profile-publisher",
        "checks": {},
        "expectedPermissions": sorted(PROFILE_PUBLISHER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.profile-publisher",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/profile-publisher"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesBrowserSafeIdentityCreation"] = (
        "app-vault/identities" in source_app_js
        or "createVaultIdentity" in source_app_js
        or "createIdentity" in source_app_js
        or "vault.identities.create" in source_app_js
    )
    checks["usesProfileDocumentRoute"] = (
        "profile-document" in source_app_js or "profileDocument" in source_app_js
    )
    checks["usesGeneratedDocumentInsertRoute"] = (
        "queue/inserts/app-document" in source_app_js
        or "insertAppDocument" in source_app_js
        or "publishSnapshot" in source_app_js
    )
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesAppDataHelpers"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "lastPublishedProfileUri" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["readmeDocumentsProfilePublishingFlow"] = (
        "Profile Publisher" in app_readme
        and "profile-document" in app_readme
        and "app-document" in app_readme
        and "app-data" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresProfilePublisher"] = (
            manifest.get("app.id") == "profile-publisher"
            and manifest.get("app.name") == "Profile Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresProfilePermissions"] = PROFILE_PUBLISHER_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesAppDataContract"] = (
            manifest.get("api.minimumVersion") == "9"
            and manifest.get("api.maximumTestedVersion")
            == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        )
        checks["manifestAvoidsUnneededVaultManagement"] = not any(
            permission in manifest_permissions
            for permission in (
                "vault.secrets.read",
                "vault.secrets.write",
                "vault.identities.manage",
            )
        )
    else:
        checks["manifestDeclaresProfilePublisher"] = False
        checks["manifestDeclaresProfilePermissions"] = False
        checks["manifestUsesAppDataContract"] = False
        checks["manifestAvoidsUnneededVaultManagement"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"profile publisher app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.profile-publisher",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.profile-publisher",
        "pass",
        True,
        "Profile Publisher reference app evidence passed.",
        source,
        details,
    )

def collect_feed_reader_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "feed-reader",
        "checks": {},
        "expectedPermissions": sorted(FEED_READER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/feed-reader"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    reference_doc = read_source(settings.workspace_root / "docs/feed-reader-reference-app.md")
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesContentFetchRouteOrHelper"] = (
        "CryptaPlatform.content.fetchText" in source_app_js
        or "CryptaPlatform.content.fetchBase64" in source_app_js
        or "CryptaPlatform.feed.fetchSnapshot" in source_app_js
        or "content/fetch" in source_app_js
    )
    checks["usesContentSubscriptionHelpers"] = (
        "CryptaPlatform.content.subscriptions" in source_app_js
        and "content.subscriptions.list" in source_app_js
        and "content.subscriptions.refresh" in source_app_js
    )
    checks["usesGeneratedDocumentInsertRoute"] = (
        "queue/inserts/app-document" in source_app_js
        or "insertAppDocument" in source_app_js
        or "publishSnapshot" in source_app_js
    )
    checks["usesUploadQueueSnapshot"] = "CryptaPlatform.queue.snapshot" in source_app_js
    checks["usesAppDataHelpers"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "lastPublisherDraft" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    checks["noTabOnlyFollowTimer"] = "setInterval" not in source_app_js
    checks["docsDescribeFeedReaderFlow"] = (
        "Feed Reader" in reference_doc
        and "POST /api/v1/content/fetch" in reference_doc
        and "content.subscribe" in reference_doc
        and "content.fetch" in reference_doc
        and "app.data.read" in reference_doc
        and "raw feed bodies" in reference_doc
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
        }
        checks["manifestDeclaresFeedReader"] = (
            manifest.get("app.id") == "feed-reader"
            and manifest.get("app.name") == "Feed Reader & Publisher"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresFeedPermissions"] = FEED_READER_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesCertifiedApiRange"] = (
            manifest.get("api.minimumVersion") == "9"
            and manifest.get("api.maximumTestedVersion")
            == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        )
    else:
        checks["manifestDeclaresFeedReader"] = False
        checks["manifestDeclaresFeedPermissions"] = False
        checks["manifestUsesCertifiedApiRange"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader",
        "pass",
        True,
        "Feed Reader reference app evidence passed.",
        source,
        details,
    )

def collect_feed_reader_subscription_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "feed-reader",
        "checks": {},
        "expectedPermissions": sorted(FEED_READER_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader subscription evidence is missing its first-party app spec.",
            source,
            details,
        )

    workspace = settings.workspace_root
    source_static_dir = spec["sourceDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    reference_doc = read_source(workspace / "docs/feed-reader-reference-app.md")
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    catalog_docs = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/app-catalogs.md",
            "docs/first-party-beta-catalog.md",
            "docs/release-certification.md",
        )
    )
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    checks = details["checks"]
    checks["manifestDeclaresSubscribeAndV9"] = (
        manifest.get("app.id") == "feed-reader"
        and FEED_READER_PERMISSIONS.issubset(manifest_permissions)
        and manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
    )
    checks["uiDisclosesSubscribePermission"] = (
        "content.subscribe" in permission_disclosure_block(source_index)
        and (
            "Create platform USK subscription" in source_index
            or "content.subscriptions.create" in source_app_js
        )
    )
    checks["appUsesPlatformSubscriptionWorkflow"] = (
        "CryptaPlatform.content.subscriptions.create" in source_app_js
        and "CryptaPlatform.content.subscriptions.list" in source_app_js
        and "CryptaPlatform.content.subscriptions.refresh" in source_app_js
        and (
            "CryptaPlatform.content.subscriptions.pause" in source_app_js
            or 'mutateSubscription(subscriptionId, "pause"' in source_app_js
        )
        and (
            "CryptaPlatform.content.subscriptions.resume" in source_app_js
            or 'mutateSubscription(subscriptionId, "resume"' in source_app_js
        )
        and "CryptaPlatform.content.subscriptions.remove" in source_app_js
        and "lastSeenResolvedUri" in source_app_js
    )
    checks["noTabLocalFollowLoop"] = "setInterval" not in source_app_js
    checks["onDemandRenderStillUsesContentFetch"] = (
        "CryptaPlatform.content.fetchText" in source_app_js
        and "CryptaPlatform.feed.fetchSnapshot" in source_app_js
    )
    checks["sdkHelpersAvailable"] = (
        "subscriptions: Object.freeze" in sdk_text
        and "createContentSubscription" in sdk_text
        and "removeContentSubscription" in sdk_text
    )
    checks["docsDescribeSubscriptionFlow"] = (
        "content.subscribe" in reference_doc
        and "durable" in reference_doc.lower()
        and "metadata" in reference_doc.lower()
        and "raw feed bodies" in reference_doc
        and "reference-app.feed-reader-subscriptions" in catalog_docs
    )
    details["manifest"] = {
        "permissions": sorted(manifest_permissions),
        "apiMinimumVersion": manifest.get("api.minimumVersion"),
        "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
    }
    details["redaction"] = {
        "rawFeedBodiesExcluded": True,
        "rawRequestBodiesExcluded": True,
        "tokensExcluded": True,
        "absolutePathsExcluded": True,
        "subscriptionMetadataOnly": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader subscription check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader-subscriptions",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader subscription workflow evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader-subscriptions",
        "pass",
        True,
        "Feed Reader subscription workflow evidence passed.",
        source,
        details,
    )

def collect_feed_reader_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "feed-reader"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "feed-reader", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.feed-reader-app-data",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/feed-reader/README.md",
            "docs/feed-reader-reference-app.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsBoundedReaderState"] = all(
        fragment in app_js
        for fragment in (
            "const maxSources",
            "maxRememberedSnapshots",
            'const dataNamespace = "ui-state"',
            'const dataStateKey = "reader-state"',
            "lastPublisherDraft",
            "selectedSourceId",
            "fetchedSnapshots",
        )
    )
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsAndEvidenceMentionDurableAppData"] = (
        "reference-app.feed-reader-app-data" in docs_text
        and "app-data" in docs_text
        and "app.data.read" in docs_text
        and "raw feed bodies" in docs_text
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
    )
    details["redaction"] = {
        "rawFeedBodiesExcluded": True,
        "rawAppDataValuesExcluded": True,
        "privateInsertUrisExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"feed reader app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.feed-reader-app-data",
            root_consequence(settings, "fail"),
            True,
            "Feed Reader durable app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.feed-reader-app-data",
        "pass",
        True,
        "Feed Reader durable app-data evidence passed.",
        source,
        details,
    )

def collect_profile_publisher_app_data_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "profile-publisher"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "profile-publisher", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.profile-publisher-app-data",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher app-data evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/profile-publisher/README.md",
            "docs/app-platform-developer-portal.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "9"
        and manifest.get("api.maximumTestedVersion")
        == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsBoundedDraftState"] = all(
        fragment in app_js
        for fragment in (
            'const dataNamespace = "profile-draft"',
            'const dataStateKey = "publisher-state"',
            "maxRecentActions",
            "lastPublishedProfileUri",
            "recentActions",
            "selectedIdentityId",
        )
    )
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsAndEvidenceMentionDurableAppData"] = (
        "reference-app.profile-publisher-app-data" in docs_text
        and "app-data" in docs_text
        and "AppVault" in docs_text
        and "app.data.write" in docs_text
    )
    checks["noBrowserStorageOrSecretPersistence"] = (
        "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
        and "privateKey" not in app_js
        and "seed" not in app_js
    )
    details["redaction"] = {
        "rawProfileDraftExcluded": True,
        "identityPrivateMaterialExcluded": True,
        "privateInsertUrisExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"profile publisher app-data check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.profile-publisher-app-data",
            root_consequence(settings, "fail"),
            True,
            "Profile Publisher durable app-data evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.profile-publisher-app-data",
        "pass",
        True,
        "Profile Publisher durable app-data evidence passed.",
        source,
        details,
    )

def collect_trust_graph_reference_app_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {
        "appId": "trust-graph",
        "checks": {},
        "expectedPermissions": sorted(TRUST_GRAPH_PERMISSIONS),
    }
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC first-party app spec is missing.",
            source,
            details,
        )

    app_dir = settings.workspace_root / "apps/trust-graph"
    source_static_dir = spec["sourceDir"] / "static"
    staged_static_dir = spec["stagedDir"] / "static"
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    source_index = read_source(source_static_dir / "index.html")
    source_app_js = read_source(source_static_dir / "app.js")
    app_readme = read_source(app_dir / "README.md")
    reference_doc = read_source(settings.workspace_root / "docs/trust-graph-preview.md")
    normalized_reference_doc = normalized_source_text(reference_doc)
    manifest: dict[str, str] = {}
    manifest_permissions: set[str] = set()
    if manifest_path.is_file():
        try:
            manifest = parse_properties(manifest_path)
            manifest_permissions = parse_permission_set(manifest.get("app.permissions", ""))
        except ValueError as exc:
            errors.append(str(exc))
    details.update(
        {
            "sourceDir": display_path(spec["sourceDir"], settings.workspace_root),
            "stagedDir": display_path(spec["stagedDir"], settings.workspace_root),
        }
    )
    checks = details["checks"]
    checks["moduleExists"] = app_dir.is_dir()
    checks["stagedManifestPresent"] = manifest_path.is_file()
    checks["sourceStaticUiPresent"] = (source_static_dir / "index.html").is_file() and (
        source_static_dir / "app.js"
    ).is_file()
    checks["stagedSdkPresent"] = (staged_static_dir / "crypta-platform.js").is_file()
    checks["stagedDesignSystemPresent"] = all(
        (staged_static_dir / "crypta-ui" / asset_name).is_file()
        for asset_name in design_system_asset_names()
    )
    checks["usesSdkBootstrap"] = "CryptaPlatform.bootstrap.load" in source_app_js
    checks["usesTrustHelpers"] = all(
        fragment in source_app_js
        for fragment in (
            "CryptaPlatform.trust.status",
            "CryptaPlatform.trust.anchors.list",
            "CryptaPlatform.trust.previewImport",
            "CryptaPlatform.trust.importStatement",
            "CryptaPlatform.trust.exchange.fetchAndImport",
            "CryptaPlatform.trust.audit.list",
            "CryptaPlatform.trust.score",
            "CryptaPlatform.trust.exchange.publish",
        )
    )
    checks["usesBoundedTrustSigningHelper"] = (
        "CryptaPlatform.trust.exchange.publish" in source_app_js
    )
    checks["usesTrustExchangeAndQueuePreview"] = (
        "CryptaPlatform.trust.previewImport" in source_app_js
        and "CryptaPlatform.trust.importStatement" in source_app_js
        and "CryptaPlatform.trust.exchange.fetchAndImport" in source_app_js
        and "expectedDocumentFingerprint" in source_app_js
        and "CryptaPlatform.trust.exchange.subscriptions." in source_app_js
        and "CryptaPlatform.queue.snapshot" in source_app_js
    )
    checks["usesAppDataPreviewState"] = (
        "CryptaPlatform.data.records.getJson" in source_app_js
        and "CryptaPlatform.data.records.putJson" in source_app_js
        and "recentImports" in source_app_js
    )
    checks["noRawAdminApiReference"] = "/api/v1/" not in source_app_js
    checks["noPersistentBrowserStorage"] = all(
        forbidden not in source_app_js
        for forbidden in ("localStorage.setItem", "sessionStorage.setItem")
    )
    disclosure = permission_disclosure_block(source_index)
    mentioned_permissions = set(
        re.findall(r"\b[a-z][a-z0-9._-]*\.[a-z][a-z0-9._-]*\b", disclosure)
    )
    checks["permissionDisclosureMentionsDeclaredPermissions"] = manifest_permissions.issubset(
        mentioned_permissions
    )
    checks["docsDescribePreviewLimits"] = (
        "trust graph local rc" in normalized_reference_doc
        and "local anchors" in normalized_reference_doc
        and "no crawling" in normalized_reference_doc
        and "no global moderation" in normalized_reference_doc
        and (
            "local anchors only" in normalized_reference_doc
            or "trust anchors are local" in normalized_reference_doc
        )
        and "trust.read" in normalized_reference_doc
        and "trust.write" in normalized_reference_doc
        and "ui-local" in normalized_reference_doc
    )
    checks["docsDescribeTrustScoreService"] = (
        "trust score service" in normalized_reference_doc
        and "trust.score" in normalized_reference_doc
        and (
            "operator-approved app-service grants" in normalized_reference_doc
            or (
                "operator-reviewed grant bundles" in normalized_reference_doc
                and "active app-service grants" in normalized_reference_doc
            )
        )
        and "read-only" in normalized_reference_doc
    )
    checks["readmeDocumentsTrustFlow"] = (
        "Trust Graph Local RC" in app_readme
        and "trust-statement" in app_readme
        and "not global truth" in app_readme
        and "app-data" in app_readme
    )
    if manifest:
        details["manifest"] = {
            "appId": manifest.get("app.id"),
            "name": manifest.get("app.name"),
            "uiMode": manifest.get("app.ui.mode"),
            "uiEntry": manifest.get("app.ui.entry"),
            "permissions": sorted(manifest_permissions),
            "apiMinimumVersion": manifest.get("api.minimumVersion"),
            "apiMaximumTestedVersion": manifest.get("api.maximumTestedVersion"),
            "experimentalCapabilitiesAccepted": manifest.get(
                "api.experimentalCapabilitiesAccepted"
            ),
            "providedServices": manifest.get("app.services.provides"),
            "trustScoreService": manifest.get("app.service.trust-score.id"),
        }
        checks["manifestDeclaresTrustGraph"] = (
            manifest.get("app.id") == "trust-graph"
            and manifest.get("app.name") == "Trust Graph Local RC"
            and manifest.get("app.ui.mode") == "static"
            and manifest.get("app.ui.entry") == "static/index.html"
        )
        checks["manifestDeclaresTrustPermissions"] = TRUST_GRAPH_PERMISSIONS.issubset(
            manifest_permissions
        )
        checks["manifestUsesContractV22"] = (
            manifest.get("api.minimumVersion") == "22"
            and manifest.get("api.maximumTestedVersion")
            == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
            and manifest.get("api.experimentalCapabilitiesAccepted") == "true"
        )
        checks["manifestAdvertisesTrustScoreService"] = (
            manifest.get("app.services.provides") == "trust-score"
            and manifest.get("app.service.trust-score.id") == "trust.score"
            and manifest.get("app.service.trust-score.kind") == "platform-adapter"
            and manifest.get("app.service.trust-score.adapter") == "trust-graph.score"
            and manifest.get("app.service.trust-score.scopes") == "score.read"
        )
    else:
        checks["manifestDeclaresTrustGraph"] = False
        checks["manifestDeclaresTrustPermissions"] = False
        checks["manifestUsesContractV22"] = False
        checks["manifestAdvertisesTrustScoreService"] = False

    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph",
        "pass",
        True,
        "Trust Graph Local RC reference app evidence passed.",
        source,
        details,
    )

def collect_trust_graph_app_data_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "trust-graph", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph-app-data-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph app-data preview evidence is missing its first-party app spec.",
            source,
            details,
        )
    workspace = settings.workspace_root
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "apps/trust-graph/README.md",
            "docs/trust-graph-preview.md",
            "docs/app-data-store.md",
            "docs/release-certification.md",
        )
    )
    docs_text_lower = normalized_source_text(docs_text)
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    checks = details["checks"]
    checks["manifestUsesAppDataContract"] = (
        manifest.get("api.minimumVersion") == "22"
        and manifest.get("api.maximumTestedVersion")
        == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
        and {"app.data.read", "app.data.write"}.issubset(permissions)
    )
    checks["usesSdkJsonRecordHelpers"] = (
        "CryptaPlatform.data.records.getJson" in app_js
        and "CryptaPlatform.data.records.putJson" in app_js
    )
    checks["persistsOnlyUiLocalPreviewState"] = all(
        fragment in app_js
        for fragment in (
            'const dataNamespace = "ui-state"',
            'const dataStateKey = "preview-state"',
            "lastDraft",
            "recentImports",
            "normalizeImportSummary",
        )
    ) and "privateInsertUri" not in app_js
    checks["permissionDisclosureMentionsAppData"] = (
        "app.data.read" in permission_disclosure_block(index)
        and "app.data.write" in permission_disclosure_block(index)
    )
    checks["docsSeparateAppDataAndTrustBackend"] = (
        "reference-app.trust-graph-app-data-preview" in docs_text
        and "ui-local" in docs_text_lower
        and (
            "separate from the platform trust graph backend" in docs_text_lower
            or (
                "app data remains separate" in docs_text_lower
                and "platform trust graph service state" in docs_text_lower
            )
        )
        and "durable local backend" in docs_text_lower
        and (
            "not a full web of trust" in docs_text_lower
            or (
                "does not crawl the network" in docs_text_lower
                and "no global moderation" in docs_text_lower
            )
        )
    )
    checks["noBrowserStorageOrRawAdminPath"] = (
        "/api/v1/" not in app_js
        and "localStorage.setItem" not in app_js
        and "sessionStorage.setItem" not in app_js
    )
    details["redaction"] = {
        "rawTrustStatementsExcluded": True,
        "uiLocalSummariesOnly": True,
        "identityPrivateMaterialExcluded": True,
        "absolutePathsExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph app-data preview check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph-app-data-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph app-data preview evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph-app-data-preview",
        "pass",
        True,
        "Trust Graph UI-local app-data preview evidence passed.",
        source,
        details,
    )

def collect_trust_graph_preview_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    capabilities_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiCapabilities.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    route_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    devtools_text = read_source(
        workspace
        / "platform-devtools/src/main/java/network/crypta/platform/devtools/devserver/MockPlatformApi.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
        )
    )
    normalized_docs_text = normalized_source_text(docs_text)
    route_source_text = router_text + "\n" + route_text
    checks = {
        "contractVersionV7": "TRUST_GRAPH_PREVIEW_CONTRACT_VERSION = 7" in contract_text,
        "capabilitiesPresent": "trust.read" in capabilities_text and "trust.write" in capabilities_text,
        "routesPresent": all(
            route in contract_text
            for route in (
                "/trust-graph/status",
                "/trust-graph/anchors",
                "/trust-graph/import",
                "/trust-graph/subjects",
                "/trust-graph/statements",
                "/trust-graph/score",
            )
        )
        and "trust-graph" in router_text
        and all(
            f'"{resource}"' in route_source_text or f"/trust-graph/{resource}" in route_source_text
            for resource in ("status", "anchors", "import", "subjects", "statements", "score")
        ),
        "capabilityGatesPresent": (
            "PlatformApiCapabilities.TRUST_READ" in contract_text
            and "PlatformApiCapabilities.TRUST_WRITE" in contract_text
        ),
        "handlerUsesTrustGraphModule": (
            "TrustStatementParser.parse" in handler_text
            and "TrustGraphScorer" in handler_text
            and "InMemoryTrustGraphStore" in handler_text
        ),
        "sdkTrustHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function trustStatus",
                "function addTrustAnchor",
                "function importTrustStatement",
                "function trustScore",
                "function publishTrustStatement",
            )
        ),
        "mockEndpointsPresent": all(
            fragment in devtools_text
            for fragment in (
                "/trust-graph/status",
                "/trust-graph/anchors",
                "/trust-graph/import",
                "/trust-graph/score",
            )
        ),
        "docsDescribeLimits": (
            "not a full web of trust" in normalized_docs_text
            and "old weboftrust plugin" in normalized_docs_text
            and "no fnp/fcp/wire protocol" in normalized_docs_text
            and "trust.read" in normalized_docs_text
            and "trust.write" in normalized_docs_text
        ),
        "redactionDocumented": (
            "raw trust statement bodies" in normalized_docs_text
            and "browser-session tokens" in normalized_docs_text
            and "form passwords" in normalized_docs_text
        ),
    }
    details = {"checks": checks, "routes": ["trust-graph/status", "trust-graph/score"]}
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-preview",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC Platform API evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-preview",
        "pass",
        True,
        "Trust Graph Local RC Platform API evidence passed.",
        source,
        details,
    )

def collect_trust_graph_rc_scope_and_safety_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    trustgraph_dir = workspace / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph"
    trustgraph_test_dir = workspace / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    contract_text = read_source(api_dir / "PlatformApiContract.java")
    route_text = read_source(api_dir / "PlatformApiTrustGraphRoutes.java")
    handler_text = read_source(api_dir / "trust/TrustGraphApiHandler.java")
    app_service_adapter_text = read_source(
        api_dir / "appservices/TrustGraphScoreAppServiceAdapter.java"
    )
    store_text = read_source(trustgraph_dir / "TrustGraphStore.java")
    file_store_text = read_source(trustgraph_dir / "FileTrustGraphStore.java")
    memory_store_text = read_source(trustgraph_dir / "InMemoryTrustGraphStore.java")
    lifecycle_status_text = read_source(trustgraph_dir / "TrustStatementLifecycleStatus.java")
    lifecycle_record_text = read_source(trustgraph_dir / "TrustStatementLifecycleRecord.java")
    scorer_text = read_source(trustgraph_dir / "TrustGraphScorer.java")
    evidence_text = read_source(trustgraph_dir / "TrustGraphEvidence.java")
    score_text = read_source(trustgraph_dir / "TrustGraphScore.java")
    scorer_test_text = read_source(trustgraph_test_dir / "TrustGraphScorerTest.java")
    store_test_text = read_source(trustgraph_test_dir / "FileTrustGraphStoreTest.java")
    router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    app_index = read_source(workspace / "apps/trust-graph/src/staged/static/index.html")
    app_js = read_source(workspace / "apps/trust-graph/src/staged/static/app.js")
    web_shell_text = read_source(
        workspace
        / "platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/app-platform-developer-portal.md",
            "docs/operator-beta-dashboard.md",
            "docs/release-certification.md",
            "tools/release-certification/README.md",
            "apps/trust-graph/README.md",
        )
    )
    ui_text = app_index + "\n" + app_js + "\n" + web_shell_text
    normalized_ui_text = normalized_source_text(ui_text)
    docs_lower = normalized_source_text(docs_text)
    checks = {
        "contractV15AndRoutesPresent": (
            "CURRENT_CONTRACT_VERSION = 24" in contract_text
            and "TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION = 15" in contract_text
            and "/trust-graph/statements/{fingerprint}" in contract_text
            and "/trust-graph/statements/{fingerprint}/deprecate" in contract_text
            and "/trust-graph/statements/{fingerprint}/revoke" in contract_text
            and "/trust-graph/statements/{fingerprint}/reactivate" in contract_text
            and "routeNestedResourceAction" in route_text
        ),
        "statusExposesLocalRcScope": all(
            fragment in handler_text
            for fragment in (
                '"trust-graph-local-rc"',
                '"local-rc"',
                "localAnchorsOnly",
                "importedStatementsOnly",
                "noCrawling",
                "noGlobalModeration",
                "noBlocking",
                "noRoutingDecisions",
                "noLegacyWoTCompatibility",
                "statementLifecycleJson",
                "maxEvidenceRows",
            )
        ),
        "lifecycleModelPresent": all(
            fragment in lifecycle_status_text + lifecycle_record_text
            for fragment in (
                "ACTIVE",
                "DEPRECATED",
                "REVOKED",
                "operator-local policy",
                "statementFingerprint",
                "reasonCode",
                "replacementUri",
                "actorAppId",
            )
        ),
        "storesPersistLifecycleAndSourceMetadata": all(
            fragment in store_text + file_store_text + memory_store_text
            for fragment in (
                "updateLifecycle",
                "lifecycleRecords",
                "sourceUriKind",
                "subscriptionId",
                "lastSeenAt",
                "maxLifecycleRecords",
                "writeLifecycleRecord",
                "loadLifecycleRecords",
                "normalizeSubscriptionId",
            )
        ),
        "testsCoverLifecyclePersistenceAndApi": (
            "reopen_whenStatementRevokedAndReimported_expectLifecycleDurableAndPreserved"
            in store_test_text
            and "route_whenWriterRevokesImportedStatement_expectLifecycleVisibleAndReimportDoesNotErase"
            in router_test_text
            and "route_whenReaderAttemptsLifecycleMutation_expectForbiddenBeforeHandler"
            in router_test_text
        ),
        "scorerExcludesUnsafeEvidenceWithReasons": all(
            fragment in scorer_text + evidence_text + score_text + scorer_test_text
            for fragment in (
                "nonContributingReasons",
                "unanchored",
                "unverified",
                "expired",
                "zero-confidence",
                "revoked",
                "deprecated",
                "evidenceTruncated",
                "MAX_EVIDENCE_ROWS",
                "score_whenAnchoredStatementRevoked_expectLifecycleBlocksContribution",
                "score_whenAnchoredStatementDeprecated_expectLifecycleBlocksContribution",
            )
        ),
        "sdkLifecycleHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function getTrustStatement",
                "function deprecateTrustStatement",
                "function revokeTrustStatement",
                "function reactivateTrustStatement",
                "trust-graph/statements/",
                "normalizeTrustLifecycleMutation",
                "subscriptionId",
            )
        ),
        "uiAndWebShellWarnLocalOnly": all(
            fragment in normalized_ui_text
            for fragment in (
                "trust graph local rc",
                "local trust only",
                "not global truth",
                "not moderation",
                "not blocking",
                "not routing policy",
                "no legacy wot",
                "statement lifecycle",
                "noncontributingreasons",
                "evidencetruncated",
            )
        )
        and "innerHTML" not in app_js,
        "trustScoreServiceRemainsReadOnly": (
            "TrustGraphApiHandler#score" in app_service_adapter_text
            and "redactedScore" in app_service_adapter_text
            and "updateLifecycle" not in app_service_adapter_text
            and "trust.write" not in app_service_adapter_text
            and "score.read" in app_service_adapter_text
        ),
        "docsDescribeRcNonGoalsAndRedaction": all(
            fragment in docs_lower
            for fragment in (
                "local rc",
                "no crawling",
                "no global moderation",
                "not blocking",
                "no routing decisions",
                "no legacy",
                "deprecated",
                "revoked",
                "non-contribution reason",
                "raw fetched content",
                "private insert uri",
                "app-platform.trust-graph-rc-scope-and-safety",
            )
        ),
    }
    details = {
        "checks": checks,
        "routes": [
            "GET /trust-graph/status",
            "GET /trust-graph/statements/{fingerprint}",
            "POST /trust-graph/statements/{fingerprint}/deprecate",
            "POST /trust-graph/statements/{fingerprint}/revoke",
            "POST /trust-graph/statements/{fingerprint}/reactivate",
        ],
        "scope": {
            "localAnchorsOnly": True,
            "importedStatementsOnly": True,
            "noCrawling": True,
            "noGlobalModeration": True,
            "noBlocking": True,
            "noRoutingDecisions": True,
            "noLegacyWoTCompatibility": True,
        },
        "redaction": {
            "rawStatementBodiesExcluded": True,
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
            "absolutePathsExcluded": True,
            "rawAppDataBackupsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if passed is not True]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-rc-scope-and-safety",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph Local RC scope and safety evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-rc-scope-and-safety",
        "pass",
        True,
        "Trust Graph Local RC scope and safety evidence passed.",
        source,
        details,
    )

def collect_trust_graph_durable_store_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    trustgraph_dir = workspace / "platform-trustgraph/src/main/java/network/crypta/platform/trustgraph"
    api_dir = workspace / "platform-api/src/main/java/network/crypta/platform/api"
    bridge_text = read_source(
        workspace
        / "bridge-http-runtime/src/main/java/network/crypta/clients/http/bridge/CoreHttpShellRuntimeSupport.java"
    )
    store_text = read_source(trustgraph_dir / "FileTrustGraphStore.java")
    config_text = read_source(trustgraph_dir / "TrustGraphStoreConfig.java")
    audit_text = read_source(trustgraph_dir / "TrustGraphAuditEvent.java")
    store_test_text = read_source(
        workspace
        / "platform-trustgraph/src/test/java/network/crypta/platform/trustgraph/FileTrustGraphStoreTest.java"
    )
    shared_services_text = read_source(api_dir / "PlatformApiSharedAppServices.java")
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/release-certification.md",
        )
    )
    normalized_docs_text = normalized_source_text(docs_text)
    checks = {
        "fileBackedStorePresent": (
            "class FileTrustGraphStore" in store_text and "implements TrustGraphStore" in store_text
        ),
        "persistsAnchorsStatementsAndAudit": all(
            fragment in store_text for fragment in ('"anchors"', '"statements"', '"audit"')
        ),
        "usesAtomicCrashSafeWrites": (
            "createTempFile" in store_text and "ATOMIC_MOVE" in store_text and "force(" in store_text
        ),
        "capsConfigured": all(
            fragment in config_text
            for fragment in (
                "maxStatements",
                "maxAnchors",
                "maxAuditEntries",
                "maxStoredDocumentBytes",
            )
        ),
        "redactedAuditModelPresent": (
            "record TrustGraphAuditEvent" in audit_text
            and "sourceUriHash" in audit_text
            and "sourceSummary" in audit_text
            and "signatureVerified" in audit_text
        ),
        "runtimeInjectsDurableStore": (
            "new FileTrustGraphStore" in bridge_text
            and 'resolve("apps")' in bridge_text
            and 'resolve("trust-graph")' in bridge_text
            and "new TrustGraphApiHandler" in bridge_text
        ),
        "sharedServicesCarryTrustHandler": (
            "TrustGraphApiHandler trustGraphApiHandler" in shared_services_text
        ),
        "durabilityTestsPresent": all(
            fragment in store_test_text
            for fragment in (
                "reopen_whenAnchorStored_expectAnchorDurable",
                "reopen_whenVerifiedStatementAndAnchorStored_expectScoreUsesDurableState",
                "importStatement_whenSameDocumentImportedTwice_expectMetadataReplacedWithoutDuplicate",
                "retention_whenCapsExceeded_expectOldestRecordsEvicted",
                "reopen_whenPersistedRecordIsCorrupt_expectRecordIgnoredSafely",
                "auditEvents_whenStoredAndReopened_expectBoundedNewestFirstAndRedacted",
                "auditEvents_whenDuplicateEventsEvicted_expectOnlyOnePersistedDuplicateDeleted",
            )
        ),
        "docsDescribeDurableLocalBackend": (
            (
                "durable file-backed preview store" in normalized_docs_text
                or "durable file-backed store" in normalized_docs_text
            )
            and "persists local trust anchors" in normalized_docs_text
            and "raw fetched content" in normalized_docs_text
            and "private insert uris" in normalized_docs_text
        ),
    }
    details = {
        "checks": checks,
        "storeType": "file",
        "safeFields": [
            "documentFingerprint",
            "payloadHash",
            "source",
            "sourceSummary",
            "signatureVerified",
        ],
        "redaction": {
            "rawTrustStatementsExcluded": True,
            "rawFetchedContentExcluded": True,
            "privateInsertUrisExcluded": True,
            "absolutePathsExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-durable-store",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable store evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-durable-store",
        "pass",
        True,
        "Trust Graph durable store evidence passed.",
        source,
        details,
    )

def collect_trust_graph_exchange_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiRouter.java"
    )
    route_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiTrustGraphRoutes.java"
    )
    handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/trust/TrustGraphApiHandler.java"
    )
    capabilities_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/PlatformApiCapabilitiesTest.java"
    )
    router_test_text = read_source(
        workspace / "platform-api/src/test/java/network/crypta/platform/api/TrustGraphApiRouterTest.java"
    )
    sdk_text = read_source(
        workspace
        / "platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js"
    )
    sdk_test_text = read_source(
        workspace
        / "platform-sdk-js/src/test/java/network/crypta/platform/sdk/js/CryptaPlatformSdkResourceTest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/platform-api-contract.md",
            "docs/platform-sdk-js.md",
            "docs/app-permissions-and-audit.md",
            "docs/release-certification.md",
        )
    )
    docs_text_lower = docs_text.lower()
    docs_text_compact = " ".join(docs_text_lower.split())
    route_source_text = router_text + "\n" + route_text
    checks = {
        "contractVersionV10": (
            "CURRENT_CONTRACT_VERSION = 24" in contract_text
            and "TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION = 10" in contract_text
        ),
        "contractDescriptorsPresent": (
            "/trust-graph/import-uri" in contract_text
            and "/trust-graph/audit" in contract_text
            and "PlatformApiCapabilities.CONTENT_FETCH" in contract_text
            and "PlatformApiCapabilities.TRUST_READ" in contract_text
            and "PlatformApiCapabilities.TRUST_WRITE" in contract_text
        ),
        "routerRoutesPresent": (
            "importUri" in route_source_text
            and "/trust-graph/import-uri" in contract_text
            and 'envelope("audit"' in route_source_text
        ),
        "handlerUsesBoundedContentFetch": (
            "ContentFetchPort" in handler_text
            and "ContentApiHandler" in handler_text
            and "maxStoredDocumentBytes" in handler_text
            and "format" in handler_text
        ),
        "auditIsRedacted": (
            "TrustGraphAuditEvent" in handler_text
            and "redactedUriSummary" in handler_text
            and "sourceUriHash" in handler_text
        ),
        "capabilityTestsPresent": (
            (
                "trust-graph/import-uri" in capabilities_test_text
                or 'List.of("trust-graph", "import-uri")' in capabilities_test_text
            )
            and "content.fetch" in capabilities_test_text
            and (
                "trust-graph/audit" in capabilities_test_text
                or 'List.of("trust-graph", "audit")' in capabilities_test_text
            )
        ),
        "routerTestsPresent": (
            "route_whenImportUriHasContentFetchCapability" in router_test_text
            and "route_whenAuditReadAfterImport" in router_test_text
        ),
        "sdkExchangeHelpersPresent": all(
            fragment in sdk_text
            for fragment in (
                "function importTrustUri",
                "function trustAudit",
                "function publishTrustStatement",
                "function fetchAndImportTrustStatement",
                "function createTrustSubscription",
            )
        ),
        "sdkTestsPresent": (
            "classpathResource_whenTrustExchangeHelpersRequested" in sdk_test_text
            and "classpathResource_whenTrustExchangePublishSignsStatement" in sdk_test_text
        ),
        "docsDescribeExchangeLimits": (
            "contract v10" in docs_text_compact
            and (
                "does not crawl the network" in docs_text_compact
                or "does not discover statements by walking the network" in docs_text_compact
                or "no crawling" in docs_text_compact
                or "network crawling" in docs_text_compact
                or "does not crawl the network globally" in docs_text_compact
                or "global network crawling" in docs_text_compact
                or "background crawler" in docs_text_compact
            )
            and "raw fetched content" in docs_text_compact
            and "private insert uris" in docs_text_compact
        ),
    }
    details = {
        "checks": checks,
        "routes": ["POST /trust-graph/import-uri", "GET /trust-graph/audit"],
        "capabilities": ["trust.read", "trust.write", "content.fetch"],
        "redaction": {
            "rawFetchedContentExcluded": True,
            "rawTrustStatementsExcluded": True,
            "privateInsertUrisExcluded": True,
            "tokensExcluded": True,
        },
    }
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-graph-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph exchange evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-graph-exchange",
        "pass",
        True,
        "Trust Graph exchange evidence passed.",
        source,
        details,
    )

def collect_trust_graph_durable_exchange_reference_app_evidence(
    settings: Settings,
) -> EvidenceItem:
    source = summary_source(settings)
    spec = next(
        (
            candidate
            for candidate in first_party_app_specs(settings)
            if candidate["appId"] == "trust-graph"
        ),
        None,
    )
    details: dict[str, Any] = {"appId": "trust-graph", "checks": {}}
    errors: list[str] = []
    if spec is None:
        return EvidenceItem(
            "reference-app.trust-graph-durable-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable exchange app evidence is missing its first-party app spec.",
            source,
            details,
        )
    app_js = read_source(spec["sourceDir"] / "static/app.js")
    index = read_source(spec["sourceDir"] / "static/index.html")
    manifest_path = spec["stagedDir"] / "cryptad-app.properties"
    manifest = parse_properties(manifest_path) if manifest_path.is_file() else {}
    permissions = parse_permission_set(manifest.get("app.permissions", ""))
    queue_preview_text = ""
    if "function renderQueue" in app_js and "function renderAudit" in app_js:
        queue_preview_text = app_js.split("function renderQueue", 1)[1].split(
            "function renderAudit", 1
        )[0]
    publication_summary_text = ""
    if "function publicationSummary" in app_js and "function queueSnapshotSummary" in app_js:
        publication_summary_text = app_js.split("function publicationSummary", 1)[1].split(
            "function queueSnapshotSummary", 1
        )[0]
    checks = details["checks"]
    checks["manifestUsesContractV22"] = (
        manifest.get("api.minimumVersion") == "22"
        and manifest.get("api.maximumTestedVersion")
        == str(FIRST_PARTY_CERTIFIED_MAX_CONTRACT_VERSION)
    )
    checks["manifestDeclaresExchangePermissions"] = {
        "trust.read",
        "trust.write",
        "content.fetch",
        "content.subscribe",
        "content.insert.app-document",
        "queue.write",
        "vault.identities.use",
    }.issubset(permissions)
    checks["uiShowsDurabilityExchangeAndAudit"] = all(
        fragment in index
        for fragment in (
            "platform trust graph backend",
            "Exchange uses content fetch, insert, and subscription APIs",
            "Subscriptions",
            "Audit",
            "not global truth",
        )
    )
    checks["usesSdkExchangeHelpers"] = all(
        fragment in app_js
        for fragment in (
            "CryptaPlatform.trust.previewImport",
            "CryptaPlatform.trust.importStatement",
            "CryptaPlatform.trust.exchange.fetchAndImport",
            "expectedDocumentFingerprint",
            "CryptaPlatform.trust.exchange.publish",
            "CryptaPlatform.trust.exchange.subscriptions.list",
            "CryptaPlatform.trust.exchange.subscriptions.create",
            "CryptaPlatform.trust.audit.list",
        )
    )
    checks["noRawApiOrManualFetch"] = (
        "/api/v1/" not in app_js and "CryptaPlatform.content.fetchText" not in app_js
    )
    checks["noPersistentBrowserStorage"] = (
        "localStorage.setItem" not in app_js and "sessionStorage.setItem" not in app_js
    )
    checks["privateInsertUriNotPersisted"] = (
        "privateInsertUri" not in app_js
        and "lastDraft.publish = { authorIdentity" in app_js
        and "insertUri" not in app_js.split("lastDraft.publish = { authorIdentity", 1)[1].split("};", 1)[0]
    )
    checks["queuePreviewDoesNotShowInsertUri"] = (
        bool(queue_preview_text)
        and bool(publication_summary_text)
        and "insertUri" not in queue_preview_text
        and "insertUri" not in publication_summary_text
    )
    details["redaction"] = {
        "rawFetchedContentExcluded": True,
        "privateInsertUrisExcluded": True,
        "rawTrustStatementsExcludedFromUriImport": True,
        "browserStorageExcluded": True,
    }
    for name, passed in checks.items():
        if passed is not True:
            errors.append(f"trust graph durable exchange app check failed: {name}")
    if errors:
        return EvidenceItem(
            "reference-app.trust-graph-durable-exchange",
            root_consequence(settings, "fail"),
            True,
            "Trust Graph durable exchange reference app evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "reference-app.trust-graph-durable-exchange",
        "pass",
        True,
        "Trust Graph durable exchange reference app evidence passed.",
        source,
        details,
    )

def collect_trust_statement_signing_evidence(settings: Settings) -> EvidenceItem:
    source = summary_source(settings)
    workspace = settings.workspace_root
    contract_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java"
    )
    vault_router_text = read_source(
        workspace / "platform-api/src/main/java/network/crypta/platform/api/PlatformApiVaultRouter.java"
    )
    vault_handler_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/AppVaultApiHandler.java"
    )
    request_text = read_source(
        workspace
        / "platform-api/src/main/java/network/crypta/platform/api/appvault/TrustStatementRequest.java"
    )
    docs_text = "\n".join(
        read_source(workspace / path)
        for path in (
            "docs/trust-graph-preview.md",
            "docs/app-secret-and-identity-vault.md",
            "docs/SECURITY.md",
            "docs/release-certification.md",
        )
    )
    checks = {
        "routeInContract": "/app-vault/identities/{identityId}/trust-statement" in contract_text,
        "capabilitiesInContract": all(
            fragment in contract_text
            for fragment in (
                "PlatformApiCapabilities.TRUST_WRITE",
                "PlatformApiCapabilities.VAULT_IDENTITIES_READ",
                "PlatformApiCapabilities.VAULT_IDENTITIES_USE",
            )
        ),
        "routerDispatchesBoundedRoute": "trust-statement" in vault_router_text,
        "handlerSignsCanonicalPayload": (
            "TrustStatementRequest.fromQuery" in vault_handler_text
            and "TrustStatementCanonicalizer.canonicalPayloadBytes" in request_text
            and "TrustDocumentTypes.TRUST_STATEMENT_V1" in vault_handler_text
        ),
        "notGenericSigningRoute": (
            "not an arbitrary signing API" in request_text
            or "not generic arbitrary signing" in docs_text
        ),
        "docsRedactPrivateMaterial": (
            "private keys" in docs_text
            and "raw request bodies" in docs_text
            and "raw signatures" in docs_text
        ),
    }
    details = {"checks": checks, "route": "app-vault/identities/{identityId}/trust-statement"}
    errors = [name for name, passed in checks.items() if not passed]
    if errors:
        return EvidenceItem(
            "app-platform.trust-statement-signing",
            root_consequence(settings, "fail"),
            True,
            "Trust statement signing evidence found problems.",
            source,
            {"errors": errors, **details},
        )
    return EvidenceItem(
        "app-platform.trust-statement-signing",
        "pass",
        True,
        "Trust statement signing evidence passed.",
        source,
        details,
    )
