package network.crypta.apps.socialinbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppDataNamespaceSchema;
import network.crypta.platform.appdist.AppRestartPolicy;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SocialInboxBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "socialInbox.appVersion";
  private static final String STAGE_DIR_PROPERTY = "socialInbox.stageDir";
  private static final String EXPECTED_APP_ID = "social-inbox";
  private static final String EXPECTED_APP_NAME = "Social Inbox RC";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/social-inbox.sh";
  private static final String APP_SCRIPT_FILE = "app.js";
  private static final String APP_STYLESHEET_FILE = "app.css";
  private static final String PLATFORM_SDK_SCRIPT_FILE = "crypta-platform.js";
  private static final String LOCAL_STORAGE_TOKEN = "localStorage";
  private static final String SESSION_STORAGE_TOKEN = "sessionStorage";
  private static final String FORM_PASSWORD_TOKEN = "formPassword";
  private static final String APP_PROCESS_TOKEN = "CRYPTAD_APP_TOKEN";
  private static final String EXPECTED_PERMISSIONS =
      "vault.identities.read,vault.identities.create,vault.identities.use,content.fetch,"
          + "content.subscribe,content.insert.app-document,queue.read,queue.write,app.data.read,"
          + "app.data.write,app.services.read,app.services.call";
  private static final List<String> EXPECTED_PERMISSION_LIST =
      List.of(
          "vault.identities.read",
          "vault.identities.create",
          "vault.identities.use",
          "content.fetch",
          "content.subscribe",
          "content.insert.app-document",
          "queue.read",
          "queue.write",
          "app.data.read",
          "app.data.write",
          "app.services.read",
          "app.services.call");
  private static final List<String> ADVERSARIAL_MARKUP_FIXTURES =
      List.of(
          "<script>alert(1)</script>",
          "<img src=x onerror=alert(1)>",
          "<a href=\"javascript:alert(1)\">click</a>",
          "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>");
  private static final int EXPECTED_PLATFORM_API_MINIMUM_VERSION = 16;
  private static final int EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION = 23;
  private static final Path PLATFORM_SDK_SOURCE_PATH =
      Path.of(
          "platform-sdk-js",
          "src",
          "main",
          "resources",
          "network",
          "crypta",
          "platform",
          "sdk",
          "js",
          PLATFORM_SDK_SCRIPT_FILE);
  private static final Path DESIGN_SYSTEM_SOURCE_PATH =
      Path.of(
          "platform-design-system",
          "src",
          "main",
          "resources",
          "network",
          "crypta",
          "platform",
          "designsystem",
          "static");

  @Test
  void stagedBundle_whenManifestParsed_expectExpectedAppHostFields() throws Exception {
    AppManifest manifest =
        AppManifestParser.parse(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    assertEquals(EXPECTED_APP_ID, manifest.appId());
    assertEquals(EXPECTED_APP_NAME, manifest.appName());
    assertEquals(EXPECTED_LAUNCHER_PATH, manifest.execPathText());
    assertEquals(AppUiMode.STATIC, manifest.uiMode());
    assertEquals(EXPECTED_UI_ENTRY, manifest.uiEntry());
    assertEquals(EXPECTED_PERMISSION_LIST, manifest.permissions());
    assertEquals(
        Integer.valueOf(EXPECTED_PLATFORM_API_MINIMUM_VERSION),
        manifest.apiCompatibility().minimumVersion());
    assertEquals(
        Integer.valueOf(EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION),
        manifest.apiCompatibility().maximumTestedVersion());
    assertEquals(TargetStability.EXPERIMENTAL, manifest.apiCompatibility().targetStability());
    assertTrue(manifest.apiCompatibility().targetStabilityDeclared());
    assertTrue(manifest.apiCompatibility().experimentalCapabilitiesAccepted());
    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxPolicy().mode());
    assertFalse(manifest.sandboxPolicy().required());
    assertEquals(AppRestartPolicy.NEVER, manifest.restartPolicy());
    assertEquals(Long.valueOf(2_097_152L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(2_097_152L), manifest.cacheQuotaBytes());
    assertEquals(1, manifest.dataSchemaContract().currentSchemaVersion());
    assertEquals(
        List.of("ui-state", "social"),
        manifest.dataSchemaContract().namespaces().stream()
            .map(AppDataNamespaceSchema::namespace)
            .toList());
    assertEquals(
        List.of(1, 1),
        manifest.dataSchemaContract().namespaces().stream()
            .map(AppDataNamespaceSchema::currentSchemaVersion)
            .toList());
    assertTrue(manifest.dataSchemaContract().migrations().isEmpty());
  }

  @Test
  void stagedBundle_whenManifestRead_expectExpectedRenderedContent() throws IOException {
    String manifestText =
        Files.readString(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    verifyManifestIdentityContent(manifestText);
    verifyManifestApiContent(manifestText);
    verifyManifestRuntimeContent(manifestText);
    verifyManifestTrustScoreDependencyContent(manifestText);
    verifyManifestDataContractContent(manifestText);
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(launcherScript.contains("log_file=\"${CRYPTAD_APP_RUN_DIR:-.}/social-inbox.log\""));
    assertTrue(launcherScript.contains("Social Inbox RC started"));
    assertTrue(launcherScript.contains("trap 'printf \"Social Inbox RC stopping"));
    assertTrue(launcherScript.contains("while :; do"));
    assertTrue(launcherScript.contains("sleep 5"));

    Assumptions.assumeTrue(Files.getFileStore(launcher).supportsFileAttributeView("posix"));
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(launcher);
    assertTrue(permissions.contains(PosixFilePermission.OWNER_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.GROUP_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.OTHERS_EXECUTE));
  }

  @Test
  void stagedBundle_whenStaticUiStaged_expectEntryAssetsAndSafeSdkUsage() throws Exception {
    Path staticDirectory = stageDirectory().resolve("static");

    verifyStaticAssetsPresent(staticDirectory);
    String indexHtml = Files.readString(staticDirectory.resolve("index.html"));
    String appScript = Files.readString(staticDirectory.resolve(APP_SCRIPT_FILE));
    String appCss = Files.readString(staticDirectory.resolve(APP_STYLESHEET_FILE));
    verifyDesignSystemCssLoadsBeforeAppCss(indexHtml);
    verifyDesignSystemComponentsLoadsBeforeSdk(indexHtml);
    verifySdkLoadsBeforeAppScript(indexHtml);
    verifyPermissionAndScopeCopy(indexHtml);
    verifyNoForbiddenBrowserPatterns(indexHtml, appScript, appCss);
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-tokens.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-components.js");
    verifyStagedSdkScript(Files.readString(staticDirectory.resolve(PLATFORM_SDK_SCRIPT_FILE)));
    verifySocialInboxAppScript(appScript);
  }

  private static void verifyStaticAssetsPresent(Path staticDirectory) {
    assertTrue(Files.isRegularFile(staticDirectory.resolve("index.html")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(APP_SCRIPT_FILE)));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(APP_STYLESHEET_FILE)));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(PLATFORM_SDK_SCRIPT_FILE)));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui-tokens.css")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui.css")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui-components.js")));
    assertTrue(Files.notExists(staticDirectory.resolve("README.txt")));
  }

  private static void verifyManifestIdentityContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "manifest.version=1",
        "app.id=" + EXPECTED_APP_ID,
        "app.name=" + EXPECTED_APP_NAME,
        "app.version=" + System.getProperty(APP_VERSION_PROPERTY));
  }

  private static void verifyManifestApiContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "api.minimumVersion=" + EXPECTED_PLATFORM_API_MINIMUM_VERSION,
        "api.maximumTestedVersion=" + EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION,
        "api.targetStability=experimental",
        "api.experimentalCapabilitiesAccepted=true",
        "app.permissions=" + EXPECTED_PERMISSIONS);
  }

  private static void verifyManifestRuntimeContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "app.exec=" + EXPECTED_LAUNCHER_PATH,
        "app.ui.mode=static",
        "app.ui.entry=" + EXPECTED_UI_ENTRY,
        "sandbox.mode=restricted-process",
        "sandbox.required=false",
        "app.restart.policy=never",
        "quota.data.bytes=2097152",
        "quota.cache.bytes=2097152");
  }

  private static void verifyManifestTrustScoreDependencyContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "app.services.requests=trust-score",
        "app.service-request.trust-score.provider=trust-graph",
        "app.service-request.trust-score.service=trust.score",
        "app.service-request.trust-score.scopes=score.read",
        "app.service-request.trust-score.contexts=message-author",
        "app.service-request.trust-score.purpose=Annotate Social Inbox message authors using"
            + " the local Trust Graph Local RC score service.",
        "app.service-request.trust-score.dependency.kind=optional",
        "app.service-request.trust-score.dependency.required=false",
        "app.service-request.trust-score.dependency.featureId=trust-score-annotations",
        "app.service-request.trust-score.dependency.featureName=Trust score annotations",
        "app.service-request.trust-score.dependency.degradeBehavior=disable-feature",
        "app.service-request.trust-score.dependency.grantBundle=trust-annotations",
        "app.service-request.trust-score.dependency.grantExpiresAfter=PT720H");
  }

  private static void verifyManifestDataContractContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "app.data.schema.current=1",
        "app.data.schema.namespaces=ui-state,social",
        "app.data.schema.namespace.ui-state.current=1",
        "app.data.schema.namespace.social.current=1");
    verifyContainsNone(
        manifestText,
        "app.data.migrations=",
        "app.data.migration.social-v1-v2",
        "migrate-social-inbox-data.sh");
  }

  private static void verifyDesignSystemCssLoadsBeforeAppCss(String indexHtml) {
    int tokensIndex = indexHtml.indexOf("crypta-ui-tokens.css");
    int uiCssIndex = indexHtml.indexOf("crypta-ui.css");
    int appCssIndex = indexHtml.indexOf(APP_STYLESHEET_FILE);

    assertTrue(tokensIndex >= 0, "index.html must load design-system tokens.");
    assertTrue(uiCssIndex > tokensIndex, "index.html must load design-system CSS after tokens.");
    assertTrue(appCssIndex > uiCssIndex, "index.html must load app.css after design-system CSS.");
  }

  private static void verifyDesignSystemComponentsLoadsBeforeSdk(String indexHtml) {
    int componentsIndex = indexHtml.indexOf("crypta-ui-components.js");
    int sdkScriptIndex = indexHtml.indexOf(PLATFORM_SDK_SCRIPT_FILE);

    assertTrue(componentsIndex >= 0, "index.html must load design-system components.");
    assertTrue(sdkScriptIndex > componentsIndex, "index.html must load the SDK after components.");
  }

  private static void verifySdkLoadsBeforeAppScript(String indexHtml) {
    int sdkScriptIndex = indexHtml.indexOf(PLATFORM_SDK_SCRIPT_FILE);
    int appScriptIndex = indexHtml.indexOf(APP_SCRIPT_FILE);

    assertTrue(sdkScriptIndex >= 0, "index.html must load the platform SDK.");
    assertTrue(appScriptIndex > sdkScriptIndex, "index.html must load app.js after the SDK.");
  }

  private static void verifyPermissionAndScopeCopy(String indexHtml) {
    verifyContainsAll(
        indexHtml,
        "data-crypta-permission-summary",
        "<code>vault.identities.read</code>",
        "<code>vault.identities.create</code>",
        "<code>vault.identities.use</code>",
        "<code>content.fetch</code>",
        "<code>content.subscribe</code>",
        "<code>content.insert.app-document</code>",
        "<code>queue.read</code>",
        "<code>queue.write</code>",
        "<code>app.data.read</code>",
        "<code>app.data.write</code>",
        "<code>app.services.read</code>",
        "<code>app.services.call</code>",
        "Reference app scope",
        "social/mail-like layer outside the daemon",
        "AppVault",
        "local message threading and read state",
        "bounded signed message documents",
        "content insert/fetch/subscriptions",
        "operator-approved Trust Graph Local RC",
        "service annotations",
        "not full WoT",
        "not compatible with old WebOfTrust plugin APIs",
        "not Freetalk, Sone, Freemail",
        "not encrypted mail",
        "does not add a daemon-core message store",
        "Format profiles",
        "<code>crypta.social.message.v1</code>",
        "<code>crypta.social.outbox.v1</code>",
        "<code>application/vnd.crypta.social.outbox+json</code>",
        "Identity",
        "Compose",
        "Publish outbox",
        "Sources and subscriptions",
        "Threads",
        "All channels",
        "Search local summaries",
        "No reply target selected.");
  }

  private static void verifyNoForbiddenBrowserPatterns(
      String indexHtml, String appScript, String appCss) {
    String combined = indexHtml + "\n" + appScript + "\n" + appCss;
    String lowerCaseHtml = indexHtml.toLowerCase(java.util.Locale.ROOT);

    verifyContainsNone(
        combined,
        LOCAL_STORAGE_TOKEN,
        SESSION_STORAGE_TOKEN,
        "indexedDB",
        "document.cookie",
        FORM_PASSWORD_TOKEN,
        APP_PROCESS_TOKEN,
        "/api/v1/",
        "innerHTML",
        "insertAdjacentHTML",
        "eval(",
        "new Function(",
        "file://");
    assertFalse(lowerCaseHtml.contains("<script src=\"http"));
    assertFalse(lowerCaseHtml.contains("<script src='http"));
    assertFalse(lowerCaseHtml.contains("<link rel=\"stylesheet\" href=\"http"));
    assertFalse(lowerCaseHtml.contains("<link rel='stylesheet' href='http"));
  }

  private static void verifyStagedDesignSystemAsset(Path staticDirectory, String assetName)
      throws Exception {
    assertEquals(
        Files.readString(repoRoot().resolve(DESIGN_SYSTEM_SOURCE_PATH).resolve(assetName)),
        Files.readString(staticDirectory.resolve("crypta-ui").resolve(assetName)));
  }

  private static void verifyStagedSdkScript(String sdkScript) throws Exception {
    assertEquals(canonicalSdkScript(), sdkScript);
    verifyContainsAll(
        sdkScript,
        "window.CryptaPlatform",
        "bootstrap:",
        "api:",
        "queue:",
        "content:",
        "data:",
        "trust:",
        "services:",
        "browserSessionToken",
        "X-Crypta-App-Session",
        "createSocialMessageDocument",
        "/social-message");
    verifyContainsNone(
        sdkScript,
        FORM_PASSWORD_TOKEN,
        APP_PROCESS_TOKEN,
        LOCAL_STORAGE_TOKEN,
        SESSION_STORAGE_TOKEN);
  }

  private static void verifySocialInboxAppScript(String appScript) {
    verifyContainsAll(
        appScript,
        "const appId = \"social-inbox\";",
        "const profileDocumentFormat = CryptaPlatform.contentFormats.profileDocument;",
        "const socialMessageFormat = CryptaPlatform.contentFormats.socialMessage;",
        "const socialOutboxFormat = CryptaPlatform.contentFormats.socialOutbox;",
        "const socialMessageType = socialMessageFormat.type;",
        "const socialOutboxType = socialOutboxFormat.type;",
        "CryptaPlatform.bootstrap.load({ appId })",
        "CryptaPlatform.vault.identities.list",
        "CryptaPlatform.vault.identities.create",
        "CryptaPlatform.vault.identities.createProfileDocument",
        "CryptaPlatform.vault.identities.createSocialMessageDocument",
        "CryptaPlatform.content.insertAppDocument",
        "CryptaPlatform.content.fetchText",
        "CryptaPlatform.content.subscriptions.create",
        "CryptaPlatform.content.subscriptions.refresh",
        "CryptaPlatform.content.subscriptions.pause",
        "CryptaPlatform.content.subscriptions.resume",
        "CryptaPlatform.content.subscriptions.remove",
        "CryptaPlatform.data.records.getJson",
        "CryptaPlatform.data.records.putJson",
        "CryptaPlatform.services.get",
        "CryptaPlatform.services.grants.list",
        "CryptaPlatform.services.bundles.list",
        "CryptaPlatform.services.bundles.request",
        "CryptaPlatform.services.invoke",
        "trustScoreProviderAppId = \"trust-graph\"",
        "trustScoreServiceId = \"trust.score\"",
        "trustScoreScope = \"score.read\"",
        "Trust score unavailable / grant required.",
        "Trust score unavailable / grant bundle pending.",
        "trustScoreContext = \"message-author\"",
        "trustServiceBundles",
        "function pendingTrustServiceBundle",
        "function grantCoversTrustScore",
        "scopes.includes(trustScoreScope)",
        "function grantContextsCoverTrustScore",
        "contexts.includes(trustScoreContext)",
        "stringListField(state.trustServiceDescriptor, \"contexts\", 16).length === 0",
        "function stringListField",
        "subjectKind: \"identity\"",
        "CryptaPlatform.queue.snapshot",
        "ui-state\", \"social-inbox\"",
        "social\", \"sources\"",
        "social\", \"outbox-summary\"",
        "social\", \"imported-message-index\"",
        "social\", \"read-state\"",
        "social\", \"drafts\"",
        "social\", \"local-filters\"",
        "dataSchemaVersion = 1",
        "namespaceSchemaVersions",
        "function schemaVersionForRecord",
        "schemaVersion: schemaVersionForRecord(record)",
        "channelFilter",
        "readFilter",
        "localFilters",
        "mutedAuthors",
        "blockedSources",
        "function buildThreadIndex",
        "function normalizeReplyReference",
        "function messageThreadRootId",
        "function threadSortKey",
        "function messageSortKey",
        "function threadUnreadCount",
        "function threadContainsMessage",
        "function visibleThreadMessages",
        "function visibleThreadView",
        "function visibleThreadSummary",
        "const visibleThread = visibleThreadView(thread)",
        "toggleThreadPin(visibleThread)",
        "archiveThread(visibleThread)",
        "exportThreadSummary(visibleThread)",
        "visibleSummary.rootMessage.subject",
        "visibleSummary.unreadMessages",
        "visibleSummary.hasArchived",
        "threadSourceCount(messages)",
        "state.readFilter === \"archived\" && !visibleSummary.hasArchived",
        "local filters hide messages in this thread",
        "function isMessageLocallyHidden",
        "function toggleMutedAuthor",
        "Author mute list is full",
        "function renderLocalFilterActions",
        "function unmuteAuthorKey",
        "Unmute all authors",
        "function clearMutedAuthors",
        "function unblockSourceKey",
        "function toggleBlockedSource",
        "Source block list is full",
        "function exportVisibleMessages",
        "function boundedExportSummary",
        "maxExportedMessages",
        "function prepareReply",
        "function renderReplyContext",
        "function refreshAllActiveSources",
        "const subscriptionStatusLabels = Object.freeze",
        "queue_pressure: \"Queue pressure\"",
        "runtime_unavailable: \"Runtime unavailable\"",
        "backoff: \"Backoff\"",
        "budget_exhausted: \"Budget exhausted\"",
        "values.push(\"Stale\")",
        "function subscriptionStatusSummary",
        "function subscriptionAttentionStatusSummary",
        "function sourceStatusAfterSubscriptionUpdate",
        "function sourceErrorAfterSubscriptionUpdate",
        "function isSubscriptionAttentionStatus",
        "lastStatus: sourceStatusAfterSubscriptionUpdate(source, attentionStatus)",
        "lastError: sourceErrorAfterSubscriptionUpdate(source, subscription, attentionStatus)",
        "function subscriptionRetrySummary",
        "function sourceSummariesForDedupe",
        "function boundedReadStateEntry",
        "sourceSummariesForDedupe(current)",
        "sourceSummariesForDedupe(incoming)",
        "seenCount: existing",
        "? Math.min(9999, Math.max(1, numberField(current, \"seenCount\")) + 1)",
        ": Math.max(1, numberField(incoming, \"seenCount\"))",
        "hasOwnProperty.call(item, \"read\")",
        "Object.keys(entry).length === 0",
        "entry.read = Boolean(item.read)",
        "if (item.pinned)",
        "if (item.archived)",
        "sourcesSeen",
        "firstImportedAt",
        "lastSeenAt",
        "seenCount",
        "Copy profile URI",
        "insertUriRedaction",
        "publicSourceUriHash",
        "uriHash",
        "uriSummary",
        "bodySha256",
        "signatureSha256",
        "bodyPreview",
        "verifySocialMessageSignature",
        "canonicalSocialMessagePayload",
        "expectedSocialMessageId",
        "canonicalSocialMessageIdPayload",
        "messageIdPattern",
        "Social message id does not match canonical payload.",
        "Object.create(null)",
        "boundedReadState",
        "isSafeMessageId",
        "optionalNumberField",
        "contributingEvidenceCount",
        "[\"trusted\", \"distrusted\", \"mixed\"].includes(trustStatus)",
        "const publicKeyBytes = decodeBase64(signature.publicKeyBase64, \"publicKeyBase64\")",
        "const publicKeyFingerprint = await sha256Hex(publicKeyBytes)",
        "isSocialSourceUri",
        "normalizedCryptaContentUri",
        "optionalCryptaContentUri",
        "boundedImportedMessage",
        "maxImportedBodyPreviewLength",
        "maxSourceLabelLength",
        "rejectUnexpectedFields(",
        "[\"type\", \"appId\", \"generatedAt\", \"profileUri\", \"sourceLabel\", \"messages\"]",
        "textContent",
        "replaceChildren",
        "FormData",
        "const socialOutboxContentType = socialOutboxFormat.contentType;",
        "const socialOutboxTargetFilename = socialOutboxFormat.defaultFilename;",
        "const maxFetchedDocumentBytes = socialOutboxFormat.maxDocumentBytes;");
    verifyBoundedRefreshAll(appScript);
    verifyAdversarialMarkupFixturesCovered(appScript);
    verifyContainsNone(
        appScript,
        "CryptaPlatform.dom.sanitizeFragment",
        "function loadBootstrap",
        "function postForm",
        "function loadJson",
        "function apiError",
        "CryptaPlatform.trust.score",
        "/api/v1/",
        LOCAL_STORAGE_TOKEN,
        SESSION_STORAGE_TOKEN,
        "indexedDB",
        "document.cookie",
        FORM_PASSWORD_TOKEN,
        APP_PROCESS_TOKEN,
        "innerHTML",
        "insertAdjacentHTML",
        "persistOutboxSummary(await localOutboxSummary())");
  }

  private static void verifyBoundedRefreshAll(String appScript) {
    String refreshAll = refreshAllActiveSourcesSlice(appScript);
    verifyContainsAll(
        refreshAll,
        ".slice(0, maxSources)",
        "for (const sourceId of activeSourceIds)",
        "await CryptaPlatform.content.subscriptions.refresh(source.subscriptionId)");
    verifyContainsNone(refreshAll, "Promise.all", "map(async", "allSettled");
  }

  private static void verifyAdversarialMarkupFixturesCovered(String appScript) {
    for (String fixture : ADVERSARIAL_MARKUP_FIXTURES) {
      assertTrue(fixture.contains("<"), () -> "Fixture must contain markup: " + fixture);
      assertTrue(
          appScript.contains("textContent"),
          () -> "Social Inbox must render hostile fixture text with textContent: " + fixture);
      assertTrue(
          appScript.contains("boundedImportedMessage"),
          () -> "Social Inbox must normalize hostile imported messages for fixture: " + fixture);
    }
  }

  private static void verifyContainsAll(String text, String... expectedFragments) {
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          text.contains(expectedFragment), () -> "Expected fragment missing: " + expectedFragment);
    }
  }

  private static void verifyContainsNone(String text, String... forbiddenFragments) {
    for (String forbiddenFragment : forbiddenFragments) {
      assertFalse(
          text.contains(forbiddenFragment),
          () -> "Forbidden fragment present: " + forbiddenFragment);
    }
  }

  private static String refreshAllActiveSourcesSlice(String text) {
    String startFragment = "async function refreshAllActiveSources";
    String endFragment = "async function refreshAllSources";
    int start = text.indexOf(startFragment);
    assertTrue(start >= 0, () -> "Expected function start missing: " + startFragment);
    int end = text.indexOf(endFragment, start + startFragment.length());
    assertTrue(end > start, () -> "Expected function end marker missing: " + endFragment);
    return text.substring(start, end);
  }

  private static String canonicalSdkScript() throws Exception {
    return Files.readString(repoRoot().resolve(PLATFORM_SDK_SOURCE_PATH));
  }

  private static Path repoRoot() throws Exception {
    Path path = Path.of("");
    Path directory = path.toAbsolutePath().normalize();
    while (directory != null && !Files.isRegularFile(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    assertNotNull(directory, "Could not locate the repo root from " + path.toAbsolutePath());
    return directory.toRealPath();
  }

  private static Path stageDirectory() {
    return Path.of(System.getProperty(STAGE_DIR_PROPERTY));
  }
}
