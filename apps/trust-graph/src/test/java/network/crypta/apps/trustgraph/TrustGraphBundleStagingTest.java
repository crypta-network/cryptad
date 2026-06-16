package network.crypta.apps.trustgraph;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;
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

class TrustGraphBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "trustGraph.appVersion";
  private static final String STAGE_DIR_PROPERTY = "trustGraph.stageDir";
  private static final String EXPECTED_APP_ID = "trust-graph";
  private static final String EXPECTED_APP_NAME = "Trust Graph Local RC";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/trust-graph.sh";
  private static final String APP_SCRIPT = "app.js";
  private static final String APP_STYLESHEET = "app.css";
  private static final String PLATFORM_SDK_SCRIPT = "crypta-platform.js";
  private static final String LOCAL_STORAGE = "localStorage";
  private static final String SESSION_STORAGE = "sessionStorage";
  private static final String FORM_PASSWORD = "formPassword";
  private static final String APP_TOKEN_ENV = "CRYPTAD_APP_TOKEN";
  private static final String EXPECTED_PERMISSIONS =
      "trust.read,trust.write,content.fetch,content.subscribe,content.insert.app-document,"
          + "queue.read,queue.write,vault.identities.read,vault.identities.create,"
          + "vault.identities.use,app.data.read,app.data.write";
  private static final List<String> EXPECTED_PERMISSION_LIST =
      List.of(
          "trust.read",
          "trust.write",
          "content.fetch",
          "content.subscribe",
          "content.insert.app-document",
          "queue.read",
          "queue.write",
          "vault.identities.read",
          "vault.identities.create",
          "vault.identities.use",
          "app.data.read",
          "app.data.write");
  private static final int EXPECTED_PLATFORM_API_MINIMUM_VERSION = 10;
  private static final int EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION = 19;
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
          PLATFORM_SDK_SCRIPT);
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
    assertTrue(manifest.apiCompatibility().experimentalCapabilitiesAccepted());
    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxPolicy().mode());
    assertFalse(manifest.sandboxPolicy().required());
    assertEquals(AppRestartPolicy.NEVER, manifest.restartPolicy());
    assertEquals(Long.valueOf(1_048_576L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(2_097_152L), manifest.cacheQuotaBytes());
    assertEquals(2, manifest.dataSchemaContract().currentSchemaVersion());
    assertEquals(1, manifest.dataSchemaContract().namespaces().size());
    assertEquals(1, manifest.dataSchemaContract().migrations().size());
    assertEquals("ui-state-v1-v2", manifest.dataSchemaContract().migrations().getFirst().stepId());
    assertFalse(manifest.dataSchemaContract().migrations().getFirst().rollbackCompatible());
  }

  @Test
  void stagedBundle_whenManifestRead_expectExpectedRenderedContent() throws IOException {
    String manifestText =
        Files.readString(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    verifyManifestIdentityContent(manifestText);
    verifyManifestTrustScoreServiceContent(manifestText);
    verifyManifestRuntimeContent(manifestText);
    verifyManifestDataMigrationContent(manifestText);
  }

  @Test
  void stagedBundle_whenMigrationScriptStaged_expectDryRunAndApplyEntrypoint() throws Exception {
    Path migrationScript = stageDirectory().resolve("bin/migrate-preview-data.sh");
    String script = Files.readString(migrationScript);

    assertTrue(script.startsWith("#!/bin/sh\n"));
    assertTrue(script.contains("CRYPTA_APP_MIGRATION_MODE"));
    assertTrue(script.contains("CRYPTA_APP_MIGRATION_INPUT"));
    assertTrue(script.contains("CRYPTA_APP_MIGRATION_OUTPUT"));
    assertTrue(script.contains("dry-run|apply"));
    assertTrue(script.contains("Trust Graph Local RC app-data migration"));
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(launcherScript.contains("log_file=\"${CRYPTAD_APP_RUN_DIR:-.}/trust-graph.log\""));
    assertTrue(launcherScript.contains("Trust Graph Local RC started"));
    assertTrue(launcherScript.contains("trap 'printf \"Trust Graph Local RC stopping"));
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
    String appScript = Files.readString(staticDirectory.resolve(APP_SCRIPT));
    String appCss = Files.readString(staticDirectory.resolve(APP_STYLESHEET));
    verifyDesignSystemCssLoadsBeforeAppCss(indexHtml);
    verifyDesignSystemComponentsLoadsBeforeSdk(indexHtml);
    verifySdkLoadsBeforeAppScript(indexHtml);
    verifyPermissionAndSafeUseNotes(indexHtml);
    verifyNoForbiddenBrowserPatterns(indexHtml, appScript, appCss);
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-tokens.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-components.js");
    verifyStagedSdkScript(Files.readString(staticDirectory.resolve(PLATFORM_SDK_SCRIPT)));
    verifyTrustGraphAppScript(appScript);
  }

  private static void verifyStaticAssetsPresent(Path staticDirectory) {
    assertTrue(Files.isRegularFile(staticDirectory.resolve("index.html")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(APP_SCRIPT)));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(APP_STYLESHEET)));
    assertTrue(Files.isRegularFile(staticDirectory.resolve(PLATFORM_SDK_SCRIPT)));
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
        "app.version=" + System.getProperty(APP_VERSION_PROPERTY),
        "api.minimumVersion=" + EXPECTED_PLATFORM_API_MINIMUM_VERSION,
        "api.maximumTestedVersion=" + EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION,
        "api.experimentalCapabilitiesAccepted=true",
        "app.exec=" + EXPECTED_LAUNCHER_PATH,
        "app.ui.mode=static",
        "app.ui.entry=" + EXPECTED_UI_ENTRY,
        "app.permissions=" + EXPECTED_PERMISSIONS);
  }

  private static void verifyManifestTrustScoreServiceContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "app.services.provides=trust-score",
        "app.service.trust-score.id=trust.score",
        "app.service.trust-score.name=Trust Score Service",
        "app.service.trust-score.version=1",
        "app.service.trust-score.kind=platform-adapter",
        "app.service.trust-score.adapter=trust-graph.score",
        "app.service.trust-score.scopes=score.read",
        "app.service.trust-score.contexts=message-author,profile",
        "app.service.trust-score.description=Returns a bounded local RC Trust Graph score summary"
            + " for an app-provided public subject.");
  }

  private static void verifyManifestRuntimeContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "sandbox.mode=restricted-process",
        "sandbox.required=false",
        "app.restart.policy=never",
        "quota.data.bytes=1048576",
        "quota.cache.bytes=2097152");
  }

  private static void verifyManifestDataMigrationContent(String manifestText) {
    verifyContainsAll(
        manifestText,
        "app.data.schema.current=2",
        "app.data.schema.namespaces=ui-state",
        "app.data.schema.namespace.ui-state.current=2",
        "app.data.migrations=ui-state-v1-v2",
        "app.data.migration.ui-state-v1-v2.command=bin/migrate-preview-data.sh",
        "app.data.migration.ui-state-v1-v2.rollbackCompatible=false");
  }

  private static void verifyDesignSystemCssLoadsBeforeAppCss(String indexHtml) {
    int tokensIndex = indexHtml.indexOf("crypta-ui-tokens.css");
    int uiCssIndex = indexHtml.indexOf("crypta-ui.css");
    int appCssIndex = indexHtml.indexOf(APP_STYLESHEET);

    assertTrue(tokensIndex >= 0, "index.html must load design-system tokens.");
    assertTrue(uiCssIndex > tokensIndex, "index.html must load design-system CSS after tokens.");
    assertTrue(appCssIndex > uiCssIndex, "index.html must load app.css after design-system CSS.");
  }

  private static void verifyDesignSystemComponentsLoadsBeforeSdk(String indexHtml) {
    int componentsIndex = indexHtml.indexOf("crypta-ui-components.js");
    int sdkScriptIndex = indexHtml.indexOf(PLATFORM_SDK_SCRIPT);

    assertTrue(componentsIndex >= 0, "index.html must load design-system components.");
    assertTrue(sdkScriptIndex > componentsIndex, "index.html must load the SDK after components.");
  }

  private static void verifySdkLoadsBeforeAppScript(String indexHtml) {
    int sdkScriptIndex = indexHtml.indexOf(PLATFORM_SDK_SCRIPT);
    int appScriptIndex = indexHtml.indexOf(APP_SCRIPT);

    assertTrue(sdkScriptIndex >= 0, "index.html must load the platform SDK.");
    assertTrue(appScriptIndex > sdkScriptIndex, "index.html must load app.js after the SDK.");
  }

  private static void verifyPermissionAndSafeUseNotes(String indexHtml) {
    verifyContainsAll(
        indexHtml,
        "data-crypta-permission-summary",
        "<code>trust.read</code>",
        "<code>trust.write</code>",
        "<code>content.fetch</code>",
        "<code>content.subscribe</code>",
        "<code>content.insert.app-document</code>",
        "<code>queue.read</code>",
        "<code>queue.write</code>",
        "<code>vault.identities.read</code>",
        "<code>vault.identities.create</code>",
        "<code>vault.identities.use</code>",
        "Local RC scope",
        "Local trust only",
        "not global truth",
        "moderation",
        "blocking",
        "routing policy",
        "legacy WoT/Freetalk/Sone/Freemail",
        "Scope and status",
        "Anchors",
        "Fetch and import",
        "Statement lifecycle",
        "Refresh statements",
        "Deprecated",
        "revoked",
        "Subscriptions",
        "Audit",
        "Pasted statement JSON",
        "Import pasted statement",
        "Score",
        "Subject kind",
        "Subject URI or identity",
        "Publish statement",
        "Queue preview",
        "persist through app data",
        "persist through the platform trust graph backend",
        "Trust Score Service",
        "operator-approved app-service grants",
        "bounded and must explain",
        "rendered only as text",
        "without exposing private signing secrets");
  }

  private static void verifyNoForbiddenBrowserPatterns(
      String indexHtml, String appScript, String appCss) {
    String combined = indexHtml + "\n" + appScript + "\n" + appCss;
    String lowerCaseHtml = indexHtml.toLowerCase(java.util.Locale.ROOT);

    verifyContainsNone(
        combined,
        LOCAL_STORAGE,
        SESSION_STORAGE,
        "indexedDB",
        "document.cookie",
        FORM_PASSWORD,
        APP_TOKEN_ENV,
        "/api/v1/",
        "innerHTML",
        "insertAdjacentHTML",
        "eval(",
        "new Function(",
        "file://");
    assertFalse(lowerCaseHtml.contains("<script src=\"http"));
    assertFalse(lowerCaseHtml.contains("<script src='http"));
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
        "dom:",
        "browserSessionToken",
        "X-Crypta-App-Session");
    verifyContainsNone(sdkScript, FORM_PASSWORD, APP_TOKEN_ENV, LOCAL_STORAGE, SESSION_STORAGE);
  }

  private static void verifyTrustGraphAppScript(String appScript) {
    verifyContainsAll(
        appScript,
        "const appId = \"trust-graph\";",
        "CryptaPlatform.bootstrap.load({ appId })",
        "CryptaPlatform.trust.status",
        "CryptaPlatform.trust.anchors.list",
        "CryptaPlatform.trust.anchors.add",
        "CryptaPlatform.trust.anchors.remove",
        "CryptaPlatform.trust.importStatement",
        "CryptaPlatform.trust.exchange.fetchAndImport",
        "CryptaPlatform.trust.audit.list",
        "CryptaPlatform.trust.statements",
        "CryptaPlatform.trust.score",
        "CryptaPlatform.trust.exchange.publish",
        "CryptaPlatform.trust.exchange.subscriptions.list",
        "CryptaPlatform.trust.exchange.subscriptions.create",
        "CryptaPlatform.trust.exchange.subscriptions.refresh",
        "CryptaPlatform.trust.exchange.subscriptions.pause",
        "CryptaPlatform.trust.exchange.subscriptions.resume",
        "CryptaPlatform.trust.exchange.subscriptions.remove",
        "CryptaPlatform.vault.identities.list",
        "CryptaPlatform.vault.identities.create",
        "CryptaPlatform.queue.snapshot",
        "CryptaPlatform.data.records.getJson",
        "CryptaPlatform.data.records.putJson",
        "textContent",
        "replaceChildren",
        "FormData",
        "textValue(formData, \"subjectKind\") || \"profile\"",
        "field instanceof HTMLSelectElement",
        "state = {",
        "lastStatementText",
        "recentImports",
        "auditEvents",
        "subscriptions",
        "statements",
        "sourceKind",
        "importSummaryLabel",
        "statementFingerprint",
        "lifecycleStatus",
        "lifecycleActionsAvailable",
        "supportsLocalRevocation === true",
        "supportsLocalDeprecation === true",
        "Platform API contract v15 status support",
        "statementLifecycleHelper",
        "updateStatementLifecycle",
        "renderStatus",
        "renderStatements",
        "renderScoreResult",
        "scoreEvidenceRows",
        "nonContributingReasons",
        "evidenceTruncated",
        "publicationSummary",
        "redactedUri",
        "renderAudit",
        "renderSubscriptions",
        "loadDurableState",
        "persistDurableState",
        "maxStatementBytes",
        "isCryptaContentUri",
        "isTrustSubscriptionUri",
        "uri.startsWith(\"KSK@\")",
        "Statement URI must start with CHK@, SSK@, USK@, KSK@, or crypta:.",
        "Subscription URI must start with USK@ or crypta:USK@.",
        "generatedIdentifier",
        "stringField(anchor, \"createdAt\", \"addedAt\", \"updatedAt\", \"updated\")",
        "stringField(identity, \"fingerprint\", \"publicKeyFingerprint\")",
        "identity.usageScopes || identity.grants || identity.permissions || []");
    verifyContainsNone(
        appScript,
        "CryptaPlatform.dom.sanitizeFragment",
        "function loadBootstrap",
        "function postForm",
        "function loadJson",
        "function apiError",
        "/api/v1/",
        LOCAL_STORAGE,
        SESSION_STORAGE,
        "indexedDB",
        "document.cookie",
        FORM_PASSWORD,
        APP_TOKEN_ENV,
        "innerHTML",
        "insertAdjacentHTML");
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
