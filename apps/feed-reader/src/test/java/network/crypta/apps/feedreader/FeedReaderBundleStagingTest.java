package network.crypta.apps.feedreader;

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

class FeedReaderBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "feedReader.appVersion";
  private static final String STAGE_DIR_PROPERTY = "feedReader.stageDir";
  private static final String EXPECTED_APP_ID = "feed-reader";
  private static final String EXPECTED_APP_NAME = "Feed Reader & Publisher";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/feed-reader.sh";
  private static final String EXPECTED_PERMISSIONS =
      "content.fetch,content.subscribe,content.insert.app-document,queue.read,queue.write,"
          + "app.data.read,app.data.write";
  private static final List<String> EXPECTED_PERMISSION_LIST =
      List.of(
          "content.fetch",
          "content.subscribe",
          "content.insert.app-document",
          "queue.read",
          "queue.write",
          "app.data.read",
          "app.data.write");
  private static final int EXPECTED_PLATFORM_API_MINIMUM_VERSION = 9;
  private static final int EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION = 12;
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
          "crypta-platform.js");
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
    assertFalse(manifest.apiCompatibility().experimentalCapabilitiesAccepted());
    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxPolicy().mode());
    assertFalse(manifest.sandboxPolicy().required());
    assertEquals(AppRestartPolicy.NEVER, manifest.restartPolicy());
    assertEquals(Long.valueOf(1_048_576L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(2_097_152L), manifest.cacheQuotaBytes());
  }

  @Test
  void stagedBundle_whenManifestRead_expectExpectedRenderedContent() throws Exception {
    String manifestText =
        Files.readString(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    assertTrue(manifestText.contains("manifest.version=1"));
    assertTrue(manifestText.contains("app.id=" + EXPECTED_APP_ID));
    assertTrue(manifestText.contains("app.name=" + EXPECTED_APP_NAME));
    assertTrue(manifestText.contains("app.version=" + System.getProperty(APP_VERSION_PROPERTY)));
    assertTrue(
        manifestText.contains("api.minimumVersion=" + EXPECTED_PLATFORM_API_MINIMUM_VERSION));
    assertTrue(
        manifestText.contains(
            "api.maximumTestedVersion=" + EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION));
    assertTrue(manifestText.contains("api.experimentalCapabilitiesAccepted=false"));
    assertTrue(manifestText.contains("app.exec=" + EXPECTED_LAUNCHER_PATH));
    assertTrue(manifestText.contains("app.ui.mode=static"));
    assertTrue(manifestText.contains("app.ui.entry=" + EXPECTED_UI_ENTRY));
    assertTrue(manifestText.contains("app.permissions=" + EXPECTED_PERMISSIONS));
    assertTrue(manifestText.contains("sandbox.mode=restricted-process"));
    assertTrue(manifestText.contains("sandbox.required=false"));
    assertTrue(manifestText.contains("app.restart.policy=never"));
    assertTrue(manifestText.contains("quota.data.bytes=1048576"));
    assertTrue(manifestText.contains("quota.cache.bytes=2097152"));
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(launcherScript.contains("log_file=\"${CRYPTAD_APP_RUN_DIR:-.}/feed-reader.log\""));
    assertTrue(launcherScript.contains("Feed Reader & Publisher started"));
    assertTrue(launcherScript.contains("trap 'printf \"Feed Reader & Publisher stopping"));
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
    String appScript = Files.readString(staticDirectory.resolve("app.js"));
    String appCss = Files.readString(staticDirectory.resolve("app.css"));
    verifyDesignSystemCssLoadsBeforeAppCss(indexHtml);
    verifyDesignSystemComponentsLoadsBeforeSdk(indexHtml);
    verifySdkLoadsBeforeAppScript(indexHtml);
    verifyPermissionAndSafeUseNotes(indexHtml);
    verifyNoForbiddenTokensStorageOrExternalScripts(indexHtml, appScript, appCss);
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-tokens.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-components.js");
    verifyStagedSdkScript(Files.readString(staticDirectory.resolve("crypta-platform.js")));
    verifyFeedReaderAppScript(appScript);
  }

  private static void verifyStaticAssetsPresent(Path staticDirectory) {
    assertTrue(Files.isRegularFile(staticDirectory.resolve("index.html")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("app.js")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("app.css")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-platform.js")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui-tokens.css")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui.css")));
    assertTrue(Files.isRegularFile(staticDirectory.resolve("crypta-ui/crypta-ui-components.js")));
    assertTrue(Files.notExists(staticDirectory.resolve("README.txt")));
  }

  private static void verifyDesignSystemCssLoadsBeforeAppCss(String indexHtml) {
    int tokensIndex = indexHtml.indexOf("crypta-ui-tokens.css");
    int uiCssIndex = indexHtml.indexOf("crypta-ui.css");
    int appCssIndex = indexHtml.indexOf("app.css");

    assertTrue(tokensIndex >= 0, "index.html must load design-system tokens.");
    assertTrue(uiCssIndex > tokensIndex, "index.html must load design-system CSS after tokens.");
    assertTrue(appCssIndex > uiCssIndex, "index.html must load app.css after design-system CSS.");
  }

  private static void verifyDesignSystemComponentsLoadsBeforeSdk(String indexHtml) {
    int componentsIndex = indexHtml.indexOf("crypta-ui-components.js");
    int sdkScriptIndex = indexHtml.indexOf("crypta-platform.js");

    assertTrue(componentsIndex >= 0, "index.html must load design-system components.");
    assertTrue(sdkScriptIndex > componentsIndex, "index.html must load the SDK after components.");
  }

  private static void verifySdkLoadsBeforeAppScript(String indexHtml) {
    int sdkScriptIndex = indexHtml.indexOf("crypta-platform.js");
    int appScriptIndex = indexHtml.indexOf("app.js");

    assertTrue(sdkScriptIndex >= 0, "index.html must load the platform SDK.");
    assertTrue(appScriptIndex > sdkScriptIndex, "index.html must load app.js after the SDK.");
  }

  private static void verifyPermissionAndSafeUseNotes(String indexHtml) {
    verifyContainsAll(
        indexHtml,
        "data-crypta-permission-summary",
        "<code>content.fetch</code>",
        "<code>content.subscribe</code>",
        "<code>content.insert.app-document</code>",
        "<code>queue.read</code>",
        "<code>queue.write</code>",
        "<code>app.data.read</code>",
        "<code>app.data.write</code>",
        "Safe-use notes",
        "Feed sources",
        "Reader",
        "Publisher",
        "Queue preview",
        "Create platform USK subscription",
        "persist through app-data records",
        "bounded metadata only",
        "Fetched content is rendered as text",
        "platform scheduler");
  }

  private static void verifyNoForbiddenTokensStorageOrExternalScripts(
      String indexHtml, String appScript, String appCss) {
    String combined = indexHtml + "\n" + appScript + "\n" + appCss;
    String lowerCaseHtml = indexHtml.toLowerCase(java.util.Locale.ROOT);

    verifyContainsNone(
        combined,
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "formPassword",
        "CRYPTAD_APP_TOKEN",
        "/api/v1/",
        "innerHTML",
        "insertAdjacentHTML",
        "eval(",
        "new Function(");
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
    verifyContainsNone(
        sdkScript, "formPassword", "CRYPTAD_APP_TOKEN", "localStorage", "sessionStorage");
  }

  private static void verifyFeedReaderAppScript(String appScript) {
    verifyContainsAll(
        appScript,
        "const appId = \"feed-reader\";",
        "CryptaPlatform.bootstrap.load({ appId })",
        "CryptaPlatform.content.fetchText",
        "CryptaPlatform.content.subscriptions",
        "CryptaPlatform.data.records.getJson",
        "CryptaPlatform.data.records.putJson",
        "CryptaPlatform.feed.fetchSnapshot",
        "CryptaPlatform.feed.parseSnapshot",
        "CryptaPlatform.feed.publishSnapshot",
        "CryptaPlatform.queue.snapshot",
        "CryptaPlatform.api.errorMessage",
        "contentHtml",
        "queueRowsFromHtml",
        "compactQueueText",
        "sources: []",
        "subscriptions: []",
        "fetchedSnapshots: []",
        "lastPublisherDraft",
        "loadDurableState",
        "persistDurableState",
        "map(durableSnapshot)",
        "itemCount: snapshotItemCount(snapshot)",
        "type: \"crypta.feed.snapshot.v1\"",
        "items:",
        "subscriptionPollIntervalSeconds",
        "loadSubscriptions",
        "refreshSubscription",
        "pauseSubscription",
        "resumeSubscription",
        "removeSubscription",
        "subscriptionsById",
        "subscriptionsBySourceUri",
        "Subscription not found",
        "textContent",
        "uri: entryLink(item)",
        "getAttribute(\"href\")",
        "replaceChildren",
        "DOMParser",
        "buildPublishedSnapshot",
        "application/vnd.crypta.feed+json");
    assertTrue(
        appScript.indexOf("CryptaPlatform.content.fetchText")
            < appScript.indexOf("CryptaPlatform.feed.fetchSnapshot"),
        "Feed Reader must try text fetch before the SDK snapshot-only helper.");
    int loadDurableStateIndex = appScript.indexOf("await loadDurableState();");
    int restorePublisherDraftIndex = appScript.indexOf("restorePublisherDraft();");
    int loadSubscriptionsIndex = appScript.indexOf("await loadSubscriptions({ silent: true });");
    assertTrue(loadDurableStateIndex >= 0, "Feed Reader must load durable state on startup.");
    assertTrue(loadSubscriptionsIndex >= 0, "Feed Reader must load subscriptions on startup.");
    assertTrue(
        restorePublisherDraftIndex > loadDurableStateIndex
            && restorePublisherDraftIndex < loadSubscriptionsIndex,
        "Feed Reader must restore the publisher draft before subscription loading can persist.");
    assertFalse(
        appScript.contains("No queue items returned."),
        "Feed Reader must render the Queue API contentHtml payload.");
    verifyContainsNone(
        appScript,
        "CryptaPlatform.dom.sanitizeFragment",
        "function loadBootstrap",
        "function postForm",
        "function loadJson",
        "function apiError",
        "function errorMessage",
        "/api/v1/",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "formPassword",
        "CRYPTAD_APP_TOKEN",
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
