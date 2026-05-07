package network.crypta.apps.publisher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublisherBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "publisher.appVersion";
  private static final String STAGE_DIR_PROPERTY = "publisher.stageDir";
  private static final String EXPECTED_APP_ID = "publisher";
  private static final String EXPECTED_APP_NAME = "Publisher";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/publisher.sh";
  private static final String EXPECTED_PERMISSIONS = "queue.read,queue.write,content.insert";
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
    assertEquals(
        java.util.List.of("queue.read", "queue.write", "content.insert"), manifest.permissions());
    assertEquals(Long.valueOf(0L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(0L), manifest.cacheQuotaBytes());
  }

  @Test
  void stagedBundle_whenManifestRead_expectExpectedRenderedContent() throws Exception {
    String manifestText =
        Files.readString(stageDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));

    assertTrue(manifestText.contains("manifest.version=1"));
    assertTrue(manifestText.contains("app.id=" + EXPECTED_APP_ID));
    assertTrue(manifestText.contains("app.name=" + EXPECTED_APP_NAME));
    assertTrue(manifestText.contains("app.version=" + System.getProperty(APP_VERSION_PROPERTY)));
    assertTrue(manifestText.contains("app.exec=" + EXPECTED_LAUNCHER_PATH));
    assertTrue(manifestText.contains("app.ui.mode=static"));
    assertTrue(manifestText.contains("app.ui.entry=" + EXPECTED_UI_ENTRY));
    assertTrue(manifestText.contains("app.permissions=" + EXPECTED_PERMISSIONS));
    assertTrue(manifestText.contains("quota.data.bytes=0"));
    assertTrue(manifestText.contains("quota.cache.bytes=0"));
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(launcherScript.contains("log_file=\"${CRYPTAD_APP_RUN_DIR:-.}/publisher.log\""));
    assertTrue(launcherScript.contains("Publisher started"));
    assertTrue(launcherScript.contains("trap 'printf \"Publisher stopping"));
    assertTrue(launcherScript.contains("while :; do"));
    assertTrue(launcherScript.contains("sleep 5"));

    Assumptions.assumeTrue(Files.getFileStore(launcher).supportsFileAttributeView("posix"));
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(launcher);
    assertTrue(permissions.contains(PosixFilePermission.OWNER_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.GROUP_EXECUTE));
    assertTrue(permissions.contains(PosixFilePermission.OTHERS_EXECUTE));
  }

  @Test
  void stagedBundle_whenStaticUiStaged_expectEntryAssetsPresent() throws Exception {
    Path staticDirectory = stageDirectory().resolve("static");

    verifyStaticAssetsPresent(staticDirectory);
    String indexHtml = Files.readString(staticDirectory.resolve("index.html"));
    verifyDesignSystemCssLoadsBeforeAppCss(indexHtml);
    verifySdkLoadsBeforeAppScript(indexHtml);
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-tokens.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-components.js");
    verifyStagedSdkScript(Files.readString(staticDirectory.resolve("crypta-platform.js")));
    verifyPublisherAppScript(Files.readString(staticDirectory.resolve("app.js")));
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

  private static void verifyStagedDesignSystemAsset(Path staticDirectory, String assetName)
      throws Exception {
    assertEquals(
        Files.readString(repoRoot().resolve(DESIGN_SYSTEM_SOURCE_PATH).resolve(assetName)),
        Files.readString(staticDirectory.resolve("crypta-ui").resolve(assetName)));
  }

  private static void verifySdkLoadsBeforeAppScript(String indexHtml) {
    int sdkScriptIndex = indexHtml.indexOf("crypta-platform.js");
    int appScriptIndex = indexHtml.indexOf("app.js");

    assertTrue(sdkScriptIndex >= 0, "index.html must load the platform SDK.");
    assertTrue(appScriptIndex > sdkScriptIndex, "index.html must load app.js after the SDK.");
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
        "dom:",
        "browserSessionToken",
        "X-Crypta-App-Session");
    verifyContainsNone(
        sdkScript, "formPassword", "CRYPTAD_APP_TOKEN", "localStorage", "sessionStorage");
  }

  private static void verifyPublisherAppScript(String appScript) {
    verifyContainsAll(
        appScript,
        "CryptaPlatform.bootstrap.load({ appId })",
        "CryptaPlatform.content.insertFile",
        "CryptaPlatform.content.insertDirectory",
        "CryptaPlatform.queue.snapshot",
        "CryptaPlatform.api.url(\"queue/keys\")",
        "CryptaPlatform.api.get(url)",
        "CryptaPlatform.dom.sanitizeFragment",
        "CryptaPlatform.api.errorMessage",
        "elements.result.addEventListener(\"submit\", interceptQueueSubmit);",
        "sortBy: state.uploadQueueSortBy",
        "reversed: state.uploadQueueReversed",
        "isUploadQueueKeyListLink",
        "queue/keys",
        "unsupportedQueueAction",
        "Queue actions are handled in Queue Manager.");
    verifyContainsNone(
        appScript,
        "function loadBootstrap",
        "function postForm",
        "function loadJson",
        "function normalizeLocalRoot",
        "function apiError",
        "function errorMessage",
        "function sanitize(",
        "CRYPTAD_APP_TOKEN");
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
