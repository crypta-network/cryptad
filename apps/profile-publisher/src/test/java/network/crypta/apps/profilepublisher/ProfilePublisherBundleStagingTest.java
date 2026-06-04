package network.crypta.apps.profilepublisher;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
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
import network.crypta.platform.devtools.CryptaAppCli;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProfilePublisherBundleStagingTest {
  private static final String APP_VERSION_PROPERTY = "profilePublisher.appVersion";
  private static final String STAGE_DIR_PROPERTY = "profilePublisher.stageDir";
  private static final String EXPECTED_APP_ID = "profile-publisher";
  private static final String EXPECTED_APP_NAME = "Profile Publisher";
  private static final String EXPECTED_UI_ENTRY = "static/index.html";
  private static final String EXPECTED_LAUNCHER_PATH = "bin/profile-publisher.sh";
  private static final String EXPECTED_PERMISSIONS =
      "queue.read,queue.write,content.insert.app-document,"
          + "vault.identities.read,vault.identities.create,vault.identities.use,"
          + "app.data.read,app.data.write";
  private static final List<String> EXPECTED_PERMISSION_LIST =
      List.of(
          "queue.read",
          "queue.write",
          "content.insert.app-document",
          "vault.identities.read",
          "vault.identities.create",
          "vault.identities.use",
          "app.data.read",
          "app.data.write");
  private static final int EXPECTED_PLATFORM_API_MINIMUM_VERSION = 9;
  private static final int EXPECTED_PLATFORM_API_MAXIMUM_TESTED_VERSION = 13;
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
    assertTrue(manifest.apiCompatibility().experimentalCapabilitiesAccepted());
    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxPolicy().mode());
    assertFalse(manifest.sandboxPolicy().required());
    assertEquals(AppRestartPolicy.NEVER, manifest.restartPolicy());
    assertEquals(Long.valueOf(1048576L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(1048576L), manifest.cacheQuotaBytes());
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
    assertTrue(manifestText.contains("api.experimentalCapabilitiesAccepted=true"));
    assertTrue(manifestText.contains("app.exec=" + EXPECTED_LAUNCHER_PATH));
    assertTrue(manifestText.contains("app.ui.mode=static"));
    assertTrue(manifestText.contains("app.ui.entry=" + EXPECTED_UI_ENTRY));
    assertTrue(manifestText.contains("app.permissions=" + EXPECTED_PERMISSIONS));
    assertTrue(manifestText.contains("sandbox.mode=restricted-process"));
    assertTrue(manifestText.contains("sandbox.required=false"));
    assertTrue(manifestText.contains("app.restart.policy=never"));
    assertTrue(manifestText.contains("quota.data.bytes=1048576"));
    assertTrue(manifestText.contains("quota.cache.bytes=1048576"));
  }

  @Test
  void stagedBundle_whenLauncherStaged_expectLongRunningExecutableLoop() throws Exception {
    Path launcher = stageDirectory().resolve(EXPECTED_LAUNCHER_PATH);
    String launcherScript = Files.readString(launcher);

    assertTrue(launcherScript.startsWith("#!/bin/sh\n"));
    assertTrue(
        launcherScript.contains("log_file=\"${CRYPTAD_APP_RUN_DIR:-.}/profile-publisher.log\""));
    assertTrue(launcherScript.contains("Profile Publisher started"));
    assertTrue(launcherScript.contains("trap 'printf \"Profile Publisher stopping"));
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
    String appScript = Files.readString(staticDirectory.resolve("app.js"));
    String appCss = Files.readString(staticDirectory.resolve("app.css"));
    verifyDesignSystemCssLoadsBeforeAppCss(indexHtml);
    verifyDesignSystemComponentsLoadsBeforeSdk(indexHtml);
    verifySdkLoadsBeforeAppScript(indexHtml);
    verifyPermissionDisclosure(indexHtml);
    verifyNoBrowserStorageOrFileInputs(indexHtml, appScript, appCss);
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-tokens.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui.css");
    verifyStagedDesignSystemAsset(staticDirectory, "crypta-ui-components.js");
    verifyStagedSdkScript(Files.readString(staticDirectory.resolve("crypta-platform.js")));
    verifyProfilePublisherAppScript(appScript);
  }

  @Test
  void stagedBundle_whenStrictUiLintRuns_expectNoFindings() throws Exception {
    CliInvocation invocation =
        runCryptaAppCli("ui", "lint", "--bundle-dir", stageDirectory().toString(), "--strict");

    assertEquals(
        0,
        invocation.exitCode(),
        () -> "stdout:\n" + invocation.stdout() + "\nstderr:\n" + invocation.stderr());
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

  private static void verifyPermissionDisclosure(String indexHtml) {
    verifyContainsAll(
        indexHtml,
        "data-crypta-permission-summary",
        "<code>queue.read</code>",
        "<code>queue.write</code>",
        "<code>content.insert.app-document</code>",
        "<code>vault.identities.read</code>",
        "<code>vault.identities.create</code>",
        "<code>vault.identities.use</code>",
        "Identity workspace",
        "Create identity",
        "Available identities",
        "Profile composition",
        "Signing preview",
        "App-document publish",
        "Upload queue progress");
    verifyContainsNone(indexHtml, "vault.secrets", "vault.identities.manage");
  }

  private static void verifyNoBrowserStorageOrFileInputs(
      String indexHtml, String appScript, String appCss) {
    String combined = indexHtml + "\n" + appScript + "\n" + appCss;
    String lowerCaseHtml = indexHtml.toLowerCase(java.util.Locale.ROOT);

    verifyContainsNone(
        combined,
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "innerHTML",
        "insertAdjacentHTML",
        "eval(",
        "new Function(",
        "http://",
        "https://");
    assertFalse(lowerCaseHtml.contains("type=\"file\""));
    assertFalse(lowerCaseHtml.contains("type='file'"));
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
        "vault:",
        "profile:",
        "data:",
        "dom:",
        "insertAppDocument",
        "createProfileDocument",
        "browserSessionToken",
        "X-Crypta-App-Session");
    verifyContainsNone(
        sdkScript, "formPassword", "CRYPTAD_APP_TOKEN", "localStorage", "sessionStorage");
  }

  private static void verifyProfilePublisherAppScript(String appScript) {
    verifyContainsAll(
        appScript,
        "const appId = \"profile-publisher\";",
        "CryptaPlatform.bootstrap.load({ appId })",
        "CryptaPlatform.vault.identities.list",
        "CryptaPlatform.vault.identities.create",
        "CryptaPlatform.vault.identities.createProfileDocument",
        "CryptaPlatform.vault.grants.list",
        "CryptaPlatform.vault.grants.request",
        "CryptaPlatform.content.insertAppDocument",
        "CryptaPlatform.queue.snapshot",
        "CryptaPlatform.data.records.getJson",
        "CryptaPlatform.data.records.putJson",
        "CryptaPlatform.api.errorMessage",
        "state.draft",
        "lastPublishedProfileUri",
        "loadDurableState",
        "persistDurableState",
        "durableSaveInFlight",
        "durableSaveQueued",
        "flushDurableStateSaves",
        "writeDurableStateSnapshot",
        "signedDocument",
        "sign.domain-separated",
        "buildProfilePayload",
        "buildPublishOptions",
        "const insertUri = publishInsertUriValue(elements.publishForm, \"insertUri\");",
        "function publishInsertUriValue(form, name)",
        "function unsafePublishUriPattern()",
        "profileDocumentFromResponse",
        "setSelectedIdentityId(identityId(identity));",
        "setSelectedIdentityId(elements.identitySelect.value);",
        "function setSelectedIdentityId(value)",
        "state.selectedIdentityId = nextIdentityId;",
        "state.signedDocument = null;",
        "function cachedSignedDocumentForSelectedIdentity()",
        "cachedSignedDocumentForSelectedIdentity() || (await createSignedProfileDocument())",
        "identityId(documentData.identity) === selectedIdentityId()",
        "return elements.identitySelect.disabled ? \"\" : state.selectedIdentityId;",
        "document: documentData",
        "application/vnd.crypta.profile+json",
        "recentActions",
        "sortBy: state.uploadQueueSortBy",
        "reversed: state.uploadQueueReversed",
        "queueRowsFromHtml",
        "queueSortLinksFromDocument",
        "safeQueueSortLink",
        "isSafeQueueSortKey",
        "renderQueueSortControls",
        "anchor.setAttribute(\"href\", link.href)",
        "updateUploadQueueSort(anchor.getAttribute(\"href\") || \"\")",
        "removeUnsafeParsedNodes",
        "unsafeParsedElementSelector",
        "iframe, frame, frameset, object, embed, link, meta, base, svg, math",
        "optionalCryptaContentUri",
        "optionalProfileWebsite",
        "rawFieldValue",
        "uri.length > maxContentUriLength",
        "website.length > maxContentUriLength",
        "boundedText",
        "textContent",
        "Open Queue Manager for detailed queue actions.");
    verifyContainsNone(
        appScript,
        "function loadBootstrap",
        "function postForm",
        "function loadJson",
        "function normalizeLocalRoot",
        "function apiError",
        "function errorMessage",
        "function sanitize(",
        "/api/v1/",
        "sourcePath",
        "payloadBase64",
        "state.signedDocument || (await createSignedProfileDocument())",
        "state.selectedIdentityId = identityId(identity)",
        "state.selectedIdentityId = elements.identitySelect.value",
        "state.selectedIdentityId = identityId(state.identities[0])",
        "state.selectedIdentityId = \"\";",
        "insertUri: fieldValue(elements.publishForm, \"insertUri\")",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "document.cookie",
        "formPassword",
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

  private static CliInvocation runCryptaAppCli(String... arguments) throws Exception {
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    Method execute =
        CryptaAppCli.class.getDeclaredMethod(
            "execute", PrintWriter.class, PrintWriter.class, String[].class);
    execute.setAccessible(true);
    int exitCode =
        (Integer)
            execute.invoke(
                null,
                new PrintWriter(stdout, true, StandardCharsets.UTF_8),
                new PrintWriter(stderr, true, StandardCharsets.UTF_8),
                (Object) arguments);
    return new CliInvocation(
        exitCode, stdout.toString(StandardCharsets.UTF_8), stderr.toString(StandardCharsets.UTF_8));
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

  private record CliInvocation(int exitCode, String stdout, String stderr) {}
}
