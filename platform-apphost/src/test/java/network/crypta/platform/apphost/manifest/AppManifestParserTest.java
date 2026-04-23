package network.crypta.platform.apphost.manifest;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppUiMode;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppManifestParserTest {
  private static final String MANIFEST_VERSION_PROPERTY = "manifest.version";
  private static final String APP_ID_PROPERTY = "app.id";
  private static final String APP_NAME_PROPERTY = "app.name";
  private static final String APP_VERSION_PROPERTY = "app.version";
  private static final String APP_EXEC_PROPERTY = "app.exec";
  private static final String APP_PERMISSIONS_PROPERTY = "app.permissions";
  private static final String GENERATED_COMMENT = "generated";
  private static final String MANIFEST_VERSION = "1";
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final String SAMPLE_APP_NAME = "Sample App";
  private static final String UTF8_APP_NAME = "Crýpta Console";
  private static final String APP_VERSION = "1.0";
  private static final String LAUNCH_COMMAND_NAME = "launch.cmd";
  private static final String READ_AND_OPEN_PERMISSIONS = "network.read, ui.open";
  private static final String START_SCRIPT = "bin/start.sh";
  private static final String UNICODE_START_SCRIPT = "bin/启动.sh";
  private static final String UNICODE_BUNDLE_ROOT_START_SCRIPT = "launch-启动.sh";
  private static final String WINDOWS_SCRIPT = "bin\\" + LAUNCH_COMMAND_NAME;
  private static final String NESTED_WINDOWS_SCRIPT = "bin\\tools\\" + LAUNCH_COMMAND_NAME;

  @TempDir Path tempDir;

  @Test
  void parseContent_whenReadingValidManifest_expectNormalizedValues() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            """
            manifest.version=1
            app.id=Sample-App
            app.name=Sample App
            app.version=1.2.3
            app.exec=bin/start.sh
            app.ui.entry=/
            app.permissions=network.read, ui.open
            quota.data.bytes=1048576
            quota.cache.bytes=2048
            """);

    assertEquals(1, manifest.manifestVersion());
    assertEquals(SAMPLE_APP_ID, manifest.appId());
    assertEquals(SAMPLE_APP_NAME, manifest.appName());
    assertEquals("1.2.3", manifest.appVersion());
    assertEquals(Path.of("bin", "start.sh"), manifest.execPath());
    assertEquals(AppUiMode.SHELL_PANEL, manifest.uiMode());
    assertEquals("/", manifest.uiEntry());
    assertEquals(java.util.List.of("network.read", "ui.open"), manifest.permissions());
    assertEquals(Long.valueOf(1048576L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(2048L), manifest.cacheQuotaBytes());
  }

  @Test
  void parseContent_whenManifestContainsUtf8Text_expectNamePreserved() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, UTF8_APP_NAME, START_SCRIPT));

    assertEquals(UTF8_APP_NAME, manifest.appName());
  }

  @Test
  void parseContent_whenAppExecUsesWindowsSeparators_expectNormalizedRelativePath()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, WINDOWS_SCRIPT));

    assertEquals(Path.of("bin", LAUNCH_COMMAND_NAME), manifest.execPath());
    assertEquals("bin/" + LAUNCH_COMMAND_NAME, manifest.execPathText());
  }

  @Test
  void parseContent_whenRawWindowsPathContainsControlEscapePrefix_expectBackslashesPreserved()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, NESTED_WINDOWS_SCRIPT));

    assertEquals(Path.of("bin", "tools", LAUNCH_COMMAND_NAME), manifest.execPath());
    assertEquals("bin/tools/" + LAUNCH_COMMAND_NAME, manifest.execPathText());
  }

  @Test
  void parseContent_whenRawWindowsPathContainsUnicodeEscapePrefix_expectBackslashesPreserved()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION,
                SAMPLE_APP_ID,
                SAMPLE_APP_NAME,
                "bin\\ui\\" + LAUNCH_COMMAND_NAME));

    assertEquals(Path.of("bin", "ui", LAUNCH_COMMAND_NAME), manifest.execPath());
    assertEquals("bin/ui/" + LAUNCH_COMMAND_NAME, manifest.execPathText());
  }

  @Test
  void parseContent_whenRawWindowsPathContainsUnicodeDigits_expectBackslashesPreserved()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION,
                SAMPLE_APP_ID,
                SAMPLE_APP_NAME,
                "bin\\u1234\\" + LAUNCH_COMMAND_NAME));

    assertEquals(Path.of("bin", "u1234", LAUNCH_COMMAND_NAME), manifest.execPath());
    assertEquals("bin/u1234/" + LAUNCH_COMMAND_NAME, manifest.execPathText());
  }

  @Test
  void parseContent_whenManifestComesFromPropertiesStore_expectEscapesDecoded() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            storedManifestContent(UTF8_APP_NAME, WINDOWS_SCRIPT, READ_AND_OPEN_PERMISSIONS));

    assertEquals(UTF8_APP_NAME, manifest.appName());
    assertEquals(Path.of("bin", LAUNCH_COMMAND_NAME), manifest.execPath());
    assertEquals("bin/" + LAUNCH_COMMAND_NAME, manifest.execPathText());
    assertEquals(java.util.List.of("network.read", "ui.open"), manifest.permissions());
  }

  @Test
  void parseContent_whenPropertiesStoreEncodesUnicodeExecPath_expectEscapesDecoded()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(storedManifestContent(UNICODE_START_SCRIPT));

    assertEquals(Path.of(UNICODE_START_SCRIPT), manifest.execPath());
    assertEquals(UNICODE_START_SCRIPT, manifest.execPathText());
  }

  @Test
  void parseContent_whenPropertiesStoreEncodesBundleRootUnicodeExec_expectEscapesDecoded()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(storedManifestContent(UNICODE_BUNDLE_ROOT_START_SCRIPT));

    assertEquals(Path.of(UNICODE_BUNDLE_ROOT_START_SCRIPT), manifest.execPath());
    assertEquals(UNICODE_BUNDLE_ROOT_START_SCRIPT, manifest.execPathText());
  }

  @Test
  void parseContent_whenManifestBeginsWithUtf8Bom_expectVersionParsed() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            "\uFEFF"
                + minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT));

    assertEquals(1, manifest.manifestVersion());
    assertEquals(SAMPLE_APP_ID, manifest.appId());
  }

  @Test
  void parse_whenManifestPathIsSymlink_expectFailure() throws Exception {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    Path targetManifest = tempDir.resolve("target.properties");
    Files.writeString(
        targetManifest,
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT),
        StandardCharsets.UTF_8);
    Path manifestSymlink = tempDir.resolve("cryptad-app.properties");
    Files.createSymbolicLink(manifestSymlink, targetManifest);

    AppManifestException exception =
        assertThrows(AppManifestException.class, () -> AppManifestParser.parse(manifestSymlink));

    assertEquals("manifest file must not be a symlink: " + manifestSymlink, exception.getMessage());
  }

  @Test
  void parseContent_whenManifestVersionIsUnsupported_expectFailure() {
    String invalidManifest = minimalManifest("2", SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT);
    AppManifestException exception =
        assertThrows(
            AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));

    assertEquals("unsupported manifest.version: 2", exception.getMessage());
  }

  @Test
  void parseContent_whenAppIdIsInvalid_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, "Bad/Id", SAMPLE_APP_NAME, START_SCRIPT);
    assertThrows(AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));
  }

  @Test
  void parseContent_whenAppExecIsAbsoluteOrTraversingParent_expectFailure() {
    String absolutePathManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, "/tmp/app.sh");
    String parentTraversalManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, "../app.sh");
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(absolutePathManifest));
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(parentTraversalManifest));
  }

  @Test
  void parseContent_whenAppExecUsesWindowsDrivePrefix_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, "C:launch.cmd");
    assertThrows(AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));
  }

  @Test
  void parseContent_whenUiModeMissingAndRelativeEntry_expectStaticMode() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
                + "app.ui.entry=static/index.html\n");

    assertEquals(AppUiMode.STATIC, manifest.uiMode());
    assertEquals(Path.of("static", "index.html"), manifest.staticUiEntryPath());
  }

  @Test
  void parseContent_whenStaticUiEntryTraversesParent_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
            + "app.ui.mode=static\n"
            + "app.ui.entry=../index.html\n";

    AppManifestException exception =
        assertThrows(
            AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));

    assertEquals(
        "app.ui.entry must stay under the app root: ../index.html", exception.getMessage());
  }

  @Test
  void parseContent_whenShellPanelUiEntryIsExternalUrl_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
            + "app.ui.mode=shell-panel\n"
            + "app.ui.entry=https://example.invalid\n";

    AppManifestException exception =
        assertThrows(
            AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));

    assertEquals("app.ui.entry must be an absolute local path", exception.getMessage());
  }

  @Test
  void parseContent_whenAppExecPointsAtDistributionSidecar_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, "cryptad-app.catalog");

    AppManifestException exception =
        assertThrows(
            AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));

    assertEquals(
        "app.exec must not point at distribution sidecar: cryptad-app.catalog",
        exception.getMessage());
  }

  @Test
  void parseContent_whenQuotaValueIsMalformed_expectFailure() {
    String invalidDataQuotaManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
            + "quota.data.bytes=not-a-number\n";
    String invalidCacheQuotaManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
            + "quota.cache.bytes=-1\n";
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(invalidDataQuotaManifest));
    assertThrows(
        AppManifestException.class,
        () -> AppManifestParser.parseContent(invalidCacheQuotaManifest));
  }

  @Test
  void parseContent_whenOptionalManifestValueIsBlank_expectFailure() {
    String invalidPermissionsManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, START_SCRIPT)
            + "app.permissions=\n";

    AppManifestException exception =
        assertThrows(
            AppManifestException.class,
            () -> AppManifestParser.parseContent(invalidPermissionsManifest));

    assertEquals("app.permissions must not be blank", exception.getMessage());
  }

  private static String minimalManifest(
      String manifestVersion, String appId, String appName, String execPath) {
    return """
    manifest.version=%s
    app.id=%s
    app.name=%s
    app.version=%s
    app.exec=%s
    """
        .formatted(manifestVersion, appId, appName, APP_VERSION, execPath);
  }

  private static String storedManifestContent(String execPath) throws IOException {
    return storedManifestContent(SAMPLE_APP_NAME, execPath, null);
  }

  private static String storedManifestContent(String appName, String execPath, String permissions)
      throws IOException {
    Properties properties = new Properties();
    properties.setProperty(MANIFEST_VERSION_PROPERTY, MANIFEST_VERSION);
    properties.setProperty(APP_ID_PROPERTY, SAMPLE_APP_ID);
    properties.setProperty(APP_NAME_PROPERTY, appName);
    properties.setProperty(APP_VERSION_PROPERTY, APP_VERSION);
    properties.setProperty(APP_EXEC_PROPERTY, execPath);
    if (permissions != null) {
      properties.setProperty(APP_PERMISSIONS_PROPERTY, permissions);
    }
    StringWriter writer = new StringWriter();
    properties.store(writer, GENERATED_COMMENT);
    return writer.toString();
  }
}
