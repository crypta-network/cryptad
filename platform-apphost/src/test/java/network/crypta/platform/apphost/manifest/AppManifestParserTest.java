package network.crypta.platform.apphost.manifest;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppManifestParserTest {
  private static final String MANIFEST_VERSION = "1";
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final String SAMPLE_APP_NAME = "Sample App";
  private static final String UTF8_APP_NAME = "Crýpta Console";
  private static final String APP_VERSION = "1.0";
  private static final String START_SCRIPT = "bin/start.sh";
  private static final String WINDOWS_SCRIPT = "bin\\launch.cmd";
  private static final String NESTED_WINDOWS_SCRIPT = "bin\\tools\\launch.cmd";

  @TempDir Path tempDir;

  @Test
  void parseContent_whenReadingValidManifest_expectNormalizedValues() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            fullManifest("Sample-App", SAMPLE_APP_NAME, "1.2.3", START_SCRIPT));

    assertEquals(1, manifest.manifestVersion());
    assertEquals(SAMPLE_APP_ID, manifest.appId());
    assertEquals(SAMPLE_APP_NAME, manifest.appName());
    assertEquals("1.2.3", manifest.appVersion());
    assertEquals(Path.of("bin", "start.sh"), manifest.execPath());
    assertEquals("/", manifest.uiEntry());
    assertEquals(java.util.List.of("network.read", "ui.open"), manifest.permissions());
    assertEquals(Long.valueOf(1048576L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(2048L), manifest.cacheQuotaBytes());
  }

  @Test
  void parseContent_whenManifestContainsUtf8Text_expectNamePreserved() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION, SAMPLE_APP_ID, UTF8_APP_NAME, APP_VERSION, START_SCRIPT));

    assertEquals(UTF8_APP_NAME, manifest.appName());
  }

  @Test
  void parseContent_whenAppExecUsesWindowsSeparators_expectNormalizedRelativePath()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, WINDOWS_SCRIPT));

    assertEquals(Path.of("bin", "launch.cmd"), manifest.execPath());
    assertEquals("bin/launch.cmd", manifest.execPathText());
  }

  @Test
  void parseContent_whenRawWindowsPathContainsControlEscapePrefix_expectBackslashesPreserved()
      throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            minimalManifest(
                MANIFEST_VERSION,
                SAMPLE_APP_ID,
                SAMPLE_APP_NAME,
                APP_VERSION,
                NESTED_WINDOWS_SCRIPT));

    assertEquals(Path.of("bin", "tools", "launch.cmd"), manifest.execPath());
    assertEquals("bin/tools/launch.cmd", manifest.execPathText());
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
                APP_VERSION,
                "bin\\ui\\launch.cmd"));

    assertEquals(Path.of("bin", "ui", "launch.cmd"), manifest.execPath());
    assertEquals("bin/ui/launch.cmd", manifest.execPathText());
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
                APP_VERSION,
                "bin\\u1234\\launch.cmd"));

    assertEquals(Path.of("bin", "u1234", "launch.cmd"), manifest.execPath());
    assertEquals("bin/u1234/launch.cmd", manifest.execPathText());
  }

  @Test
  void parseContent_whenManifestComesFromPropertiesStore_expectEscapesDecoded() throws Exception {
    Properties properties = new Properties();
    properties.setProperty("manifest.version", "1");
    properties.setProperty("app.id", SAMPLE_APP_ID);
    properties.setProperty("app.name", UTF8_APP_NAME);
    properties.setProperty("app.version", APP_VERSION);
    properties.setProperty("app.exec", WINDOWS_SCRIPT);
    properties.setProperty("app.permissions", "network.read, ui.open");
    StringWriter writer = new StringWriter();
    properties.store(writer, "generated");

    AppManifest manifest = AppManifestParser.parseContent(writer.toString());

    assertEquals(UTF8_APP_NAME, manifest.appName());
    assertEquals(Path.of("bin", "launch.cmd"), manifest.execPath());
    assertEquals("bin/launch.cmd", manifest.execPathText());
    assertEquals(java.util.List.of("network.read", "ui.open"), manifest.permissions());
  }

  @Test
  void parseContent_whenPropertiesStoreEncodesUnicodeExecPath_expectEscapesDecoded()
      throws Exception {
    Properties properties = new Properties();
    properties.setProperty("manifest.version", "1");
    properties.setProperty("app.id", SAMPLE_APP_ID);
    properties.setProperty("app.name", SAMPLE_APP_NAME);
    properties.setProperty("app.version", APP_VERSION);
    properties.setProperty("app.exec", "bin/\u542F\u52A8.sh");
    StringWriter writer = new StringWriter();
    properties.store(writer, "generated");

    AppManifest manifest = AppManifestParser.parseContent(writer.toString());

    assertEquals(Path.of("bin", "启动.sh"), manifest.execPath());
    assertEquals("bin/启动.sh", manifest.execPathText());
  }

  @Test
  void parseContent_whenPropertiesStoreEncodesBundleRootUnicodeExec_expectEscapesDecoded()
      throws Exception {
    Properties properties = new Properties();
    properties.setProperty("manifest.version", "1");
    properties.setProperty("app.id", SAMPLE_APP_ID);
    properties.setProperty("app.name", SAMPLE_APP_NAME);
    properties.setProperty("app.version", APP_VERSION);
    properties.setProperty("app.exec", "launch-启动.sh");
    StringWriter writer = new StringWriter();
    properties.store(writer, "generated");

    AppManifest manifest = AppManifestParser.parseContent(writer.toString());

    assertEquals(Path.of("launch-启动.sh"), manifest.execPath());
    assertEquals("launch-启动.sh", manifest.execPathText());
  }

  @Test
  void parseContent_whenManifestBeginsWithUtf8Bom_expectVersionParsed() throws Exception {
    AppManifest manifest =
        AppManifestParser.parseContent(
            "\uFEFF"
                + minimalManifest(
                    MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT));

    assertEquals(1, manifest.manifestVersion());
    assertEquals(SAMPLE_APP_ID, manifest.appId());
  }

  @Test
  void parse_whenManifestPathIsSymlink_expectFailure() throws Exception {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    Path targetManifest = tempDir.resolve("target.properties");
    Files.writeString(
        targetManifest,
        minimalManifest(
            MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT),
        StandardCharsets.UTF_8);
    Path manifestSymlink = tempDir.resolve("cryptad-app.properties");
    Files.createSymbolicLink(manifestSymlink, targetManifest);

    AppManifestException exception =
        assertThrows(AppManifestException.class, () -> AppManifestParser.parse(manifestSymlink));

    assertEquals("manifest file must not be a symlink: " + manifestSymlink, exception.getMessage());
  }

  @Test
  void parseContent_whenManifestVersionIsUnsupported_expectFailure() {
    String invalidManifest =
        minimalManifest("2", SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT);
    AppManifestException exception =
        assertThrows(
            AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));

    assertEquals("unsupported manifest.version: 2", exception.getMessage());
  }

  @Test
  void parseContent_whenAppIdIsInvalid_expectFailure() {
    String invalidManifest =
        minimalManifest(MANIFEST_VERSION, "Bad/Id", SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT);
    assertThrows(AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));
  }

  @Test
  void parseContent_whenAppExecIsAbsoluteOrTraversingParent_expectFailure() {
    String absolutePathManifest =
        minimalManifest(
            MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, "/tmp/app.sh");
    String parentTraversalManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, "../app.sh");
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(absolutePathManifest));
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(parentTraversalManifest));
  }

  @Test
  void parseContent_whenAppExecUsesWindowsDrivePrefix_expectFailure() {
    String invalidManifest =
        minimalManifest(
            MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, "C:launch.cmd");
    assertThrows(AppManifestException.class, () -> AppManifestParser.parseContent(invalidManifest));
  }

  @Test
  void parseContent_whenQuotaValueIsMalformed_expectFailure() {
    String invalidDataQuotaManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT)
            + "quota.data.bytes=not-a-number\n";
    String invalidCacheQuotaManifest =
        minimalManifest(MANIFEST_VERSION, SAMPLE_APP_ID, SAMPLE_APP_NAME, APP_VERSION, START_SCRIPT)
            + "quota.cache.bytes=-1\n";
    assertThrows(
        AppManifestException.class, () -> AppManifestParser.parseContent(invalidDataQuotaManifest));
    assertThrows(
        AppManifestException.class,
        () -> AppManifestParser.parseContent(invalidCacheQuotaManifest));
  }

  private static String fullManifest(
      String appId, String appName, String appVersion, String execPath) {
    return """
    manifest.version=1
    app.id=%s
    app.name=%s
    app.version=%s
    app.exec=%s
    app.ui.entry=/
    app.permissions=network.read, ui.open
    quota.data.bytes=1048576
    quota.cache.bytes=2048
    """
        .formatted(appId, appName, appVersion, execPath);
  }

  private static String minimalManifest(
      String manifestVersion, String appId, String appName, String appVersion, String execPath) {
    return """
    manifest.version=%s
    app.id=%s
    app.name=%s
    app.version=%s
    app.exec=%s
    """
        .formatted(manifestVersion, appId, appName, appVersion, execPath);
  }
}
