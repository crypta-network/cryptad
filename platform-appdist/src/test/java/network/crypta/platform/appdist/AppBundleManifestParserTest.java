package network.crypta.platform.appdist;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppBundleManifestParserTest {
  @Test
  void parseContent_whenExecUsesWindowsBackslashes_expectNormalizedRelativeExecPath()
      throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            """
            manifest.version=1
            app.id=sample-app
            app.name=Sample App
            app.version=1.0.0
            app.exec=bin\\launch.bat
            """);

    assertEquals("bin/launch.bat", manifest.execPathText());
  }

  @Test
  void parseContent_whenUiEntryMissing_expectNoUiMode() throws Exception {
    AppBundleManifest manifest = AppBundleManifestParser.parseContent(minimalManifest(""));

    assertEquals(AppUiMode.NONE, manifest.uiMode());
    assertNull(manifest.uiEntry());
  }

  @Test
  void parseContent_whenUiModeMissingAndEntryIsAbsolute_expectShellPanelMode() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(minimalManifest("app.ui.entry=/app/node/#queue\n"));

    assertEquals(AppUiMode.SHELL_PANEL, manifest.uiMode());
    assertEquals("/app/node/#queue", manifest.uiEntry());
  }

  @Test
  void parseContent_whenUiModeMissingAndEntryIsRelative_expectStaticMode() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(minimalManifest("app.ui.entry=static/index.html\n"));

    assertEquals(AppUiMode.STATIC, manifest.uiMode());
    assertEquals("static/index.html", manifest.uiEntry());
  }

  @Test
  void parseContent_whenUiEntryValueIsBlank_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleManifestParser.parseContent(minimalManifest("app.ui.entry=\n")));

    assertEquals("app.ui.entry must not be blank", exception.getMessage());
  }

  @Test
  void parseContent_whenStaticUiEntryIsAbsolute_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.ui.mode=static\napp.ui.entry=/static/index.html\n")));

    assertEquals("app.ui.entry must be relative: /static/index.html", exception.getMessage());
  }

  @Test
  void parseContent_whenStaticUiEntryTraversesParent_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.ui.mode=static\napp.ui.entry=../index.html\n")));

    assertEquals(
        "app.ui.entry must stay under the app root: ../index.html", exception.getMessage());
  }

  @Test
  void parseContent_whenStaticUiEntryPointsAtDistributionSidecar_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.ui.mode=static\napp.ui.entry=cryptad-app.catalog\n")));

    assertEquals(
        "app.ui.entry must not point at distribution sidecar: cryptad-app.catalog",
        exception.getMessage());
  }

  @Test
  void parseContent_whenStaticUiEntryPointsAtCaseVariantDistributionSidecar_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.ui.mode=static\napp.ui.entry=CRYPTAD-APP.CATALOG\n")));

    assertEquals(
        "app.ui.entry must not point at distribution sidecar: CRYPTAD-APP.CATALOG",
        exception.getMessage());
  }

  @Test
  void parseContent_whenStaticUiEntryContainsControlCharacter_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.ui.mode=static\napp.ui.entry=static\\u0009index.html\n")));

    assertEquals(
        "app.ui.entry contains an unsafe path segment: static\tindex.html", exception.getMessage());
  }

  @Test
  void parseContent_whenShellPanelUiEntryIsExternalUrl_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest(
                        "app.ui.mode=shell-panel\napp.ui.entry=https://example.invalid\n")));

    assertEquals("app.ui.entry must be an absolute local path", exception.getMessage());
  }

  @Test
  void parseContent_whenExecPointsAtDistributionSidecar_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    """
                    manifest.version=1
                    app.id=sample-app
                    app.name=Sample App
                    app.version=1.0.0
                    app.exec=cryptad-app.catalog
                    """));

    assertEquals(
        "app.exec must not point at distribution sidecar: cryptad-app.catalog",
        exception.getMessage());
  }

  @Test
  void parseContent_whenExecPointsAtCaseVariantDistributionSidecar_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    """
                    manifest.version=1
                    app.id=sample-app
                    app.name=Sample App
                    app.version=1.0.0
                    app.exec=CRYPTAD-APP.CATALOG
                    """));

    assertEquals(
        "app.exec must not point at distribution sidecar: CRYPTAD-APP.CATALOG",
        exception.getMessage());
  }

  @Test
  void parseContent_whenOptionalPermissionsValueIsBlank_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    """
                    manifest.version=1
                    app.id=sample-app
                    app.name=Sample App
                    app.version=1.0.0
                    app.exec=bin/launch.sh
                    app.permissions=
                    """));

    assertEquals("app.permissions must not be blank", exception.getMessage());
  }

  @Test
  void parseContent_whenOptionalQuotaValueIsBlank_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    """
                    manifest.version=1
                    app.id=sample-app
                    app.name=Sample App
                    app.version=1.0.0
                    app.exec=bin/launch.sh
                    quota.data.bytes=
                    """));

    assertEquals("quota.data.bytes must not be blank", exception.getMessage());
  }

  private static String minimalManifest(String uiProperties) {
    return """
    manifest.version=1
    app.id=sample-app
    app.name=Sample App
    app.version=1.0.0
    app.exec=bin/launch.sh
    """
        + uiProperties;
  }
}
