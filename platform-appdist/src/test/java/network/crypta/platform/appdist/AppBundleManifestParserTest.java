package network.crypta.platform.appdist;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    assertEquals(AppSandboxMode.NONE, manifest.sandboxMode());
    assertFalse(manifest.sandboxRequired());
    assertEquals(AppRestartPolicy.NEVER, manifest.restartPolicy());
    assertEquals(0, manifest.restartMaxAttempts());
    assertEquals(0L, manifest.restartBackoffMillis());
    assertFalse(manifest.apiCompatibility().declared());
  }

  @Test
  void parseContent_whenRestrictedSandboxDeclared_expectSandboxFields() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            minimalManifest(
                """
                sandbox.mode=restricted-process
                sandbox.required=true
                """));

    assertEquals(AppSandboxMode.RESTRICTED_PROCESS, manifest.sandboxMode());
    assertTrue(manifest.sandboxRequired());
  }

  @Test
  void parseContent_whenWasmPreviewSandboxDeclared_expectReservedModeParsed() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(minimalManifest("sandbox.mode=wasm-preview\n"));

    assertEquals(AppSandboxMode.WASM_PREVIEW, manifest.sandboxMode());
    assertFalse(manifest.sandboxRequired());
  }

  @Test
  void parseContent_whenSandboxModeIsUnsupported_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleManifestParser.parseContent(minimalManifest("sandbox.mode=docker\n")));

    assertEquals("unsupported sandbox.mode: docker", exception.getMessage());
  }

  @Test
  void parseContent_whenSandboxRequiredIsMalformed_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(minimalManifest("sandbox.required=maybe\n")));

    assertEquals("invalid sandbox.required: maybe", exception.getMessage());
  }

  @Test
  void parseContent_whenRestartPolicyDeclared_expectRestartFields() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            minimalManifest(
                """
                app.restart.policy=on-failure
                app.restart.maxAttempts=3
                app.restart.backoff.ms=250
                """));

    assertEquals(AppRestartPolicy.ON_FAILURE, manifest.restartPolicy());
    assertEquals(3, manifest.restartMaxAttempts());
    assertEquals(250L, manifest.restartBackoffMillis());
  }

  @Test
  void parseContent_whenQuotaDeclared_expectQuotaFields() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            minimalManifest(
                """
                quota.data.bytes=1024
                quota.cache.bytes=512
                """));

    assertEquals(Long.valueOf(1024L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(512L), manifest.cacheQuotaBytes());
  }

  @Test
  void parseContent_whenQuotaIsZero_expectRawMetadataPreservedForCompatibility() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            minimalManifest(
                """
                quota.data.bytes=0
                quota.cache.bytes=0
                """));

    assertEquals(Long.valueOf(0L), manifest.dataQuotaBytes());
    assertEquals(Long.valueOf(0L), manifest.cacheQuotaBytes());
  }

  @Test
  void parseContent_whenQuotaIsNegative_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleManifestParser.parseContent(minimalManifest("quota.cache.bytes=-1\n")));

    assertEquals("quota.cache.bytes must be >= 0", exception.getMessage());
  }

  @Test
  void parseContent_whenRestartAttemptsNegative_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("app.restart.maxAttempts=-1\n")));

    assertEquals("app.restart.maxAttempts must be >= 0", exception.getMessage());
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
  void parseContent_whenApiCompatibilityDeclared_expectNormalizedMetadata() throws Exception {
    AppBundleManifest manifest =
        AppBundleManifestParser.parseContent(
            minimalManifest(
                """
                api.minimumVersion=1
                api.maximumTestedVersion=2
                api.optionalCapabilities=ALERTS.READ, diagnostics.read,alerts.read
                api.experimentalCapabilitiesAccepted=true
                """));

    AppApiCompatibilityMetadata compatibility = manifest.apiCompatibility();
    assertEquals(Integer.valueOf(1), compatibility.minimumVersion());
    assertEquals(Integer.valueOf(2), compatibility.maximumTestedVersion());
    assertEquals(List.of("alerts.read", "diagnostics.read"), compatibility.optionalCapabilities());
    assertTrue(compatibility.experimentalCapabilitiesAccepted());
  }

  @Test
  void parseContent_whenApiMinimumVersionIsInvalid_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () -> AppBundleManifestParser.parseContent(minimalManifest("api.minimumVersion=0\n")));

    assertEquals("api.minimumVersion must be a positive integer", exception.getMessage());
  }

  @Test
  void parseContent_whenApiMaximumTestedBelowMinimum_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("api.minimumVersion=2\napi.maximumTestedVersion=1\n")));

    assertEquals("api.maximumTestedVersion must be >= api.minimumVersion", exception.getMessage());
  }

  @Test
  void parseContent_whenApiExperimentalFlagIsMalformed_expectFailure() {
    AppDistributionException exception =
        assertThrows(
            AppDistributionException.class,
            () ->
                AppBundleManifestParser.parseContent(
                    minimalManifest("api.experimentalCapabilitiesAccepted=maybe\n")));

    assertEquals("invalid api.experimentalCapabilitiesAccepted: maybe", exception.getMessage());
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
