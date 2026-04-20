package network.crypta.platform.appdist;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
}
