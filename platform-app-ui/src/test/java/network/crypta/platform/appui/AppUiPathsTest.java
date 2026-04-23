package network.crypta.platform.appui;

import java.util.List;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class AppUiPathsTest {
  @Test
  void uiUrl_whenStaticEntryIsAtBundleRoot_expectAppRootUrl() {
    AppManifest manifest = manifest(AppUiMode.STATIC, "index.html");

    assertEquals("/apps/demo-app/", AppUiPaths.uiUrl(manifest));
  }

  @Test
  void uiUrl_whenStaticEntryIsNested_expectEntryDirectoryUrl() {
    AppManifest manifest = manifest(AppUiMode.STATIC, "ui/admin/index.html");

    assertEquals("/apps/demo-app/ui/admin/", AppUiPaths.uiUrl(manifest));
  }

  @Test
  void uiUrl_whenStaticEntryDirectoryContainsSpaces_expectEncodedEntryDirectoryUrl() {
    AppManifest manifest = manifest(AppUiMode.STATIC, "ui admin/index.html");

    assertEquals("/apps/demo-app/ui%20admin/", AppUiPaths.uiUrl(manifest));
  }

  @Test
  void uiUrl_whenShellPanelEntryDeclared_expectManifestEntryPreserved() {
    AppManifest manifest = manifest(AppUiMode.SHELL_PANEL, "/app/node/#queue");

    assertEquals("/app/node/#queue", AppUiPaths.uiUrl(manifest));
  }

  @Test
  void uiUrl_whenNoUiDeclared_expectNull() {
    AppManifest manifest = manifest(AppUiMode.NONE, null);

    assertNull(AppUiPaths.uiUrl(manifest));
  }

  private static AppManifest manifest(AppUiMode uiMode, String uiEntry) {
    return new AppManifest(
        1,
        "demo-app",
        "Demo App",
        "1.0.0",
        "bin/launch.sh",
        uiMode,
        uiEntry,
        List.of(),
        null,
        null);
  }
}
