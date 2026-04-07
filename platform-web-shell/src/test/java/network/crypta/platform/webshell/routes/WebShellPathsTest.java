package network.crypta.platform.webshell.routes;

import network.crypta.platform.webshell.WebShellResources;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class WebShellPathsTest {
  @Test
  void resourcePath_whenStaticIndexRequested_expectStableClasspathLocation() {
    String expectedPath =
        "/" + WebShellResources.class.getPackageName().replace('.', '/') + "/static/index.html";

    assertEquals(expectedPath, WebShellPaths.resourcePath("static/index.html"));
    assertEquals(WebShellPaths.INDEX_RESOURCE_PATH, expectedPath);
  }

  @Test
  void resourcePath_whenStaticDirectoryRequested_expectStableAssetResourceRoot() {
    assertEquals(WebShellPaths.ASSET_RESOURCE_ROOT, WebShellPaths.resourcePath("static/"));
  }

  @Test
  void resourcePath_whenPathAlreadyAbsolute_expectRejected() {
    assertThrows(
        IllegalArgumentException.class, () -> WebShellPaths.resourcePath("/static/index.html"));
  }
}
