package network.crypta.platform.webshell;

import java.util.List;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrapJson;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellBootstrapTest {
  @Test
  void nodeManagement_whenLegacyLinksProvided_expectStableDefaultRoutesAndProvidedLinks() {
    List<WebShellBootstrap.LegacyLink> legacyLinks =
        List.of(
            new WebShellBootstrap.LegacyLink("/friends-custom/", "Friends"),
            new WebShellBootstrap.LegacyLink("/downloads-custom/", "Downloads"));
    WebShellBootstrap bootstrap = WebShellBootstrap.nodeManagement(legacyLinks);

    assertEquals(WebShellBootstrap.DEFAULT_SHELL_TITLE, bootstrap.shellTitle());
    assertEquals(WebShellPaths.SHELL_ROOT, bootstrap.shellRoot());
    assertEquals(WebShellPaths.ASSET_ROOT, bootstrap.assetRoot());
    assertEquals(WebShellBootstrap.DEFAULT_PLATFORM_API_ROOT, bootstrap.platformApiRoot());
    assertEquals(WebShellBootstrap.DEFAULT_LEGACY_ROOT, bootstrap.legacyRoot());
    assertEquals(legacyLinks, bootstrap.legacyLinks());
  }

  @Test
  void toJson_whenValuesContainJsonSensitiveCharacters_expectEscapedPayload() {
    WebShellBootstrap bootstrap =
        new WebShellBootstrap(
            "A \"shell\" <node> & more",
            "Read-only shell",
            "/app/node/",
            "/app/node/static/",
            "/api/v1/",
            "/",
            List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends & Allies")));

    assertEquals(
        "{\"shellTitle\":\"A \\\"shell\\\" \\u003cnode\\u003e \\u0026 more\","
            + "\"shellDescription\":\"Read-only shell\","
            + "\"shellRoot\":\"/app/node/\","
            + "\"assetRoot\":\"/app/node/static/\","
            + "\"platformApiRoot\":\"/api/v1/\","
            + "\"legacyRoot\":\"/\","
            + "\"legacyLinks\":[{\"path\":\"/friends/\",\"label\":\"Friends \\u0026 Allies\"}]}",
        WebShellBootstrapJson.serialize(bootstrap));
  }

  @Test
  void legacyLink_whenConstructed_expectAbsoluteLegacyPath() {
    WebShellBootstrap.LegacyLink link = new WebShellBootstrap.LegacyLink("/stats/", "Statistics");

    assertEquals("/stats/", link.path());
    assertEquals("Statistics", link.label());
    assertTrue(link.toString().contains("Statistics"));
  }
}
