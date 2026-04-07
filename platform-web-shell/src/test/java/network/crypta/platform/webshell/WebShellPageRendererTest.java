package network.crypta.platform.webshell;

import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellPageRendererTest {
  @Test
  void render_whenBootstrapProvided_expectTemplateAndBootstrapInjected() {
    String html =
        WebShellPageRenderer.render(
            WebShellBootstrap.nodeManagement(
                java.util.List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends"))));

    assertTrue(html.contains("Web Shell v1"));
    assertTrue(html.contains(WebShellPaths.STYLESHEET_PATH));
    assertTrue(html.contains(WebShellPaths.SCRIPT_PATH));
    assertTrue(html.contains(WebShellPaths.BOOTSTRAP_ELEMENT_ID));
    assertTrue(html.contains(WebShellBootstrap.DEFAULT_SHELL_TITLE));
    assertFalse(html.contains("__BOOTSTRAP_JSON__"));
  }
}
