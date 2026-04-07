package network.crypta.platform.webshell;

import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellResourcesTest {
  @Test
  void readText_whenIndexResourceRequested_expectShellMarkup() {
    String html = WebShellResources.readText(WebShellPaths.INDEX_RESOURCE_PATH);

    assertTrue(html.contains("Web Shell v1"));
    assertTrue(html.contains("__BOOTSTRAP_JSON__"));
  }
}
