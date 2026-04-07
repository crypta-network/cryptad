package network.crypta.clients.http;

import java.util.List;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class WebShellToadletBootstrapTest {

  @Test
  void createNodeManagementBootstrap_whenCustomLegacyPathsProvided_usesConfiguredPaths() {
    WebShellBootstrap bootstrap =
        WebShellToadlet.createNodeManagementBootstrap(
            List.of(
                new WebShellBootstrap.LegacyLink("/friends-custom/", "Friends"),
                new WebShellBootstrap.LegacyLink("/strangers-custom/", "Strangers"),
                new WebShellBootstrap.LegacyLink("/downloads-custom/", "Downloads"),
                new WebShellBootstrap.LegacyLink("/connectivity-custom/", "Connectivity"),
                new WebShellBootstrap.LegacyLink("/seclevels-custom/", "Security levels"),
                new WebShellBootstrap.LegacyLink("/stats-custom/", "Statistics"),
                new WebShellBootstrap.LegacyLink("/alerts-custom/", "Alerts"),
                new WebShellBootstrap.LegacyLink("/config-custom/", "Config")));

    assertEquals(WebShellPaths.SHELL_ROOT, bootstrap.shellRoot());
    assertEquals(
        List.of(
            "/friends-custom/",
            "/strangers-custom/",
            "/downloads-custom/",
            "/connectivity-custom/",
            "/seclevels-custom/",
            "/stats-custom/",
            "/alerts-custom/",
            "/config-custom/"),
        bootstrap.legacyLinks().stream().map(WebShellBootstrap.LegacyLink::path).toList());
  }
}
