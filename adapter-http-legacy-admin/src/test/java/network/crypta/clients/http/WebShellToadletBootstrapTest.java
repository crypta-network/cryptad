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
            "/security-custom/",
            "/diagnostic-custom/",
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
    assertEquals("/security-custom/", bootstrap.legacySecurityLevelsPath());
    assertEquals("/diagnostic-custom/", bootstrap.legacyDiagnosticPath());
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

  @Test
  void createNodeManagementBootstrap_whenDefaultBuilt_expectSecurityFallbackPathFromRegistry() {
    WebShellBootstrap bootstrap =
        WebShellToadlet.createNodeManagementBootstrap(WebShellToadlet.defaultLegacyLinks());

    assertEquals(
        LegacyAdminRetirementRegistry.require("security-levels").legacyPath(),
        bootstrap.legacySecurityLevelsPath());
    assertEquals(
        LegacyAdminRetirementRegistry.require("diagnostic").legacyPath(),
        bootstrap.legacyDiagnosticPath());
  }

  @Test
  void createNodeManagementBootstrap_whenSlashlessFallbackPathsProvided_preservesConfiguredPaths() {
    WebShellBootstrap bootstrap =
        WebShellToadlet.createNodeManagementBootstrap(
            "/security-custom", "/diagnostic-custom", WebShellToadlet.defaultLegacyLinks());

    assertEquals("/security-custom", bootstrap.legacySecurityLevelsPath());
    assertEquals("/diagnostic-custom", bootstrap.legacyDiagnosticPath());
  }

  @Test
  void defaultLegacyLinks_whenBuilt_expectOnlyPendingOrRetainedFallbackPages() {
    List<WebShellBootstrap.LegacyLink> links = WebShellToadlet.defaultLegacyLinks();

    assertEquals(
        List.of(
            "/send_n2ntm/",
            "/chat/",
            "/translation/",
            "/help/",
            LegacyContentFilterSupport.CONTENT_FILTER_PATH),
        links.stream().map(WebShellBootstrap.LegacyLink::path).toList());
    assertEquals(
        List.of(
            "Node-to-node messages", "Chat and forums", "Translation", "Help", "Content filter"),
        links.stream().map(WebShellBootstrap.LegacyLink::label).toList());
  }
}
