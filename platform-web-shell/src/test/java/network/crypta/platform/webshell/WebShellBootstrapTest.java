package network.crypta.platform.webshell;

import java.util.List;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrap;
import network.crypta.platform.webshell.bootstrap.WebShellBootstrapJson;
import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellBootstrapTest {
  private static final String CONFIGURED_SECURITY_LEVELS_PATH = "/security-custom/";
  private static final String CONFIGURED_DIAGNOSTIC_PATH = "/diagnostic-custom/";

  @Test
  void nodeManagement_whenLegacyLinksAndSecurityPathProvided_expectStableRoutesAndProvidedLinks() {
    List<WebShellBootstrap.LegacyLink> legacyLinks =
        List.of(
            new WebShellBootstrap.LegacyLink("/friends-custom/", "Friends"),
            new WebShellBootstrap.LegacyLink("/downloads-custom/", "Downloads"));
    WebShellBootstrap bootstrap =
        WebShellBootstrap.nodeManagement(
            CONFIGURED_SECURITY_LEVELS_PATH, CONFIGURED_DIAGNOSTIC_PATH, legacyLinks);

    assertEquals(WebShellBootstrap.DEFAULT_SHELL_TITLE, bootstrap.shellTitle());
    assertEquals(WebShellPaths.SHELL_ROOT, bootstrap.shellRoot());
    assertEquals(WebShellPaths.ASSET_ROOT, bootstrap.assetRoot());
    assertEquals(WebShellBootstrap.DEFAULT_PLATFORM_API_ROOT, bootstrap.platformApiRoot());
    assertNull(bootstrap.formPassword());
    assertEquals(WebShellBootstrap.DEFAULT_LEGACY_ROOT, bootstrap.legacyRoot());
    assertEquals(CONFIGURED_SECURITY_LEVELS_PATH, bootstrap.legacySecurityLevelsPath());
    assertEquals(CONFIGURED_DIAGNOSTIC_PATH, bootstrap.legacyDiagnosticPath());
    assertEquals(legacyLinks, bootstrap.legacyLinks());
  }

  @Test
  void nodeManagement_whenSecurityPathProvided_expectConfiguredLegacyFallbackPath() {
    WebShellBootstrap bootstrap =
        WebShellBootstrap.nodeManagement(
            CONFIGURED_SECURITY_LEVELS_PATH,
            CONFIGURED_DIAGNOSTIC_PATH,
            List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends")));

    assertEquals(CONFIGURED_SECURITY_LEVELS_PATH, bootstrap.legacySecurityLevelsPath());
    assertEquals(CONFIGURED_DIAGNOSTIC_PATH, bootstrap.legacyDiagnosticPath());
  }

  @Test
  void nodeManagement_whenSlashlessSecurityPathProvided_expectConfiguredPathPreserved() {
    WebShellBootstrap bootstrap =
        WebShellBootstrap.nodeManagement(
            "/security-custom",
            CONFIGURED_DIAGNOSTIC_PATH,
            List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends")));

    assertEquals("/security-custom", bootstrap.legacySecurityLevelsPath());
  }

  @Test
  void nodeManagement_whenSlashlessDiagnosticPathProvided_expectConfiguredPathPreserved() {
    WebShellBootstrap bootstrap =
        WebShellBootstrap.nodeManagement(
            CONFIGURED_SECURITY_LEVELS_PATH,
            "/diagnostic-custom",
            List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends")));

    assertEquals("/diagnostic-custom", bootstrap.legacyDiagnosticPath());
  }

  @Test
  void toJson_whenValuesContainJsonSensitiveCharacters_expectEscapedPayload() {
    WebShellBootstrap bootstrap =
        new WebShellBootstrap(
            "A \"shell\" <node> & more",
            "Queue-aware shell",
            "/app/node/",
            "/app/node/static/",
            "/api/v1/",
            "secret<token>",
            "/",
            "/security-custom/",
            "/diagnostic-custom/",
            List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends & Allies")));

    assertEquals(
        "{\"shellTitle\":\"A \\\"shell\\\" \\u003cnode\\u003e \\u0026 more\","
            + "\"shellDescription\":\"Queue-aware shell\","
            + "\"shellRoot\":\"/app/node/\","
            + "\"assetRoot\":\"/app/node/static/\","
            + "\"platformApiRoot\":\"/api/v1/\","
            + "\"formPassword\":\"secret\\u003ctoken\\u003e\","
            + "\"legacyRoot\":\"/\","
            + "\"legacySecurityLevelsPath\":\"/security-custom/\","
            + "\"legacyDiagnosticPath\":\"/diagnostic-custom/\","
            + "\"legacyLinks\":[{\"path\":\"/friends/\",\"label\":\"Friends \\u0026 Allies\"}]}",
        WebShellBootstrapJson.serialize(bootstrap));
  }

  @Test
  void withFormPassword_whenBlank_expectMutationTokenCleared() {
    WebShellBootstrap bootstrap =
        WebShellBootstrap.nodeManagement(
                CONFIGURED_SECURITY_LEVELS_PATH,
                CONFIGURED_DIAGNOSTIC_PATH,
                List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends")))
            .withFormPassword("");

    assertNull(bootstrap.formPassword());
  }

  @Test
  void legacyLink_whenConstructed_expectAbsoluteLegacyPath() {
    WebShellBootstrap.LegacyLink link = new WebShellBootstrap.LegacyLink("/stats/", "Statistics");

    assertEquals("/stats/", link.path());
    assertEquals("Statistics", link.label());
    assertTrue(link.toString().contains("Statistics"));
  }

  @Test
  void legacyLink_whenPathIsSchemeRelativeOrContainsQuery_expectRejected() {
    List<WebShellBootstrap.LegacyLink> validLegacyLinks =
        List.of(new WebShellBootstrap.LegacyLink("/friends/", "Friends"));

    assertThrows(
        IllegalArgumentException.class,
        () -> new WebShellBootstrap.LegacyLink("//evil.example/", "External"));
    assertThrows(
        IllegalArgumentException.class,
        () -> new WebShellBootstrap.LegacyLink("/friends/?tab=all", "Friends"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            WebShellBootstrap.nodeManagement(
                "/seclevels/?tab=legacy", CONFIGURED_DIAGNOSTIC_PATH, validLegacyLinks));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            WebShellBootstrap.nodeManagement(
                CONFIGURED_SECURITY_LEVELS_PATH,
                "/diagnostic/?legacyFallback=diagnostic-export",
                validLegacyLinks));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            WebShellBootstrap.nodeManagement(
                CONFIGURED_SECURITY_LEVELS_PATH, "/diagnostic/#export", validLegacyLinks));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            WebShellBootstrap.nodeManagement(
                CONFIGURED_SECURITY_LEVELS_PATH, "//evil.example/diagnostic/", validLegacyLinks));
  }
}
