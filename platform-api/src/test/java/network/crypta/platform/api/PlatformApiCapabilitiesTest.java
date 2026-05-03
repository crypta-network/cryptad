package network.crypta.platform.api;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiCapabilitiesTest {
  @Test
  void authorize_whenHostOperatorRequest_expectAllowedWithoutCapabilities() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            new PlatformApiRequest("POST", List.of("config", "persist"), Map.of()));

    assertTrue(decision.allowed());
    assertEquals("host_operator", decision.reasonCode());
  }

  @Test
  void knownCapabilities_whenReadByDeveloperTooling_expectSortedRegistry() {
    assertEquals(
        List.of(
            "alerts.read",
            "alerts.write",
            "apps.manage",
            "apps.read",
            "catalogs.manage",
            "catalogs.read",
            "config.read",
            "config.write",
            "connectivity.read",
            "content.insert",
            "diagnostics.read",
            "node.read",
            "peers.read",
            "peers.write",
            "platform.contract.read",
            "queue.read",
            "queue.write",
            "security.read",
            "security.write",
            "updates.read",
            "updates.write",
            "wizard.read",
            "wizard.write"),
        List.copyOf(PlatformApiCapabilityRegistry.knownCapabilities()));
  }

  @Test
  void knownCapabilities_whenCallerMutatesRegistry_expectUnsupportedOperation() {
    Set<String> knownCapabilities = PlatformApiCapabilityRegistry.knownCapabilities();
    Iterator<String> iterator = knownCapabilities.iterator();

    assertTrue(iterator.hasNext());
    assertThrows(UnsupportedOperationException.class, iterator::remove);
  }

  @Test
  void authorize_whenAppHasReadCapability_expectRepresentativeReadAllowed() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("GET", List.of("queue"), List.of("queue.read")));

    assertTrue(decision.allowed());
    assertEquals(List.of("queue.read"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenBrowserAppHasReadCapability_expectRepresentativeReadAllowed() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            browserAppRequest("GET", List.of("queue"), List.of("queue.read")));

    assertTrue(decision.allowed());
    assertEquals(List.of("queue.read"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenBrowserAppLacksPeerWriteCapability_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            browserAppRequest("POST", List.of("peers", "add"), List.of("peers.read")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(List.of("peers.write"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenAppHasRequiredCapabilities_expectAllowed() {
    for (RouteCase routeCase : allowedRoutes()) {
      PlatformApiAuthorizationDecision decision =
          PlatformApiCapabilities.authorize(
              appRequest(routeCase.method(), routeCase.segments(), routeCase.capabilities()));

      assertTrue(decision.allowed(), routeCase.actionLabel());
      assertEquals("capability_present", decision.reasonCode(), routeCase.actionLabel());
      assertEquals(routeCase.endpointFamily(), decision.action().endpointFamily());
      assertEquals(routeCase.actionLabel(), decision.action().label());
      assertEquals(routeCase.capabilities(), decision.action().requiredCapabilities());
    }
  }

  @Test
  void authorize_whenAppInsertLacksContentInsert_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("POST", List.of("queue", "inserts", "file"), List.of("queue.write")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(
        List.of("content.insert", "queue.write"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenAppHitsUnmappedRoute_expectDeniedByDefault() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("POST", List.of("node", "greeting"), List.of("node.read")));

    assertFalse(decision.allowed());
    assertEquals("unmapped_route", decision.reasonCode());
  }

  @Test
  void authorize_whenAppRouteIsUnmapped_expectDeniedByDefault() {
    for (UnmappedRouteCase routeCase : unmappedAppRoutes()) {
      PlatformApiAuthorizationDecision decision =
          PlatformApiCapabilities.authorize(
              appRequest(
                  routeCase.method(),
                  routeCase.segments(),
                  List.of("apps.manage", "node.read", "queue.write")));

      assertFalse(decision.allowed(), routeCase.segments().toString());
      assertEquals("unmapped_route", decision.reasonCode(), routeCase.segments().toString());
      assertEquals("unmapped", decision.action().requiredCapabilities().getFirst());
    }
  }

  private static List<RouteCase> allowedRoutes() {
    return List.of(
        route("GET", List.of("node", "greeting"), "node", "node.read", "node.read"),
        route("GET", List.of("node", "reference"), "node", "node.read", "node.read"),
        route(
            "GET",
            List.of("connectivity"),
            "connectivity",
            "connectivity.read",
            "connectivity.read"),
        route("GET", List.of("queue"), "queue", "queue.read", "queue.read"),
        route("GET", List.of("queue", "count"), "queue", "queue.read", "queue.read"),
        route("GET", List.of("queue", "keys"), "queue", "queue.read", "queue.read"),
        route(
            "POST",
            List.of("queue", "downloads"),
            "queue",
            "queue.downloads.create",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "inserts", "file"),
            "queue",
            "queue.inserts.file",
            "content.insert",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "requests", "remove"),
            "queue",
            "queue.requests.remove",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "cleanup", "uploads"),
            "queue",
            "queue.cleanup.uploads",
            "queue.write"),
        route("GET", List.of("peers"), "peers", "peers.read", "peers.read"),
        route("GET", List.of("peers", "peer-123"), "peers", "peers.read", "peers.read"),
        route("POST", List.of("peers", "add"), "peers", "peers.add", "peers.write"),
        route(
            "POST",
            List.of("peers", "peer-123", "settings"),
            "peers",
            "peers.settings",
            "peers.write"),
        route("GET", List.of("config"), "config", "config.read", "config.read"),
        route("POST", List.of("config", "overrides"), "config", "config.overrides", "config.write"),
        route(
            "GET", List.of("security-levels"), "security-levels", "security.read", "security.read"),
        route(
            "GET",
            List.of("security-levels", "network-warning"),
            "security-levels",
            "security.network-warning",
            "security.read"),
        route(
            "POST",
            List.of("security-levels", "network"),
            "security-levels",
            "security.network",
            "security.write"),
        route("GET", List.of("updates", "core"), "updates", "updates.read", "updates.read"),
        route(
            "POST",
            List.of("updates", "core", "download"),
            "updates",
            "updates.core.download",
            "updates.write"),
        route("GET", List.of("wizard", "first-time"), "wizard", "wizard.read", "wizard.read"),
        route(
            "POST",
            List.of("wizard", "first-time", "apply"),
            "wizard",
            "wizard.first-time.apply",
            "wizard.write"),
        route("GET", List.of("alerts"), "alerts", "alerts.read", "alerts.read"),
        route(
            "POST", List.of("alerts", "42", "dismiss"), "alerts", "alerts.dismiss", "alerts.write"),
        route("GET", List.of("diagnostics"), "diagnostics", "diagnostics.read", "diagnostics.read"),
        route("GET", List.of("apps"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "runtime"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "logs"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "permissions"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "audit"), "apps", "apps.read", "apps.read"),
        route("POST", List.of("apps", "install"), "apps", "apps.install", "apps.manage"),
        route("DELETE", List.of("apps", "alpha"), "apps", "apps.uninstall", "apps.manage"),
        route("GET", List.of("app-catalogs"), "app-catalogs", "catalogs.read", "catalogs.read"),
        route(
            "GET",
            List.of("platform", "contract"),
            "platform",
            "platform.contract.read",
            "platform.contract.read"),
        route(
            "GET",
            List.of("app-catalogs", "default", "apps"),
            "app-catalogs",
            "catalogs.read",
            "catalogs.read"),
        route(
            "GET",
            List.of("app-catalogs", "default", "apps", "alpha"),
            "app-catalogs",
            "catalogs.read",
            "catalogs.read"),
        route(
            "POST",
            List.of("app-catalogs", "add"),
            "app-catalogs",
            "catalogs.add",
            "catalogs.manage"),
        route(
            "POST",
            List.of("app-catalogs", "default", "apps", "alpha", "install"),
            "app-catalogs",
            "catalogs.apps.install",
            "catalogs.manage"),
        route(
            "DELETE",
            List.of("app-catalogs", "default"),
            "app-catalogs",
            "catalogs.remove",
            "catalogs.manage"));
  }

  private static List<UnmappedRouteCase> unmappedAppRoutes() {
    return List.of(
        new UnmappedRouteCase("POST", List.of("node", "greeting")),
        new UnmappedRouteCase("GET", List.of("node", "unknown")),
        new UnmappedRouteCase("GET", List.of("connectivity", "status")),
        new UnmappedRouteCase("GET", List.of("diagnostics", "heap")),
        new UnmappedRouteCase("PUT", List.of("queue", "requests", "remove")),
        new UnmappedRouteCase("GET", List.of("queue", "downloads")),
        new UnmappedRouteCase("GET", List.of("queue", "requests", "remove")),
        new UnmappedRouteCase("POST", List.of("queue", "inserts", "unknown")),
        new UnmappedRouteCase("GET", List.of("peers", "peer-123", "settings")),
        new UnmappedRouteCase("GET", List.of("config", "overrides")),
        new UnmappedRouteCase("GET", List.of("config", "persist")),
        new UnmappedRouteCase("GET", List.of("security-levels", "network")),
        new UnmappedRouteCase("GET", List.of("updates", "core", "download")),
        new UnmappedRouteCase("GET", List.of("wizard", "first-time", "apply")),
        new UnmappedRouteCase("GET", List.of("alerts", "42", "dismiss")),
        new UnmappedRouteCase("GET", List.of("apps", "alpha", "start")),
        new UnmappedRouteCase("GET", List.of("apps", "alpha", "unknown")),
        new UnmappedRouteCase("POST", List.of("apps", "alpha", "logs")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default", "refresh")),
        new UnmappedRouteCase(
            "GET", List.of("app-catalogs", "default", "apps", "alpha", "install")),
        new UnmappedRouteCase(
            "DELETE", List.of("app-catalogs", "default", "apps", "alpha", "install")));
  }

  private static RouteCase route(
      String method,
      List<String> segments,
      String endpointFamily,
      String actionLabel,
      String... capabilities) {
    return new RouteCase(method, segments, endpointFamily, actionLabel, List.of(capabilities));
  }

  private static PlatformApiRequest appRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method, segments, Map.of(), PlatformApiPrincipal.appToken("demo-app", permissions));
  }

  private static PlatformApiRequest browserAppRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method,
        segments,
        Map.of(),
        PlatformApiPrincipal.appBrowserSession("demo-app", permissions));
  }

  private record RouteCase(
      String method,
      List<String> segments,
      String endpointFamily,
      String actionLabel,
      List<String> capabilities) {}

  private record UnmappedRouteCase(String method, List<String> segments) {}
}
