package network.crypta.platform.api;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppAuditLogTest {
  @Test
  void append_whenCapacityExceeded_expectOldestEventsDropped() {
    AppAuditLog log =
        new AppAuditLog(2, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));

    log.append(event("demo-app", "queue.read", AppAuditDecision.ALLOWED, 200));
    log.append(event("demo-app", "queue.write", AppAuditDecision.DENIED, 403));
    log.append(event("demo-app", "alerts.read", AppAuditDecision.ALLOWED, 200));

    List<AppAuditEvent> recent = log.recentForApp("demo-app", 10);
    assertEquals(2, recent.size());
    assertEquals("alerts.read", recent.get(0).action());
    assertEquals("queue.write", recent.get(1).action());
    assertEquals(1L, log.deniedCountForApp("demo-app"));
  }

  @Test
  void constructor_whenCapacityIsNotPositive_expectIllegalArgumentException() {
    Clock clock = Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC);

    assertThrows(IllegalArgumentException.class, () -> new AppAuditLog(0, clock));
    assertThrows(IllegalArgumentException.class, () -> new AppAuditLog(-1, clock));
  }

  @Test
  void recentForApp_whenLimitIsNonPositive_expectEmptyResult() {
    AppAuditLog log =
        new AppAuditLog(3, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));
    log.append(event("demo-app", "queue.read", AppAuditDecision.ALLOWED, 200));

    assertTrue(log.recentForApp("demo-app", 0).isEmpty());
    assertTrue(log.recentForApp("demo-app", -1).isEmpty());
  }

  @Test
  void recentForApp_whenMultipleAppsRecorded_expectNewestMatchingEventsOnly() {
    AppAuditLog log =
        new AppAuditLog(4, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));
    log.append(event("demo-app", "queue.read", AppAuditDecision.ALLOWED, 200));
    log.append(event("other-app", "alerts.read", AppAuditDecision.DENIED, 403));
    log.append(event("demo-app", "node.read", AppAuditDecision.ALLOWED, 200));

    List<AppAuditEvent> recent = log.recentForApp("demo-app", 1);

    assertEquals(1, recent.size());
    assertEquals("node.read", recent.getFirst().action());
    assertEquals(0L, log.deniedCountForApp("demo-app"));
  }

  @Test
  void appendDecision_whenRequestIsHostOperator_expectNoAuditEvent() {
    AppAuditLog log =
        new AppAuditLog(3, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));
    PlatformApiRequest request =
        new PlatformApiRequest("GET", List.of("node", "greeting"), java.util.Map.of());

    log.appendDecision(
        request,
        PlatformApiAuthorizationDecision.hostAllowed(),
        AppAuditDecision.ALLOWED,
        200,
        "route_completed");

    assertEquals(0, log.size());
    assertTrue(log.recentForApp("demo-app", 10).isEmpty());
  }

  @Test
  void appendDecision_whenRequestIsBrowserAppSession_expectAuthSourceRecorded() {
    AppAuditLog log =
        new AppAuditLog(3, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));
    PlatformApiRequest request =
        new PlatformApiRequest(
            "GET",
            List.of("queue"),
            java.util.Map.of(),
            PlatformApiPrincipal.appBrowserSession("demo-app", List.of("queue.read")));
    PlatformApiAuthorizationDecision authorization = PlatformApiCapabilities.authorize(request);

    log.appendDecision(request, authorization, AppAuditDecision.ALLOWED, 200, "route_completed");

    List<AppAuditEvent> events = log.recentForApp("demo-app", 10);
    assertEquals(1, events.size());
    assertEquals(PlatformApiAuthSource.APP_BROWSER_SESSION, events.getFirst().authSource());
  }

  @Test
  void appendDecision_whenRequestIsProcessAppToken_expectAuthSourceRecorded() {
    AppAuditLog log =
        new AppAuditLog(3, Clock.fixed(Instant.parse("2026-04-27T00:00:00Z"), ZoneOffset.UTC));
    PlatformApiRequest request =
        new PlatformApiRequest(
            "GET",
            List.of("queue"),
            java.util.Map.of(),
            PlatformApiPrincipal.appToken("demo-app", List.of("queue.read")));
    PlatformApiAuthorizationDecision authorization = PlatformApiCapabilities.authorize(request);

    log.appendDecision(request, authorization, AppAuditDecision.ALLOWED, 200, "route_completed");

    List<AppAuditEvent> events = log.recentForApp("demo-app", 10);
    assertEquals(1, events.size());
    assertEquals(PlatformApiAuthSource.APP_TOKEN, events.getFirst().authSource());
  }

  private static AppAuditEvent event(
      String appId, String action, AppAuditDecision decision, int statusCode) {
    return new AppAuditEvent(
        Instant.parse("2026-04-27T00:00:00Z"),
        appId,
        "GET",
        "queue",
        action,
        List.of("queue.read"),
        PlatformApiAuthSource.APP_TOKEN,
        decision,
        statusCode,
        decision.name().toLowerCase(java.util.Locale.ROOT));
  }
}
