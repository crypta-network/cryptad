package network.crypta.platform.api.networkbudget;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppNetworkBudgetServiceTest {
  private static final Instant START = Instant.parse("2026-06-12T00:00:00Z");

  @Test
  void acquire_whenPerAppRateLimitReached_expectDeniedUntilWindowReset() {
    MutableClock clock = new MutableClock(START);
    AppNetworkBudgetService service = service(config(2, 20, 4, 8), clock);

    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals(429, denied.statusCode());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
    assertEquals(Instant.parse("2026-06-12T00:01:00Z"), denied.nextAvailableAt());

    clock.set(Instant.parse("2026-06-12T00:01:01Z"));
    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
  }

  @Test
  void acquire_whenGlobalRateLimitReachedAcrossApps_expectDenied() {
    AppNetworkBudgetService service = service(config(10, 2, 4, 8), new MutableClock(START));

    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    assertAllowed(
        service.acquire("social-inbox", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    AppNetworkBudgetDecision denied =
        service.acquire("trust-graph", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
  }

  @Test
  void acquire_whenPerAppConcurrencyReached_expectDeniedUntilLeaseClosed() {
    AppNetworkBudgetService service = service(config(10, 20, 1, 8), new MutableClock(START));
    AppNetworkBudgetDecision first =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertTrue(first.allowed());
    assertFalse(denied.allowed());
    assertEquals("network_budget_concurrency_limited", denied.errorCode());

    first.lease().close();
    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
  }

  @Test
  void acquire_whenGlobalConcurrencyReachedAcrossApps_expectDeniedUntilLeaseClosed() {
    AppNetworkBudgetService service = service(config(10, 20, 2, 1), new MutableClock(START));
    AppNetworkBudgetDecision first =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    AppNetworkBudgetDecision denied =
        service.acquire("social-inbox", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertTrue(first.allowed());
    assertFalse(denied.allowed());
    assertEquals("network_budget_concurrency_limited", denied.errorCode());

    first.lease().close();
    assertAllowed(
        service.acquire("social-inbox", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
  }

  @Test
  void acquire_whenLeaseClosedByExceptionPath_expectConcurrencyReleased() {
    AppNetworkBudgetService service = service(config(10, 20, 1, 8), new MutableClock(START));
    try {
      try (var _ =
          service
              .acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH)
              .lease()) {
        throw new IllegalStateException("simulated fetch failure");
      }
    } catch (IllegalStateException _) {
      // The try-with-resources close path is the behavior under test.
    }

    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
  }

  @Test
  void acquire_whenSubscriptionConcurrencyReached_expectSubscriptionConcurrencyCode() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 1, 8, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));
    AppNetworkBudgetDecision first =
        service.acquire("social-inbox", AppNetworkBudgetOperation.SUBSCRIPTION_POLL);

    AppNetworkBudgetDecision denied =
        service.acquire("social-inbox", AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH);

    assertTrue(first.allowed());
    assertFalse(denied.allowed());
    assertEquals("content_subscription_concurrency_limited", denied.errorCode());
    assertEquals("Content subscription network budget concurrency is exhausted.", denied.message());

    first.lease().close();
    assertAllowed(
        service.acquire("social-inbox", AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH));
  }

  @Test
  void acquire_whenTrustGraphImportConcurrencyReached_expectTrustConcurrencyCode() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 10, 10, 1, 8);
    AppNetworkBudgetService service = service(config, new MutableClock(START));
    AppNetworkBudgetDecision first =
        service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    AppNetworkBudgetDecision denied =
        service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertTrue(first.allowed());
    assertFalse(denied.allowed());
    assertEquals("trust_graph_import_concurrency_limited", denied.errorCode());
    assertEquals("Trust Graph import concurrency budget is exhausted.", denied.message());

    first.lease().close();
    assertAllowed(service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
  }

  @Test
  void acquire_whenSubscriptionConsumesSharedContentFetchBudget_expectForegroundBlocked() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 1, 4, 8, 10, 10, 2, 4, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(service.acquire("social-inbox", AppNetworkBudgetOperation.SUBSCRIPTION_POLL));
    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
  }

  @Test
  void acquire_whenTrustGraphImportUriConsumesSharedContentFetchBudget_expectForegroundBlocked() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 1, 4, 8, 10, 10, 2, 4, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI));
    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
  }

  @Test
  void acquire_whenTrustGraphImportUriConsumesPerAppContentFetchBudget_expectSameAppBlocked() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(1, 20, 4, 8, 10, 10, 2, 4, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI));
    AppNetworkBudgetDecision denied =
        service.acquire("trust-graph", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
  }

  @Test
  void acquire_whenAppIdMatchesFormerGlobalScope_expectGlobalCounterIsSeparate() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(service.acquire("node-global", AppNetworkBudgetOperation.SUBSCRIPTION_POLL));

    assertEquals(1, subscriptionPollCount(service, "node-global"));
    assertEquals(1, subscriptionPollCount(service, AppNetworkBudgetScope.GLOBAL));
  }

  @Test
  void acquire_whenHostOperatorScopeUsesTrustBudget_expectOperatorAppBudgetIsSeparate() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 1, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(
        service.acquire(
            AppNetworkBudgetScope.HOST_OPERATOR, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    AppNetworkBudgetDecision operatorAppDecision =
        service.acquire("operator", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertAllowed(operatorAppDecision);
  }

  @Test
  void acquire_whenHostOperatorScopeUsesImportUriBudget_expectOperatorAppFetchBudgetIsSeparate() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(1, 20, 4, 8, 10, 10, 2, 4, 10, 10, 2, 4);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    assertAllowed(
        service.acquire(
            AppNetworkBudgetScope.HOST_OPERATOR, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI));
    AppNetworkBudgetDecision operatorAppDecision =
        service.acquire("operator", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertAllowed(operatorAppDecision);
  }

  @Test
  void acquire_whenUnknownInternalScopeProvided_expectRejectedBeforeStoreUse() {
    AppNetworkBudgetService service = service(config(10, 20, 2, 16), new MutableClock(START));

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                service.acquire(
                    "_cryptad_unrecognized", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));

    assertEquals("invalid internal budget scope", exception.getMessage());
  }

  @Test
  void acquire_whenFileCounterIsMalformed_expectNetworkBudgetUnavailable(@TempDir Path tempDir)
      throws Exception {
    Files.createDirectories(tempDir.resolve("feed-reader"));
    Files.writeString(
        tempDir.resolve("feed-reader").resolve("foreground_content_fetch.properties"),
        "not=valid\n",
        StandardCharsets.UTF_8);
    AppNetworkBudgetService service =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(tempDir), config(10, 20, 2, 16), new MutableClock(START));

    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertFalse(denied.allowed());
    assertEquals(503, denied.statusCode());
    assertEquals("network_budget_unavailable", denied.errorCode());
    assertEquals("App network budget service is unavailable.", denied.message());
  }

  private static void assertAllowed(AppNetworkBudgetDecision decision) {
    assertTrue(decision.allowed(), decision.errorCode());
    decision.lease().close();
  }

  private static int subscriptionPollCount(AppNetworkBudgetService service, String appId) {
    return service.snapshots().stream()
        .filter(snapshot -> snapshot.appId().equals(appId))
        .filter(snapshot -> snapshot.operation() == AppNetworkBudgetOperation.SUBSCRIPTION_POLL)
        .mapToInt(AppNetworkBudgetSnapshot::count)
        .findFirst()
        .orElse(0);
  }

  private static AppNetworkBudgetService service(AppNetworkBudgetConfig config, Clock clock) {
    return new AppNetworkBudgetService(new InMemoryAppNetworkBudgetStore(), config, clock);
  }

  private static AppNetworkBudgetConfig config(
      int foregroundPerApp,
      int foregroundGlobal,
      int foregroundPerAppConcurrency,
      int globalConcurrency) {
    return new AppNetworkBudgetConfig(
        foregroundPerApp,
        foregroundGlobal,
        foregroundPerAppConcurrency,
        globalConcurrency,
        10,
        10,
        2,
        4,
        10,
        10,
        2,
        4);
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    void set(Instant instant) {
      this.instant = instant;
    }

    @Override
    public ZoneId getZone() {
      return ZoneId.of("UTC");
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
