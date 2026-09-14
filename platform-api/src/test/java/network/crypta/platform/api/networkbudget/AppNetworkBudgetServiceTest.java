package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class AppNetworkBudgetServiceTest {
  @Test
  void externallyConstructedDiagnosticsCannotBeChangedThroughItsSourceList() {
    var rows = new java.util.ArrayList<AppNetworkBudgetSnapshot>();
    var snapshot = new AppNetworkBudgetService.Diagnostics(true, Instant.EPOCH, rows, 0, 0);

    rows.add(null);

    var usage = snapshot.usage();
    assertTrue(usage.isEmpty());
    assertThrows(UnsupportedOperationException.class, usage::clear);
  }

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
  void check_whenAllowed_expectNoRateCounterConsumed() {
    AppNetworkBudgetService service = service(config(1, 20, 4, 8), new MutableClock(START));

    AppNetworkBudgetDecision preflight =
        service.check("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    AppNetworkBudgetDecision firstAcquire =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    AppNetworkBudgetDecision denied =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertAllowed(preflight);
    assertAllowed(firstAcquire);
    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
  }

  @Test
  void reserve_whenAllowedButNotCommitted_expectNoRateCounterConsumed() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 1, 10, 1, 8);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    try (var reservation =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)) {
      assertTrue(reservation.allowed());
      assertEquals(0, trustGraphImportCount(service, "trust-graph"));
    }
    AppNetworkBudgetDecision allowedAfterClose =
        service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertAllowed(allowedAfterClose);
  }

  @Test
  void reserve_whenCommitted_expectRateCounterConsumed() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 1, 10, 1, 8);
    AppNetworkBudgetService service = service(config, new MutableClock(START));

    try (var reservation =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)) {
      assertTrue(reservation.allowed());
      assertAllowed(reservation.commit());
    }
    AppNetworkBudgetDecision denied =
        service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertFalse(denied.allowed());
    assertEquals("trust_graph_import_budget_exhausted", denied.errorCode());
  }

  @Test
  void reserve_whenClosedBeforeCommit_expectCommitDeniedAndRateCounterNotConsumed() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 1, 10, 1, 8);
    AppNetworkBudgetService service = service(config, new MutableClock(START));
    AppNetworkBudgetReservation reservation =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    reservation.close();
    AppNetworkBudgetDecision deniedCommit = reservation.commit();
    AppNetworkBudgetDecision allowedAfterClose =
        service.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertFalse(deniedCommit.allowed());
    assertEquals("network_budget_unavailable", deniedCommit.errorCode());
    assertAllowed(allowedAfterClose);
  }

  @Test
  void reserve_whenPerAppConcurrencyReached_expectDeniedUntilReservationClosed() {
    AppNetworkBudgetConfig config =
        new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 10, 10, 1, 8);
    AppNetworkBudgetService service = service(config, new MutableClock(START));
    AppNetworkBudgetReservation first =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    AppNetworkBudgetReservation denied =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);

    assertTrue(first.allowed());
    assertFalse(denied.allowed());
    assertEquals("trust_graph_import_concurrency_limited", denied.decision().errorCode());

    first.close();
    try (var allowed =
        service.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)) {
      assertTrue(allowed.allowed());
    }
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

  @Test
  void reserve_whenRateCapacityHeld_expectDeniedUntilUncommittedReservationReleased() {
    AppNetworkBudgetService service = service(config(1, 20, 4, 8), new MutableClock(START));
    var reservation =
        service.reserve("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    var denied = service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    var held = service.diagnostics();
    reservation.close();
    var released = service.diagnostics();
    var acquired =
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);

    assertTrue(reservation.allowed());
    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
    assertEquals(2, held.activeFamilyLeases());
    assertEquals(2, held.reservedFamilyRates());
    assertEquals(0, released.activeFamilyLeases());
    assertEquals(0, released.reservedFamilyRates());
    assertAllowed(acquired);
  }

  @Test
  void commit_whenReservationCrossesWindowAndNewWindowConsumed_expectDeniedWithoutOverbooking() {
    MutableClock clock = new MutableClock(START);
    AppNetworkBudgetService service = service(config(1, 20, 4, 8), clock);
    var reservation =
        service.reserve("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    clock.set(START.plusSeconds(60));
    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));

    var committed = reservation.commit();
    reservation.close();

    assertFalse(committed.allowed());
    assertEquals(START.plusSeconds(120), committed.nextAvailableAt());
    assertEquals(0, service.diagnostics().reservedFamilyRates());
    assertEquals(0, service.diagnostics().activeFamilyLeases());
    assertTrue(
        service.snapshots().stream()
            .allMatch(usage -> usage.windowStart().equals(START.plusSeconds(60))));
    assertTrue(service.snapshots().stream().allMatch(usage -> usage.count() == 1));
  }

  @Test
  void diagnostics_whenStoreEnumerationFails_expectUnavailableAndLegacyEmpty() throws IOException {
    AppNetworkBudgetStore store = mock(AppNetworkBudgetStore.class);
    when(store.listAll()).thenThrow(new IOException("private path"));
    when(store.observe(4096)).thenThrow(new IOException("private path"));
    AppNetworkBudgetService service =
        new AppNetworkBudgetService(store, config(2, 20, 1, 8), new MutableClock(START));

    var diagnostic = service.diagnostics();

    assertFalse(diagnostic.valid());
    assertTrue(diagnostic.usage().isEmpty());
    assertTrue(service.snapshots().isEmpty());
    assertFalse(service.observation().snapshot().toString().contains("private path"));
  }

  @Test
  void recreate_whenSameWindowHasActiveLease_expectPersistedRateAndResetConcurrency() {
    InMemoryAppNetworkBudgetStore store = new InMemoryAppNetworkBudgetStore();
    MutableClock clock = new MutableClock(START);
    AppNetworkBudgetService original =
        new AppNetworkBudgetService(store, config(2, 20, 1, 8), clock);
    var first = original.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    AppNetworkBudgetService recreated =
        new AppNetworkBudgetService(store, config(2, 20, 1, 8), clock);

    assertTrue(first.allowed());
    assertEquals(0, recreated.diagnostics().activeFamilyLeases());
    assertAllowed(
        recreated.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));
    var denied =
        recreated.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    first.lease().close();

    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
    assertEquals(0, original.diagnostics().activeFamilyLeases());
  }

  @Test
  void reserve_whenComposedFetchPrerequisiteDenied_expectImportNotChargedAndAllHoldsReleased() {
    AppNetworkBudgetService service = service(config(1, 1, 4, 8), new MutableClock(START));
    assertAllowed(service.acquire("other-app", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));

    try (var reserved =
        service.reserve("feed-reader", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)) {
      assertTrue(reserved.allowed());
      var fetch = service.acquire("feed-reader", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI);
      assertFalse(fetch.allowed());
      assertEquals("content_fetch_budget_exhausted", fetch.errorCode());
    }

    assertEquals(0, trustGraphImportCount(service, "feed-reader"));
    assertEquals(0, service.diagnostics().activeFamilyLeases());
    assertEquals(0, service.diagnostics().reservedFamilyRates());
  }

  @Test
  void
      observation_whenSubscriptionAndForegroundInterleave_expectCorrelatedFamilyWindowsAndScopes() {
    var budget = service(config(10, 20, 4, 8), new MutableClock(START));
    var subscription = budget.reserve("feed-reader", AppNetworkBudgetOperation.SUBSCRIPTION_POLL);
    var foreground =
        budget.acquire("control-app", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH);
    var committed = subscription.commit();
    foreground.lease().close();
    subscription.close();

    var events = budget.observation().snapshot().events();
    var charges =
        events.stream()
            .filter(event -> event.kind() == RuntimeWorkObservation.Kind.RATE_CHARGED)
            .toList();
    var subscriptionCharges =
        charges.stream()
            .filter(event -> event.operationId() == subscription.observationId())
            .toList();
    var released =
        events.stream()
            .filter(event -> event.kind() == RuntimeWorkObservation.Kind.BUDGET_RELEASED)
            .toList();

    assertTrue(committed.allowed());
    assertEquals(5, charges.size());
    assertEquals(3, subscriptionCharges.size());
    assertEquals(2, subscriptionCharges.stream().filter(event -> event.scope() == 1).count());
    assertEquals(1, subscriptionCharges.stream().filter(event -> event.scope() > 1).count());
    assertTrue(
        subscriptionCharges.stream()
            .allMatch(event -> event.windowStartEpochSecond() == START.getEpochSecond()));
    assertEquals(
        2,
        subscriptionCharges.stream()
            .filter(event -> event.operation() == AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL)
            .findFirst()
            .orElseThrow()
            .value());
    assertEquals(2, released.size());
    assertEquals(
        2, released.stream().map(RuntimeWorkObservation.Event::operationId).distinct().count());
    assertFalse(events.toString().contains("feed-reader"));
    assertFalse(events.toString().contains("control-app"));
  }

  @Test
  void diagnostics_whenLegacyListingSkipsCorruptFile_expectUnavailable(@TempDir Path directory)
      throws Exception {
    Files.createDirectories(directory.resolve("feed-reader"));
    Files.writeString(
        directory.resolve("feed-reader").resolve("foreground_content_fetch.properties"),
        "broken=true");
    var service =
        new AppNetworkBudgetService(
            new FileAppNetworkBudgetStore(directory), config(2, 20, 1, 8), new MutableClock(START));

    assertTrue(service.snapshots().isEmpty());
    assertFalse(service.diagnostics().valid());
  }

  @Test
  void observe_whenInspectionLimitExceeded_expectUnavailableRatherThanPartial(
      @TempDir Path directory) throws Exception {
    var store = new FileAppNetworkBudgetStore(directory);
    var service = new AppNetworkBudgetService(store, config(2, 20, 1, 8), new MutableClock(START));
    assertAllowed(
        service.acquire("feed-reader", AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH));

    assertThrows(IOException.class, () -> store.observe(1));
    assertEquals(2, store.observe(4).size());
  }

  @ParameterizedTest
  @CsvSource({"1,false", "1,true", "2,false", "2,true"})
  void acquire_whenImportFamilyWriteFails_expectConservativePersistedPrefix(
      int failedWrite, boolean afterWrite, @TempDir Path directory) throws Exception {
    assertWriteFailure(
        directory, failedWrite, afterWrite, false, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
  }

  @ParameterizedTest
  @CsvSource({"1,false", "1,true", "2,false", "2,true"})
  void commit_whenImportFamilyWriteFails_expectConservativePersistedPrefixAndCachedDenial(
      int failedWrite, boolean afterWrite, @TempDir Path directory) throws Exception {
    assertWriteFailure(
        directory, failedWrite, afterWrite, true, AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
  }

  @ParameterizedTest
  @CsvSource({"1,false", "1,true", "2,false", "2,true", "3,false", "3,true"})
  void acquire_whenSubscriptionFamilyWriteFails_expectConservativePersistedPrefix(
      int failedWrite, boolean afterWrite, @TempDir Path directory) throws Exception {
    assertWriteFailure(
        directory,
        failedWrite,
        afterWrite,
        false,
        AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH);
  }

  @ParameterizedTest
  @CsvSource({"1,false", "1,true", "2,false", "2,true"})
  void acquire_whenUriFetchFamilyWriteFails_expectConservativePersistedPrefix(
      int failedWrite, boolean afterWrite, @TempDir Path directory) throws Exception {
    assertWriteFailure(
        directory,
        failedWrite,
        afterWrite,
        false,
        AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI);
  }

  private static void assertWriteFailure(
      Path directory,
      int failedWrite,
      boolean afterWrite,
      boolean reserved,
      AppNetworkBudgetOperation operation)
      throws Exception {
    var durable = new FileAppNetworkBudgetStore(directory);
    var fault = new FaultStore(durable, failedWrite, afterWrite);
    var budget = new AppNetworkBudgetService(fault, config(10, 20, 4, 8), new MutableClock(START));
    AppNetworkBudgetDecision decision;
    if (reserved) {
      var reservation = budget.reserve("trust-graph", operation);
      assertTrue(reservation.allowed());
      decision = reservation.commit();
      assertSame(decision, reservation.commit());
      assertEquals(2, budget.diagnostics().activeFamilyLeases());
      assertEquals(0, budget.diagnostics().reservedFamilyRates());
      reservation.close();
      reservation.close();
      assertSame(decision, reservation.commit());
    } else {
      decision = budget.acquire("trust-graph", operation);
      decision.lease().close();
    }

    assertFalse(decision.allowed());
    assertEquals("network_budget_unavailable", decision.errorCode());
    assertEquals(failedWrite, fault.writes);
    assertEquals(0, budget.diagnostics().activeFamilyLeases());
    assertEquals(0, budget.diagnostics().reservedFamilyRates());
    var persisted = new FileAppNetworkBudgetStore(directory);
    boolean subscription = operation == AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH;
    boolean fetch = operation == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI;
    var family =
        subscription
            ? AppNetworkBudgetOperation.SUBSCRIPTION_POLL
            : fetch ? AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH : operation;
    var globalFamily = fetch ? AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL : family;
    int prefix = failedWrite - (afterWrite ? 0 : 1);
    assertEquals(
        prefix >= 1 ? 1 : 0,
        persisted.read("trust-graph", family).map(AppNetworkBudgetUsage::count).orElse(0));
    assertEquals(
        prefix >= 2 ? 1 : 0,
        persisted
            .read(AppNetworkBudgetScope.GLOBAL, globalFamily)
            .map(AppNetworkBudgetUsage::count)
            .orElse(0));
    assertEquals(
        (subscription && prefix >= 3) || (fetch && prefix >= 2) ? 1 : 0,
        persisted
            .read(AppNetworkBudgetScope.GLOBAL, AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL)
            .map(AppNetworkBudgetUsage::count)
            .orElse(0));
    var events = budget.observation().snapshot().events();
    assertEquals(
        failedWrite - 1,
        events.stream().filter(e -> e.kind() == RuntimeWorkObservation.Kind.RATE_CHARGED).count());
    assertTrue(
        events.stream().anyMatch(e -> e.kind() == RuntimeWorkObservation.Kind.STORE_UNAVAILABLE));
    assertFalse(
        events.stream().anyMatch(e -> e.kind() == RuntimeWorkObservation.Kind.BUDGET_COMMITTED));
    assertFalse(events.toString().contains("private-write-canary"));
  }

  @Test
  void commit_whenCloseCompetesDuringDurableWrite_expectOneChargeAndOneRelease() throws Exception {
    var entered = new CountDownLatch(1);
    var proceed = new CountDownLatch(1);
    var closeStarted = new CountDownLatch(1);
    var store =
        new FaultStore(new InMemoryAppNetworkBudgetStore(), 0, false) {
          @Override
          public void write(AppNetworkBudgetUsage usage) throws IOException {
            entered.countDown();
            try {
              if (!proceed.await(10, TimeUnit.SECONDS)) {
                throw new IOException("bounded test wait expired");
              }
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
              throw new IOException("bounded test interrupted", interrupted);
            }
            super.write(usage);
          }
        };
    var budget = new AppNetworkBudgetService(store, config(10, 20, 4, 8), new MutableClock(START));
    var reservation = budget.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
      var commit = executor.submit(reservation::commit);
      try {
        assertTrue(entered.await(10, TimeUnit.SECONDS));
        var close =
            executor.submit(
                () -> {
                  closeStarted.countDown();
                  reservation.close();
                });
        assertTrue(closeStarted.await(10, TimeUnit.SECONDS));
        proceed.countDown();
        var committed = commit.get(10, TimeUnit.SECONDS);
        close.get(10, TimeUnit.SECONDS);
        assertTrue(committed.allowed());
        assertSame(committed, reservation.commit());
        reservation.close();
      } finally {
        proceed.countDown();
      }
    }
    assertEquals(0, budget.diagnostics().activeFamilyLeases());
    assertEquals(0, budget.diagnostics().reservedFamilyRates());
    assertEquals(1, trustGraphImportCount(budget, "trust-graph"));
    assertEquals(1, trustGraphImportCount(budget, AppNetworkBudgetScope.GLOBAL));
    assertEquals(
        1,
        budget.observation().snapshot().events().stream()
            .filter(e -> e.kind() == RuntimeWorkObservation.Kind.BUDGET_RELEASED)
            .count());
  }

  @Test
  void
      commit_whenImportCrossesHourWithCompetingGlobalCharge_expectFetchRetainedAndOldHoldsReleased() {
    var clock = new MutableClock(START);
    var limits = new AppNetworkBudgetConfig(10, 20, 4, 8, 10, 10, 2, 4, 10, 1, 2, 4);
    var budget = service(limits, clock);
    var reservation = budget.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    assertAllowed(budget.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI));
    clock.set(START.plusSeconds(3600));
    assertAllowed(budget.acquire("other-app", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));

    var denied = reservation.commit();
    reservation.close();

    assertFalse(denied.allowed());
    assertEquals("trust_graph_import_budget_exhausted", denied.errorCode());
    assertEquals(0, trustGraphImportCount(budget, "trust-graph"));
    assertEquals(1, trustGraphImportCount(budget, AppNetworkBudgetScope.GLOBAL));
    assertEquals(0, budget.diagnostics().activeFamilyLeases());
    assertEquals(0, budget.diagnostics().reservedFamilyRates());
    var fetch =
        budget.snapshots().stream()
            .filter(row -> row.operation() == AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH)
            .findFirst()
            .orElseThrow();
    assertEquals(START, fetch.windowStart());
    assertEquals(1, fetch.count());
    assertTrue(
        budget.observation().snapshot().events().stream()
            .filter(e -> e.kind() == RuntimeWorkObservation.Kind.RATE_RESERVATION_RELEASED)
            .allMatch(e -> e.windowStartEpochSecond() == START.getEpochSecond()));
  }

  @Test
  void commit_whenImportCrossesHourWithoutCompetition_expectCurrentWindowCharge() {
    var clock = new MutableClock(START);
    var budget = service(config(10, 20, 4, 8), clock);
    var reservation = budget.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    clock.set(START.plusSeconds(3600));

    var committed = reservation.commit();
    reservation.close();

    assertTrue(committed.allowed());
    assertEquals(2, budget.diagnostics().usage().size());
    assertTrue(
        budget.diagnostics().usage().stream()
            .allMatch(
                row -> row.count() == 1 && row.windowStart().equals(START.plusSeconds(3600))));
    assertEquals(0, budget.diagnostics().reservedFamilyRates());
    assertEquals(0, budget.diagnostics().activeFamilyLeases());
  }

  @Test
  void recreate_whenFileBackedImportIsPending_expectDurableFetchAndResetTransientHolds(
      @TempDir Path directory) {
    var clock = new MutableClock(START);
    var limits = config(1, 20, 4, 8);
    var original =
        new AppNetworkBudgetService(new FileAppNetworkBudgetStore(directory), limits, clock);
    var pending = original.reserve("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT);
    var fetch = original.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI);
    assertTrue(fetch.allowed());
    var recovered =
        new AppNetworkBudgetService(new FileAppNetworkBudgetStore(directory), limits, clock);

    var denied = recovered.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT_URI);
    assertFalse(denied.allowed());
    assertEquals("content_fetch_budget_exhausted", denied.errorCode());
    assertEquals(0, recovered.diagnostics().activeFamilyLeases());
    assertEquals(0, recovered.diagnostics().reservedFamilyRates());
    assertEquals(0, trustGraphImportCount(recovered, "trust-graph"));
    assertAllowed(recovered.acquire("trust-graph", AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT));
    fetch.lease().close();
    pending.close();
    assertEquals(1, trustGraphImportCount(recovered, "trust-graph"));
  }

  private static class FaultStore implements AppNetworkBudgetStore {
    private final AppNetworkBudgetStore delegate;
    private final int failedWrite;
    private final boolean afterWrite;
    private int writes;

    private FaultStore(AppNetworkBudgetStore delegate, int failedWrite, boolean afterWrite) {
      this.delegate = delegate;
      this.failedWrite = failedWrite;
      this.afterWrite = afterWrite;
    }

    @Override
    public Optional<AppNetworkBudgetUsage> read(String appId, AppNetworkBudgetOperation operation)
        throws IOException {
      return delegate.read(appId, operation);
    }

    @Override
    public void write(AppNetworkBudgetUsage usage) throws IOException {
      writes++;
      if (writes == failedWrite && !afterWrite) {
        throw new IOException("private-write-canary");
      }
      delegate.write(usage);
      if (writes == failedWrite && afterWrite) {
        throw new IOException("private-write-canary");
      }
    }

    @Override
    public List<AppNetworkBudgetUsage> listAll() throws IOException {
      return delegate.listAll();
    }

    @Override
    public List<AppNetworkBudgetUsage> observe(int maximumEntries) throws IOException {
      return delegate.observe(maximumEntries);
    }
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

  private static int trustGraphImportCount(AppNetworkBudgetService service, String appId) {
    return service.snapshots().stream()
        .filter(snapshot -> snapshot.appId().equals(appId))
        .filter(snapshot -> snapshot.operation() == AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT)
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
