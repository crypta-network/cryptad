package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.InMemoryAppNetworkBudgetStore;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ContentSubscriptionServiceTest {
  private static final String APP_ID = "feed-reader";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");
  private static final String SOURCE = "crypta:USK@example/feed/7/feed.json";
  private static final String RUNTIME_SOURCE = "USK@example/feed/7/feed.json";
  private static final int GLOBAL_SUBSCRIPTION_LIMIT = 4;
  private static final int PER_TICK_FETCH_LIMIT = 2;
  private static final int CONTENT_FETCH_GLOBAL_PER_MINUTE = 100;
  private static final int SUBSCRIPTION_POLL_CONCURRENT_PER_APP = 1;

  @Test
  void create_whenSourceIsUsk_expectSafeScheduledSummary() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(2));

    Map<String, Object> summary = service.create(APP_ID, createParams(SOURCE));

    assertEquals(APP_ID, summary.get("appId"));
    assertEquals("Daily feed", summary.get("label"));
    assertEquals(SOURCE, summary.get("sourceUri"));
    assertEquals("USK", summary.get("normalizedSourceKind"));
    assertEquals("scheduled", summary.get("status"));
    assertEquals(5L, summary.get("pollIntervalSeconds"));
    assertEquals(256L, summary.get("maxBytes"));
    assertEquals(1000L, summary.get("timeoutMillis"));
    assertFalse(summary.toString().contains("/work/cryptad"));
  }

  @Test
  void create_whenSourceIsUnsupported_expectBadRequest() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(2));

    for (String source :
        List.of(
            "CHK@example",
            "SSK@example/feed",
            "KSK@example",
            "http://example.invalid/feed.json",
            "https://example.invalid/feed.json",
            "file:///tmp/feed.json",
            "/tmp/feed.json",
            "relative/feed.json",
            "USK@example/feed/7/feed.json?debug=true",
            "USK@example/feed/7/feed.json#fragment",
            "USK@example/feed with space/7/feed.json",
            "USK@example/feed/7/feed.json\nnext")) {
      Map<String, List<String>> parameters = createParams(source);

      PlatformApiException failure =
          assertThrows(PlatformApiException.class, () -> service.create(APP_ID, parameters));

      assertEquals(400, failure.statusCode(), source);
      assertEquals("unsupported_content_subscription_source", failure.errorCode(), source);
    }
  }

  @Test
  void create_whenLabelIsBlank_expectBadRequest() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(2));
    Map<String, List<String>> parameters =
        Map.of("label", List.of(" "), "uri", List.of(SOURCE), "pollIntervalSeconds", List.of("5"));

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.create(APP_ID, parameters));

    assertEquals(400, failure.statusCode());
    assertEquals("invalid_query_parameter", failure.errorCode());
  }

  @Test
  void create_whenPerAppLimitExceeded_expectTooManyRequests() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(1));
    service.create(APP_ID, createParams(SOURCE));
    Map<String, List<String>> parameters =
        createParams("USK@example/second/7/feed.json", "Second feed");

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.create(APP_ID, parameters));

    assertEquals(429, failure.statusCode());
    assertEquals("content_subscription_limit_exceeded", failure.errorCode());
  }

  @Test
  void refresh_whenContentMetadataChanges_expectDigestEditionAndDedupe() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    fetchPort.enqueue("first body", "USK@example/feed/7/feed.json");

    Map<String, Object> first = service.refresh(APP_ID, subscriptionId);

    assertEquals(1, fetchPort.calls);
    assertEquals(RUNTIME_SOURCE, fetchPort.lastRequest.uri());
    assertEquals(1, first.get("updateCount"));
    assertEquals(7L, first.get("lastSeenEdition"));
    assertEquals(10L, first.get("bytesLength"));
    assertEquals("USK@example/feed/7/feed.json", first.get("lastSeenResolvedUri"));
    assertEquals(64, ((String) first.get("contentSha256")).length());
    assertFalse(first.toString().contains("first body"));

    fetchPort.enqueue("first body", "USK@example/feed/7/feed.json");
    Map<String, Object> unchanged = service.refresh(APP_ID, subscriptionId);
    assertEquals(1, unchanged.get("updateCount"));

    fetchPort.enqueue("second body", "USK@example/feed/8/feed.json");
    Map<String, Object> changed = service.refresh(APP_ID, subscriptionId);
    assertEquals(2, changed.get("updateCount"));
    assertEquals(8L, changed.get("lastSeenEdition"));
  }

  @Test
  void refresh_whenFetchFails_expectStableRedactedFailureMetadata() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    fetchPort.enqueueTimeoutFailure();

    Map<String, Object> failed = service.refresh(APP_ID, subscriptionId);

    assertEquals("backoff", failed.get("status"));
    assertEquals(1, failed.get("failureCount"));
    assertEquals("content_fetch_timeout", failed.get("lastErrorCode"));
    assertEquals("Subscription fetch failed.", failed.get("message"));
    assertFalse(failed.toString().contains("/tmp/secret"));
  }

  @Test
  void refresh_whenSubscriptionBudgetExhausted_expectSafeStatusWithoutFetch() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2), subscriptionBudget(1));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    fetchPort.enqueue("first body", "USK@example/feed/7/feed.json");
    service.refresh(APP_ID, subscriptionId);

    Map<String, Object> denied = service.refresh(APP_ID, subscriptionId);

    assertEquals(1, fetchPort.calls);
    assertEquals("budget_exhausted", denied.get("status"));
    assertEquals("content_subscription_budget_exhausted", denied.get("lastErrorCode"));
    assertEquals("Content subscription network budget is exhausted.", denied.get("message"));
    assertFalse(denied.toString().contains("first body"));
  }

  @Test
  void schedulerPoll_whenSubscriptionBudgetExhausted_expectNoFetch() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    AppNetworkBudgetService budget = subscriptionBudget(1);
    ContentSubscriptionService service = service(fetchPort, config(2), budget);
    service.create(APP_ID, createParams(SOURCE));
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    budget.acquire(APP_ID, AppNetworkBudgetOperation.SUBSCRIPTION_POLL).lease().close();

    ContentSubscription result = service.schedulerPoll(snapshot, NOW);

    assertEquals(ContentSubscriptionStatus.BUDGET_EXHAUSTED, result.status());
    assertEquals("content_subscription_budget_exhausted", result.lastErrorCode());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void refresh_whenFetchThrows_expectBudgetLeaseReleasedForNextRefresh() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2), subscriptionBudget(10));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    fetchPort.enqueueTimeoutFailure();

    Map<String, Object> failed = service.refresh(APP_ID, subscriptionId);
    fetchPort.enqueue("second body", "USK@example/feed/8/feed.json");
    Map<String, Object> succeeded = service.refresh(APP_ID, subscriptionId);

    assertEquals("backoff", failed.get("status"));
    assertEquals("success", succeeded.get("status"));
    assertEquals(2, fetchPort.calls);
  }

  @Test
  void refresh_whenRunningStateWriteFails_expectBudgetReservedUntilNextRefresh() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    FailingWriteContentSubscriptionStore store = new FailingWriteContentSubscriptionStore();
    ContentSubscriptionService service =
        service(store, fetchPort, config(2), subscriptionBudget(1));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    store.failNextWrite();

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> service.refresh(APP_ID, subscriptionId));
    fetchPort.enqueue("second body", "USK@example/feed/8/feed.json");
    Map<String, Object> succeeded = service.refresh(APP_ID, subscriptionId);

    assertEquals(503, failure.statusCode());
    assertEquals("content_subscription_store_failed", failure.errorCode());
    assertEquals("success", succeeded.get("status"));
    assertEquals(1, fetchPort.calls);
  }

  @Test
  void schedulerPoll_whenSubscriptionDeletedAfterTickSnapshot_expectNoFetchOrResurrection() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    service.delete(APP_ID, subscriptionId);

    ContentSubscription result = service.schedulerPoll(snapshot, NOW);

    assertEquals(ContentSubscriptionStatus.DELETED, result.status());
    assertEquals(0, fetchPort.calls);
    assertTrue(service.list(APP_ID).isEmpty());
  }

  @Test
  void schedulerPoll_whenManualRefreshAlreadyMovedDueTime_expectNoSecondFetch() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    fetchPort.enqueue("first body", "USK@example/feed/7/feed.json");
    service.refresh(APP_ID, subscriptionId);
    fetchPort.enqueue("second body", "USK@example/feed/8/feed.json");

    ContentSubscription result = service.schedulerPoll(snapshot, NOW);

    assertEquals(ContentSubscriptionStatus.SUCCESS, result.status());
    assertEquals(1, fetchPort.calls);
    assertEquals(1, service.list(APP_ID).getFirst().get("updateCount"));
    assertEquals(7L, result.lastSeenEdition());
  }

  @Test
  void schedulerSkip_whenSubscriptionDeletedAfterTickSnapshot_expectNoResurrection() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    service.delete(APP_ID, subscriptionId);

    ContentSubscription result =
        service.schedulerSkip(
            snapshot,
            NOW,
            ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
            "runtime_unavailable",
            "Skipped.");

    assertEquals(ContentSubscriptionStatus.DELETED, result.status());
    assertTrue(service.list(APP_ID).isEmpty());
  }

  @Test
  void schedulerSkip_whenSubscriptionPausedAfterTickSnapshot_expectPausedStatePreserved() {
    ContentSubscriptionService service = service(new RecordingFetchPort(), config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    service.pause(APP_ID, subscriptionId);

    ContentSubscription result =
        service.schedulerSkip(
            snapshot,
            NOW,
            ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
            "runtime_unavailable",
            "Skipped.");

    assertEquals(ContentSubscriptionStatus.PAUSED, result.status());
    assertFalse(result.enabled());
    assertEquals(
        ContentSubscriptionStatus.PAUSED.jsonValue(),
        service.list(APP_ID).getFirst().get("status"));
  }

  @Test
  void schedulerSkip_whenManualRefreshAlreadyMovedDueTime_expectFreshSuccessPreserved() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort, config(2));
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE)).get("subscriptionId");
    ContentSubscription snapshot = service.listAllForScheduler().getFirst();
    fetchPort.enqueue("first body", "USK@example/feed/7/feed.json");
    service.refresh(APP_ID, subscriptionId);

    ContentSubscription result =
        service.schedulerSkip(
            snapshot,
            NOW,
            ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
            "runtime_unavailable",
            "Skipped.");

    assertEquals(ContentSubscriptionStatus.SUCCESS, result.status());
    assertEquals(0, result.failureCount());
    assertNull(result.lastErrorCode());
    assertEquals(
        ContentSubscriptionStatus.SUCCESS.jsonValue(),
        service.list(APP_ID).getFirst().get("status"));
  }

  private static ContentSubscriptionService service(
      RecordingFetchPort fetchPort, ContentSubscriptionSchedulerConfig config) {
    return service(fetchPort, config, null);
  }

  private static ContentSubscriptionService service(
      RecordingFetchPort fetchPort,
      ContentSubscriptionSchedulerConfig config,
      AppNetworkBudgetService budgetService) {
    return service(new InMemoryContentSubscriptionStore(), fetchPort, config, budgetService);
  }

  private static ContentSubscriptionService service(
      ContentSubscriptionStore store,
      RecordingFetchPort fetchPort,
      ContentSubscriptionSchedulerConfig config,
      AppNetworkBudgetService budgetService) {
    return new ContentSubscriptionService(
        store, fetchPort, config, budgetService, Clock.fixed(NOW, ZoneOffset.UTC), new Random(0));
  }

  private static AppNetworkBudgetService subscriptionBudget(int subscriptionPerAppPerHour) {
    return new AppNetworkBudgetService(
        new InMemoryAppNetworkBudgetStore(),
        new AppNetworkBudgetConfig(
            20,
            CONTENT_FETCH_GLOBAL_PER_MINUTE,
            2,
            16,
            subscriptionPerAppPerHour,
            1024,
            SUBSCRIPTION_POLL_CONCURRENT_PER_APP,
            8,
            120,
            1024,
            1,
            8),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static Map<String, List<String>> createParams(String source) {
    return createParams(source, "Daily feed");
  }

  private static Map<String, List<String>> createParams(String source, String label) {
    return Map.of(
        "label",
        List.of(label),
        "uri",
        List.of(source),
        "pollIntervalSeconds",
        List.of("5"),
        "maxBytes",
        List.of("256"),
        "timeoutMillis",
        List.of("1000"));
  }

  static ContentSubscriptionSchedulerConfig config(int perAppLimit) {
    return new ContentSubscriptionSchedulerConfig(
        true,
        Duration.ZERO,
        Duration.ofSeconds(1),
        Duration.ofSeconds(10),
        Duration.ofSeconds(5),
        Duration.ofHours(1),
        Duration.ZERO,
        Duration.ofSeconds(5),
        Duration.ofSeconds(30),
        perAppLimit,
        GLOBAL_SUBSCRIPTION_LIMIT,
        PER_TICK_FETCH_LIMIT,
        256L,
        1024L,
        Duration.ofSeconds(1),
        Duration.ofSeconds(5));
  }

  static final class RecordingFetchPort implements ContentFetchPort {
    private final ArrayDeque<Object> results = new ArrayDeque<>();
    private int calls;
    private BoundedContentFetchRequest lastRequest;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
        throws ContentFetchException {
      calls++;
      lastRequest = request;
      assertNotNull(request);
      Object next = results.removeFirst();
      if (next instanceof ContentFetchException failure) {
        throw failure;
      }
      return (BoundedContentFetchResult) next;
    }

    void enqueue(String body, String resolvedUri) {
      results.addLast(
          new BoundedContentFetchResult(
              body.getBytes(StandardCharsets.UTF_8), RUNTIME_SOURCE, resolvedUri, "ok"));
    }

    void enqueueTimeoutFailure() {
      results.addLast(
          new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_TIMEOUT, "timeout below /tmp/secret/feed.json"));
    }
  }

  static final class FailingWriteContentSubscriptionStore implements ContentSubscriptionStore {
    private final InMemoryContentSubscriptionStore delegate =
        new InMemoryContentSubscriptionStore();
    private boolean failNextWrite;

    void failNextWrite() {
      failNextWrite = true;
    }

    @Override
    public List<ContentSubscription> listForApp(String appId) {
      return delegate.listForApp(appId);
    }

    @Override
    public List<ContentSubscription> listAll() {
      return delegate.listAll();
    }

    @Override
    public Optional<ContentSubscription> read(String appId, String subscriptionId) {
      return delegate.read(appId, subscriptionId);
    }

    @Override
    public void write(ContentSubscription subscription) throws IOException {
      if (failNextWrite) {
        failNextWrite = false;
        throw new IOException("simulated subscription store failure below /tmp/secret");
      }
      delegate.write(subscription);
    }

    @Override
    public boolean delete(String appId, String subscriptionId) {
      return delegate.delete(appId, subscriptionId);
    }

    @Override
    public void deleteAllForApp(String appId) {
      delegate.deleteAllForApp(appId);
    }
  }
}
