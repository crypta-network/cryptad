package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Shared deterministic app-network budget service.
 *
 * <p>The service combines durable fixed-window rate counters with process-local concurrency
 * counters. It is intentionally small and JDK-only: callers ask for a decision before starting a
 * network-initiating operation and close the returned lease in a {@code finally} block or
 * try-with-resources. Durable records contain only safe app ids, operation labels, counts, decision
 * labels, and timestamps.
 *
 * <p>The service is synchronized because each decision may read counters, check active leases,
 * update durable metadata, and return a lease whose close action later releases process-local
 * counts. Rate counters are durable fixed windows; concurrency counters are deliberately in-process
 * and reset when the node restarts. That trade-off keeps normal routing cheap while still
 * preventing long-lived app workflows from bypassing foreground content-fetch, subscription, and
 * Trust Graph import limits.
 *
 * <p>Several operations charge more than one budget family. Subscription polls and manual refreshes
 * charge subscription limits and the global content-fetch family. Trust Graph import by URI charges
 * Trust Graph import budget in the handler and content-fetch budget through the content fetch
 * operation. Store failures fail closed with safe metadata instead of resetting quota.
 */
public final class AppNetworkBudgetService {
  private static final String GLOBAL_SCOPE_ID = AppNetworkBudgetScope.GLOBAL;
  private static final Duration MINUTE_WINDOW = Duration.ofMinutes(1);
  private static final Duration HOUR_WINDOW = Duration.ofHours(1);

  private final AppNetworkBudgetStore store;
  private final AppNetworkBudgetConfig config;
  private final Clock clock;
  private final Map<String, Integer> activeLeases = new LinkedHashMap<>();

  /**
   * Creates a service using the system UTC clock.
   *
   * <p>Production runtime wiring normally uses this constructor with a file-backed store beneath
   * the app-platform data directory. The service reads the clock only while evaluating decisions,
   * so the instance can be shared by content routes, subscription services, and Trust Graph routes.
   *
   * @param store durable safe counter store used for fixed-window rate records
   * @param config finite budget configuration used for every decision
   */
  public AppNetworkBudgetService(AppNetworkBudgetStore store, AppNetworkBudgetConfig config) {
    this(store, config, Clock.systemUTC());
  }

  /**
   * Creates a service with deterministic time for tests.
   *
   * <p>Tests and deterministic offline certification checks use this constructor to advance fixed
   * windows without sleeping. The supplied store is still authoritative for rate counters, while
   * active leases remain process-local state inside this service instance.
   *
   * @param store durable safe counter store used for fixed-window rate records
   * @param config finite budget configuration used for every decision
   * @param clock clock used for fixed-window boundaries and decision timestamps
   */
  public AppNetworkBudgetService(
      AppNetworkBudgetStore store, AppNetworkBudgetConfig config, Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Attempts to acquire budget for one app operation.
   *
   * <p>Denied decisions fail closed with a safe status and message. Store read/write failures
   * return a service-unavailable decision rather than leaking path or exception details.
   *
   * <p>Callers must request budget after validating app-facing source strings and bounds, but
   * before invoking runtime network ports. If the returned decision is allowed, callers must close
   * the lease after the bounded network work completes or fails. If the decision is denied, callers
   * should surface only its stable status, error code, message, and retry timestamp.
   *
   * @param appId authenticated app id or reserved internal scope to charge
   * @param operation requested network operation and budget family
   * @return allowed decision with a closeable lease or denied decision with safe failure metadata
   */
  public synchronized AppNetworkBudgetDecision acquire(
      String appId, AppNetworkBudgetOperation operation) {
    String normalizedAppId = AppNetworkBudgetScope.normalize(appId);
    AppNetworkBudgetOperation checkedOperation = Objects.requireNonNull(operation, "operation");
    Instant now = clock.instant();
    List<RateLimit> rateLimits = rateLimits(normalizedAppId, checkedOperation);
    List<ConcurrencyLimit> concurrencyLimits = concurrencyLimits(normalizedAppId, checkedOperation);
    try {
      AppNetworkBudgetDecision concurrencyDecision =
          concurrencyDecision(normalizedAppId, checkedOperation, now, concurrencyLimits);
      if (!concurrencyDecision.allowed()) {
        recordConcurrencyDenial(normalizedAppId, checkedOperation, now, rateLimits);
        return concurrencyDecision;
      }
      AppNetworkBudgetDecision rateDecision =
          rateDecision(normalizedAppId, checkedOperation, now, rateLimits);
      if (!rateDecision.allowed()) {
        return rateDecision;
      }
      for (RateLimit limit : rateLimits) {
        store.write(usage(limit, now).allowedAt(now));
      }
      for (ConcurrencyLimit limit : concurrencyLimits) {
        activeLeases.merge(limit.key(), 1, Integer::sum);
      }
      return AppNetworkBudgetDecision.allowed(
          normalizedAppId,
          checkedOperation,
          now,
          new AppNetworkBudgetLease(() -> release(concurrencyLimits)));
    } catch (IOException _) {
      return AppNetworkBudgetDecision.denied(
          503,
          normalizedAppId,
          checkedOperation,
          "network_budget_unavailable",
          "App network budget service is unavailable.",
          now,
          null);
    }
  }

  /**
   * Returns safe snapshots for currently stored counters.
   *
   * <p>Snapshots are intended for operator diagnostics and release evidence. They expose normalized
   * app ids, operation labels, counts, configured limits, timestamps, and stable decision labels
   * only. If the store cannot enumerate records, the method returns an empty list rather than
   * leaking an exception or filesystem detail.
   *
   * @return deterministic safe snapshots sorted by app id and operation label
   */
  public synchronized List<AppNetworkBudgetSnapshot> snapshots() {
    try {
      return store.listAll().stream()
          .map(this::snapshotFor)
          .sorted(
              Comparator.comparing(AppNetworkBudgetSnapshot::appId)
                  .thenComparing(snapshot -> snapshot.operation().jsonValue()))
          .toList();
    } catch (IOException _) {
      return List.of();
    }
  }

  private AppNetworkBudgetSnapshot snapshotFor(AppNetworkBudgetUsage usage) {
    return new AppNetworkBudgetSnapshot(
        usage.appId(),
        usage.operation(),
        usage.windowStart(),
        usage.window().toSeconds(),
        usage.count(),
        configuredLimit(usage.appId(), usage.operation()),
        usage.lastDecisionAt(),
        usage.lastDecision(),
        usage.nextAvailableAt());
  }

  private AppNetworkBudgetDecision concurrencyDecision(
      String appId,
      AppNetworkBudgetOperation operation,
      Instant now,
      List<ConcurrencyLimit> concurrencyLimits) {
    for (ConcurrencyLimit limit : concurrencyLimits) {
      if (activeLeases.getOrDefault(limit.key(), 0) >= limit.limit()) {
        return AppNetworkBudgetDecision.denied(
            429,
            appId,
            operation,
            concurrencyErrorCode(operation),
            concurrencyMessage(operation),
            now,
            null);
      }
    }
    return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
  }

  private AppNetworkBudgetDecision rateDecision(
      String appId, AppNetworkBudgetOperation operation, Instant now, List<RateLimit> rateLimits)
      throws IOException {
    for (RateLimit limit : rateLimits) {
      AppNetworkBudgetUsage usage = usage(limit, now);
      if (usage.count() >= limit.limit()) {
        Instant nextAvailableAt = usage.windowStart().plus(usage.window());
        store.write(usage.deniedAt(now, "rate_limited", nextAvailableAt));
        return AppNetworkBudgetDecision.denied(
            429,
            appId,
            operation,
            rateErrorCode(operation),
            rateMessage(operation),
            now,
            nextAvailableAt);
      }
    }
    return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
  }

  private AppNetworkBudgetUsage usage(RateLimit limit, Instant now) throws IOException {
    Instant windowStart = truncate(now, limit.window());
    return store
        .read(limit.appId(), limit.operation())
        .orElseGet(
            () ->
                AppNetworkBudgetUsage.empty(
                    limit.appId(), limit.operation(), windowStart, limit.window()))
        .inWindow(windowStart, limit.window());
  }

  private void recordConcurrencyDenial(
      String appId, AppNetworkBudgetOperation operation, Instant now, List<RateLimit> rateLimits)
      throws IOException {
    for (RateLimit limit : rateLimits) {
      if (limit.appId().equals(appId) && limit.operation() == operation) {
        store.write(usage(limit, now).deniedAt(now, "concurrency_limited", null));
        return;
      }
    }
  }

  private synchronized void release(List<ConcurrencyLimit> limits) {
    for (ConcurrencyLimit limit : limits) {
      activeLeases.computeIfPresent(limit.key(), (_, count) -> count <= 1 ? null : count - 1);
    }
  }

  private List<RateLimit> rateLimits(String appId, AppNetworkBudgetOperation operation) {
    ArrayList<RateLimit> limits = new ArrayList<>();
    switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                MINUTE_WINDOW,
                config.foregroundContentFetchPerAppPerMinute()));
        limits.add(contentFetchGlobalRateLimit());
      }
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                HOUR_WINDOW,
                config.subscriptionPollPerAppPerHour()));
        limits.add(
            new RateLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                HOUR_WINDOW,
                config.subscriptionPollGlobalPerHour()));
        limits.add(contentFetchGlobalRateLimit());
      }
      case TRUST_GRAPH_IMPORT -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                HOUR_WINDOW,
                config.trustGraphImportPerAppPerHour()));
        limits.add(
            new RateLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                HOUR_WINDOW,
                config.trustGraphImportGlobalPerHour()));
      }
      case CONTENT_FETCH_GLOBAL -> limits.add(contentFetchGlobalRateLimit());
    }
    return limits;
  }

  private List<ConcurrencyLimit> concurrencyLimits(
      String appId, AppNetworkBudgetOperation operation) {
    ArrayList<ConcurrencyLimit> limits = new ArrayList<>();
    switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                config.foregroundContentFetchConcurrentPerApp()));
        limits.add(contentFetchGlobalConcurrencyLimit());
      }
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                config.subscriptionPollConcurrentPerApp()));
        limits.add(
            new ConcurrencyLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                config.subscriptionPollConcurrentGlobal()));
        limits.add(contentFetchGlobalConcurrencyLimit());
      }
      case TRUST_GRAPH_IMPORT -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                config.trustGraphImportConcurrentPerApp()));
        limits.add(
            new ConcurrencyLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                config.trustGraphImportConcurrentGlobal()));
      }
      case CONTENT_FETCH_GLOBAL -> limits.add(contentFetchGlobalConcurrencyLimit());
    }
    return limits;
  }

  private RateLimit contentFetchGlobalRateLimit() {
    return new RateLimit(
        GLOBAL_SCOPE_ID,
        AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL,
        MINUTE_WINDOW,
        config.foregroundContentFetchGlobalPerMinute());
  }

  private ConcurrencyLimit contentFetchGlobalConcurrencyLimit() {
    return new ConcurrencyLimit(
        GLOBAL_SCOPE_ID,
        AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL,
        config.foregroundContentFetchConcurrentGlobal());
  }

  private int configuredLimit(String appId, AppNetworkBudgetOperation operation) {
    boolean global = AppNetworkBudgetScope.GLOBAL.equals(appId);
    return switch (operation) {
      case FOREGROUND_CONTENT_FETCH -> config.foregroundContentFetchPerAppPerMinute();
      case CONTENT_FETCH_GLOBAL, TRUST_GRAPH_IMPORT_URI ->
          config.foregroundContentFetchGlobalPerMinute();
      case SUBSCRIPTION_POLL ->
          global ? config.subscriptionPollGlobalPerHour() : config.subscriptionPollPerAppPerHour();
      case SUBSCRIPTION_MANUAL_REFRESH -> config.subscriptionPollPerAppPerHour();
      case TRUST_GRAPH_IMPORT ->
          global ? config.trustGraphImportGlobalPerHour() : config.trustGraphImportPerAppPerHour();
    };
  }

  private static Instant truncate(Instant now, Duration window) {
    long seconds = window.toSeconds();
    long epochSecond = now.getEpochSecond();
    return Instant.ofEpochSecond(Math.floorDiv(epochSecond, seconds) * seconds);
  }

  private static String rateErrorCode(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI, CONTENT_FETCH_GLOBAL ->
          "content_fetch_budget_exhausted";
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "content_subscription_budget_exhausted";
      case TRUST_GRAPH_IMPORT -> "trust_graph_import_budget_exhausted";
    };
  }

  private static String concurrencyErrorCode(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "content_subscription_concurrency_limited";
      case TRUST_GRAPH_IMPORT -> "trust_graph_import_concurrency_limited";
      default -> "network_budget_concurrency_limited";
    };
  }

  private static String rateMessage(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "Content subscription network budget is exhausted.";
      case TRUST_GRAPH_IMPORT -> "Trust Graph import budget is exhausted.";
      default -> "Content fetch budget is exhausted.";
    };
  }

  private static String concurrencyMessage(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "Content subscription network budget concurrency is exhausted.";
      case TRUST_GRAPH_IMPORT -> "Trust Graph import concurrency budget is exhausted.";
      default -> "App network budget concurrency is exhausted.";
    };
  }

  private record RateLimit(
      String appId, AppNetworkBudgetOperation operation, Duration window, int limit) {}

  private record ConcurrencyLimit(String appId, AppNetworkBudgetOperation operation, int limit) {
    String key() {
      return AppNetworkBudgetScope.normalize(appId) + '\n' + operation.jsonValue();
    }
  }
}
