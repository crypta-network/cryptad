package network.crypta.platform.api;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Objects;

/**
 * Bounded process-local audit log for app-originated Platform API decisions.
 *
 * <p>The log is intentionally in-memory only. It keeps the most recent {@link #DEFAULT_CAPACITY}
 * events by default and drops the oldest entries when full.
 *
 * <p>This type is owned by a {@link PlatformApiRouter} instance and is not a durable compliance
 * store. It exists to give the Web Shell and Apps API a recent, token-free view of capability
 * enforcement for currently managed apps. All mutating and snapshot methods synchronize on the log
 * instance, so callers can record and read from different request threads without seeing partial
 * updates. The trade-off is simple bounded retention rather than persistence, indexing, or
 * cross-process aggregation.
 */
public final class AppAuditLog {
  /**
   * Default maximum number of audit events retained by one router instance.
   *
   * <p>The value is intentionally small enough for cheap in-memory snapshots while still giving
   * operators useful recent context. Older events are discarded silently when this bound is
   * exceeded.
   */
  public static final int DEFAULT_CAPACITY = 512;

  /**
   * Default number of recent events returned for one app through the Apps API.
   *
   * <p>The Apps API uses this value for per-app detail views so the browser receives a concise
   * recent-history slice instead of the full process-local ring buffer.
   */
  public static final int DEFAULT_APP_EVENT_LIMIT = 25;

  private final int capacity;
  private final Clock clock;
  private final Deque<AppAuditEvent> events = new ArrayDeque<>();

  /**
   * Creates an audit log using the default capacity and system UTC clock.
   *
   * <p>This constructor is the normal production path. Tests that need deterministic timestamps can
   * use the explicit constructor with a fixed {@link Clock}.
   */
  public AppAuditLog() {
    this(DEFAULT_CAPACITY, Clock.systemUTC());
  }

  /**
   * Creates an audit log with an explicit capacity and clock.
   *
   * <p>The supplied capacity applies to the whole log, not to each app. When the log is full,
   * recording one more event removes the oldest retained event regardless of app id. This keeps
   * memory use fixed and predictable for long-running daemons.
   *
   * @param capacity maximum retained events across all app principals
   * @param clock event timestamp source used when router decisions are recorded
   * @throws IllegalArgumentException if {@code capacity} is zero or negative
   */
  public AppAuditLog(int capacity, Clock clock) {
    if (capacity <= 0) {
      throw new IllegalArgumentException("capacity must be positive");
    }
    this.capacity = capacity;
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Appends one completed authorization decision.
   *
   * <p>The event is appended to the newest end of the log. If appending exceeds the configured
   * capacity, the oldest retained events are dropped until the bound is restored. The method stores
   * the already constructed event as a value object; callers should build events without raw
   * tokens, request bodies, or local filesystem paths.
   *
   * @param event token-free audit event to append to the bounded log
   */
  public synchronized void append(AppAuditEvent event) {
    events.addLast(Objects.requireNonNull(event, "event"));
    while (events.size() > capacity) {
      events.removeFirst();
    }
  }

  /**
   * Appends an app-originated router decision.
   *
   * <p>Host/operator requests are ignored because this log is scoped to app-originated security
   * decisions. For app principals, the method builds a token-free event from the request principal,
   * selected action, HTTP-style status, and stable reason code. If no action is available, it falls
   * back to an unmapped route label so denied default-deny cases are still visible.
   *
   * @param request authenticated request metadata already stripped of raw credentials
   * @param authorization capability decision produced before endpoint dispatch
   * @param decision audit decision to record for the app-originated request
   * @param statusCode HTTP-style status code returned to the caller
   * @param reasonCode stable machine-readable reason for the decision
   */
  void appendDecision(
      PlatformApiRequest request,
      PlatformApiAuthorizationDecision authorization,
      AppAuditDecision decision,
      int statusCode,
      String reasonCode) {
    if (!request.principal().isApp()) {
      return;
    }
    PlatformApiAction action =
        authorization.optionalAction().orElseGet(() -> fallbackAction(request));
    append(
        new AppAuditEvent(
            Instant.now(clock),
            request.principal().appId(),
            request.method(),
            action.endpointFamily(),
            action.label(),
            action.requiredCapabilities(),
            decision,
            statusCode,
            reasonCode));
  }

  /**
   * Returns recent events for one app in newest-first order.
   *
   * <p>The method scans the bounded log from newest to oldest and returns only events whose app id
   * exactly matches the supplied id. A non-positive limit returns an empty list. The returned list
   * is an immutable snapshot; subsequent log writes do not change it.
   *
   * @param appId normalized app id to match against retained events
   * @param limit maximum number of matching events to return
   * @return immutable newest-first event snapshot for the requested app
   */
  public synchronized List<AppAuditEvent> recentForApp(String appId, int limit) {
    Objects.requireNonNull(appId, "appId");
    if (limit <= 0) {
      return List.of();
    }
    ArrayList<AppAuditEvent> matches = new ArrayList<>(Math.min(limit, events.size()));
    var descending = events.descendingIterator();
    while (descending.hasNext() && matches.size() < limit) {
      AppAuditEvent event = descending.next();
      if (appId.equals(event.appId())) {
        matches.add(event);
      }
    }
    return List.copyOf(matches);
  }

  /**
   * Counts currently retained denied decisions for one app.
   *
   * <p>The count is derived only from events that still fit inside the bounded log. It is intended
   * for recent operator context in app cards, not as an all-time denied-request counter.
   *
   * @param appId normalized app id to match against retained events
   * @return denied event count within the current bounded in-memory log
   */
  public synchronized long deniedCountForApp(String appId) {
    Objects.requireNonNull(appId, "appId");
    return events.stream()
        .filter(event -> appId.equals(event.appId()))
        .filter(event -> event.decision() == AppAuditDecision.DENIED)
        .count();
  }

  synchronized int size() {
    return events.size();
  }

  private static PlatformApiAction fallbackAction(PlatformApiRequest request) {
    List<String> segments = request.pathSegments();
    String endpointFamily = segments.isEmpty() ? "unknown" : segments.getFirst();
    return PlatformApiAction.of(endpointFamily, endpointFamily + ".unmapped", List.of("unmapped"));
  }
}
