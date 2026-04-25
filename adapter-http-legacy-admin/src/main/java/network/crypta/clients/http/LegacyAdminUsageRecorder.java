package network.crypta.clients.http;

import java.time.Clock;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.LegacyAdminUsageSnapshot;

/**
 * Thread-safe process-local usage recorder for legacy admin HTTP surfaces.
 *
 * <p>The recorder is bounded by {@link LegacyAdminRetirementRegistry}. It only counts known surface
 * ids and records the latest observation time. It does not persist data and does not store request
 * parameters, bodies, peer references, URIs, filesystem paths, or remote addresses.
 *
 * <p>The legacy HTTP adapter records a visit only after a request has passed the container-level
 * gates and produced an accepted response. This class assumes that policy decision has already
 * happened; it only maps the supplied path or surface to a bounded counter. The resulting snapshot
 * is useful for retirement planning because it answers which fallback pages are still exercised
 * during the current process lifetime without becoming an audit log.
 *
 * <p>Instances are safe for concurrent request threads. Counts and timestamps are maintained with
 * atomic fields, and snapshots include every diagnostic surface whether it has been observed or
 * not. Counters are intentionally reset on process restart and are not written to disk.
 *
 * @see LegacyAdminUsagePort
 * @see LegacyAdminUsageSnapshot
 */
public final class LegacyAdminUsageRecorder implements LegacyAdminUsagePort {
  private static final LegacyAdminUsageRecorder DEFAULT =
      new LegacyAdminUsageRecorder(Clock.systemUTC());

  private final Clock clock;
  private final ConcurrentMap<String, Counter> counters = new ConcurrentHashMap<>();

  /**
   * Creates a recorder using the supplied clock.
   *
   * <p>The constructor is package-private so focused tests can inject a fixed clock while
   * production code uses {@link #defaultRecorder()}. The recorder does not retain request context;
   * the clock is only sampled when a tracked observation is accepted.
   *
   * @param clock clock used to timestamp observations in epoch milliseconds
   */
  LegacyAdminUsageRecorder(Clock clock) {
    this.clock = clock;
  }

  /**
   * Returns the process-wide recorder used by the legacy HTTP adapter.
   *
   * <p>The shared recorder is intentionally process-local. All legacy admin requests in the current
   * JVM contribute to this instance, and diagnostics reads expose its current counters. Restarting
   * the node starts a fresh telemetry window.
   *
   * @return shared recorder instance for the running node process
   */
  public static LegacyAdminUsageRecorder defaultRecorder() {
    return DEFAULT;
  }

  /**
   * Records a visit by request path when the path belongs to a tracked legacy-admin surface.
   *
   * <p>The path should be the local request path after authorization decisions have completed and
   * before any query string is considered. Unknown paths, blank input, retained infrastructure
   * helpers, and registry entries excluded from diagnostics are ignored. Callers that already
   * resolved a surface should prefer {@link #recordSurface(LegacyAdminSurface)} so internal
   * redirects do not change the attribution.
   *
   * @param requestPath local request path without query string or fragment
   */
  public void recordPath(String requestPath) {
    LegacyAdminRetirementRegistry.findByLegacyPath(requestPath).ifPresent(this::recordSurface);
  }

  /**
   * Records a visit for one registry surface when diagnostics include that surface.
   *
   * <p>The method increments only surfaces whose metadata opts into usage diagnostics. It uses the
   * stable surface id as the counter key, so multiple paths that resolve to the same surface are
   * aggregated. Timestamps are monotonic with respect to the supplied clock value for each counter;
   * concurrent observations cannot move a surface's latest-seen value backward.
   *
   * @param surface surface metadata resolved by the registry before recording
   */
  public void recordSurface(LegacyAdminSurface surface) {
    if (!surface.includeInUsageDiagnostics()) {
      return;
    }
    Counter counter = counters.computeIfAbsent(surface.id(), _ -> new Counter());
    counter.increment(clock.millis());
  }

  /** Clears all counters. Intended for focused tests. */
  void clear() {
    counters.clear();
  }

  /**
   * Returns a point-in-time view of all diagnostic legacy admin surfaces.
   *
   * <p>The snapshot preserves registry order and includes zero-count entries for surfaces that have
   * not been observed. This keeps Platform API responses structurally stable and lets callers
   * distinguish "known but unused since startup" from "not part of the retirement map."
   *
   * @return immutable snapshot containing one entry per diagnostic surface
   */
  @Override
  public LegacyAdminUsageSnapshot snapshot() {
    List<LegacyAdminSurfaceUsage> surfaces =
        LegacyAdminRetirementRegistry.diagnosticSurfaces().stream()
            .map(this::usageForSurface)
            .toList();
    return new LegacyAdminUsageSnapshot(surfaces);
  }

  private LegacyAdminSurfaceUsage usageForSurface(LegacyAdminSurface surface) {
    Counter counter = counters.get(surface.id());
    return new LegacyAdminSurfaceUsage(
        surface.id(),
        surface.title(),
        surface.legacyPath(),
        surface.state().name(),
        surface.replacementUrl(),
        counter == null ? 0L : counter.count(),
        counter == null ? 0L : counter.lastSeenEpochMillis());
  }

  private static final class Counter {
    private final AtomicLong count = new AtomicLong();
    private final AtomicLong lastSeenEpochMillis = new AtomicLong();

    void increment(long observedEpochMillis) {
      count.incrementAndGet();
      lastSeenEpochMillis.updateAndGet(previous -> Math.max(previous, observedEpochMillis));
    }

    long count() {
      return count.get();
    }

    long lastSeenEpochMillis() {
      return lastSeenEpochMillis.get();
    }
  }
}
