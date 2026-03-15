package network.crypta.runtime.spi;

/**
 * Exposes the narrow diagnostic-report capability needed by the legacy admin HTTP endpoint.
 *
 * <p>This port is intentionally report-oriented rather than metric-oriented. The legacy {@code
 * /diagnostic/} page is a plain-text operational summary that aggregates live daemon state into a
 * small sequence of human-readable sections. Callers request one detached report snapshot and
 * render it as-is without depending on daemon-only node, FCP, thread-diagnostics, or stats types.
 * That keeps the HTTP layer narrow while still preserving the current operator-facing page shape.
 *
 * <p>The port is read-only. It does not perform access control, does not expose incremental or
 * queryable counters, and does not attempt to define a future metrics schema. Implementations may
 * traverse the live runtime state when building the snapshot, but callers should see only immutable
 * JDK-only DTOs that are safe to retain for the lifetime of one request.
 *
 * <ul>
 *   <li>Returns one detached report per render.
 *   <li>Preserves the legacy section ordering and line-oriented output model.
 *   <li>Keeps daemon-only traversal and formatting decisions inside the runtime adapter.
 * </ul>
 *
 * @see DiagnosticReportSnapshot
 * @see DiagnosticSectionSnapshot
 */
public interface DiagnosticPort {
  /**
   * Returns one detached snapshot of the current diagnostic report.
   *
   * <p>The returned snapshot should preserve the broad section ordering and line-oriented semantics
   * of the legacy diagnostic page while remaining fully detached from the daemon-owned state.
   * Callers may render the sections directly without an additional traversal of runtime internals,
   * caching layer, or follow-up query API. Implementations are free to collect the data on demand,
   * but they should treat the returned object as a stable point-in-time report rather than as a
   * live view.
   *
   * @return immutable diagnostic report snapshot containing section titles and report lines
   */
  DiagnosticReportSnapshot snapshot();
}
