package network.crypta.node.diagnostics;

/**
 * Aggregates high-level diagnostic entry points for a running node.
 *
 * <p>This interface acts as a lightweight façade that groups diagnostics subsystems which expose
 * point-in-time, read-only information about the node. Implementations are expected to be cheap to
 * query and safe to call from arbitrary threads, providing stable, inspection-oriented views rather
 * than control surfaces. Typical consumers include administrative tools, support utilities, and UI
 * components that periodically refresh their state to present health and activity information.
 *
 * <p>Implementations should document their freshness model (for example, whether values are sampled
 * on access or derived from a periodically updated snapshot) and any limits on retained history.
 * Unless otherwise stated by a concrete implementation, instances are presumed to be thread-safe
 * for concurrent callers, and returned diagnostic objects represent immutable snapshots or
 * read-mostly structures intended for observation only.
 *
 * <ul>
 *   <li>Responsibility: expose observability hooks without mutating node state.
 *   <li>Pattern: obtain the component and call its accessors for current views.
 *   <li>Scope: surfaces thread-related insights; additional domains may be added over time.
 * </ul>
 */
public interface NodeDiagnostics {

  /**
   * Returns access to thread-level diagnostics for the node.
   *
   * <p>The returned component provides a view of the node's threads and related execution metrics
   * suitable for periodic polling by monitoring UIs or support tools. Implementations typically
   * expose inexpensive, snapshot-based data that callers may read frequently without coordinating
   * with the underlying scheduler. The method itself is idempotent and should return the same
   * logical diagnostics handle across invocations for a given {@code NodeDiagnostics} instance.
   *
   * <p>Concurrency: callers may invoke this method from any thread. Implementations should avoid
   * heavy synchronization and refrain from blocking on long-running computation.
   *
   * @return a non-null diagnostics handle offering thread snapshots and metrics; callers should
   *     treat it as read-only and assume values reflect recent, point-in-time sampling
   *     <pre>{@code
   * // Example: obtain and use thread diagnostics
   * NodeDiagnostics nd = null; // acquired from node wiring
   * var threads = nd.getThreadDiagnostics().getThreadSnapshot();
   * }</pre>
   */
  ThreadDiagnostics getThreadDiagnostics();
}
