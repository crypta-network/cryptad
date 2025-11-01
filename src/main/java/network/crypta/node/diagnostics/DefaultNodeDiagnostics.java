package network.crypta.node.diagnostics;

import network.crypta.node.NodeStats;
import network.crypta.node.diagnostics.threads.DefaultThreadDiagnostics;
import network.crypta.support.Ticker;

/**
 * Facade that wires node diagnostics and exposes thread-related insights.
 *
 * <p>This lightweight implementation provides access to diagnostics components that sample and
 * report on the state of a running node. It focuses on thread-level information and delegates the
 * actual sampling and snapshot publication to {@link
 * network.crypta.node.diagnostics.threads.DefaultThreadDiagnostics}. Callers obtain this façade
 * from node wiring, start it during application bootstrap, and subsequently read diagnostics via
 * the exposed accessors. The class itself contains no heavy logic; it primarily composes
 * collaborators and forwards lifecycle events.
 *
 * <p><strong>Lifecycle and thread-safety</strong>: Instances are typically created once per node
 * and used across the application. {@link #start()} schedules periodic sampling and {@link #stop()}
 * cancels future runs; both operations are safe to invoke from arbitrary threads and may be called
 * more than once without adverse effects in typical usage. All returned diagnostics objects
 * represent read-only snapshots from the perspective of callers.
 *
 * <ul>
 *   <li><em>Responsibilities</em>: compose diagnostics, forward lifecycle, expose accessors.
 *   <li><em>Non-goals</em>: perform heavy analysis or maintain historical time series data.
 *   <li><em>Typical usage</em>: construct → {@link #start()} → periodically read → {@link #stop()}.
 * </ul>
 *
 * @author desyncr
 * @see ThreadDiagnostics
 * @see network.crypta.node.diagnostics.threads.DefaultThreadDiagnostics
 */
public class DefaultNodeDiagnostics implements NodeDiagnostics {
  /**
   * Creates a diagnostics façade bound to the given node statistics and scheduler.
   *
   * <p>The instance wires a {@link
   * network.crypta.node.diagnostics.threads.DefaultThreadDiagnostics} that periodically samples JVM
   * threads and publishes snapshots. Construction is cheap and does not schedule any background
   * work; callers should invoke {@link #start()} to begin sampling.
   *
   * @param nodeStats provider of live thread snapshots and related node metrics; must be non-null
   *     and is expected to return a stable array for the duration of a single sampling pass
   * @param ticker timing facility used to schedule periodic sampling work; must be non-null and
   *     thread-safe because it may be called from arbitrary threads to enqueue or cancel tasks
   */
  public DefaultNodeDiagnostics(NodeStats nodeStats, Ticker ticker) {
    defaultThreadDiagnostics = new DefaultThreadDiagnostics(nodeStats, ticker);
  }

  /**
   * Starts periodic diagnostics sampling.
   *
   * <p>Delegates to the underlying thread diagnostics component to enqueue its first run with the
   * configured {@link Ticker}. Subsequent executions reschedule themselves. Calling this method
   * multiple times is harmless; the underlying component manages duplicate scheduling according to
   * its own semantics.
   */
  public void start() {
    defaultThreadDiagnostics.start();
  }

  /**
   * Stops periodic diagnostics sampling.
   *
   * <p>Requests cancellation of any future scheduled executions for the underlying thread
   * diagnostics component. In-flight runs are not interrupted. The most recently computed snapshot
   * remains available via {@link #getThreadDiagnostics()}.
   */
  public void stop() {
    defaultThreadDiagnostics.stop();
  }

  /**
   * Returns access to thread-level diagnostics for the node.
   *
   * <p>The returned object exposes a point-in-time view of active threads and related metrics.
   * Snapshots are lightweight and safe to read frequently. The reference is stable for the lifetime
   * of this {@code DefaultNodeDiagnostics} instance and should be treated as read-only by callers.
   *
   * @return a non-null diagnostics handle that publishes immutable snapshots of thread activity;
   *     callers may keep the reference and poll it periodically for updated data
   */
  @Override
  public ThreadDiagnostics getThreadDiagnostics() {
    return defaultThreadDiagnostics;
  }

  private final DefaultThreadDiagnostics defaultThreadDiagnostics;
}
