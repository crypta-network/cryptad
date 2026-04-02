package network.crypta.runtime.diagnostics;

import network.crypta.runtime.diagnostics.threads.NodeThreadSnapshot;

/**
 * Exposes lightweight diagnostics for threads running in the node.
 *
 * <p>Implementations provide a periodically refreshed, point-in-time view of active threads and
 * related metrics suitable for UI pages and support tooling. Unless stated otherwise by a specific
 * implementation, instances are safe to use from multiple threads.
 */
public interface ThreadDiagnostics {

  /**
   * Returns the most recent snapshot of node threads.
   *
   * <p>The returned {@link NodeThreadSnapshot} represents a single sampling interval collected by
   * the implementation. It typically includes a list of thread/job entries and the sampling
   * interval used to compute recent CPU deltas. When no data has been collected yet, the snapshot
   * may contain no threads.
   *
   * <p>Thread-safety: Callers may invoke this method from any thread. Implementations should return
   * the latest available snapshot without blocking for long-running work.
   *
   * @return a snapshot object describing currently known threads
   */
  NodeThreadSnapshot getThreadSnapshot();
}
