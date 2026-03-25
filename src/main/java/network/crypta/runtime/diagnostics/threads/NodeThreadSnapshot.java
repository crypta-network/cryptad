package network.crypta.runtime.diagnostics.threads;

import java.util.ArrayList;
import java.util.List;

/**
 * Immutable, value-based snapshot of thread diagnostics for a single sampling interval.
 *
 * <p>This record models the result of one sampling pass of the node's thread diagnostics subsystem.
 * It carries a list of {@link NodeThreadInfo} entries describing the attributes and recent CPU
 * usage of threads that were eligible during sampling, together with the sampling interval (in
 * milliseconds) used to compute short-term CPU deltas. Instances are designed for read-mostly
 * workflows such as rendering UI tables, producing logs, or exporting lightweight telemetry. The
 * internal list is kept immutable; callers should use {@link #getThreads()} to obtain a fresh
 * modifiable copy when they need to sort or otherwise manipulate the data without affecting the
 * snapshot.
 *
 * <p>Typical call patterns are to retrieve a snapshot from a diagnostics service, obtain the
 * threads, sort by {@link NodeThreadInfo#getCpuTime()} descending, and then render or filter the
 * result. The object itself does not schedule or update; it represents a point-in-time view and is
 * safe to retain and read concurrently across threads after creation.
 *
 * <ul>
 *   <li><strong>Immutability</strong>: internally immutable; access via {@link #getThreads()}
 *       returns a defensive copy for caller-owned mutations.
 *   <li><strong>Thread-safety</strong>: safe for concurrent reads after construction; there is no
 *       mutation API.
 *   <li><strong>Semantics</strong>: {@code interval} is measured in milliseconds and corresponds to
 *       the sampling period that produced the CPU deltas contained in the entries.
 * </ul>
 *
 * @param threads the thread entries captured during the sampling pass; must be non-null and contain
 *     non-null elements; the internal representation is immutable and detached from the caller's
 *     list
 * @param interval the sampling interval used to compute CPU deltas, expressed in milliseconds;
 *     callers may treat it as a display hint or use it when deriving percentages
 */
public record NodeThreadSnapshot(List<NodeThreadInfo> threads, int interval) {

  /**
   * Creates a new snapshot.
   *
   * <p>The constructor defensively copies the provided list to ensure immutability of the internal
   * state. Subsequent modifications to the {@code threads} list supplied by the caller do not
   * affect this snapshot instance.
   *
   * @param threads list of thread entries for this snapshot; must be non-null and contain only
   *     non-null elements; contents are copied to an internal, unmodifiable list
   * @param interval sampling interval in milliseconds; typically matches the cadence of the
   *     diagnostics sampler that produced this snapshot
   */
  public NodeThreadSnapshot {
    // Keep the internal representation immutable while preserving existing API behavior via
    // getThreads() which returns a fresh modifiable copy.
    threads = List.copyOf(threads);
  }

  /**
   * Returns a modifiable copy of the snapshot's thread list.
   *
   * <p>The returned list is a shallow copy that callers own and may freely sort or mutate without
   * affecting the snapshot's internal state. Each {@link NodeThreadInfo} entry is immutable, so
   * mutations typically consist of reordering or filtering rather than element updates.
   *
   * @return a new list instance containing the entries of this snapshot; callers may modify or sort
   *     it without impacting the snapshot
   */
  public List<NodeThreadInfo> getThreads() {
    return new ArrayList<>(threads);
  }

  /**
   * Returns the sampling interval associated with this snapshot.
   *
   * <p>The value is expressed in milliseconds and typically corresponds to the period between two
   * consecutive sampling passes used to compute recent CPU deltas in {@link NodeThreadInfo}
   * entries.
   *
   * @return the sampling interval in milliseconds for which this snapshot was computed
   */
  public int getInterval() {
    return interval;
  }
}
