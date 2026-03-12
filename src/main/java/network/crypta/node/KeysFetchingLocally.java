package network.crypta.node;

import network.crypta.keys.Key;

/**
 * Tracks locally running fetch/insert activity and provides routing helpers for scheduling.
 *
 * <p>Implementations expose a snapshot of keys currently in flight on this node and lightweight
 * predicates to avoid duplicate work (for example, skipping a fetch when another request already
 * handles the same key). Some methods may perform routing probes that are intentionally
 * heavyweight; callers should avoid invoking them while holding unrelated locks.
 *
 * <p>Threading and locking: Implementations may synchronize on internal structures and, for routing
 * probes, may lock {@code PeerNode} instances and other components. Acquire these locks last
 * relative to other subsystem locks to prevent deadlocks.
 */
public interface KeysFetchingLocally {

  /**
   * Performs a local routing probe to determine whether sending a request for {@code key} would be
   * rejected due to a recent failure.
   *
   * <p>This operation can be heavyweight and may lock {@code PeerNode} instances and other
   * structures. Prefer calling it outside coarse-grained locks.
   *
   * @param key the key to evaluate
   * @param realTime when {@code true}, apply real-time routing heuristics; otherwise use bulk
   *     heuristics
   * @return a non-positive value when the request can be sent immediately; otherwise the absolute
   *     wakeup time (milliseconds since the epoch) when it may be retried. Callers should record
   *     the returned wakeup in their cooldown tracking to avoid repeated probes.
   */
  long checkRecentlyFailed(Key key, boolean realTime);

  /**
   * Returns whether {@code key} is currently being fetched by a locally originated request.
   *
   * <p>If the key is already in flight and {@code getterWaiting} is non-{@code null},
   * implementations may register the provided getter to be woken when the in-flight request
   * completes. Lock ordering must ensure the internal guard lock for this structure is acquired
   * last.
   *
   * @param key the key to test
   * @param getterWaiting optional requester to register for wakeup when the existing fetch
   *     completes; may be {@code null}
   * @return {@code true} if the key is currently fetching locally; otherwise {@code false}
   */
  boolean hasKey(Key key, BaseSendableGet getterWaiting);

  /**
   * Returns whether the given request:token pair is currently executing.
   *
   * <p>Used to avoid duplicate inserts originating from the same scheduler context.
   *
   * <p>Note: this could move into the inserter implementation when "request:token" association is
   * tracked there.
   *
   * @param token identifier for the in-flight insert
   * @return {@code true} if the token is executing locally; otherwise {@code false}
   */
  boolean hasInsert(SendableRequestItemKey token);
}
