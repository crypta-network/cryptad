package network.crypta.node;

import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import network.crypta.io.AddressTracker;
import network.crypta.support.BooleanLastTrueTracker;
import network.crypta.support.WeakHashSet;

/**
 * Connection-adjacent state for {@link PeerNode} that keeps lightweight, lock-avoiding metadata.
 *
 * <p>This helper centralizes several pieces of state that are needed frequently by the peer
 * connection lifecycle but should not require callers to hold the main peer lock. It tracks when
 * the peer was last connected, maintains a weakly referenced set of status-change listeners, and
 * caches the decision for burst-only handshakes so that callers can query it cheaply.
 *
 * <p>Typical usage is to create one instance per {@link PeerNode}, update the connection flag on
 * transitions, and read the last-connected time to drive UI or backoff logic. The burst-only
 * decision uses a randomized probe with a fixed refresh window; once computed, the choice remains
 * stable for the configured period to avoid excessive entropy consumption.
 *
 * <p>Thread-safety: this class delegates concurrency to its internal helpers and a synchronized
 * listener set. Callers should treat instances as mutable and avoid externally synchronizing on
 * them. Listener callbacks execute while holding the listener-set lock, so listeners should be
 * short and non-blocking.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Tracking connection state transitions with caller-supplied timestamps.
 *   <li>Notifying status listeners without retaining strong references.
 *   <li>Caching the burst-only decision for definitely port-forwarded connectivity.
 * </ul>
 */
final class PeerNodeConnectionState {
  /**
   * Minimum interval in milliseconds between recalculating burst-only decisions.
   *
   * <p>The cached burst decision is reused until this period elapses to limit calls to the random
   * source while keeping the behavior responsive to connectivity changes.
   */
  private static final long UPDATE_BURST_NOW_PERIOD = TimeUnit.MINUTES.toMillis(5);

  /**
   * Burst only 19 in 20 times if definitely port forwarded. Save entropy by writing this as 20 not
   * 0.95.
   */
  private static final int P_BURST_IF_DEFINITELY_FORWARDED = 20;

  /**
   * Tracks when the connection was last observed as true using a caller-supplied time base.
   *
   * <p>The tracker is updated only on false-to-true transitions and provides a fast read of the
   * most recent connection time, or the current time while connected.
   */
  private final BooleanLastTrueTracker connectedTracker;

  /**
   * Registered status listeners, held weakly to avoid retaining long-lived peer references.
   *
   * <p>The set is synchronized to permit safe registration and iteration, but callbacks still
   * execute under the set lock, so listeners should avoid heavy work or reentrancy.
   */
  private final Set<PeerManager.PeerStatusChangeListener> listeners =
      Collections.synchronizedSet(new WeakHashSet<>());

  /**
   * Cached decision for whether burst-only handshakes are enabled at this moment.
   *
   * <p>The value is recalculated periodically based on connectivity status and a random probe, and
   * then reused until {@link #timeSetBurstNow} indicates the cache has expired.
   */
  private boolean burstNow;

  /**
   * Time in milliseconds when the burst-only decision was last refreshed.
   *
   * <p>This timestamp uses {@link System#currentTimeMillis()} and is compared against {@link
   * #UPDATE_BURST_NOW_PERIOD} to determine when the cached decision should be recomputed.
   */
  private long timeSetBurstNow;

  /**
   * Creates a new connection-state helper seeded with the last known connection time.
   *
   * <p>The supplied value is treated as the most recent {@code false -> true} transition until a
   * new connection is observed. When {@code lastConnectedTime} is not positive, the helper starts
   * in the "never connected" state, and {@link #timeLastConnected(long)} will return {@code -1}
   * while disconnected.
   *
   * @param lastConnectedTime last known connection time in the caller's time base; non-positive
   *     values indicate no prior connection data is available.
   */
  PeerNodeConnectionState(long lastConnectedTime) {
    if (lastConnectedTime > 0) {
      connectedTracker = new BooleanLastTrueTracker(lastConnectedTime);
    } else {
      connectedTracker = new BooleanLastTrueTracker();
    }
  }

  /**
   * Returns whether the peer is currently marked as connected.
   *
   * <p>This is a snapshot of the last state set via {@link #setConnected(boolean, long)} and does
   * not imply any network liveness checks. The method is side-effect free and suitable for frequent
   * polling by callers that need to render status or make scheduling decisions.
   *
   * @return {@code true} if the connection state is currently marked as connected; {@code false}
   *     otherwise.
   */
  boolean isConnected() {
    return connectedTracker.isTrue();
  }

  /**
   * Updates the connected state and records a new last-connected time on transitions to true.
   *
   * <p>When the state changes from {@code false} to {@code true}, the provided {@code now} value
   * becomes the latest connection time. When the state stays the same or transitions to
   * disconnected, the stored timestamp is left unchanged. This method is idempotent with respect to
   * repeating the same {@code connected} value.
   *
   * @param connected new state to store; {@code true} means connected, {@code false} means not
   *     connected.
   * @param now current time in milliseconds from a caller-supplied, consistent time base.
   * @return the previous connected state before applying this update.
   */
  boolean setConnected(boolean connected, long now) {
    return connectedTracker.set(connected, now);
  }

  /**
   * Returns the last-connected time using the caller's time base.
   *
   * <p>If the connection is currently marked as connected, this method returns {@code now} to
   * reflect an "as of" value. If disconnected, it returns the most recent time recorded by {@link
   * #setConnected(boolean, long)}, or {@code -1} when the connection has never been marked true.
   * Callers should pass a consistent time base for meaningful comparisons.
   *
   * @param now current time in milliseconds, only used when the connection is currently true.
   * @return {@code now} if connected; otherwise the last recorded connection time or {@code -1}
   *     when no prior connection was recorded.
   */
  long timeLastConnected(long now) {
    return connectedTracker.getTimeLastTrue(now);
  }

  /**
   * Registers a listener to be notified when peer status changes are broadcast.
   *
   * <p>Listeners are stored with weak references, so they may be reclaimed if no strong references
   * exist elsewhere. This method does not validate duplicates; registering the same instance
   * multiple times may result in multiple callbacks depending on set semantics.
   *
   * @param listener callback to invoke on status changes; must be non-null and externally
   *     referenced to avoid garbage collection.
   */
  void registerStatusChangeListener(PeerManager.PeerStatusChangeListener listener) {
    listeners.add(listener);
  }

  /**
   * Notifies all currently registered status listeners of a peer status change.
   *
   * <p>Callbacks are invoked while holding the listener-set lock to ensure a consistent snapshot.
   * Listeners should return promptly and avoid calling back into peer code that could deadlock.
   * This method has no return value and makes no guarantees about ordering beyond iteration order
   * of the underlying set.
   */
  void notifyStatusChangeListeners() {
    synchronized (listeners) {
      for (PeerManager.PeerStatusChangeListener listener : listeners) {
        listener.onPeerStatusChange();
      }
    }
  }

  /**
   * Returns whether the connection should use burst-only handshake behavior.
   *
   * <p>The decision depends on the connectivity status reported by {@code outgoingMangler}. For
   * unknown or NATed statuses, this method returns {@code false} immediately. For definitely
   * port-forwarded status, it periodically samples a random probe to determine whether bursting is
   * enabled, and caches the decision for {@link #UPDATE_BURST_NOW_PERIOD} milliseconds.
   *
   * <p>Because the cache relies on {@link System#currentTimeMillis()}, callers should treat the
   * result as time-sensitive and re-query when they need an updated value. The method performs no
   * I/O and is safe to call frequently.
   *
   * @param outgoingMangler connectivity source used to determine the current port-forward status;
   *     must be non-null and return a stable {@link AddressTracker.Status} value.
   * @param random random source used to decide burst-only enablement when definitely forwarded;
   *     must be non-null and provide consistent {@link Random#nextInt(int)} behavior.
   * @return {@code true} when burst-only behavior is selected for the current cache window; {@code
   *     false} for unknown, NATed, or non-selected periods.
   */
  boolean isBurstOnly(OutgoingPacketMangler outgoingMangler, Random random) {
    AddressTracker.Status status = outgoingMangler.getConnectivityStatus();
    if (status == AddressTracker.Status.DONT_KNOW) return false;
    if (status == AddressTracker.Status.DEFINITELY_NATED
        || status == AddressTracker.Status.MAYBE_NATED) {
      return false;
    }

    // Note: consider using a lower probability once packet-deltas
    // mechanisms are validated in production environments.
    if (status == AddressTracker.Status.MAYBE_PORT_FORWARDED) return false;
    long now = System.currentTimeMillis();
    if (now - timeSetBurstNow > UPDATE_BURST_NOW_PERIOD) {
      burstNow = (random.nextInt(P_BURST_IF_DEFINITELY_FORWARDED) == 0);
      timeSetBurstNow = now;
    }
    return burstNow;
  }
}
