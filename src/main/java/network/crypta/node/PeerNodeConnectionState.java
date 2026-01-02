package network.crypta.node;

import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import network.crypta.io.AddressTracker;
import network.crypta.support.BooleanLastTrueTracker;
import network.crypta.support.WeakHashSet;

/**
 * Connection-adjacent state for {@link PeerNode}.
 *
 * <p>This helper owns:
 *
 * <ul>
 *   <li>Connected tracking (last time connected) without requiring callers to hold the main peer
 *       lock.
 *   <li>Status change listeners (weakly referenced).
 *   <li>Burst-only handshake decision state.
 * </ul>
 */
final class PeerNodeConnectionState {
  private static final long UPDATE_BURST_NOW_PERIOD = TimeUnit.MINUTES.toMillis(5);

  /**
   * Burst only 19 in 20 times if definitely port forwarded. Save entropy by writing this as 20 not
   * 0.95.
   */
  private static final int P_BURST_IF_DEFINITELY_FORWARDED = 20;

  private final BooleanLastTrueTracker connectedTracker;
  private final Set<PeerManager.PeerStatusChangeListener> listeners =
      Collections.synchronizedSet(new WeakHashSet<>());

  private boolean burstNow;
  private long timeSetBurstNow;

  PeerNodeConnectionState(long lastConnectedTime) {
    if (lastConnectedTime > 0) {
      connectedTracker = new BooleanLastTrueTracker(lastConnectedTime);
    } else {
      connectedTracker = new BooleanLastTrueTracker();
    }
  }

  boolean isConnected() {
    return connectedTracker.isTrue();
  }

  /**
   * Updates the connected state.
   *
   * @param connected new state
   * @param now current time in milliseconds (caller-supplied time base)
   * @return the previous connected state
   */
  boolean setConnected(boolean connected, long now) {
    return connectedTracker.set(connected, now);
  }

  long timeLastConnected(long now) {
    return connectedTracker.getTimeLastTrue(now);
  }

  void registerStatusChangeListener(PeerManager.PeerStatusChangeListener listener) {
    listeners.add(listener);
  }

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
   * <p>Primarily true when the local address appears port-forwarded and periodic bursting is used
   * to reduce false positives.
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
