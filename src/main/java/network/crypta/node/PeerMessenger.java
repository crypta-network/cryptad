package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates outbound peer messaging and disconnect workflows for {@link PeerManager}.
 *
 * <p>This helper centralizes the common patterns used when disconnecting a {@link PeerNode} and
 * when broadcasting local messages to connected peers. Typical usage is from the owning {@link
 * Node} or {@link PeerManager} to either send protocol disconnect messages, schedule disconnect
 * timeouts, or deliver node-to-node messages to eligible peers.
 *
 * <p>Notable behaviors include deferring removal until an acknowledgment (when requested),
 * recording disconnect traffic with a dedicated {@link ByteCounter}, and filtering broadcast
 * targets by routability, connection type, and build number. Timeouts are scheduled through the
 * node ticker and only apply to non-seed peers.
 *
 * <p>Thread-safety: this class does not introduce additional synchronization. Callers must respect
 * {@link PeerManager} and {@link PeerNode} concurrency requirements when invoking its methods.
 *
 * <ul>
 *   <li>Disconnects may be immediate, acknowledged, or timeout-driven.
 *   <li>Broadcasts are best-effort; disconnected peers are skipped.
 *   <li>Removals optionally trigger urgent peer persistence writes.
 * </ul>
 *
 * @see PeerManager
 * @see PeerNode
 * @see Node
 */
public class PeerMessenger {
  private static final Logger LOG = LoggerFactory.getLogger(PeerMessenger.class);

  private final Node node;
  private final PeerManager peerManager;

  private final ByteCounter disconnCounter =
      new ByteCounter() {
        @Override
        public void receivedBytes(int x) {
          node.getNodeStats().disconnBytesReceived(x);
        }

        @Override
        public void sentBytes(int x) {
          node.getNodeStats().disconnBytesSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };

  PeerMessenger(Node node, PeerManager peerManager) {
    this.node = node;
    this.peerManager = peerManager;
  }

  /**
   * Returns the byte counter used for disconnect traffic accounting.
   *
   * <p>The returned counter reports received and sent disconnect bytes into {@link NodeStats},
   * allowing disconnect message overhead to be tracked separately from normal traffic. The counter
   * is owned by this instance and should be treated as read-only by callers; it is safe to reuse
   * for multiple disconnect sends.
   *
   * @return the shared counter that attributes disconnect bytes to node statistics.
   */
  public ByteCounter getDisconnCounter() {
    return disconnCounter;
  }

  /**
   * Disconnects a peer and removes it from the routing table.
   *
   * <p>This is a convenience wrapper that requests a disconnect message and removal using the
   * default inactivity timeout. Removal can be immediate or deferred until an acknowledgment,
   * depending on the {@code waitForAck} flag. If the peer is already disconnecting, the call is a
   * no-op.
   *
   * @param pn peer to disconnect; must be non-null and known.
   * @param sendDisconnectMessage whether to send the protocol disconnect message.
   * @param waitForAck whether to wait for disconnect acknowledgment before removal.
   * @param purge whether to request remote purge of old-peer state.
   */
  public void disconnectAndRemove(
      PeerNode pn, boolean sendDisconnectMessage, boolean waitForAck, boolean purge) {
    disconnect(pn, sendDisconnectMessage, waitForAck, purge, false, true, Node.MAX_PEER_INACTIVITY);
  }

  /**
   * Disconnects from a specified node.
   *
   * <p>If {@code sendDisconnectMessage} is true, a disconnect message is sent asynchronously and
   * removal is either immediate (when {@code waitForAck} is false) or deferred until the callback
   * is acknowledged. If the peer is not connected, removal occurs only when the peer is already in
   * a disconnecting state. When {@code sendDisconnectMessage} is false, removal is immediate if
   * {@code remove} is true. Timeouts are scheduled via the node ticker and apply only to non-seed
   * peers.
   *
   * <p>Typical usage is during peer shutdown or routing table cleanup. The method is idempotent for
   * peers already in the disconnecting state.
   *
   * @param pn peer to disconnect; must be non-null and tracked.
   * @param sendDisconnectMessage whether to send the protocol disconnect message.
   * @param waitForAck whether to wait for disconnect acknowledgment before removal.
   * @param purge whether to request remote purge of old-peer lists.
   * @param dumpMessagesNow whether to drop queued messages immediately.
   * @param remove whether to remove the peer after disconnect flow.
   * @param timeout timeout in milliseconds before forced removal if disconnecting.
   */
  public void disconnect(
      PeerNode pn,
      boolean sendDisconnectMessage,
      boolean waitForAck,
      boolean purge,
      boolean dumpMessagesNow,
      boolean remove,
      long timeout) {
    if (LOG.isDebugEnabled()) LOG.debug("Disconnecting {}", pn.shortToString());
    if (!shouldProceedWithDisconnect(pn, dumpMessagesNow)) return;
    if (sendDisconnectMessage) {
      Message msg = createDisconnectMessage(remove, purge);
      try {
        pn.transport()
            .sendAsync(msg, createDisconnectCallback(pn, remove, waitForAck), disconnCounter);
      } catch (NotConnectedException _) {
        removePeerIfRequested(pn, remove);
        return;
      }
      scheduleDisconnectTimeoutHandling(pn, remove, timeout);
    } else if (remove) {
      peerManager.removePeer(pn);
      if (!pn.isSeed()) peerManager.writePeersUrgent(pn.isOpennet());
    }
  }

  /**
   * Asynchronously sends a message to all eligible peers using unbounded version filters.
   *
   * <p>This overload forwards to {@link #localBroadcast(Message, boolean, boolean, ByteCounter,
   * int, int)} with the minimum and maximum build numbers set to the full integer range. It is a
   * best-effort broadcast; disconnected peers are skipped and connection loss during send is
   * ignored.
   *
   * @param msg message to send; must be non-null and reusable.
   * @param ignoreRoutability whether to treat connected peers as eligible.
   * @param onlyRealConnections whether to exclude non-real connections.
   * @param ctr counter used to attribute bytes to statistics.
   */
  public void localBroadcast(
      Message msg, boolean ignoreRoutability, boolean onlyRealConnections, ByteCounter ctr) {
    localBroadcast(
        msg, ignoreRoutability, onlyRealConnections, ctr, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }

  /**
   * Asynchronously sends a message to all eligible peers.
   *
   * <p>Eligibility is determined by connection/routability, connection type, and build number
   * range. If {@code ignoreRoutability} is true, connected peers are eligible even when not
   * routable. If {@code onlyRealConnections} is true, transient or non-real connections are
   * excluded. Build numbers are compared inclusively against {@code minVersion} and {@code
   * maxVersion}.
   *
   * <p>Not connected errors are ignored to keep the broadcast best-effort. The method does not
   * retry or queue messages on failure.
   *
   * <pre>{@code
   * // Example: send a message to all routable peers at or above a build.
   * messenger.localBroadcast(msg, false, true, ctr, 1000, Integer.MAX_VALUE);
   * }</pre>
   *
   * @param msg message to send; must be non-null and reusable.
   * @param ignoreRoutability whether to include connected but non-routable peers.
   * @param onlyRealConnections whether to exclude non-real connections.
   * @param ctr counter used to attribute bytes to statistics.
   * @param minVersion minimum accepted build number, inclusive.
   * @param maxVersion maximum accepted build number, inclusive.
   */
  public void localBroadcast(
      Message msg,
      boolean ignoreRoutability,
      boolean onlyRealConnections,
      ByteCounter ctr,
      int minVersion,
      int maxVersion) {
    // myPeers not connectedPeers as connectedPeers only contains
    // ROUTABLE peers, and we may want to send to non-routable peers
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode peer : peers) {
      if (!shouldSendLocal(peer, ignoreRoutability, onlyRealConnections, minVersion, maxVersion))
        continue;
      try {
        peer.transport().sendAsync(msg, null, ctr);
      } catch (NotConnectedException _) {
        // Ignore
      }
    }
  }

  /**
   * Asynchronously sends a differential node reference to every matching connected peer.
   *
   * <p>This uses the N2N diff node reference message type and targets peers selected by darknet and
   * opennet flags. When both {@code toDarknetOnly} and {@code toOpennetOnly} are false, all
   * connected peers are eligible. The message is sent best-effort and is not queued for
   * disconnected peers.
   *
   * @param fs field set containing the diff node reference payload.
   * @param toDarknetOnly whether to restrict sending to darknet peers.
   * @param toOpennetOnly whether to restrict sending to opennet peers.
   */
  public void locallyBroadcastDiffNodeRef(
      SimpleFieldSet fs, boolean toDarknetOnly, boolean toOpennetOnly) {
    // myPeers not connectedPeers as connectedPeers only contains
    // ROUTABLE peers, and we want to also send to non-routable peers
    PeerNode[] peers = peerManager.myPeers();
    for (PeerNode peer : peers) {
      boolean okDarknet = !toDarknetOnly || peer.isDarknet();
      boolean okOpennet = !toOpennetOnly || peer.isOpennet();
      if (peer.isConnected() && okDarknet && okOpennet) {
        peer.sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
      }
    }
  }

  private AsyncMessageCallback createDisconnectCallback(
      PeerNode pn, boolean remove, boolean waitForAck) {
    return new AsyncMessageCallback() {
      boolean done = false;

      @Override
      public void acknowledged() {
        markDone();
      }

      @Override
      public void disconnected() {
        markDone();
      }

      @Override
      public void fatalError() {
        markDone();
      }

      @Override
      public void sent() {
        if (!waitForAck) markDone();
      }

      void markDone() {
        synchronized (this) {
          if (done) return;
          done = true;
        }
        if (remove) {
          peerManager.removePeer(pn);
          if (!pn.isSeed()) peerManager.writePeersUrgent(pn.isOpennet());
        }
      }
    };
  }

  private boolean shouldProceedWithDisconnect(PeerNode pn, boolean dumpMessagesNow) {
    if (!peerManager.havePeer(pn)) return false;
    if (pn.notifyDisconnecting(dumpMessagesNow)) {
      if (LOG.isDebugEnabled()) LOG.debug("Already disconnecting {}", pn.shortToString());
      return false;
    }
    return true;
  }

  private static Message createDisconnectMessage(boolean remove, boolean purge) {
    return DMT.createFNPDisconnect(remove, purge, -1, new ShortBuffer(new byte[0]));
  }

  private void removePeerIfRequested(PeerNode pn, boolean remove) {
    if (remove && pn.isDisconnecting()) {
      peerManager.removePeer(pn);
      if (!pn.isSeed()) {
        peerManager.writePeersUrgent(pn.isOpennet());
      }
    }
  }

  private void scheduleDisconnectTimeoutHandling(PeerNode pn, boolean remove, long timeout) {
    if (pn.isSeed()) return;
    node.getTicker()
        .queueTimedJob(
            () -> {
              if (pn.isDisconnecting()) {
                if (remove) {
                  peerManager.removePeer(pn);
                  if (!pn.isSeed()) {
                    peerManager.writePeersUrgent(pn.isOpennet());
                  }
                }
                pn.disconnected(true, true);
              }
            },
            timeout);
  }

  private static boolean shouldSendLocal(
      PeerNode peer,
      boolean ignoreRoutability,
      boolean onlyRealConnections,
      int minVersion,
      int maxVersion) {
    int version = peer.getBuildNumber();
    boolean routableOrConnected = ignoreRoutability ? peer.isConnected() : peer.isRoutable();
    return routableOrConnected
        && (!onlyRealConnections || peer.isRealConnection())
        && version >= minVersion
        && version <= maxVersion;
  }
}
