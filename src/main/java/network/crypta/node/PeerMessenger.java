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

/** Handles peer messaging and disconnect workflows for {@link PeerManager}. */
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

  /** Returns the byte counter used for disconnect traffic. */
  public ByteCounter getDisconnCounter() {
    return disconnCounter;
  }

  /**
   * Disconnects a peer and removes it from the routing table.
   *
   * @param pn Peer to disconnect.
   * @param sendDisconnectMessage If true, send a protocol disconnect message.
   * @param waitForAck If true, wait for the disconnect acknowledgment before removal.
   * @param purge If true, request the remote to purge this node from old-peer state.
   */
  public void disconnectAndRemove(
      PeerNode pn, boolean sendDisconnectMessage, boolean waitForAck, boolean purge) {
    disconnect(pn, sendDisconnectMessage, waitForAck, purge, false, true, Node.MAX_PEER_INACTIVITY);
  }

  /**
   * Disconnects from a specified node.
   *
   * @param pn Peer to disconnect.
   * @param sendDisconnectMessage If false, do not send the protocol disconnect message.
   * @param waitForAck If false, do not wait for the disconnect acknowledgment.
   * @param purge If true, request the remote to purge this node from old-peer lists.
   * @param dumpMessagesNow If true, drop queued messages immediately before completing disconnect.
   * @param remove If true, remove the peer locally after disconnect.
   * @param timeout Timeout in milliseconds to wait before completing removal if still
   *     disconnecting.
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
        pn.sendAsync(msg, createDisconnectCallback(pn, remove, waitForAck), disconnCounter);
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

  /** Asynchronously sends a message to all eligible peers. */
  public void localBroadcast(
      Message msg, boolean ignoreRoutability, boolean onlyRealConnections, ByteCounter ctr) {
    localBroadcast(
        msg, ignoreRoutability, onlyRealConnections, ctr, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }

  /**
   * Asynchronously sends a message to all eligible peers.
   *
   * @param msg Message to send.
   * @param ignoreRoutability When true, send to connected peers even if not routable.
   * @param onlyRealConnections When true, exclude non-real connections.
   * @param ctr Counter to attribute bytes to.
   * @param minVersion Minimum accepted build number (inclusive).
   * @param maxVersion Maximum accepted build number (inclusive).
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
        peer.sendAsync(msg, null, ctr);
      } catch (NotConnectedException _) {
        // Ignore
      }
    }
  }

  /** Asynchronously sends a differential node reference to every connected peer. */
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
