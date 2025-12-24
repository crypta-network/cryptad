package network.crypta.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import network.crypta.crypt.HMAC;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Dispatcher;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.PeerLoadStats;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.node.probe.Probe;
import network.crypta.store.BlockMetadata;
import network.crypta.support.Fields;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dispatches unmatched FNP messages and coordinates routed message flow.
 *
 * <p>This dispatcher is the entry point for messages not claimed by other subsystems. It handles
 * control messages (ping/pong, time/uptime, visibility), location and load updates, swap flows,
 * data/insert requests, announcement flows, and the small routed-to-node family (routed ping/pong
 * and rejections).
 *
 * <p>Threading: instances are shared across multiple I/O and worker threads. Incoming data requests
 * may be processed off-thread via {@code queueRunner}. Ephemeral routed message state is tracked in
 * {@code routedContexts} and pruned periodically.
 */
public class NodeDispatcher implements Dispatcher, Runnable {

  /** Milliseconds after which a routed context expires and can be removed. */
  private static final long STALE_CONTEXT = 20000;

  /** Milliseconds between successive prune checks for stale routed contexts. */
  private static final long STALE_CONTEXT_CHECK = 20000;

  private static final Logger LOG = LoggerFactory.getLogger(NodeDispatcher.class);
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  final Node node;
  final RequestTracker tracker;
  final Probe probe;
  final Map<Long, RoutedContext> routedContexts = new ConcurrentHashMap<>();
  private final ArrayBlockingQueue<Message> requestQueue = new ArrayBlockingQueue<>(100);
  ByteCounter pingCounter =
      new ByteCounter() {

        @Override
        public void receivedBytes(int x) {
          node.getNodeStats().pingCounterReceived(x);
        }

        @Override
        public void sentBytes(int x) {
          node.getNodeStats().pingCounterSent(x);
        }

        @Override
        public void sentPayload(int x) {
          // Ignore
        }
      };
  private NodeStats nodeStats;
  private final PrioRunnable queueRunner =
      new PrioRunnable() {

        @Override
        public void run() {
          // Exit when the thread is interrupted; keeps queue processing bounded to daemon life.
          while (!Thread.currentThread().isInterrupted()) {
            try {
              Message msg = requestQueue.take();
              boolean isSSK = msg.getSpec() == DMT.FNPSSKDataRequest;
              innerHandleDataRequest(msg, (PeerNode) msg.getSource(), isSSK);
            } catch (InterruptedException _) {
              Thread.currentThread().interrupt();
              return;
            }
          }
        }

        @Override
        public int getPriority() {
          // Slightly less than the actual requests themselves because accepting requests increases
          // load.
          return NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;
        }

        private void innerHandleDataRequest(Message m, PeerNode source, boolean isSSK) {
          if (preconditionsFail(m, source, isSSK)) return;

          long id = m.getLong(DMT.UID);
          ByteCounter ctr =
              isSSK
                  ? NodeDispatcher.this.node.getNodeStats().sskRequestCtr
                  : NodeDispatcher.this.node.getNodeStats().chkRequestCtr;
          short htl = normalizedHtl(m.getShort(DMT.HTL));
          Key key = (Key) m.getObject(DMT.FREENET_ROUTING_KEY);
          boolean realTimeFlag = DMT.getRealTimeFlag(m);
          final RequestTag tag =
              new RequestTag(
                  isSSK,
                  RequestTag.START.REMOTE,
                  source,
                  realTimeFlag,
                  id,
                  NodeDispatcher.this.node);

          if (rejectAlreadyRunningData(id, isSSK, source, ctr, key, htl, tag)) return;

          KeyBlock block = tryFetchBlock(key, tag);
          if (rejectIfOverloadedData(source, isSSK, id, ctr, realTimeFlag, tag, block)) return;

          NodeDispatcher.this.nodeStats.reportIncomingRequestLocation(key.toNormalizedDouble());

          boolean needsPubKey = key instanceof NodeSSK && m.getBoolean(DMT.NEED_PUB_KEY);
          RequestHandler rh =
              new RequestHandler(
                  source,
                  id,
                  NodeDispatcher.this.node,
                  htl,
                  key,
                  tag,
                  block,
                  realTimeFlag,
                  needsPubKey);
          rh.receivedBytes(m.receivedByteCount());
          NodeDispatcher.this
              .node
              .getExecutor()
              .execute(
                  rh,
                  "RequestHandler for UID "
                      + id
                      + " on "
                      + NodeDispatcher.this.node.getDarknetPortNumber());
        }

        private boolean preconditionsFail(Message m, PeerNode source, boolean isSSK) {
          if (!source.isConnected()) {
            if (LOG.isDebugEnabled())
              LOG.debug(
                  "Skip off-thread handling; source disconnected (source={}, msg={})", source, m);
            return true;
          }
          if (!source.isRoutable()) {
            if (LOG.isDebugEnabled())
              LOG.debug(
                  "Skip off-thread handling; source not routable (source={}, msg={})", source, m);
            NodeDispatcher.this.rejectRequest(
                m,
                isSSK
                    ? NodeDispatcher.this.node.getNodeStats().sskRequestCtr
                    : NodeDispatcher.this.node.getNodeStats().chkRequestCtr);
            return true;
          }
          return false;
        }

        private short normalizedHtl(short htl) {
          return (htl <= 0) ? (short) 1 : htl;
        }

        private boolean rejectAlreadyRunningData(
            long id,
            boolean isSSK,
            PeerNode source,
            ByteCounter ctr,
            Key key,
            short htl,
            RequestTag tag) {
          if (NodeDispatcher.this.tracker.lockUID(
              id, isSSK, false, false, false, tag.realTimeFlag, tag)) {
            if (LOG.isDebugEnabled()) LOG.debug("Lock acquired for id {}", id);
            return false;
          }
          if (LOG.isDebugEnabled()) LOG.debug(LOG_ALREADY_RUNNING, id);
          Message rejected = DMT.createFNPRejectedLoop(id);
          try {
            source.sendAsync(rejected, null, ctr);
          } catch (NotConnectedException e) {
            LOG.info(
                "Reject request; sendAsync failed (peer={}, error={})",
                source.getPeer(),
                e.toString());
          }
          NodeDispatcher.this
              .node
              .getFailureTable()
              .onFinalFailure(key, null, htl, htl, -1, -1, source);
          return true;
        }

        private KeyBlock tryFetchBlock(Key key, RequestTag tag) {
          BlockMetadata meta = new BlockMetadata();
          KeyBlock block = NodeDispatcher.this.node.fetch(key, false, false, false, false, meta);
          if (block != null) tag.setNotRoutedOnwards();
          return block;
        }

        private boolean rejectIfOverloadedData(
            PeerNode source,
            boolean isSSK,
            long id,
            ByteCounter ctr,
            boolean realTimeFlag,
            RequestTag tag,
            KeyBlock block) {
          RejectReason rejectReason =
              NodeDispatcher.this.nodeStats.shouldRejectRequest(
                  !isSSK,
                  false,
                  isSSK,
                  false,
                  false,
                  source,
                  block != null,
                  false,
                  realTimeFlag,
                  tag);
          if (rejectReason == null) return false;
          LOG.info(
              "Reject {} request preemptively (peer={}, reason={})",
              (isSSK ? "SSK" : "CHK"),
              source.getPeer(),
              rejectReason);
          Message rejected = DMT.createFNPRejectedOverload(id, true);
          if (rejectReason.soft()) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
          try {
            source.sendAsync(rejected, null, ctr);
          } catch (NotConnectedException e) {
            LOG.info(
                "Rejecting (overload) data request from {}: {}", source.getPeer(), e.toString());
          }
          tag.setRejected();
          tag.unlockHandler(rejectReason.soft());
          return true;
        }
      };
  private NodeDispatcherCallback callback;

  NodeDispatcher(Node node) {
    this.node = node;
    this.tracker = node.getTracker();
    this.nodeStats = node.getNodeStats();
    node.getTicker().queueTimedJob(this, STALE_CONTEXT_CHECK);
    this.probe = new Probe(node);
  }

  public static String peersUIDsToString(long[] peerUIDs, double[] peerLocs) {
    StringBuilder sb = new StringBuilder(peerUIDs.length * 23 + peerLocs.length * 26);
    int min = Math.min(peerUIDs.length, peerLocs.length);
    for (int i = 0; i < min; i++) {
      double loc = peerLocs[i];
      long uid = peerUIDs[i];
      sb.append(loc);
      sb.append('=');
      sb.append(uid);
      if (i != min - 1) sb.append('|');
    }
    if (peerUIDs.length > min) {
      for (int i = min; i < peerUIDs.length; i++) {
        sb.append("|U:");
        sb.append(peerUIDs[i]);
      }
    } else if (peerLocs.length > min) {
      for (int i = min; i < peerLocs.length; i++) {
        sb.append("|L:");
        sb.append(peerLocs[i]);
      }
    }
    return sb.toString();
  }

  @Override
  public boolean handleMessage(Message m) {
    PeerNode source = (PeerNode) m.getSource();
    if (source == null) {
      // Node has been disconnected and garbage collected already! Ouch.
      return true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Dispatch {} from {}", m, source);
    if (callback != null) {
      try {
        callback.snoop(m, node);
      } catch (Exception e) {
        LOG.error("Callback threw exception", e);
      }
    }
    MessageType spec = m.getSpec();

    // Fast-path handlers that don't depend on routability
    if (handlePreRoutabilityMessages(m, source, spec)) return true;

    // Reject early when the source is not routable
    if (!source.isRoutable()) return handleNotRoutableMessages(m, spec);

    // Remaining message families
    if (handleSwapMessages(m, source, spec)) return true;
    if (handleDataOrInsertRequests(m, source, spec)) return true;
    if (handleRoutedMessages(m, source, spec)) return true;
    if (handleOfferAndNoderef(m, source, spec)) return true;
    return handleProbe(m, source, spec);
  }

  private boolean handlePreRoutabilityMessages(Message m, PeerNode source, MessageType spec) {
    return handleSimpleControlMessages(m, source, spec)
        || handleUomMessages(m, source, spec)
        || handleAnnounceOrRoutingStatus(m, source, spec)
        || handleLocationChangeIfRealConnection(m, source, spec)
        || handlePeerLoadStatuses(m, source, spec);
  }

  private boolean handleSimpleControlMessages(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPPing) {
      Message reply = DMT.createFNPPong(m.getInt(DMT.PING_SEQNO));
      try {
        source.sendAsync(reply, null, pingCounter);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection while replying to {}", m);
      }
      return true;
    }
    if (spec == DMT.FNPDetectedIPAddress) {
      Peer p = (Peer) m.getObject(DMT.EXTERNAL_ADDRESS);
      source.setRemoteDetectedPeer(p);
      node.getIpDetector().redetectAddress();
      return true;
    }
    if (spec == DMT.FNPTime) return handleTime(m, source);
    if (spec == DMT.FNPUptime) return handleUptime(m, source);
    if (spec == DMT.FNPVisibility && source instanceof DarknetPeerNode peerNode1) {
      peerNode1.handleVisibility(m);
      return true;
    }
    if (spec == DMT.FNPVoid) return true;
    if (spec == DMT.FNPDisconnect) {
      handleDisconnect(m, source);
      return true;
    }
    if (spec == DMT.nodeToNodeMessage) {
      node.receivedNodeToNodeMessage(m, source);
      return true;
    }
    return false;
  }

  private boolean handleUomMessages(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.CryptadUOMAnnouncement && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleAnnounce(m, source);
    }
    if (spec == DMT.CryptadUOMRequestRevocation && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleRequestRevocation(m, source);
    }
    if (spec == DMT.CryptadUOMSendingRevocation && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleSendingRevocation(m, source);
    }
    if (spec == DMT.CryptadUOMRequestMainJar
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.getNodeUpdater().getUpdateOverMandatory().handleRequestJar(m, source);
      return true;
    }
    if (spec == DMT.CryptadUOMSendingMainJar
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleSendingMain(m, source);
    }
    if (spec == DMT.CryptadUOMFetchDependency
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.getNodeUpdater().getUpdateOverMandatory().handleFetchDependency(m, source);
      return true;
    }
    return false;
  }

  private boolean handleAnnounceOrRoutingStatus(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPOpennetAnnounceRequest) {
      handleAnnounceRequest(m, source);
      return true;
    }
    if (spec == DMT.FNPRoutingStatus) {
      if (source instanceof DarknetPeerNode peerNode) {
        boolean value = m.getBoolean(DMT.ROUTING_ENABLED);
        if (LOG.isDebugEnabled()) LOG.debug("Peer {} requests routing={}", source, value);
        peerNode.setRoutingStatus(value, false);
      }
      return true;
    }
    return false;
  }

  private boolean handleLocationChangeIfRealConnection(
      Message m, PeerNode source, MessageType spec) {
    if (!(source.isRealConnection() && spec == DMT.FNPLocChangeNotificationNew)) return false;

    double newLoc = m.getDouble(DMT.LOCATION);
    ShortBuffer buffer = ((ShortBuffer) m.getObject(DMT.PEER_LOCATIONS));
    double[] locs = Fields.bytesToDoubles(buffer.getData());

    // See: http://archives.freenetproject.org/message/20080718.144240.359e16d3.en.html
    if ((OpennetManager.MAX_PEERS_FOR_SCALING < locs.length) && (source.isOpennet())) {
      if (locs.length > OpennetManager.PANIC_MAX_PEERS) {
        LOG.error(
            "Received {} locations from {}; unexpected count; possible attack",
            locs.length,
            source);
        source.forceDisconnect();
        return true;
      } else {
        LOG.info(
            "Received locations from {}: count={}; using first {}",
            source,
            locs.length,
            OpennetManager.MAX_PEERS_FOR_SCALING);
        locs = Arrays.copyOf(locs, OpennetManager.MAX_PEERS_FOR_SCALING);
      }
    }
    source.updateLocation(newLoc, locs);
    return true;
  }

  private boolean handlePeerLoadStatuses(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPPeerLoadStatusByte
        || spec == DMT.FNPPeerLoadStatusShort
        || spec == DMT.FNPPeerLoadStatusInt) {
      return handlePeerLoadStatus(m, source);
    }
    return false;
  }

  private boolean handleNotRoutableMessages(Message m, MessageType spec) {
    if (LOG.isTraceEnabled()) LOG.trace("Peer not routable");
    if (spec == DMT.FNPCHKDataRequest) {
      rejectRequest(m, node.getNodeStats().chkRequestCtr);
    } else if (spec == DMT.FNPSSKDataRequest) {
      rejectRequest(m, node.getNodeStats().sskRequestCtr);
    } else if (spec == DMT.FNPInsertRequest) {
      rejectRequest(m, node.getNodeStats().chkInsertCtr);
    } else if (spec == DMT.FNPSSKInsertRequest) {
      rejectRequest(m, node.getNodeStats().sskInsertCtr);
    } else if (spec == DMT.FNPSSKInsertRequestNew) {
      rejectRequest(m, node.getNodeStats().sskInsertCtr);
    } else if (spec == DMT.FNPGetOfferedKey) {
      rejectRequest(m, node.getFailureTable().senderCounter);
    } else {
      return false;
    }
    return true;
  }

  private boolean handleSwapMessages(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPSwapRequest) {
      node.getLocationManager().handleSwapRequest(m, source);
      return true;
    } else if (spec == DMT.FNPSwapReply) {
      return node.getLocationManager().handleSwapReply(m, source);
    } else if (spec == DMT.FNPSwapRejected) {
      return node.getLocationManager().handleSwapRejected(m, source);
    } else if (spec == DMT.FNPSwapCommit) {
      return node.getLocationManager().handleSwapCommit(m, source);
    } else if (spec == DMT.FNPSwapComplete) {
      return node.getLocationManager().handleSwapComplete(m, source);
    }
    return false;
  }

  private boolean handleDataOrInsertRequests(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPCHKDataRequest) {
      handleDataRequest(m, false);
      return true;
    } else if (spec == DMT.FNPSSKDataRequest) {
      handleDataRequest(m, true);
      return true;
    } else if (spec == DMT.FNPInsertRequest) {
      handleInsertRequest(m, source, false);
      return true;
    } else if (spec == DMT.FNPSSKInsertRequest || spec == DMT.FNPSSKInsertRequestNew) {
      handleInsertRequest(m, source, true);
      return true;
    }
    return false;
  }

  private boolean handleRoutedMessages(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPRoutedPing) {
      handleRouted(m, source);
      return true;
    } else if (spec == DMT.FNPRoutedPong) {
      return handleRoutedReply(m);
    } else if (spec == DMT.FNPRoutedRejected) {
      return handleRoutedRejected(m);
    }
    return false;
  }

  private boolean handleOfferAndNoderef(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.FNPOfferKey) {
      return handleOfferKey(m, source);
    } else if (spec == DMT.FNPGetOfferedKey) {
      handleGetOfferedKey(m, source);
      return true;
    } else if (spec == DMT.FNPGetYourFullNoderef && source instanceof DarknetPeerNode peerNode1) {
      peerNode1.sendFullNoderef();
      return true;
    } else if (spec == DMT.FNPMyFullNoderef && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleFullNoderef(m);
      return true;
    }
    return false;
  }

  private boolean handleProbe(Message m, PeerNode source, MessageType spec) {
    if (spec == DMT.ProbeRequest) {
      probe.request(m, source);
      return true;
    }
    return false;
  }

  private void rejectRequest(Message m, ByteCounter ctr) {
    long uid = m.getLong(DMT.UID);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      m.getSource().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  private boolean handlePeerLoadStatus(Message m, PeerNode source) {
    PeerLoadStats stat = node.getNodeStats().parseLoadStats(source, m);
    source.reportLoadStatus(stat);
    return true;
  }

  private boolean handleUptime(Message m, PeerNode source) {
    byte uptime = m.getByte(DMT.UPTIME_PERCENT_48H);
    source.setUptime(uptime);
    return true;
  }

  private boolean handleOfferKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    node.getFailureTable().onOffer(key, source, authenticator);
    return true;
  }

  private void handleGetOfferedKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    long uid = m.getLong(DMT.UID);
    if (invalidOfferAuthenticator(source, key, authenticator, uid)) return;
    if (LOG.isDebugEnabled()) LOG.debug("Valid GetOfferedKey (key={}, source={})", key, source);

    boolean isSSK = key instanceof NodeSSK;
    boolean realTimeFlag = DMT.getRealTimeFlag(m);
    OfferReplyTag tag = new OfferReplyTag(isSSK, source, realTimeFlag, uid, node);
    if (rejectAlreadyRunning(uid, isSSK, source, tag)) return;

    processOfferWithLock(m, source, key, isSSK, uid, tag, realTimeFlag);
  }

  private boolean invalidOfferAuthenticator(
      PeerNode source, Key key, byte[] authenticator, long uid) {
    if (HMAC.verifyWithSHA256(
        node.getFailureTable().offerAuthenticatorKey, key.getFullKey(), authenticator)) {
      return false;
    }
    LOG.error("Invalid GetOfferedKey; authenticator does not verify (source={})", source);
    try {
      source.sendAsync(
          DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR),
          null,
          node.getFailureTable().senderCounter);
    } catch (NotConnectedException _) {
      // Too bad.
    }
    return true;
  }

  private boolean rejectAlreadyRunning(
      long uid, boolean isSSK, PeerNode source, OfferReplyTag tag) {
    if (tracker.lockUID(uid, isSSK, false, true, false, tag.realTimeFlag, tag)) {
      if (LOG.isDebugEnabled()) LOG.debug("Lock acquired for id {}", uid);
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug(LOG_ALREADY_RUNNING, uid);
    Message rejected = DMT.createFNPRejectedLoop(uid);
    try {
      source.sendAsync(rejected, null, node.getFailureTable().senderCounter);
    } catch (NotConnectedException e) {
      LOG.info(
          "Reject request; sendAsync failed (peer={}, error={})", source.getPeer(), e.toString());
    }
    return true;
  }

  @SuppressWarnings("java:S1181")
  private void processOfferWithLock(
      Message m,
      PeerNode source,
      Key key,
      boolean isSSK,
      long uid,
      OfferReplyTag tag,
      boolean realTimeFlag) {
    boolean needPubKey;
    try {
      needPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
      RejectReason reject =
          nodeStats.shouldRejectRequest(
              true, false, isSSK, false, true, source, false, false, realTimeFlag, tag);
      if (reject != null) {
        LOG.info("Reject FNPGetOfferedKey (source={}, key={}, reason={})", source, key, reject);
        Message rejected = DMT.createFNPRejectedOverload(uid, true);
        if (reject.soft()) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
        sendAsyncIgnoreNotConnected(source, rejected, node.getFailureTable().senderCounter);
        tag.unlockHandler(reject.soft());
        return;
      }
    } catch (Error | RuntimeException e) {
      tag.unlockHandler();
      throw e;
    }

    try {
      node.getFailureTable().sendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
    } catch (NotConnectedException _) {
      // Too bad.
    }
  }

  private void sendAsyncIgnoreNotConnected(PeerNode peer, Message msg, ByteCounter ctr) {
    try {
      peer.sendAsync(msg, null, ctr);
    } catch (NotConnectedException e) {
      if (LOG.isInfoEnabled())
        LOG.info(
            "Reject (overload) request; sendAsync failed (peer={}, error={})",
            peer.getPeer(),
            e.toString());
    }
  }

  // We need to check the datastore before deciding whether to accept a request.
  // This can block - in bad cases, for a long time.
  // So we need to run it on a separate thread.

  private void handleDisconnect(final Message m, final PeerNode source) {
    // Wait for 1 second to ensure that the ack gets sent first.
    node.getTicker().queueTimedJob(() -> finishDisconnect(m, source), 1000);
  }

  private void finishDisconnect(final Message m, final PeerNode source) {
    source.disconnected(true, true);
    // If true, remove from active routing table, likely to be down for a while.
    // Otherwise, just dump all current connection state and keep trying to connect.
    boolean remove = m.getBoolean(DMT.REMOVE);
    if (remove) {
      node.getPeers().disconnectAndRemove(source, false, false, false);
      if (source instanceof DarknetPeerNode peerNode)
        LOG.info(
            "Disconnecting permanently from your friend \"{}\" because they asked us to remove"
                + " them.",
            peerNode.getName());
    }
    // If true, purge all references to this node. Otherwise, we can keep the node
    // around in secondary tables etc. in order to more easily reconnect later.
    // (Mostly used on opennet)
    boolean purge = m.getBoolean(DMT.PURGE);
    if (purge) {
      OpennetManager om = node.getOpennet();
      if (om != null && source instanceof OpennetPeerNode peerNode)
        om.purgeOldOpennetPeer(peerNode);
    }
    // Process parting message
    int type = m.getInt(DMT.NODE_TO_NODE_MESSAGE_TYPE);
    ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
    if (messageData.getLength() == 0) return;
    node.receivedNodeToNodeMessage(source, type, messageData, true);
  }

  private boolean handleTime(Message m, PeerNode source) {
    long delta = m.getLong(DMT.TIME) - System.currentTimeMillis();
    source.setTimeDelta(delta);
    return true;
  }

  private void handleDataRequest(Message m, boolean isSSK) {
    // Note: could check probablyInStore and handle inline when available.
    // This and DatastoreChecker would need support for that path.
    if (!requestQueue.offer(m)) {
      rejectRequest(
          m, isSSK ? node.getNodeStats().sskRequestCtr : node.getNodeStats().chkRequestCtr);
    }
  }

  /**
   * Handle an incoming insert. We should parse it and determine whether it is valid before we
   * accept it. However, in the case of inserts it *IS* possible for the request sender to cause it
   * to fail later during the receive of the data or the DataInsert.
   *
   * @param m The incoming message.
   * @param source The node that sent the message.
   * @param isSSK True if it is an SSK insert, false if it is a CHK insert.
   */
  private void handleInsertRequest(Message m, PeerNode source, boolean isSSK) {
    ByteCounter ctr = isSSK ? node.getNodeStats().sskInsertCtr : node.getNodeStats().chkInsertCtr;
    long id = m.getLong(DMT.UID);
    boolean realTimeFlag = DMT.getRealTimeFlag(m);
    InsertTag tag = new InsertTag(isSSK, InsertTag.START.REMOTE, source, realTimeFlag, id, node);
    if (rejectAlreadyRunningInsert(id, isSSK, source, ctr, tag)) return;

    InsertOptions opts = parseInsertOptions(m);
    // SSKs don't fix bwlimitDelayTime so shouldn't be accepted when overloaded.
    RejectReason rejectReason =
        nodeStats.shouldRejectRequest(
            !isSSK, true, isSSK, false, false, source, false, opts.preferInsert, realTimeFlag, tag);
    if (rejectReason != null) {
      LOG.info("Reject insert preemptively (peer={}, reason={})", source.getPeer(), rejectReason);
      Message rejected = DMT.createFNPRejectedOverload(id, true);
      if (rejectReason.soft()) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
      try {
        source.sendAsync(rejected, null, ctr);
      } catch (NotConnectedException e) {
        LOG.info(
            "Reject (overload) insert request; sendAsync failed (peer={}, error={})",
            source.getPeer(),
            e.toString());
      }
      tag.unlockHandler(rejectReason.soft());
      return;
    }

    scheduleInsertHandlers(m, source, id, realTimeFlag, tag, opts);
    if (LOG.isDebugEnabled()) LOG.debug("Start InsertHandler for {}", id);
  }

  private boolean rejectAlreadyRunningInsert(
      long id, boolean isSSK, PeerNode source, ByteCounter ctr, InsertTag tag) {
    if (tracker.lockUID(id, isSSK, true, false, false, tag.realTimeFlag, tag)) return false;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_ALREADY_RUNNING, id);
    Message rejected = DMT.createFNPRejectedLoop(id);
    try {
      source.sendAsync(rejected, null, ctr);
    } catch (NotConnectedException e) {
      LOG.info(
          "Reject insert request; sendAsync failed (peer={}, error={})",
          source.getPeer(),
          e.toString());
    }
    return true;
  }

  private record InsertOptions(
      boolean preferInsert, boolean ignoreLowBackoff, boolean forkOnCacheable) {}

  private InsertOptions parseInsertOptions(Message m) {
    boolean preferInsert = Node.PREFER_INSERT_DEFAULT;
    boolean ignoreLowBackoff = Node.IGNORE_LOW_BACKOFF_DEFAULT;
    boolean forkOnCacheable = Node.FORK_ON_CACHEABLE_DEFAULT;
    Message forkControl = m.getSubMessage(DMT.FNPSubInsertForkControl);
    if (forkControl != null)
      forkOnCacheable = forkControl.getBoolean(DMT.ENABLE_INSERT_FORK_WHEN_CACHEABLE);
    Message lowBackoff = m.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff);
    if (lowBackoff != null) ignoreLowBackoff = lowBackoff.getBoolean(DMT.IGNORE_LOW_BACKOFF);
    Message preference = m.getSubMessage(DMT.FNPSubInsertPreferInsert);
    if (preference != null) preferInsert = preference.getBoolean(DMT.PREFER_INSERT);
    return new InsertOptions(preferInsert, ignoreLowBackoff, forkOnCacheable);
  }

  private void scheduleInsertHandlers(
      Message m,
      PeerNode source,
      long id,
      boolean realTimeFlag,
      InsertTag tag,
      InsertOptions opts) {
    long now = System.currentTimeMillis();
    if (m.getSpec().equals(DMT.FNPSSKInsertRequest)) {
      NodeSSK key = (NodeSSK) m.getObject(DMT.FREENET_ROUTING_KEY);
      byte[] data = ((ShortBuffer) m.getObject(DMT.DATA)).getData();
      byte[] headers = ((ShortBuffer) m.getObject(DMT.BLOCK_HEADERS)).getData();
      short htl = m.getShort(DMT.HTL);
      if (htl <= 0) htl = 1;
      SSKInsertHandler rh =
          new SSKInsertHandler(
              key,
              data,
              headers,
              htl,
              source,
              id,
              node,
              now,
              tag,
              node.canWriteDatastoreInsert(htl),
              opts.forkOnCacheable,
              opts.preferInsert,
              opts.ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.getExecutor()
          .execute(rh, "SSKInsertHandler for " + id + " on " + node.getDarknetPortNumber());
    } else if (m.getSpec().equals(DMT.FNPSSKInsertRequestNew)) {
      NodeSSK key = (NodeSSK) m.getObject(DMT.FREENET_ROUTING_KEY);
      short htl = m.getShort(DMT.HTL);
      if (htl <= 0) htl = 1;
      SSKInsertHandler rh =
          new SSKInsertHandler(
              key,
              null,
              null,
              htl,
              source,
              id,
              node,
              now,
              tag,
              node.canWriteDatastoreInsert(htl),
              opts.forkOnCacheable,
              opts.preferInsert,
              opts.ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.getExecutor()
          .execute(rh, "SSKInsertHandler for " + id + " on " + node.getDarknetPortNumber());
    } else {
      NodeCHK key = (NodeCHK) m.getObject(DMT.FREENET_ROUTING_KEY);
      short htl = m.getShort(DMT.HTL);
      if (htl <= 0) htl = 1;
      CHKInsertHandler rh =
          new CHKInsertHandler(
              key,
              htl,
              source,
              id,
              node,
              now,
              tag,
              opts.forkOnCacheable,
              opts.preferInsert,
              opts.ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.getExecutor()
          .execute(rh, "CHKInsertHandler for " + id + " on " + node.getDarknetPortNumber());
    }
  }

  private void handleAnnounceRequest(Message m, PeerNode source) {
    long uid = m.getLong(DMT.UID);
    double target = m.getDouble(DMT.TARGET_LOCATION);
    short htl = (short) Math.min(m.getShort(DMT.HTL), node.maxHTL());
    long xferUID = m.getLong(DMT.TRANSFER_UID);
    int noderefLength = m.getInt(DMT.NODEREF_LENGTH);
    int paddedLength = m.getInt(DMT.PADDED_LENGTH);

    if (rejectIfInvalidAnnounce(source, uid, target, htl, noderefLength, paddedLength)) return;

    OpennetManager om = node.getOpennet();
    if (rejectIfAnnouncementsDisabled(om, source, uid)) return;

    boolean success = false;
    try {
      NodeStats.AnnouncementDecision decision = node.getNodeStats().shouldAcceptAnnouncement(uid);
      if (rejectBasedOnDecision(om, source, uid, decision)) return;
      if (rejectIfPeerLimit(om, source, uid)) return;
      if (rejectIfSeedTrackerLimit(om, source, uid)) return;
      htl = normalizeHtlForSeedClient(source, htl);
      AnnouncementCallback cb = buildAnnounceCallback(source, htl);
      AnnounceSender sender =
          new AnnounceSender(
              target, htl, uid, source, om, node, xferUID, noderefLength, paddedLength, cb);
      node.getExecutor().execute(sender, "Announcement sender for " + uid);
      success = true;
      if (LOG.isDebugEnabled()) LOG.debug("Accepted announcement from {}", source);
    } finally {
      if (!success) source.completedAnnounce(uid);
    }
  }

  private boolean rejectIfInvalidAnnounce(
      PeerNode source, long uid, double target, short htl, int noderefLength, int paddedLength) {
    if (target >= 0.0
        && target < 1.0
        && htl > 0
        && paddedLength >= 0
        && paddedLength <= OpennetManager.MAX_OPENNET_NODEREF_LENGTH
        && noderefLength <= paddedLength) {
      return false;
    }
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled()) LOG.debug("Got bogus announcement message from {}", source);
    return true;
  }

  private boolean rejectIfAnnouncementsDisabled(OpennetManager om, PeerNode source, long uid) {
    if (om != null && source.canAcceptAnnouncements()) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    Message msg = DMT.createFNPOpennetDisabled(uid);
    try {
      source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement; opennet or announcements disabled (source={})", source);
    return true;
  }

  private boolean rejectBasedOnDecision(
      OpennetManager om, PeerNode source, long uid, NodeStats.AnnouncementDecision decision) {
    if (NodeStats.AnnouncementDecision.ACCEPT == decision) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    Message msg;
    switch (decision) {
      case NodeStats.AnnouncementDecision.OVERLOAD -> {
        msg = DMT.createFNPRejectedOverload(uid, true);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Reject announcement due to overall overload (source={})", source);
        }
      }
      case NodeStats.AnnouncementDecision.LOOP -> {
        msg = DMT.createFNPRejectedLoop(uid);
        if (LOG.isDebugEnabled()) {
          LOG.debug("Reject announcement due to loop (source={})", source);
        }
      }
      default -> throw new IllegalStateException("This shouldn't happen. Please report");
    }
    try {
      source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    return true;
  }

  private boolean rejectIfPeerLimit(OpennetManager om, PeerNode source, long uid) {
    if (source.shouldAcceptAnnounce(uid)) return false;
    if (om != null && source instanceof SeedClientPeerNode peerNode)
      om.getSeedTracker().rejectedAnnounce(peerNode);
    node.getNodeStats().endAnnouncement(uid);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement due to peer limit (source={})", source);
    return true;
  }

  private boolean rejectIfSeedTrackerLimit(OpennetManager om, PeerNode source, long uid) {
    if (!(om != null && source instanceof SeedClientPeerNode peerNode)) return false;
    if (om.getSeedTracker().acceptAnnounce(peerNode, node.getFastWeakRandom())) return false;
    node.getNodeStats().endAnnouncement(uid);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
    } catch (NotConnectedException _) {
      // OK
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reject announcement due to seednode limit (source={})", source);
    return true;
  }

  private short normalizeHtlForSeedClient(PeerNode source, short htl) {
    if (source instanceof SeedClientPeerNode) {
      short maxHTL = node.maxHTL();
      if (htl < maxHTL - 1) {
        LOG.error("Seed client announcement not at max HTL: {} (source={})", htl, source);
        return maxHTL;
      }
    }
    return htl;
  }

  private AnnouncementCallback buildAnnounceCallback(PeerNode source, short htl) {
    if (!LOG.isDebugEnabled()) return null;
    final String origin = source + " (htl " + htl + ")";
    return new AnnouncementCallback() {
      private int totalAdded;
      private int totalNotWanted;
      private boolean acceptedSomewhere;

      @Override
      public synchronized void acceptedSomewhere() {
        acceptedSomewhere = true;
      }

      @Override
      public void addedNode(PeerNode pn) {
        synchronized (this) {
          totalAdded++;
        }
        LOG.debug(
            "Announcement {} adds node {}{}",
            origin,
            pn,
            (pn instanceof SeedClientPeerNode ? " (seed server added the peer directly)" : ""));
      }

      @Override
      public void bogusNoderef(String reason) {
        LOG.debug(
            "Announcement {} has invalid noderef: {}", origin, reason, new Exception("debug"));
      }

      @Override
      public void completed() {
        synchronized (this) {
          LOG.debug("Announcement {} completes", origin);
        }
        int shallow = node.maxHTL() - (totalAdded + totalNotWanted);
        if (acceptedSomewhere)
          LOG.debug(
              "Announcement {} completes (added={}, notWanted={}, shallow={})",
              origin,
              totalAdded,
              totalNotWanted,
              shallow);
        else LOG.debug("Announcement {} not accepted anywhere.", origin);
      }

      @Override
      public void nodeFailed(PeerNode pn, String reason) {
        LOG.debug("Announcement {} fails: {}", origin, reason);
      }

      @Override
      public void noMoreNodes() {
        LOG.debug("Announcement {} runs out of nodes (route not found)", origin);
      }

      @Override
      public void nodeNotWanted() {
        synchronized (this) {
          totalNotWanted++;
        }
        LOG.debug("Announcement {}: node not wanted; total={}", origin, totalNotWanted);
      }

      @Override
      public void nodeNotAdded() {
        LOG.debug("Announcement {}: node not added (already present or routing disabled)", origin);
      }

      @Override
      public void relayedNoderef() {
        synchronized (this) {
          totalAdded++;
          LOG.debug(
              "Announcement from {} accepted by a downstream node, relaying noderef for a total of"
                  + " {} from this announcement)",
              origin,
              totalAdded);
        }
      }
    };
  }

  /**
   * Prunes stale routed contexts and reschedules the next check.
   *
   * <p>Removes entries older than {@link #STALE_CONTEXT} and schedules the next run after {@link
   * #STALE_CONTEXT_CHECK} milliseconds.
   */
  @Override
  public void run() {
    long now = System.currentTimeMillis();
    routedContexts.values().removeIf(rc -> now - rc.createdTime > STALE_CONTEXT);
    node.getTicker().queueTimedJob(this, STALE_CONTEXT_CHECK);
  }

  /** Handle a routed rejection (FNPRoutedRejected). */
  private boolean handleRoutedRejected(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    RoutedContext rc = routedContexts.get(id);
    if (rc == null) {
      // No matching context; likely expired or local.
      LOG.error("Unrecognized FNPRoutedRejected; missing context");
      return false; // locally originated??
    }
    short htl = rc.lastHtl;
    if (rc.source != null) htl = rc.source.decrementHTL(htl);
    short ohtl = m.getShort(DMT.HTL);
    if (ohtl < htl) htl = ohtl;
    if (htl == 0) {
      // Equivalent to DNF.
      // Relay.
      if (rc.source != null) {
        try {
          rc.source.sendAsync(
              DMT.createFNPRoutedRejected(id, (short) 0), null, nodeStats.routedMessageCtr);
        } catch (NotConnectedException _) {
          LOG.error("Relay of probe DNF failed; peer disconnected: {}", rc.source);
        }
      }
    } else {
      // Try routing to the next node
      forward(rc.msg, id, rc.source, htl, rc.msg.getDouble(DMT.TARGET_LOCATION), rc, rc.identity);
    }
    return true;
  }

  /**
   * Handles a message addressed to a specific node ("routed" family).
   *
   * <p>Always consumes the message by one of: local dispatch, forward to a next hop, or send an
   * explicit rejection. The method does not return a status; callers should treat the message as
   * handled on return.
   *
   * @param m the message to handle
   * @param source the peer node that sent the message (may be {@code null} during disconnects)
   */
  void handleRouted(Message m, PeerNode source) {
    if (!node.enableRoutedPing()) return;
    if (LOG.isDebugEnabled()) LOG.debug("Handle routed message: {}", m);

    long id = m.getLong(DMT.UID);
    short htl = m.getShort(DMT.HTL);
    byte[] identity = ((ShortBuffer) m.getObject(DMT.NODE_IDENTITY)).getData();
    if (source != null) htl = source.decrementHTL(htl);

    if (rejectDuplicateRoutedIfAny(id, htl, source, m)) return;

    RoutedContext ctx = new RoutedContext(m, source, identity);
    routedContexts.put(id, ctx);

    double target = m.getDouble(DMT.TARGET_LOCATION);
    if (LOG.isDebugEnabled())
      LOG.debug("Routed id={} from {} htl={} target={}", id, source, htl, target);
    processRoutedDispatchOrForward(m, source, id, htl, target, ctx, identity);
  }

  private boolean rejectDuplicateRoutedIfAny(long id, short htl, PeerNode source, Message m) {
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) return false;
    try {
      source.sendAsync(DMT.createFNPRoutedRejected(id, htl), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection rejecting {}", m);
    }
    return true;
  }

  private void processRoutedDispatchOrForward(
      Message m,
      PeerNode source,
      long id,
      short htl,
      double target,
      RoutedContext ctx,
      byte[] identity) {
    if (isLocalTarget(target)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Dispatching {} on {}", m.getSpec(), node.getDarknetPortNumber());
      dispatchRoutedMessage(m, source, id);
      return;
    }
    if (htl == 0) {
      sendRoutedReject(source, id, m);
      return;
    }
    forward(m, id, source, htl, target, ctx, identity);
  }

  private boolean isLocalTarget(double target) {
    return Math.abs(node.getLocationManager().getLocation() - target)
        <= Double.MIN_VALUE; // exact match
  }

  private void sendRoutedReject(PeerNode source, long id, Message m) {
    Message reject = DMT.createFNPRoutedRejected(id, (short) 0);
    if (source != null)
      try {
        source.sendAsync(reject, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection while sending reject for {}", m);
      }
  }

  boolean handleRoutedReply(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    if (LOG.isDebugEnabled()) LOG.debug("Received routed reply: {}", m);
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) {
      LOG.error("Unrecognized routed reply: {}", m);
      return false;
    }
    PeerNode pn = ctx.source;
    if (pn == null) return false;
    try {
      pn.sendAsync(m.cloneAndDropSubMessages(), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection while forwarding {} to {}", m, pn);
    }
    return true;
  }

  private void forward(
      Message m,
      long id,
      PeerNode pn,
      short htl,
      double target,
      RoutedContext ctx,
      byte[] targetIdentity) {
    if (LOG.isDebugEnabled()) LOG.debug("Evaluate forwarding decision");
    m = preForward(m, htl);
    while (true) {
      PeerNode next = selectNextHop(pn, htl, target, ctx, targetIdentity);
      if (LOG.isDebugEnabled()) LOG.debug("Next hop={} message={}", next, m);
      if (next != null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Forward {} to {}", m.getSpec(), next.getPeer().getPort());
        ctx.addSent(next);
        if (!trySendToNext(next, m)) continue;
      } else {
        sendDeadEndReject(pn, id, htl, m);
      }
      return;
    }
  }

  private PeerNode selectNextHop(
      PeerNode pn, short htl, double target, RoutedContext ctx, byte[] targetIdentity) {
    PeerNode next = node.getPeers().getByPubKeyHash(targetIdentity);
    if (next != null && !next.isConnected()) {
      LOG.error("Target found but disconnected: {}", next);
      next = null;
    }
    if (next == null)
      next =
          node.getPeers()
              .closerPeer(
                  pn,
                  ctx.routedTo,
                  target,
                  true,
                  node.isAdvancedModeEnabled(),
                  -1,
                  null,
                  null,
                  htl,
                  0,
                  pn == null,
                  false,
                  false);
    return next;
  }

  private boolean trySendToNext(PeerNode next, Message m) {
    try {
      next.sendAsync(m, null, nodeStats.routedMessageCtr);
      return true;
    } catch (NotConnectedException _) {
      return false;
    }
  }

  private void sendDeadEndReject(PeerNode pn, long id, short htl, Message m) {
    if (LOG.isDebugEnabled())
      LOG.debug("Reach dead end for {} on {}", m.getSpec(), node.getDarknetPortNumber());
    Message reject = DMT.createFNPRoutedRejected(id, htl);
    if (pn != null)
      try {
        pn.sendAsync(reject, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        LOG.error("Send reject back to source {} failed", pn);
      }
  }

  /** Prepare a routed-to-node message for forwarding. */
  private Message preForward(Message m, short newHTL) {
    m = m.cloneAndDropSubMessages();
    m.set(DMT.HTL, newHTL); // update htl
    if (m.getSpec() == DMT.FNPRoutedPing) {
      int x = m.getInt(DMT.COUNTER);
      x++;
      m.set(DMT.COUNTER, x);
    }
    return m;
  }

  /**
   * Deal with a routed-to-node message that landed on this node. This is where
   * message-type-specific code executes.
   *
   * @param m The message to dispatch
   * @param src The source peer node
   * @param id The message ID
   */
  private void dispatchRoutedMessage(Message m, PeerNode src, long id) {
    if (m.getSpec() == DMT.FNPRoutedPing) {
      if (LOG.isDebugEnabled()) LOG.debug("RoutedPing reaches target ({})", id);
      int x = m.getInt(DMT.COUNTER);
      Message reply = DMT.createFNPRoutedPong(id, x);
      if (LOG.isDebugEnabled()) LOG.debug("Reply routed pong; counter={} id={}", x, id);
      try {
        src.sendAsync(reply, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Lost connection while replying to {} in dispatchRoutedMessage", m);
      }
    }
  }

  /**
   * Initializes runtime stats and starts the off-thread request runner.
   *
   * <p>Schedules {@code queueRunner} on the node executor to process data requests taken from the
   * internal queue. Safe to call once during node initialization.
   *
   * @param stats runtime counters and load information used by this dispatcher
   */
  void start(NodeStats stats) {
    this.nodeStats = stats;
    node.getExecutor().execute(queueRunner);
  }

  /**
   * Sets an optional callback to inspect messages as they pass through the dispatcher.
   *
   * <p>Intended for tests and instrumentation. The callback runs on the caller's thread and should
   * return quickly.
   *
   * @param cb callback invoked for each handled message; may be {@code null} to clear
   */
  public void setHook(NodeDispatcherCallback cb) {
    this.callback = cb;
  }

  /** Callback interface for observing dispatcher traffic. */
  public interface NodeDispatcherCallback {
    /**
     * Invoked for each message handled by the dispatcher.
     *
     * @param m the message being processed (never {@code null})
     * @param n the node owning this dispatcher (never {@code null})
     */
    void snoop(Message m, Node n);
  }

  /** Per-UID state for routed message handling. */
  static class RoutedContext {
    final HashSet<PeerNode> routedTo;
    final byte[] identity;
    long createdTime;
    long accessTime;
    PeerNode source;
    Message msg;
    short lastHtl;

    RoutedContext(Message msg, PeerNode source, byte[] identity) {
      createdTime = accessTime = System.currentTimeMillis();
      this.source = source;
      routedTo = new HashSet<>();
      this.msg = msg;
      lastHtl = msg.getShort(DMT.HTL);
      this.identity = identity;
    }

    // Tracks peers the message has been forwarded to; used to avoid loops when choosing next hop.
    void addSent(PeerNode n) {
      routedTo.add(n);
    }
  }
}
