package network.crypta.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
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
 * @author amphibian
 *     <p>Dispatcher for unmatched FNP messages.
 *     <p>What can we get?
 *     <p>SwapRequests
 *     <p>DataRequests
 *     <p>InsertRequests
 *     <p>Probably a few others; those are the important bits.
 *     <p>Requests: - Loop detection only works when the request is actually running. We do NOT
 *     remember what UID's we have routed in the past. Hence there is no possibility of an attacker
 *     probing for old UID's. Also, even in the rare-ish case where a request forks because an
 *     Accepted is delayed, this isn't a big problem: Since we moved on, we're not waiting for it,
 *     there will be no timeout/snarl-up beyond what has already happened. - We should parse the
 *     message completely before checking the UID, overload, and passing it to the handler. Invalid
 *     requests should never be accepted. However, because of inserts, we cannot guarantee that we
 *     never check the UID before we know the request is fully routable.
 */
public class NodeDispatcher implements Dispatcher, Runnable {

  private static final long STALE_CONTEXT = 20000;
  private static final long STALE_CONTEXT_CHECK = 20000;
  private static final Logger LOG = LoggerFactory.getLogger(NodeDispatcher.class);

  final Node node;
  final RequestTracker tracker;
  final Probe probe;
  final Hashtable<Long, RoutedContext> routedContexts = new Hashtable<>();
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
          while (true) {
            try {
              Message msg = requestQueue.take();
              boolean isSSK = msg.getSpec() == DMT.FNPSSKDataRequest;
              innerHandleDataRequest(msg, (PeerNode) msg.getSource(), isSSK);
            } catch (InterruptedException e) {
              // Ignore
            }
          }
        }

        @Override
        public int getPriority() {
          // Slightly less than the actual requests themselves because accepting requests increases
          // load.
          return NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;
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
    if (LOG.isDebugEnabled()) LOG.debug("Dispatching {} from {}", m, source);
    if (callback != null) {
      try {
        callback.snoop(m, node);
      } catch (Throwable t) {
        LOG.error("Callback threw", t);
      }
    }
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPPing) {
      // Send an FNPPong
      Message reply = DMT.createFNPPong(m.getInt(DMT.PING_SEQNO));
      try {
        source.sendAsync(reply, null, pingCounter); // nothing we can do if can't contact source
      } catch (NotConnectedException e) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection replying to {}", m);
      }
      return true;
    } else if (spec == DMT.FNPDetectedIPAddress) {
      Peer p = (Peer) m.getObject(DMT.EXTERNAL_ADDRESS);
      source.setRemoteDetectedPeer(p);
      node.getIpDetector().redetectAddress();
      return true;
    } else if (spec == DMT.FNPTime) {
      return handleTime(m, source);
    } else if (spec == DMT.FNPUptime) {
      return handleUptime(m, source);
    } else if (spec == DMT.FNPVisibility && source instanceof DarknetPeerNode peerNode1) {
      peerNode1.handleVisibility(m);
      return true;
    } else if (spec == DMT.FNPVoid) {
      return true;
    } else if (spec == DMT.FNPDisconnect) {
      handleDisconnect(m, source);
      return true;
    } else if (spec == DMT.nodeToNodeMessage) {
      node.receivedNodeToNodeMessage(m, source);
      return true;
    } else if (spec == DMT.CryptadUOMAnnouncement && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleAnnounce(m, source);
    } else if (spec == DMT.CryptadUOMRequestRevocation && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleRequestRevocation(m, source);
    } else if (spec == DMT.CryptadUOMSendingRevocation && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleSendingRevocation(m, source);
    } else if (spec == DMT.CryptadUOMRequestMainJar
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.getNodeUpdater().getUpdateOverMandatory().handleRequestJar(m, source);
      return true;
    } else if (spec == DMT.CryptadUOMSendingMainJar
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      return node.getNodeUpdater().getUpdateOverMandatory().handleSendingMain(m, source);
    } else if (spec == DMT.CryptadUOMFetchDependency
        && node.getNodeUpdater().supportsJarUOM()
        && source.isRealConnection()) {
      node.getNodeUpdater().getUpdateOverMandatory().handleFetchDependency(m, source);
      return true;
    } else if (spec == DMT.FNPOpennetAnnounceRequest) {
      return handleAnnounceRequest(m, source);
    } else if (spec == DMT.FNPRoutingStatus) {
      if (source instanceof DarknetPeerNode peerNode) {
        boolean value = m.getBoolean(DMT.ROUTING_ENABLED);
        if (LOG.isDebugEnabled())
          LOG.debug("The peer ({}) asked us to set routing={}", source, value);
        peerNode.setRoutingStatus(value, false);
      }
      // We claim it in any case
      return true;
    } else if (source.isRealConnection() && spec == DMT.FNPLocChangeNotificationNew) {
      double newLoc = m.getDouble(DMT.LOCATION);
      ShortBuffer buffer = ((ShortBuffer) m.getObject(DMT.PEER_LOCATIONS));
      double[] locs = Fields.bytesToDoubles(buffer.getData());

      /**
       * Do *NOT* remove the sanity check below!
       *
       * @see http://archives.freenetproject.org/message/20080718.144240.359e16d3.en.html
       */
      if ((OpennetManager.MAX_PEERS_FOR_SCALING < locs.length) && (source.isOpennet())) {
        if (locs.length > OpennetManager.PANIC_MAX_PEERS) {
          // This can't happen by accident
          LOG.error(
              "We received {} locations from {}! That should *NOT* happen! Possible attack!",
              locs.length,
              source);
          source.forceDisconnect();
          return true;
        } else {
          // A few extra can happen by accident. Just use the first 20.
          LOG.info(
              "Too many locations from {} : {} could be an accident, using the first {}",
              source,
              Integer.valueOf(locs.length),
              Integer.valueOf(OpennetManager.MAX_PEERS_FOR_SCALING));
          locs = Arrays.copyOf(locs, OpennetManager.MAX_PEERS_FOR_SCALING);
        }
      }
      // We are on darknet and we trust our peers OR we are on opennet
      // and the amount of locations sent to us seems reasonable
      source.updateLocation(newLoc, locs);

      return true;
    } else if (spec == DMT.FNPPeerLoadStatusByte
        || spec == DMT.FNPPeerLoadStatusShort
        || spec == DMT.FNPPeerLoadStatusInt) {
      // Must be handled before doing the routable check!
      // We may not have received the Location yet, etc.
      return handlePeerLoadStatus(m, source);
    }

    if (!source.isRoutable()) {
      if (LOG.isTraceEnabled()) LOG.trace("Not routable");

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

    if (spec == DMT.FNPSwapRequest) {
      return node.getLocationManager().handleSwapRequest(m, source);
    } else if (spec == DMT.FNPSwapReply) {
      return node.getLocationManager().handleSwapReply(m, source);
    } else if (spec == DMT.FNPSwapRejected) {
      return node.getLocationManager().handleSwapRejected(m, source);
    } else if (spec == DMT.FNPSwapCommit) {
      return node.getLocationManager().handleSwapCommit(m, source);
    } else if (spec == DMT.FNPSwapComplete) {
      return node.getLocationManager().handleSwapComplete(m, source);
    } else if (spec == DMT.FNPCHKDataRequest) {
      handleDataRequest(m, source, false);
      return true;
    } else if (spec == DMT.FNPSSKDataRequest) {
      handleDataRequest(m, source, true);
      return true;
    } else if (spec == DMT.FNPInsertRequest) {
      handleInsertRequest(m, source, false);
      return true;
    } else if (spec == DMT.FNPSSKInsertRequest) {
      handleInsertRequest(m, source, true);
      return true;
    } else if (spec == DMT.FNPSSKInsertRequestNew) {
      handleInsertRequest(m, source, true);
      return true;
    } else if (spec == DMT.FNPRoutedPing) {
      return handleRouted(m, source);
    } else if (spec == DMT.FNPRoutedPong) {
      return handleRoutedReply(m);
    } else if (spec == DMT.FNPRoutedRejected) {
      return handleRoutedRejected(m);
    } else if (spec == DMT.FNPOfferKey) {
      return handleOfferKey(m, source);
    } else if (spec == DMT.FNPGetOfferedKey) {
      return handleGetOfferedKey(m, source);
    } else if (spec == DMT.FNPGetYourFullNoderef && source instanceof DarknetPeerNode peerNode1) {
      peerNode1.sendFullNoderef();
      return true;
    } else if (spec == DMT.FNPMyFullNoderef && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleFullNoderef(m);
      return true;
    } else if (spec == DMT.ProbeRequest) {
      // Response is handled by callbacks within probe.
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
    } catch (NotConnectedException e) {
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

  private boolean handleGetOfferedKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    long uid = m.getLong(DMT.UID);
    if (!HMAC.verifyWithSHA256(
        node.getFailureTable().offerAuthenticatorKey, key.getFullKey(), authenticator)) {
      LOG.error("Invalid offer request from {} : authenticator did not verify", source);
      try {
        source.sendAsync(
            DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR),
            null,
            node.getFailureTable().senderCounter);
      } catch (NotConnectedException e) {
        // Too bad.
      }
      return true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Valid GetOfferedKey for {} from {}", key, source);

    // Do we want it? We can RejectOverload if we don't have the bandwidth...
    boolean isSSK = key instanceof NodeSSK;
    boolean realTimeFlag = DMT.getRealTimeFlag(m);
    OfferReplyTag tag = new OfferReplyTag(isSSK, source, realTimeFlag, uid, node);

    if (!tracker.lockUID(uid, isSSK, false, true, false, realTimeFlag, tag)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Could not lock ID {} -> rejecting (already running)", uid);
      Message rejected = DMT.createFNPRejectedLoop(uid);
      try {
        source.sendAsync(rejected, null, node.getFailureTable().senderCounter);
      } catch (NotConnectedException e) {
        LOG.info("Rejecting request from {}: {}", source.getPeer(), e.toString());
      }
      return true;
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Locked {}", uid);
    }
    boolean needPubKey;
    try {
      needPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
      RejectReason reject =
          nodeStats.shouldRejectRequest(
              true, false, isSSK, false, true, source, false, false, realTimeFlag, tag);
      if (reject != null) {
        LOG.info("Rejecting FNPGetOfferedKey from {} for {} : {}", source, key, reject);
        Message rejected = DMT.createFNPRejectedOverload(uid, true);
        if (reject.soft) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
        try {
          source.sendAsync(rejected, null, node.getFailureTable().senderCounter);
        } catch (NotConnectedException e) {
          LOG.info("Rejecting (overload) data request from {}: {}", source.getPeer(), e.toString());
        }
        tag.unlockHandler(reject.soft);
        return true;
      }

    } catch (Error | RuntimeException e) {
      tag.unlockHandler();
      throw e;
    } // Otherwise, sendOfferedKey is responsible for unlocking.

    // Accept it.

    try {
      node.getFailureTable().sendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
    } catch (NotConnectedException e) {
      // Too bad.
    }
    return true;
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
    // Otherwise just dump all current connection state and keep trying to connect.
    boolean remove = m.getBoolean(DMT.REMOVE);
    if (remove) {
      node.getPeers().disconnectAndRemove(source, false, false, false);
      if (source instanceof DarknetPeerNode peerNode)
        // FIXME remove, dirty logs.
        // FIXME add a useralert?
        System.out.println(
            "Disconnecting permanently from your friend \""
                + peerNode.getName()
                + "\" because they asked us to remove them.");
    }
    // If true, purge all references to this node. Otherwise, we can keep the node
    // around in secondary tables etc in order to more easily reconnect later.
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

  private void handleDataRequest(Message m, PeerNode source, boolean isSSK) {
    // FIXME check probablyInStore and if not, we can handle it inline.
    // This and DatastoreChecker require that method be implemented...
    // For now just handle everything on the thread...
    if (!requestQueue.offer(m)) {
      rejectRequest(
          m, isSSK ? node.getNodeStats().sskRequestCtr : node.getNodeStats().chkRequestCtr);
    }
  }

  /**
   * Handle an incoming FNPDataRequest. We should parse it and determine whether it is valid before
   * we accept it.
   */
  private void innerHandleDataRequest(Message m, PeerNode source, boolean isSSK) {
    if (!source.isConnected()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Handling request off thread, source disconnected: {} for {}", source, m);
      return;
    }
    if (!source.isRoutable()) {
      if (LOG.isDebugEnabled())
        LOG.debug("Handling request off thread, source no longer routable: {} for {}", source, m);
      rejectRequest(
          m, isSSK ? node.getNodeStats().sskRequestCtr : node.getNodeStats().chkRequestCtr);
      return;
    }
    long id = m.getLong(DMT.UID);
    ByteCounter ctr = isSSK ? node.getNodeStats().sskRequestCtr : node.getNodeStats().chkRequestCtr;
    short htl = m.getShort(DMT.HTL);
    if (htl <= 0) htl = 1;
    Key key = (Key) m.getObject(DMT.FREENET_ROUTING_KEY);
    boolean realTimeFlag = DMT.getRealTimeFlag(m);
    final RequestTag tag =
        new RequestTag(isSSK, RequestTag.START.REMOTE, source, realTimeFlag, id, node);
    if (!tracker.lockUID(id, isSSK, false, false, false, realTimeFlag, tag)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Could not lock ID {} -> rejecting (already running)", id);
      Message rejected = DMT.createFNPRejectedLoop(id);
      try {
        source.sendAsync(rejected, null, ctr);
      } catch (NotConnectedException e) {
        LOG.info("Rejecting request from {}: {}", source.getPeer(), e.toString());
      }
      node.getFailureTable().onFinalFailure(key, null, htl, htl, -1, -1, source);
      return;
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Locked {}", id);
    }

    // There are at least 2 threads that call this function.
    // DO NOT reuse the meta object, unless on a per-thread basis.
    // Object allocation is pretty cheap in modern Java anyway...
    // If we do reuse it, call reset().
    BlockMetadata meta = new BlockMetadata();
    KeyBlock block = node.fetch(key, false, false, false, false, meta);
    if (block != null) tag.setNotRoutedOnwards();

    RejectReason rejectReason =
        nodeStats.shouldRejectRequest(
            !isSSK, false, isSSK, false, false, source, block != null, false, realTimeFlag, tag);
    if (rejectReason != null) {
      // can accept 1 CHK request every so often, but not with SSKs because they aren't throttled so
      // won't sort out bwlimitDelayTime, which was the whole reason for accepting them when
      // overloaded...
      LOG.info(
          "Rejecting {} request from {} preemptively because {}",
          (isSSK ? "SSK" : "CHK"),
          source.getPeer(),
          rejectReason);
      Message rejected = DMT.createFNPRejectedOverload(id, true);
      if (rejectReason.soft) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
      try {
        source.sendAsync(rejected, null, ctr);
      } catch (NotConnectedException e) {
        LOG.info("Rejecting (overload) data request from {}: {}", source.getPeer(), e.toString());
      }
      tag.setRejected();
      tag.unlockHandler(rejectReason.soft);
      // Do not tell failure table.
      // Otherwise an attacker can flood us with requests very cheaply and purge our
      // failure table even though we didn't accept any of them.
      return;
    }
    nodeStats.reportIncomingRequestLocation(key.toNormalizedDouble());
    // if(!node.lockUID(id)) return false;
    boolean needsPubKey = false;
    if (key instanceof NodeSSK) needsPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
    RequestHandler rh =
        new RequestHandler(source, id, node, htl, key, tag, block, realTimeFlag, needsPubKey);
    rh.receivedBytes(m.receivedByteCount());
    node.getExecutor()
        .execute(rh, "RequestHandler for UID " + id + " on " + node.getDarknetPortNumber());
  }

  /**
   * Handle an incoming insert. We should parse it and determine whether it is valid before we
   * accept it. However in the case of inserts it *IS* possible for the request sender to cause it
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
    if (!tracker.lockUID(id, isSSK, true, false, false, realTimeFlag, tag)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Could not lock ID {} -> rejecting (already running)", id);
      Message rejected = DMT.createFNPRejectedLoop(id);
      try {
        source.sendAsync(rejected, null, ctr);
      } catch (NotConnectedException e) {
        LOG.info("Rejecting insert request from {}: {}", source.getPeer(), e.toString());
      }
      return;
    }
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
    // SSKs don't fix bwlimitDelayTime so shouldn't be accepted when overloaded.
    RejectReason rejectReason =
        nodeStats.shouldRejectRequest(
            !isSSK, true, isSSK, false, false, source, false, preferInsert, realTimeFlag, tag);
    if (rejectReason != null) {
      LOG.info("Rejecting insert from {} preemptively because {}", source.getPeer(), rejectReason);
      Message rejected = DMT.createFNPRejectedOverload(id, true);
      if (rejectReason.soft) rejected.addSubMessage(DMT.createFNPRejectIsSoft());
      try {
        source.sendAsync(rejected, null, ctr);
      } catch (NotConnectedException e) {
        LOG.info("Rejecting (overload) insert request from {}: {}", source.getPeer(), e.toString());
      }
      tag.unlockHandler(rejectReason.soft);
      return;
    }
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
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
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
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
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
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.getExecutor()
          .execute(rh, "CHKInsertHandler for " + id + " on " + node.getDarknetPortNumber());
    }
    if (LOG.isDebugEnabled()) LOG.debug("Started InsertHandler for {}", id);
  }

  private boolean handleAnnounceRequest(Message m, PeerNode source) {
    long uid = m.getLong(DMT.UID);
    double target = m.getDouble(DMT.TARGET_LOCATION); // FIXME validate
    short htl = (short) Math.min(m.getShort(DMT.HTL), node.maxHTL());
    long xferUID = m.getLong(DMT.TRANSFER_UID);
    int noderefLength = m.getInt(DMT.NODEREF_LENGTH);
    int paddedLength = m.getInt(DMT.PADDED_LENGTH);

    // Only accept a valid message. See comments at top of NodeDispatcher, but it's a good idea
    // anyway.
    if (target < 0.0
        || target >= 1.0
        || htl <= 0
        || paddedLength < 0
        || paddedLength > OpennetManager.MAX_OPENNET_NODEREF_LENGTH
        || noderefLength > paddedLength) {
      Message msg = DMT.createFNPRejectedOverload(uid, true);
      try {
        source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
      } catch (NotConnectedException e) {
        // OK
      }
      if (LOG.isDebugEnabled()) LOG.debug("Got bogus announcement message from {}", source);
      return true;
    }

    OpennetManager om = node.getOpennet();
    if (om == null || !source.canAcceptAnnouncements()) {
      if (om != null && source instanceof SeedClientPeerNode peerNode)
        om.getSeedTracker().rejectedAnnounce(peerNode);
      Message msg = DMT.createFNPOpennetDisabled(uid);
      try {
        source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
      } catch (NotConnectedException e) {
        // OK
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Rejected announcement (opennet or announcement disabled) from {}", source);
      return true;
    }
    boolean success = false;
    try {
      // UIDs for announcements are separate from those for requests.
      // So we don't need to, and should not, ask Node.
      NodeStats.AnnouncementDecision shouldAcceptAnnouncement =
          node.getNodeStats().shouldAcceptAnnouncement(uid);
      if (!(NodeStats.AnnouncementDecision.ACCEPT == shouldAcceptAnnouncement)) {
        if (om != null && source instanceof SeedClientPeerNode peerNode)
          om.getSeedTracker().rejectedAnnounce(peerNode);
        Message msg = null;
        if (NodeStats.AnnouncementDecision.OVERLOAD == shouldAcceptAnnouncement) {
          msg = DMT.createFNPRejectedOverload(uid, true);
          if (LOG.isDebugEnabled())
            LOG.debug("Rejected announcement (overall overload) from {}", source);
        } else if (NodeStats.AnnouncementDecision.LOOP == shouldAcceptAnnouncement) {
          msg = DMT.createFNPRejectedLoop(uid);
          if (LOG.isDebugEnabled()) LOG.debug("Rejected announcement (loop) from {}", source);
        } else {
          throw new Error("This shouldn't happen. Please report");
        }

        try {
          source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
        } catch (NotConnectedException e) {
          // OK
        }
        return true;
      }
      if (!source.shouldAcceptAnnounce(uid)) {
        if (om != null && source instanceof SeedClientPeerNode peerNode)
          om.getSeedTracker().rejectedAnnounce(peerNode);
        node.getNodeStats().endAnnouncement(uid);
        Message msg = DMT.createFNPRejectedOverload(uid, true);
        try {
          source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
        } catch (NotConnectedException e) {
          // OK
        }
        if (LOG.isDebugEnabled()) LOG.debug("Rejected announcement (peer limit) from {}", source);
        return true;
      }
      if (om != null && source instanceof SeedClientPeerNode peerNode) {
        if (!om.getSeedTracker().acceptAnnounce(peerNode, node.getFastWeakRandom())) {
          node.getNodeStats().endAnnouncement(uid);
          Message msg = DMT.createFNPRejectedOverload(uid, true);
          try {
            source.sendAsync(msg, null, node.getNodeStats().announceByteCounter);
          } catch (NotConnectedException e) {
            // OK
          }
          if (LOG.isDebugEnabled())
            LOG.debug("Rejected announcement (seednode limit) from {}", source);
          return true;
        }
      }
      if (source instanceof SeedClientPeerNode) {
        short maxHTL = node.maxHTL();
        if (htl < maxHTL - 1) {
          LOG.error("Announcement from seed client not at max HTL: {} for {}", htl, source);
          htl = maxHTL;
        }
      }
      AnnouncementCallback cb = null;
      if (LOG.isDebugEnabled()) {
        final String origin = source + " (htl " + htl + ")";
        // Log the progress of the announcement.
        // This is similar to Announcer's logging.
        cb =
            new AnnouncementCallback() {
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
                    "Announcement from {} added node {}{}",
                    origin,
                    pn,
                    (pn instanceof SeedClientPeerNode
                        ? " (seed server added the peer directly)"
                        : ""));
              }

              @Override
              public void bogusNoderef(String reason) {
                LOG.debug(
                    "Announcement from {} got bogus noderef: {}",
                    origin,
                    reason,
                    new Exception("debug"));
              }

              @Override
              public void completed() {
                synchronized (this) {
                  LOG.debug("Announcement from {} completed", origin);
                }
                int shallow = node.maxHTL() - (totalAdded + totalNotWanted);
                if (acceptedSomewhere)
                  LOG.debug(
                      "Announcement from {} completed ({} added, {} not wanted, {} shallow)",
                      origin,
                      Integer.valueOf(totalAdded),
                      Integer.valueOf(totalNotWanted),
                      Integer.valueOf(shallow));
                else LOG.debug("Announcement from {} not accepted anywhere.", origin);
              }

              @Override
              public void nodeFailed(PeerNode pn, String reason) {
                LOG.debug("Announcement from {} failed: {}", origin, reason);
              }

              @Override
              public void noMoreNodes() {
                LOG.debug("Announcement from {} ran out of nodes (route not found)", origin);
              }

              @Override
              public void nodeNotWanted() {
                synchronized (this) {
                  totalNotWanted++;
                }
                LOG.debug(
                    "Announcement from {} returned node not wanted for a total of {} from this"
                        + " announcement)",
                    origin,
                    Integer.valueOf(totalNotWanted));
              }

              @Override
              public void nodeNotAdded() {
                LOG.debug(
                    "Announcement from {} : node not wanted (maybe already have it, opennet just"
                        + " turned off, etc)",
                    origin);
              }

              @Override
              public void relayedNoderef() {
                synchronized (this) {
                  totalAdded++;
                  LOG.debug(
                      "Announcement from {} accepted by a downstream node, relaying noderef for a"
                          + " total of {} from this announcement)",
                      origin,
                      Integer.valueOf(totalAdded));
                }
              }
            };
      }
      AnnounceSender sender =
          new AnnounceSender(
              target, htl, uid, source, om, node, xferUID, noderefLength, paddedLength, cb);
      node.getExecutor().execute(sender, "Announcement sender for " + uid);
      success = true;
      if (LOG.isDebugEnabled()) LOG.debug("Accepted announcement from {}", source);
      return true;
    } finally {
      if (!success) source.completedAnnounce(uid);
    }
  }

  /** Cleanup any old/stale routing contexts and reschedule execution. */
  @Override
  public void run() {
    long now = System.currentTimeMillis();
    synchronized (routedContexts) {
      Iterator<RoutedContext> i = routedContexts.values().iterator();
      while (i.hasNext()) {
        RoutedContext rc = i.next();
        if (now - rc.createdTime > STALE_CONTEXT) {
          i.remove();
        }
      }
    }
    node.getTicker().queueTimedJob(this, STALE_CONTEXT_CHECK);
  }

  /** Handle an FNPRoutedRejected message. */
  private boolean handleRoutedRejected(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    RoutedContext rc = routedContexts.get(id);
    if (rc == null) {
      // Gah
      LOG.error("Unrecognized FNPRoutedRejected");
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
        } catch (NotConnectedException e) {
          // Ouch.
          LOG.error("Unable to relay probe DNF: peer disconnected: {}", rc.source);
        }
      }
    } else {
      // Try routing to the next node
      forward(rc.msg, id, rc.source, htl, rc.msg.getDouble(DMT.TARGET_LOCATION), rc, rc.identity);
    }
    return true;
  }

  /**
   * Handle a routed-to-a-specific-node message.
   *
   * @param m The message to handle
   * @param source The peer node that sent the message
   * @return False if we want the message put back on the queue.
   */
  boolean handleRouted(Message m, PeerNode source) {
    if (!node.enableRoutedPing()) return true;
    if (LOG.isDebugEnabled()) LOG.debug("handleRouted({})", m);

    long id = m.getLong(DMT.UID);
    short htl = m.getShort(DMT.HTL);
    byte[] identity = ((ShortBuffer) m.getObject(DMT.NODE_IDENTITY)).getData();
    if (source != null) htl = source.decrementHTL(htl);
    RoutedContext ctx;
    ctx = routedContexts.get(id);
    if (ctx != null) {
      try {
        source.sendAsync(DMT.createFNPRoutedRejected(id, htl), null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException e) {
        if (LOG.isDebugEnabled()) LOG.debug("Lost connection rejecting {}", m);
      }
      return true;
    }
    ctx = new RoutedContext(m, source, identity);
    synchronized (routedContexts) {
      routedContexts.put(id, ctx);
    }
    // source == null => originated locally, keep full htl
    double target = m.getDouble(DMT.TARGET_LOCATION);
    if (LOG.isDebugEnabled()) LOG.debug("id {} from {} htl {} target {}", id, source, htl, target);
    if (Math.abs(node.getLocationManager().getLocation() - target) <= Double.MIN_VALUE) {
      if (LOG.isDebugEnabled())
        LOG.debug("Dispatching {} on {}", m.getSpec(), node.getDarknetPortNumber());
      // Handle locally
      // Message type specific processing
      dispatchRoutedMessage(m, source, id);
      return true;
    } else if (htl == 0) {
      Message reject = DMT.createFNPRoutedRejected(id, (short) 0);
      if (source != null)
        try {
          source.sendAsync(reject, null, nodeStats.routedMessageCtr);
        } catch (NotConnectedException e) {
          if (LOG.isDebugEnabled()) LOG.debug("Lost connection rejecting {}", m);
        }
      return true;
    } else {
      return forward(m, id, source, htl, target, ctx, identity);
    }
  }

  boolean handleRoutedReply(Message m) {
    if (!node.enableRoutedPing()) return true;
    long id = m.getLong(DMT.UID);
    if (LOG.isDebugEnabled()) LOG.debug("Got reply: {}", m);
    RoutedContext ctx = routedContexts.get(id);
    if (ctx == null) {
      LOG.error("Unrecognized routed reply: {}", m);
      return false;
    }
    PeerNode pn = ctx.source;
    if (pn == null) return false;
    try {
      pn.sendAsync(m.cloneAndDropSubMessages(), null, nodeStats.routedMessageCtr);
    } catch (NotConnectedException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection forwarding {} to {}", m, pn);
    }
    return true;
  }

  private boolean forward(
      Message m,
      long id,
      PeerNode pn,
      short htl,
      double target,
      RoutedContext ctx,
      byte[] targetIdentity) {
    if (LOG.isDebugEnabled()) LOG.debug("Should forward");
    // Forward
    m = preForward(m, htl);
    while (true) {
      PeerNode next = node.getPeers().getByPubKeyHash(targetIdentity);
      if (next != null && !next.isConnected()) {
        LOG.error("Found target but disconnected!: {}", next);
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
      if (LOG.isDebugEnabled()) LOG.debug("Next: {} message: {}", next, m);
      if (next != null) {
        // next is connected, or at least has been => next.getPeer() CANNOT be null.
        if (LOG.isDebugEnabled())
          LOG.debug("Forwarding {} to {}", m.getSpec(), next.getPeer().getPort());
        ctx.addSent(next);
        try {
          next.sendAsync(m, null, nodeStats.routedMessageCtr);
        } catch (NotConnectedException e) {
          continue;
        }
      } else {
        if (LOG.isDebugEnabled())
          LOG.debug("Reached dead end for {} on {}", m.getSpec(), node.getDarknetPortNumber());
        // Reached a dead end...
        Message reject = DMT.createFNPRoutedRejected(id, htl);
        if (pn != null)
          try {
            pn.sendAsync(reject, null, nodeStats.routedMessageCtr);
          } catch (NotConnectedException e) {
            LOG.error("Cannot send reject message back to source {}", pn);
            return true;
          }
      }
      return true;
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
   * @return True if the message was handled successfully
   */
  private boolean dispatchRoutedMessage(Message m, PeerNode src, long id) {
    if (m.getSpec() == DMT.FNPRoutedPing) {
      if (LOG.isDebugEnabled()) LOG.debug("RoutedPing reached other side! ({})", id);
      int x = m.getInt(DMT.COUNTER);
      Message reply = DMT.createFNPRoutedPong(id, x);
      if (LOG.isDebugEnabled()) LOG.debug("Replying - counter = {} for {}", Integer.valueOf(x), id);
      try {
        src.sendAsync(reply, null, nodeStats.routedMessageCtr);
      } catch (NotConnectedException e) {
        if (LOG.isDebugEnabled())
          LOG.debug("Lost connection replying to {} in dispatchRoutedMessage", m);
      }
      return true;
    }
    return false;
  }

  void start(NodeStats stats) {
    this.nodeStats = stats;
    node.getExecutor().execute(queueRunner);
  }

  public void setHook(NodeDispatcherCallback cb) {
    this.callback = cb;
  }

  public interface NodeDispatcherCallback {
    void snoop(Message m, Node n);
  }

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

    void addSent(PeerNode n) {
      routedTo.add(n);
    }
  }
}
