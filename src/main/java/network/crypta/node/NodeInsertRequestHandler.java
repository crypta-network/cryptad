package network.crypta.node;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles incoming insert requests (CHK and SSK). */
final class NodeInsertRequestHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeInsertRequestHandler.class);
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  private final Node node;
  private final RequestTracker tracker;
  private NodeStats nodeStats;

  NodeInsertRequestHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPInsertRequest) {
      handleInsertRequest(m, source, false);
      return true;
    } else if (spec == DMT.FNPSSKInsertRequest || spec == DMT.FNPSSKInsertRequestNew) {
      handleInsertRequest(m, source, true);
      return true;
    }
    return false;
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
    ByteCounter ctr =
        isSSK ? node.network().stats().sskInsertCtr : node.network().stats().chkInsertCtr;
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
        source.transport().sendAsync(rejected, null, ctr);
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
      source.transport().sendAsync(rejected, null, ctr);
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
              node.routing().canWriteDatastoreInsert(htl),
              opts.forkOnCacheable,
              opts.preferInsert,
              opts.ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.network()
          .executor()
          .execute(rh, "SSKInsertHandler for " + id + " on " + node.network().darknetPortNumber());
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
              node.routing().canWriteDatastoreInsert(htl),
              opts.forkOnCacheable,
              opts.preferInsert,
              opts.ignoreLowBackoff,
              realTimeFlag);
      rh.receivedBytes(m.receivedByteCount());
      node.network()
          .executor()
          .execute(rh, "SSKInsertHandler for " + id + " on " + node.network().darknetPortNumber());
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
      node.network()
          .executor()
          .execute(rh, "CHKInsertHandler for " + id + " on " + node.network().darknetPortNumber());
    }
  }
}
