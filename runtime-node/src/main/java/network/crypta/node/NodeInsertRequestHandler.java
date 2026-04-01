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

/**
 * Handles inbound CHK and SSK insert requests at the routing layer.
 *
 * <p>This handler inspects inbound insert messages, validates basic eligibility, and wires the
 * request into the appropriate insert handler. It is invoked from message dispatch with the raw
 * {@link Message} and source {@link PeerNode}, selects the request subtype (CHK, SSK, or SSK-new),
 * and schedules a {@link CHKInsertHandler} or {@link SSKInsertHandler} on the node executor. The
 * entry points are short-lived and non-blocking; long-running work is deferred to the scheduled
 * handler instances.
 *
 * <p>Invariants and lifecycle: a UID is locked with {@link RequestTracker} before work starts to
 * prevent duplicate processing. Rejections are sent immediately when the UID is already active or
 * when {@link NodeStats} indicates overload. Successful requests always result in exactly one
 * handler scheduled, with options derived from optional sub-messages. This class is stateful only
 * in that it caches the {@link NodeStats} reference and is expected to be reinitialized via {@link
 * #start(NodeStats)} when the stats instance changes.
 *
 * <p>Thread-safety: instances are not explicitly synchronized. The handler is expected to be used
 * from the node's message dispatch thread(s); it relies on thread-safe collaborators such as {@link
 * RequestTracker} and {@link NodeStats}. Fields are effectively read-only after construction except
 * for the stats reference updated during startup.
 *
 * <ul>
 *   <li>Parses and validates insert requests for both CHK and SSK keys.
 *   <li>Performs UID locking and overload checks before scheduling work.
 *   <li>Delegates the heavy lifting to type-specific insert handlers.
 * </ul>
 *
 * @see CHKInsertHandler
 * @see SSKInsertHandler
 * @see RequestTracker
 */
final class NodeInsertRequestHandler {

  /** Logger for insert request admission, rejection, and scheduling diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeInsertRequestHandler.class);

  /** Message template used when UID contention prevents accepting an insert. */
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  /** The owning node used for routing, network, and storage interactions. */
  private final Node node;

  /** UID tracker for insert deduplication and lifecycle bookkeeping. */
  private final RequestTracker tracker;

  /** Current statistics instance used for overload checks and counters. */
  private NodeStats nodeStats;

  /**
   * Creates a handler bound to a specific node.
   *
   * <p>The handler snapshots the routing tracker and initial stats reference from the node and
   * expects {@link #start(NodeStats)} to be invoked during startup if the stats instance changes.
   * This constructor performs no I/O and does not schedule work; it only wires references.
   *
   * @param node owning node; must be non-null and fully initialized for routing access
   */
  NodeInsertRequestHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  /**
   * Supplies the current {@link NodeStats} instance after startup.
   *
   * <p>This is a lightweight setter used when the networking subsystem swaps or initializes the
   * stats component. It is expected to be called during node startup and does not retroactively
   * affect in-flight insert handlers; only later admissions use the new reference.
   *
   * @param stats active statistics instance; must be non-null for admission decisions
   */
  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  /**
   * Attempts to handle a single inbound insert request.
   *
   * <p>This method recognizes CHK and SSK insert message types, delegates to the specific insert
   * admission flow, and returns {@code true} when the message type is understood. For other message
   * types it performs no work and returns {@code false}. The method is non-blocking; any long
   * processing is deferred to a handler scheduled via the node executor.
   *
   * @param m inbound protocol message containing the insert request metadata and payload
   * @param source peer that sent the message; used for rejection replies and handler wiring
   * @return {@code true} when the message type is handled; {@code false} otherwise
   */
  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (DMT.FNPInsertRequest.equals(spec)) {
      handleInsertRequest(m, source, false);
      return true;
    } else if (DMT.FNPSSKInsertRequest.equals(spec) || DMT.FNPSSKInsertRequestNew.equals(spec)) {
      handleInsertRequest(m, source, true);
      return true;
    }
    return false;
  }

  /**
   * Handle an incoming insert. We should parse it and determine whether it is valid before we
   * accept it. However, in the case of inserts, it *IS* possible for the request sender to cause it
   * to fail later during the receiving of the data or the DataInsert.
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

    InsertRoutingOptions opts = parseInsertOptions(m);
    // SSKs don't fix bwlimitDelayTime so shouldn't be accepted when overloaded.
    RejectReason rejectReason =
        nodeStats.shouldRejectRequest(
            RequestAdmissionContext.of(
                !isSSK,
                true,
                isSSK,
                false,
                false,
                source,
                false,
                opts.preferInsert(),
                realTimeFlag,
                tag));
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

  /**
   * Attempts to lock the UID and reject the insert if another handler already owns it.
   *
   * <p>On contention, this method sends a {@code FNPRejectedLoop} reply to the source and returns
   * {@code true} to signal that the caller should stop processing. When the UID is successfully
   * locked, it returns {@code false} and leaves the caller responsible for continuing admission and
   * scheduling work.
   *
   * @param id request UID used for de-duplication across concurrent inserts
   * @param isSSK whether the insert targets an SSK key (otherwise CHK)
   * @param source upstream peer to notify when rejection is required
   * @param ctr byte counter used to attribute rejection overhead
   * @param tag the insert tag representing the UID lifecycle for this request
   * @return {@code true} if the insert was rejected due to a duplicate UID
   */
  private boolean rejectAlreadyRunningInsert(
      long id, boolean isSSK, PeerNode source, ByteCounter ctr, InsertTag tag) {
    if (tracker.lockUID(
        id, RequestAdmissionMode.of(false, isSSK, true, false, tag.realTimeFlag), tag))
      return false;
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

  /**
   * Parses insert option submessages into a consolidated option record.
   *
   * <p>Each option is optional and, when absent, falls back to the node defaults. This method does
   * not validate option consistency and performs no side effects beyond reading the message; it is
   * safe to call multiple times but is typically invoked once per request.
   *
   * @param m the insert request message that may carry option submessages
   * @return immutable option snapshot representing defaults plus any overrides present
   */
  private InsertRoutingOptions parseInsertOptions(Message m) {
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
    return new InsertRoutingOptions(preferInsert, ignoreLowBackoff, forkOnCacheable);
  }

  /**
   * Instantiates and schedules the appropriate insert handler for the request type.
   *
   * <p>This method selects a CHK or SSK handler based on the message type, normalizes invalid HTL
   * values to a minimum of {@code 1}, and attaches the configured options and timing metadata. The
   * handler is submitted to the node's priority-aware executor with a descriptive name to aid
   * diagnostics. This method performs no blocking I/O and returns immediately after scheduling.
   *
   * @param m original insert request message containing keys and optional payloads
   * @param source peer that initiated the insert; used as the upstream for the handler
   * @param id request UID used to correlate subsequent protocol messages
   * @param realTimeFlag whether the request should be treated as real-time traffic
   * @param tag insert tag guarding UID lifecycle for this request
   * @param opts parsed insert options derived from request submessages
   */
  private void scheduleInsertHandlers(
      Message m,
      PeerNode source,
      long id,
      boolean realTimeFlag,
      InsertTag tag,
      InsertRoutingOptions opts) {
    long now = System.currentTimeMillis();
    InsertHandlerContext context =
        new InsertHandlerContext(node, source, id, now, tag, opts, realTimeFlag);
    if (m.getSpec().equals(DMT.FNPSSKInsertRequest)) {
      NodeSSK key = (NodeSSK) m.getObject(DMT.FREENET_ROUTING_KEY);
      byte[] data = ((ShortBuffer) m.getObject(DMT.DATA)).getData();
      byte[] headers = ((ShortBuffer) m.getObject(DMT.BLOCK_HEADERS)).getData();
      short htl = m.getShort(DMT.HTL);
      if (htl <= 0) htl = 1;
      SSKInsertHandler rh =
          new SSKInsertHandler(
              key, data, headers, htl, context, node.routing().canWriteDatastoreInsert(htl));
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
              key, null, null, htl, context, node.routing().canWriteDatastoreInsert(htl));
      rh.receivedBytes(m.receivedByteCount());
      node.network()
          .executor()
          .execute(rh, "SSKInsertHandler for " + id + " on " + node.network().darknetPortNumber());
    } else {
      NodeCHK key = (NodeCHK) m.getObject(DMT.FREENET_ROUTING_KEY);
      short htl = m.getShort(DMT.HTL);
      if (htl <= 0) htl = 1;
      CHKInsertHandler rh = new CHKInsertHandler(key, htl, context);
      rh.receivedBytes(m.receivedByteCount());
      node.network()
          .executor()
          .execute(rh, "CHKInsertHandler for " + id + " on " + node.network().darknetPortNumber());
    }
  }
}
