package network.crypta.node;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.OpennetAnnounceRequest;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends or forwards an Opennet announce request carrying a node reference ("noderef").
 *
 * <p>The sender chooses successive peers that are closer to a target location and relays replies
 * back to the request source. It manages the initial handshake, HTL (hop-to-live) decrementing,
 * acceptance/rejection handling, and final completion or route-not-found signaling. Byte accounting
 * is reported via {@link ByteCounter}.
 *
 * <p>Threading: an instance is designed to be executed once on the node's executor. Incoming
 * AnnouncementReply payloads are validated and relayed on background tasks; before emitting a
 * terminal message (Completed or RouteNotFound), the instance waits for those background tasks to
 * finish to avoid dropping late replies.
 */
public class AnnounceSender implements PrioRunnable, ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(AnnounceSender.class);

  // Timeouts (milliseconds)
  static final int ACCEPTED_TIMEOUT = 10000;
  static final int ANNOUNCE_TIMEOUT =
      120000; // Longer than a regular request: noderefs transfer hop-by-hop.
  static final int END_TIMEOUT =
      30000; // After receiving Completed, wait for late, possibly reordered replies.
  // Replies may arrive slightly after completion due to reordering.

  private final PeerNode source;
  private final long uid;
  private final OpennetManager om;
  private final Node node;
  private final long xferUID;
  private final int noderefLength;
  private final int paddedLength;
  private byte[] noderefBuf;
  private short htl;
  private final double target;
  private final AnnouncementCallback cb;
  private final PeerNode onlyNode;
  private int forwardedRefs;

  /**
   * Creates a sender used while forwarding an incoming announcement from another peer.
   *
   * @param request announce request metadata describing the target, HTL, and transfer sizes
   * @param source upstream peer that originated the request we are forwarding
   * @param om opennet manager for protocol helpers and crypto
   * @param node local node services and executors
   * @param cb optional callback for progress notifications; may be {@code null}
   */
  public AnnounceSender(
      OpennetAnnounceRequest request,
      PeerNode source,
      OpennetManager om,
      Node node,
      AnnouncementCallback cb) {
    this.source = source;
    this.uid = request.uid();
    this.om = om;
    this.node = node;
    this.onlyNode = null;
    this.htl = request.htl();
    this.xferUID = request.transferUID();
    this.paddedLength = request.paddedLength();
    this.noderefLength = request.noderefLength();
    this.target = request.target();
    this.cb = cb;
  }

  /**
   * Creates a sender for an origin announcement initiated by this node.
   *
   * <p>The noderef to broadcast is taken from our crypto state. When {@code onlyNode} is supplied,
   * the announcement is attempted only to that peer; otherwise the routing chooses successive
   * closer peers.
   *
   * @param target Location key we route toward.
   * @param om Opennet manager for protocol helpers and crypto.
   * @param node Local node services and executors.
   * @param cb Optional callback for progress notifications; may be {@code null}.
   * @param onlyNode If non-null, restricts sending to this single peer.
   */
  public AnnounceSender(
      double target, OpennetManager om, Node node, AnnouncementCallback cb, PeerNode onlyNode) {
    source = null;
    this.uid = node.bootstrap().random().nextLong();
    // Prevent it being routed back to us.
    node.routing().tracker().completed(uid);
    this.om = om;
    this.node = node;
    this.htl = node.maxHTL();
    this.target = target;
    this.cb = cb;
    this.onlyNode = onlyNode;
    noderefBuf = om.getCrypto().myCompressedFullRef();
    this.xferUID = 0;
    this.paddedLength = 0;
    this.noderefLength = 0;
  }

  /**
   * Executes the announcement routing loop.
   *
   * <p>Always performs cleanup and stats reporting on exit, including notifying the tracker and
   * completing the {@link AnnouncementCallback} when provided. All exceptions are caught and logged
   * to avoid tearing down the executor thread.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    try {
      realRun();
      node.network().stats().reportAnnounceForwarded(forwardedRefs, source);
    } catch (Throwable t) {
      LOG.error("Caught {} announcing {} from {}", t, uid, source, t);
    } finally {
      if (source != null) {
        source.completedAnnounce(uid);
      }
      node.routing().tracker().completed(uid);
      if (cb != null) cb.completed();
      node.network().stats().endAnnouncement(uid);
    }
  }

  private void realRun() {
    if (!initialHandshakeAndMaybeTransfer()) {
      return;
    }

    RoutingState state = new RoutingState();
    boolean keepRunning = true;
    while (keepRunning) {
      keepRunning = processNextHop(state);
    }
  }

  private static final class RoutingState {
    private final Set<PeerNode> nodesRoutedTo = new HashSet<>();
    private PeerNode last;
    private boolean hasForwarded;
  }

  private boolean processNextHop(RoutingState state) {
    if (LOG.isDebugEnabled()) LOG.debug("htl={}", getHtl());

    updateHtl(state.hasForwarded, state.last);

    if (shouldCompleteNow()) {
      complete();
      return false;
    }

    PeerNode next = chooseNextNode(state.nodesRoutedTo);
    if (next == null) {
      handleNoNextNode();
      return false;
    }

    NodeProcessResult result = routeOnce(state.nodesRoutedTo, next);
    return applyRouteResult(state, next, result);
  }

  private void handleNoNextNode() {
    if (onlyNode == null) {
      rnf(null);
    }
  }

  private boolean applyRouteResult(RoutingState state, PeerNode next, NodeProcessResult result) {
    return switch (result) {
      case TERMINATE -> false;
      case CONTINUE_FORWARDED -> {
        state.hasForwarded = true;
        state.last = next;
        yield true;
      }
      case CONTINUE_NO_FORWARD -> {
        // Track the attempted peer even if we failed to send/forward.
        // This keeps HTL decrement attribution consistent with the peer we just tried.
        state.last = next;
        yield true;
      }
    };
  }

  private enum NodeProcessResult {
    TERMINATE,
    CONTINUE_NO_FORWARD,
    CONTINUE_FORWARDED
  }

  private NodeProcessResult routeOnce(Set<PeerNode> nodesRoutedTo, PeerNode next) {
    short currentHtl = getHtl();
    if (LOG.isDebugEnabled()) LOG.debug("Routing request to {}", next);
    if (onlyNode == null)
      PeerNodeRoutingReporter.reportRoutedTo(
          node,
          next,
          new PeerNodeRoutingReportParams(
              target, source == null, false, source, nodesRoutedTo, currentHtl));
    nodesRoutedTo.add(next);

    long transferUID = sendTo(next, currentHtl);
    if (transferUID == -1) {
      return NodeProcessResult.CONTINUE_NO_FORWARD;
    }

    if (!waitForAccepted(next)) {
      return NodeProcessResult.CONTINUE_FORWARDED;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Got Accepted");
    if (cb != null) cb.acceptedSomewhere();

    if (!sendRestSafely(next, transferUID)) {
      return NodeProcessResult.CONTINUE_FORWARDED;
    }

    if (waitForFinalResponses(next) == Flow.TERMINATE) {
      return NodeProcessResult.TERMINATE;
    }

    return NodeProcessResult.CONTINUE_FORWARDED;
  }

  private boolean shouldCompleteNow() {
    return (getHtl() == 0) || !node.network().isOpennetEnabled();
  }

  private void updateHtl(boolean hasForwarded, PeerNode last) {
    if (onlyNode == null) {
      // Decrement at this point so HTL==0 is detected before routing the next hop.
      short currentHtl = getHtl();
      short decremented = node.routing().decrementHTL(hasForwarded ? last : source, currentHtl);
      setHtl(decremented);
    }
  }

  private PeerNode chooseNextNode(Set<PeerNode> routed) {
    if (onlyNode == null) {
      return node.network()
          .peers()
          .routingSelector()
          .closerPeer(
              new PeerRoutingSelectionParams(
                  source,
                  routed,
                  target,
                  true,
                  node.isAdvancedModeEnabled(),
                  -1,
                  null,
                  2.0,
                  null,
                  getHtl(),
                  0L,
                  source == null,
                  false,
                  null,
                  false,
                  System.currentTimeMillis(),
                  false));
    }
    if (routed.contains(onlyNode)) {
      rnf(onlyNode);
      return null;
    }
    return onlyNode;
  }

  private boolean initialHandshakeAndMaybeTransfer() {
    if (source == null) return true;
    try {
      source.transport().sendAsync(DMT.createFNPAccepted(uid), null, this);
    } catch (NotConnectedException _) {
      return false;
    }
    return transferNoderef();
  }

  private enum Flow {
    CONTINUE,
    TERMINATE
  }

  private boolean waitForAccepted(PeerNode next) {
    while (true) {
      MessageFilter mf = buildAcceptedWaitFilter(next);
      Message msg;
      try {
        msg = node.network().usm().waitFor(mf, this);
        if (LOG.isDebugEnabled()) LOG.debug("Accepted wait received {}", msg);
      } catch (DisconnectedException _) {
        LOG.info("Disconnected from {} while waiting for Accepted (uid={})", next, uid);
        return false;
      }

      AcceptWaitOutcome outcome = evaluateAcceptedMessage(msg);
      if (outcome == AcceptWaitOutcome.ACCEPTED) return true;
      if (outcome == AcceptWaitOutcome.TRY_ANOTHER) return false;
      // KEEP_WAITING: loop again
    }
  }

  private enum AcceptWaitOutcome {
    ACCEPTED,
    TRY_ANOTHER,
    KEEP_WAITING
  }

  private MessageFilter buildAcceptedWaitFilter(PeerNode next) {
    MessageFilter mfAccepted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ACCEPTED_TIMEOUT)
            .setType(DMT.FNPAccepted);
    // Build alternative message filters in priority order; all constrain the same UID.
    MessageFilter mfRejectedLoop =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ACCEPTED_TIMEOUT)
            .setType(DMT.FNPRejectedLoop);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ACCEPTED_TIMEOUT)
            .setType(DMT.FNPRejectedOverload);
    MessageFilter mfOpennetDisabled =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ACCEPTED_TIMEOUT)
            .setType(DMT.FNPOpennetDisabled);
    return mfRejectedOverload.or(mfRejectedLoop.or(mfOpennetDisabled.or(mfAccepted)));
  }

  private AcceptWaitOutcome evaluateAcceptedMessage(Message msg) {
    if (msg == null) {
      if (LOG.isDebugEnabled()) LOG.debug("Accepted wait timed out");
      return AcceptWaitOutcome.TRY_ANOTHER;
    }
    MessageType spec = msg.getSpec();
    if (DMT.FNPRejectedLoop.equals(spec)) {
      if (LOG.isDebugEnabled()) LOG.debug("Accepted rejected: loop");
      return AcceptWaitOutcome.TRY_ANOTHER;
    } else if (DMT.FNPRejectedOverload.equals(spec)) {
      if (LOG.isDebugEnabled()) LOG.debug("Accepted rejected: overload");
      return AcceptWaitOutcome.TRY_ANOTHER;
    } else if (DMT.FNPOpennetDisabled.equals(spec)) {
      if (LOG.isDebugEnabled()) LOG.debug("Accepted rejected: opennet disabled");
      return AcceptWaitOutcome.TRY_ANOTHER;
    } else if (DMT.FNPAccepted.equals(spec)) {
      return AcceptWaitOutcome.ACCEPTED;
    }
    LOG.error("Unrecognized accepted-wait message: {}", msg);
    return AcceptWaitOutcome.KEEP_WAITING;
  }

  private boolean sendRestSafely(PeerNode next, long xferUID) {
    try {
      sendRest(next, xferUID);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Not connected while sending noderef on {}", next);
      return false;
    }
  }

  private Flow waitForFinalResponses(PeerNode next) {
    while (true) {
      Message msg;
      MessageFilter mf = buildFinalWaitFilter(next);
      try {
        msg = node.network().usm().waitFor(mf, this);
      } catch (DisconnectedException _) {
        LOG.info("Disconnected from {} while waiting for final announcement response", next);
        return Flow.CONTINUE;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Final response received {}", msg);

      FinalOutcome outcome = evaluateFinalMessage(msg, next);
      if (outcome == FinalOutcome.TERMINATE) {
        return Flow.TERMINATE;
      }
      if (outcome == FinalOutcome.CONTINUE) {
        // Exit the final-response wait loop and try another peer.
        return Flow.CONTINUE;
      }
      if (outcome == FinalOutcome.COMPLETED) {
        handleCompletedSequence(next);
        return Flow.TERMINATE;
      }
      // KEEP_WAITING: loop again
    }
  }

  private enum FinalOutcome {
    TERMINATE,
    CONTINUE,
    COMPLETED,
    KEEP_WAITING
  }

  private MessageFilter buildFinalWaitFilter(PeerNode next) {
    MessageFilter mfAnnounceCompleted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPOpennetAnnounceCompleted);
    MessageFilter mfRouteNotFound =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPRouteNotFound);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPRejectedOverload);
    MessageFilter mfAnnounceReply =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPOpennetAnnounceReply);
    MessageFilter mfOpennetDisabled =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPOpennetDisabled);
    MessageFilter mfNotWanted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPOpennetAnnounceNodeNotWanted);
    MessageFilter mfOpennetNoderefRejected =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(ANNOUNCE_TIMEOUT)
            .setType(DMT.FNPOpennetNoderefRejected);
    return mfAnnounceCompleted.or(
        mfRouteNotFound.or(
            mfRejectedOverload.or(
                mfAnnounceReply.or(
                    mfOpennetDisabled.or(mfNotWanted.or(mfOpennetNoderefRejected))))));
  }

  private FinalOutcome evaluateFinalMessage(Message msg, PeerNode next) {
    if (msg == null) {
      timedOut(next);
      return FinalOutcome.TERMINATE;
    }

    MessageType spec = msg.getSpec();
    java.util.function.BiFunction<Message, PeerNode, FinalOutcome> handler = handlerFor(spec);
    if (handler != null) {
      return handler.apply(msg, next);
    }

    LOG.error("Unexpected final-response message: {}", msg);
    return FinalOutcome.KEEP_WAITING;
  }

  private java.util.function.BiFunction<Message, PeerNode, FinalOutcome> handlerFor(
      MessageType spec) {
    if (Objects.equals(spec, DMT.FNPOpennetNoderefRejected)) return this::handleNoderefRejected;
    if (Objects.equals(spec, DMT.FNPOpennetAnnounceCompleted))
      return (_, _) -> FinalOutcome.COMPLETED;
    if (Objects.equals(spec, DMT.FNPRouteNotFound)) return this::handleRouteNotFound;
    if (Objects.equals(spec, DMT.FNPRejectedOverload)) return this::handleRejectedOverload;
    if (Objects.equals(spec, DMT.FNPOpennetDisabled)) return this::handleOpennetDisabled;
    if (Objects.equals(spec, DMT.FNPOpennetAnnounceReply)) return this::handleAnnounceReply;
    if (Objects.equals(spec, DMT.FNPOpennetAnnounceNodeNotWanted))
      return (_, _) -> handleNodeNotWanted();
    return null;
  }

  private FinalOutcome handleNoderefRejected(Message msg, PeerNode next) {
    int reason = msg.getInt(DMT.REJECT_CODE);
    LOG.atInfo()
        .addArgument(next)
        .addArgument(() -> DMT.getOpennetRejectedCode(reason))
        .log("Announce rejected by {} : {}");
    return FinalOutcome.CONTINUE;
  }

  private FinalOutcome handleRouteNotFound(Message msg, PeerNode next) {
    backtrackWithinHops(msg);
    return FinalOutcome.CONTINUE;
  }

  private FinalOutcome handleRejectedOverload(Message msg, PeerNode next) {
    if (onlyNode != null) {
      rnf(next);
      return FinalOutcome.TERMINATE;
    }
    return FinalOutcome.CONTINUE;
  }

  private FinalOutcome handleOpennetDisabled(Message msg, PeerNode next) {
    LOG.debug("Final response: opennet disabled");
    return FinalOutcome.CONTINUE;
  }

  private FinalOutcome handleAnnounceReply(Message msg, PeerNode next) {
    validateForwardReply(msg, next);
    // Keep waiting on this peer for more replies or completion
    return FinalOutcome.KEEP_WAITING;
  }

  private FinalOutcome handleNodeNotWanted() {
    if (cb != null) cb.nodeNotWanted();
    if (source != null) {
      try {
        sendNotWanted();
      } catch (NotConnectedException _) {
        LOG.warn("Lost connection to source (announce not wanted)");
        return FinalOutcome.TERMINATE;
      }
    }
    // Keep waiting for the downstream terminal message (Completed/RNF).
    return FinalOutcome.KEEP_WAITING;
  }

  private void backtrackWithinHops(Message msg) {
    short newHtl = msg.getShort(DMT.HTL);
    if (newHtl < 0) newHtl = 0;
    capHtl(newHtl);
  }

  private void handleCompletedSequence(PeerNode next) {
    complete();
    MessageFilter followup = buildCompletionFollowupFilter(next);
    waitForCompletionFollowups(next, followup);
  }

  private MessageFilter buildCompletionFollowupFilter(PeerNode next) {
    MessageFilter mfAnnounceReply =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(END_TIMEOUT)
            .setTimeoutRelativeToCreation(true)
            .setType(DMT.FNPOpennetAnnounceReply);
    MessageFilter mfNotWanted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(END_TIMEOUT)
            .setTimeoutRelativeToCreation(true)
            .setType(DMT.FNPOpennetAnnounceNodeNotWanted);
    mfAnnounceReply.clearOr();
    mfNotWanted.clearOr();
    return mfAnnounceReply.or(mfNotWanted);
  }

  private void waitForCompletionFollowups(PeerNode next, MessageFilter mf) {
    while (true) {
      Message msg;
      try {
        msg = node.network().usm().waitFor(mf, this);
      } catch (DisconnectedException _) {
        return;
      }
      if (!processCompletionFollowup(msg, next)) return;
    }
  }

  private boolean processCompletionFollowup(Message msg, PeerNode next) {
    if (msg == null) return false;
    MessageType spec = msg.getSpec();
    if (DMT.FNPOpennetAnnounceReply.equals(spec)) {
      validateForwardReply(msg, next);
      return true; // keep waiting; there may be more
    }
    if (DMT.FNPOpennetAnnounceNodeNotWanted.equals(spec)) {
      if (cb != null) cb.nodeNotWanted();
      if (source != null) {
        try {
          sendNotWanted();
        } catch (NotConnectedException _) {
          LOG.warn("Lost connection to source (announce completed)");
          return false;
        }
      }
      return true;
    }
    // Unexpected message; keep waiting.
    return true;
  }

  private int waitingForTransfers = 0;

  // Tracks the number of background reply-transfer tasks in flight. The sender blocks on this
  // counter before emitting terminal messages, so upstream peers do not miss late AnnouncementReply
  // relays.

  /**
   * Validates an incoming {@code AnnouncementReply} and relays it upstream or adds the node.
   *
   * <p>The reply body (noderef) is received asynchronously on a background task. While that task
   * runs, {@code waitingForTransfers} is incremented to prevent premature completion.
   */
  @SuppressWarnings("java:S1181")
  private void validateForwardReply(Message msg, final PeerNode next) {
    final long replyTransferUID = msg.getLong(DMT.TRANSFER_UID);
    final int replyNoderefLength = msg.getInt(DMT.NODEREF_LENGTH);
    final int replyPaddedLength = msg.getInt(DMT.PADDED_LENGTH);
    synchronized (this) {
      waitingForTransfers++;
    }
    Runnable r =
        () -> {
          try {
            processAnnouncementReply(replyTransferUID, replyPaddedLength, replyNoderefLength, next);
          } finally {
            synchronized (AnnounceSender.this) {
              waitingForTransfers--;
              AnnounceSender.this.notifyAll();
            }
          }
        };
    try {
      node.network().executor().execute(r);
    } catch (Throwable _) {
      synchronized (this) {
        waitingForTransfers--;
      }
    }
  }

  private void processAnnouncementReply(
      long transferUID, int paddedLen, int length, PeerNode from) {
    byte[] buf =
        OpennetNoderefWaiter.innerWaitForOpennetNoderef(
            transferUID,
            paddedLen,
            length,
            new OpennetNoderefWaiter.NoderefTransferCtx(from, false, uid, true, this, node));
    if (buf == null) {
      return; // Don't relay
    }
    SimpleFieldSet fs = OpennetNoderefValidator.validateNoderef(buf, from, false);
    if (fs == null) {
      if (cb != null) cb.bogusNoderef("invalid noderef");
      return; // Don't relay
    }
    if (source != null) {
      relayToSource(buf);
      return;
    }
    addNodeFromFs(fs);
  }

  private void relayToSource(byte[] buf) {
    try {
      forwardedRefs++;
      om.sendAnnouncementReply(uid, source, buf, this);
      if (cb != null) cb.relayedNoderef();
    } catch (NotConnectedException _) {
      // ignore
    }
  }

  private void addNodeFromFs(SimpleFieldSet fs) {
    OpennetPeerNode pn = node.network().addNewOpennetNode(fs, ConnectionType.ANNOUNCE);
    if (cb != null) {
      if (pn != null) cb.addedNode(pn);
      else cb.nodeNotAdded();
    }
  }

  /**
   * Sends the first part of an announcement request to {@code next}.
   *
   * @param next Destination peer.
   * @return Transfer UID used for the noderef payload, or {@code -1} if disconnected.
   */
  private long sendTo(PeerNode next, short currentHtl) {
    try {
      return om.startSendAnnouncementRequest(uid, next, noderefBuf, this, target, currentHtl);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Disconnected");
      return -1;
    }
  }

  /**
   * Sends the remaining announcement payload (the noderef) after an Accepted.
   *
   * @param next Destination peer.
   * @param xferUID Transfer UID obtained from {@link #sendTo(PeerNode, short)}.
   * @throws NotConnectedException if {@code next} disconnects before the payload is sent.
   */
  private void sendRest(PeerNode next, long xferUID) throws NotConnectedException {
    om.finishSentAnnouncementRequest(next, noderefBuf, this, xferUID);
  }

  private void timedOut(PeerNode next) {
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    if (source != null) {
      try {
        source.transport().sendAsync(msg, null, this);
      } catch (NotConnectedException _) {
        // Ok
      }
    }
    if (cb != null) cb.nodeFailed(next, "timed out");
  }

  private synchronized void waitForRunningTransfers() {
    while (waitingForTransfers > 0) {
      try {
        wait();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private void rnf(PeerNode next) {
    waitForRunningTransfers();
    Message msg = DMT.createFNPRouteNotFound(uid, getHtl());
    if (source != null) {
      try {
        source.transport().sendAsync(msg, null, this);
      } catch (NotConnectedException _) {
        // Ok
      }
    }
    if (cb != null) {
      if (next != null) cb.nodeFailed(next, "route not found");
      else cb.noMoreNodes();
    }
  }

  private void complete() {
    waitForRunningTransfers();
    Message msg = DMT.createFNPOpennetAnnounceCompleted(uid);
    if (source != null) {
      try {
        source.transport().sendAsync(msg, null, this);
      } catch (NotConnectedException _) {
        // Oh well.
      }
    }
  }

  /** Returns {@code true} when the upstream noderef was received and validated. */
  private boolean transferNoderef() {
    noderefBuf =
        OpennetNoderefWaiter.innerWaitForOpennetNoderef(
            xferUID,
            paddedLength,
            noderefLength,
            new OpennetNoderefWaiter.NoderefTransferCtx(source, false, uid, true, this, node));
    if (noderefBuf == null) {
      return false;
    }
    SimpleFieldSet fs = OpennetNoderefValidator.validateNoderef(noderefBuf, source, false);
    if (fs == null) {
      OpennetManager.rejectRef(uid, source, DMT.NODEREF_REJECTED_INVALID, this);
      return false;
    }
    // If we want it, add it and send it.
    try {
      // Allow reconnection - sometimes one side has the ref and the other side doesn't.
      if (om.addNewOpennetNode(fs, ConnectionType.ANNOUNCE, true) != null) {
        sendOurRef(source, om.getCrypto().myCompressedFullRef());
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Don't need the node");
        sendNotWanted();
        // Okay, just route it.
      }
    } catch (NotConnectedException _) {
      LOG.info("Could not receive noderef, disconnected");
      return false;
    }
    return true;
  }

  private void sendNotWanted() throws NotConnectedException {
    Message msg = DMT.createFNPOpennetAnnounceNodeNotWanted(uid);
    source.transport().sendAsync(msg, null, this);
  }

  private void sendOurRef(PeerNode next, byte[] ref) throws NotConnectedException {
    om.sendAnnouncementReply(uid, next, ref, this);
  }

  /** Reports sent bytes to the announcement byte counter. */
  @Override
  public void sentBytes(int x) {
    node.network().stats().announceByteCounter.sentBytes(x);
  }

  /** Reports received bytes to the announcement byte counter. */
  @Override
  public void receivedBytes(int x) {
    node.network().stats().announceByteCounter.receivedBytes(x);
  }

  /** Reports payload bytes; not counted toward the total byte counter. */
  @Override
  public void sentPayload(int x) {
    node.network().stats().announceByteCounter.sentPayload(x);
    // Doesn't count.
  }

  /**
   * Returns the thread priority used when scheduling this runnable.
   *
   * @return {@link NativeThread.PriorityLevel#HIGH_PRIORITY} numeric value.
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  private synchronized short getHtl() {
    return htl;
  }

  private synchronized void setHtl(short value) {
    htl = value;
  }

  private synchronized void capHtl(short candidate) {
    if (candidate < htl) htl = candidate;
  }
}
