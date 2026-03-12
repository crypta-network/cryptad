package network.crypta.node;

import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.List;
import network.crypta.io.comm.Peer;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates handshake finalization, tracker promotion, and post-handshake side effects for a
 * {@link PeerNode}.
 *
 * <p>This helper centralizes the logic that runs after key negotiation succeeds but before the peer
 * is considered fully connected. It validates the incoming noderef, derives routability from
 * version and clock checks, rotates session trackers, and triggers restart/disconnect notifications
 * when boot IDs or packet formats change. Keeping these steps in one part makes handshake
 * completion easier to reason about and keeps {@link PeerNodeRuntime} focused on broader runtime
 * concerns.
 *
 * <p>The class is stateful only through references to its owning peer and runtime collaborators.
 * Callers execute it on handshake paths where peer-level synchronization and ordering already
 * matter, so this class relies on {@link PeerNode} synchronization rules instead of introducing new
 * locks.
 *
 * <ul>
 *   <li>Normalizes tracker IDs and applies negotiated key material.
 *   <li>Detects replayed keys and rejects unsafe promotions.
 *   <li>Notifies subsystems when a peer reconnects, restarts, or disconnects.
 * </ul>
 */
final class PeerNodeHandshakeLifecycle {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeHandshakeLifecycle.class);

  private final PeerNode peerNode;
  private final Node node;
  private final PeerNodeRuntime runtime;

  /**
   * Creates a lifecycle coordinator bound to a specific peer and runtime context.
   *
   * <p>The coordinator keeps references to collaborators and does not perform network or disk work
   * during construction. Callers should create one instance per {@link PeerNode} lifecycle and
   * reuse it for later handshake completions.
   *
   * @param peerNode owning peer whose trackers and status will be updated during completion
   * @param node node-level service container used for peer, routing, and restart notifications
   * @param runtime runtime adapter used for transport and packet-format transitions
   */
  PeerNodeHandshakeLifecycle(PeerNode peerNode, Node node, PeerNodeRuntime runtime) {
    this.peerNode = peerNode;
    this.node = node;
    this.runtime = runtime;
  }

  /**
   * Builds a runnable that re-evaluates peer backoff status after deferred transitions.
   *
   * <p>The returned checker keeps only a weak reference to the peer, so scheduled callbacks do not
   * prolong the peer lifetime. It is typically registered when routing backoff windows expires.
   *
   * @param peerRef weak reference to the peer whose backoff status should be refreshed
   * @return runnable checker that safely no-ops if the peer has been garbage collected
   */
  static Runnable createBackoffStatusChecker(WeakReference<PeerNode> peerRef) {
    return new PeerNodeBackoffStatusChecker(peerRef);
  }

  /**
   * Applies negotiated handshake parameters and transitions the peer into its next session state.
   *
   * <p>The method parses the peer's noderef, computes routability flags, performs replay checks,
   * rotates trackers, and triggers connect/disconnect notifications as needed. A negative tracker
   * ID from input is normalized to a random non-negative identifier. When parsing fails or replayed
   * keys are detected, the method aborts and returns {@code -1}.
   *
   * @param paramsObject handshake completion payload expected to be a {@link
   *     HandshakeCompletionParams} instance
   * @return resolved tracker identifier on success, or {@code -1} when completion is rejected
   * @throws ClassCastException if {@code paramsObject} is not a {@link HandshakeCompletionParams}
   *     instance
   */
  long completeHandshake(Object paramsObject) {
    HandshakeCompletionParams params = (HandshakeCompletionParams) paramsObject;
    long now = System.currentTimeMillis();
    long trackerID = params.trackerID;
    // If trackerID is negative, pick a random positive ID; then keep using trackerID.
    // Avoid Math.abs(Long.MIN_VALUE) overflow; mask a sign bit instead.
    trackerID = trackerID < 0 ? (peerNode.random.nextLong() & Long.MAX_VALUE) : trackerID;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Tracker ID {} isJFK4={} jfk4SameAsOld={}",
          trackerID,
          params.isJFK4,
          params.jfk4SameAsOld);

    // Update sendHandshakeTime; don't send another handshake for a while.
    // If unverified, "a while" determines the timeout; if not, it's just good practice to avoid a
    // race below.
    if (!(peerNode.isSeed() && peerNode instanceof SeedServerPeerNode))
      peerNode.calcNextHandshake(true, true, false);
    peerNode.stopARKFetcher();
    try {
      // First, the new noderef
      processHandshakeNoderef(params.data, params.length);
    } catch (FSParseException e1) {
      synchronized (peerNode) {
        peerNode.bogusNoderef = true;
        // Disconnect, something broke
        runtime.setConnected(false, now);
      }
      LOG.error("Failed to parse new noderef for {}: {}", peerNode, e1, e1);
      node.network().peers().disconnected(peerNode.selfPeerNode());
      return -1;
    }
    RoutabilityDecision rd = decideRoutability();
    peerNode.changedIP(params.replyTo);
    HandshakeApplyResult har = applyHandshakeState(params, rd, trackerID, now);
    if (har == null) return -1;
    finalizeHandshake(har, rd, params.replyTo, params.thisBootID, now);

    return trackerID;
  }

  private void finalizeHandshake(
      HandshakeApplyResult har, RoutabilityDecision rd, Peer replyTo, long thisBootID, long now) {
    applyDisconnectSideEffects(har);
    logAndUpdateThrottle(replyTo, thisBootID);
    peerNode.setPeerNodeStatus(now);
    if (rd.newer() || rd.older() || !peerNode.isConnected())
      node.network().peers().disconnected(peerNode.selfPeerNode());
    else if (!har.wasARekey) {
      node.network().peers().addConnectedPeer(peerNode.selfPeerNode());
      peerNode.maybeOnConnect();
    }
    peerNode.crypto.maybeBootConnection(peerNode.selfPeerNode(), replyTo.getFreenetAddress());
  }

  private void applyDisconnectSideEffects(HandshakeApplyResult har) {
    if (har.messagesTellDisconnected != null) {
      for (MessageItem item : har.messagesTellDisconnected) item.onDisconnect();
    }
    if (har.bootIDChanged) {
      node.network().locationManager().lostOrRestartedNode(peerNode.selfPeerNode());
      node.network().usm().onRestart(peerNode);
      node.routing().tracker().onRestartOrDisconnect(peerNode.selfPeerNode());
    }
    if (har.oldPrev != null) har.oldPrev.disconnected();
    if (har.oldCur != null) har.oldCur.disconnected();
    if (har.oldPacketFormat != null) {
      List<MessageItem> tellDisconnect = har.oldPacketFormat.onDisconnect();
      if (tellDisconnect != null) for (MessageItem item : tellDisconnect) item.onDisconnect();
    }
  }

  private void logAndUpdateThrottle(Peer replyTo, long thisBootID) {
    runtime.maybeDisconnected();
    LOG.info(
        "Completed handshake with {} on {} - current: {} old: {} unverified: {} bootID: {}"
            + PeerNode.STR_FOR
            + "{}",
        peerNode,
        replyTo,
        peerNode.currentTracker,
        peerNode.previousTracker,
        peerNode.unverifiedTracker,
        thisBootID,
        peerNode.shortToString());
  }

  private record RoutabilityDecision(boolean routable, boolean newer, boolean older) {}

  private RoutabilityDecision decideRoutability() {
    boolean routable = true;
    boolean newer = false;
    boolean older = false;
    if (peerNode.isSeed()) {
      routable = false;
      if (LOG.isDebugEnabled())
        LOG.debug("Routing disabled (announcement-only seed): peer={}", peerNode);
    } else if (peerNode.bogusNoderef) {
      LOG.info("Routing disabled (bogus noderef): peer={}", peerNode);
      routable = false;
    } else if (peerNode.reverseInvalidVersion()) {
      LOG.info(
          "Routing disabled (reverse version check): peer={}, localVersion={},"
              + " peerLastGoodVersion={}",
          peerNode,
          Version.getVersionString(),
          peerNode.getLastGoodVersion());
      newer = true;
    }
    if (peerNode.forwardInvalidVersion()) {
      LOG.info(
          "Routing disabled (forward version check): peer={}, peerVersion={}",
          peerNode,
          peerNode.getVersion());
      older = true;
      routable = false;
    } else if (Math.abs(peerNode.clockDelta) > PeerNode.MAX_CLOCK_DELTA) {
      LOG.info("Routing disabled (clock skew): peer={}", peerNode);
      routable = false;
    }
    return new RoutabilityDecision(routable, newer, older);
  }

  private static final class HandshakeApplyResult {
    boolean bootIDChanged;
    boolean wasARekey;
    SessionKey oldPrev;
    SessionKey oldCur;
    MessageItem[] messagesTellDisconnected;
    PacketFormat oldPacketFormat;
  }

  private HandshakeApplyResult applyHandshakeState(
      HandshakeCompletionParams params, RoutabilityDecision rd, long trackerID, long now) {
    HandshakeApplyResult result = new HandshakeApplyResult();
    synchronized (peerNode) {
      peerNode.disconnecting = false;
      if (isReplayedKey(params)) return null;
      updateRoutabilityAndBootId(params, rd, now, result);
      SessionKey newTracker = buildSessionKey(params, trackerID);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "New key tracker in completedHandshake: {}" + PeerNode.STR_FOR + "{} neg type {}",
            newTracker,
            peerNode.shortToString(),
            params.negType);
      assignTrackersAndTimes(params, now, result, newTracker);
    }
    return result;
  }

  private boolean isReplayedKey(HandshakeCompletionParams params) {
    if (peerNode.currentTracker != null
        && Arrays.equals(params.outgoingKey, peerNode.currentTracker.outgoingKey)
        && Arrays.equals(params.incommingKey, peerNode.currentTracker.incommingKey)) {
      LOG.error("Handshake replay suspected: new keys match current tracker");
      return true;
    }
    if (peerNode.previousTracker != null
        && Arrays.equals(params.outgoingKey, peerNode.previousTracker.outgoingKey)
        && Arrays.equals(params.incommingKey, peerNode.previousTracker.incommingKey)) {
      LOG.error("Handshake replay suspected: new keys match previous tracker");
      return true;
    }
    if (peerNode.unverifiedTracker != null
        && Arrays.equals(params.outgoingKey, peerNode.unverifiedTracker.outgoingKey)
        && Arrays.equals(params.incommingKey, peerNode.unverifiedTracker.incommingKey)) {
      LOG.error("Handshake replay suspected: new keys match unverified tracker");
      return true;
    }
    return false;
  }

  private void updateRoutabilityAndBootId(
      HandshakeCompletionParams params,
      RoutabilityDecision rd,
      long now,
      HandshakeApplyResult result) {
    peerNode.handshakeCount.set(0);
    peerNode.bogusNoderef = false;
    if (!peerNode.isConnected()) {
      peerNode.connectedTime = now;
      peerNode.countSelectionsSinceConnected.set(0);
      peerNode.sentInitialMessages = false;
    } else result.wasARekey = true;
    peerNode.disableRouting =
        peerNode.disableRoutingHasBeenSetLocally || peerNode.disableRoutingHasBeenSetRemotely;
    peerNode.isRoutable = rd.routable();
    peerNode.unroutableNewerVersion = rd.newer();
    peerNode.unroutableOlderVersion = rd.older();
    long oldBootID = peerNode.bootID;
    peerNode.bootID = params.thisBootID;
    result.bootIDChanged = oldBootID != params.thisBootID;
    if (peerNode.myLastSuccessfulBootID != peerNode.myBootID) {
      result.bootIDChanged = true;
      peerNode.myLastSuccessfulBootID = peerNode.myBootID;
    }
    if (result.bootIDChanged && result.wasARekey) {
      LOG.info(
          "Changed boot ID while rekeying! from {} to {}" + PeerNode.STR_FOR + "{}",
          oldBootID,
          params.thisBootID,
          peerNode.getPeer());
      result.wasARekey = false;
      peerNode.connectedTime = now;
      peerNode.countSelectionsSinceConnected.set(0);
      peerNode.sentInitialMessages = false;
    } else if (result.bootIDChanged && LOG.isDebugEnabled())
      LOG.debug(
          "Changed boot ID from {} to {}" + PeerNode.STR_FOR + "{}",
          oldBootID,
          params.thisBootID,
          peerNode.getPeer());
    if (result.bootIDChanged) {
      result.oldPrev = peerNode.previousTracker;
      result.oldCur = peerNode.currentTracker;
      peerNode.previousTracker = null;
      peerNode.currentTracker = null;
      result.messagesTellDisconnected = peerNode.grabQueuedMessageItems();
      peerNode.offeredCorePackageVersion = 0;
      result.oldPacketFormat = runtime.packetFormat();
      runtime.clearPacketFormat();
    }
  }

  private SessionKey buildSessionKey(HandshakeCompletionParams params, long trackerID) {
    return new SessionKey(
        peerNode.selfPeerNode(),
        new SessionKeyCryptoMaterial(
            params.outgoingCipher,
            params.outgoingKey,
            params.incommingCipher,
            params.incommingKey,
            params.ivCipher,
            params.ivNonce,
            params.hmacKey),
        new NewPacketFormatKeyContext(params.ourInitialSeqNum, params.theirInitialSeqNum),
        trackerID);
  }

  private void assignTrackersAndTimes(
      HandshakeCompletionParams params,
      long now,
      HandshakeApplyResult result,
      SessionKey newTracker) {
    if (params.unverified) {
      if (peerNode.unverifiedTracker != null && peerNode.previousTracker == null)
        peerNode.previousTracker = peerNode.unverifiedTracker;
      peerNode.unverifiedTracker = newTracker;
    } else {
      result.oldPrev = peerNode.previousTracker;
      peerNode.previousTracker = peerNode.currentTracker;
      peerNode.currentTracker = newTracker;
      peerNode.neverConnected = false;
      peerNode.maybeClearPeerAddedTimeOnConnect();
    }
    runtime.setConnected(peerNode.currentTracker != null, now);
    peerNode.handshake.clearKeyAgreementSchemeContext();
    peerNode.isRekeying = false;
    peerNode.timeLastRekeyed =
        now - (params.unverified ? 0 : FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY / 2);
    peerNode.totalBytesExchangedWithCurrentTracker = 0;
    if (peerNode.currentTracker != null
        && peerNode.previousTracker != null
        && Arrays.equals(peerNode.currentTracker.outgoingKey, peerNode.previousTracker.outgoingKey)
        && Arrays.equals(
            peerNode.currentTracker.incommingKey, peerNode.previousTracker.incommingKey))
      LOG.error(
          "currentTracker key equals previousTracker key: cur {} prev {}",
          peerNode.currentTracker,
          peerNode.previousTracker);
    if (peerNode.previousTracker != null
        && peerNode.unverifiedTracker != null
        && Arrays.equals(
            peerNode.previousTracker.outgoingKey, peerNode.unverifiedTracker.outgoingKey)
        && Arrays.equals(
            peerNode.previousTracker.incommingKey, peerNode.unverifiedTracker.incommingKey))
      LOG.error(
          "previousTracker key equals unverifiedTracker key: prev {} unv {}",
          peerNode.previousTracker,
          peerNode.unverifiedTracker);
    peerNode.timeLastSentPacket = now;
    if (runtime.packetFormat() == null) {
      runtime.setPacketFormat(
          new NewPacketFormat(peerNode, params.ourInitialMsgID, params.theirInitialMsgID));
    }
    peerNode.timeLastReceivedPacket = now;
    peerNode.timeLastReceivedDataPacket = now;
    peerNode.timeLastReceivedAck = now;
  }

  private void processHandshakeNoderef(byte[] data, int length) throws FSParseException {
    SimpleFieldSet fs = PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, length);
    peerNode.processNewNoderef(fs, false, false, false);
  }
}
