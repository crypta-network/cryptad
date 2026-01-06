package network.crypta.node;

import network.crypta.crypt.HMAC;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles offered-key messages and noderef exchange. */
final class NodeOfferMessageHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeOfferMessageHandler.class);
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  private final Node node;
  private final RequestTracker tracker;
  private NodeStats nodeStats;

  NodeOfferMessageHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  void start(NodeStats stats) {
    this.nodeStats = stats;
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPOfferKey) {
      return handleOfferKey(m, source);
    } else if (spec == DMT.FNPGetOfferedKey) {
      handleGetOfferedKey(m, source);
      return true;
    } else if (spec == DMT.FNPGetYourFullNoderef && source instanceof DarknetPeerNode peerNode) {
      peerNode.sendFullNoderef();
      return true;
    } else if (spec == DMT.FNPMyFullNoderef && source instanceof DarknetPeerNode peerNode) {
      peerNode.handleFullNoderef(m);
      return true;
    }
    return false;
  }

  private boolean handleOfferKey(Message m, PeerNode source) {
    Key key = (Key) m.getObject(DMT.KEY);
    byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
    node.routing().failureTable().onOffer(key, source, authenticator);
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
        node.routing().failureTable().offerAuthenticatorKey, key.getFullKey(), authenticator)) {
      return false;
    }
    LOG.error("Invalid GetOfferedKey; authenticator does not verify (source={})", source);
    try {
      source
          .transport()
          .sendAsync(
              DMT.createFNPGetOfferedKeyInvalid(
                  uid, DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR),
              null,
              node.routing().failureTable().senderCounter);
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
      source.transport().sendAsync(rejected, null, node.routing().failureTable().senderCounter);
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
        sendAsyncIgnoreNotConnected(source, rejected, node.routing().failureTable().senderCounter);
        tag.unlockHandler(reject.soft());
        return;
      }
    } catch (Error | RuntimeException e) {
      tag.unlockHandler();
      throw e;
    }

    try {
      node.routing()
          .failureTable()
          .sendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
    } catch (NotConnectedException _) {
      // Too bad.
    }
  }

  private void sendAsyncIgnoreNotConnected(PeerNode peer, Message msg, ByteCounter ctr) {
    try {
      peer.transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException e) {
      if (LOG.isInfoEnabled())
        LOG.info(
            "Reject (overload) request; sendAsync failed (peer={}, error={})",
            peer.getPeer(),
            e.toString());
    }
  }
}
