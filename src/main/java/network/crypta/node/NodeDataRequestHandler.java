package network.crypta.node;

import java.util.concurrent.ArrayBlockingQueue;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageType;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.node.NodeStats.RejectReason;
import network.crypta.store.BlockMetadata;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles incoming CHK/SSK data requests and request queue processing. */
final class NodeDataRequestHandler {

  private static final Logger LOG = LoggerFactory.getLogger(NodeDataRequestHandler.class);
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  private final Node node;
  private final RequestTracker tracker;
  private final ArrayBlockingQueue<Message> requestQueue = new ArrayBlockingQueue<>(100);
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
              isSSK ? node.network().stats().sskRequestCtr : node.network().stats().chkRequestCtr;
          short htl = normalizedHtl(m.getShort(DMT.HTL));
          Key key = (Key) m.getObject(DMT.FREENET_ROUTING_KEY);
          boolean realTimeFlag = DMT.getRealTimeFlag(m);
          final RequestTag tag =
              new RequestTag(isSSK, RequestTag.START.REMOTE, source, realTimeFlag, id, node);

          if (rejectAlreadyRunningData(id, isSSK, source, ctr, key, htl, tag)) return;

          KeyBlock block = tryFetchBlock(key, tag);
          if (rejectIfOverloadedData(source, isSSK, id, ctr, realTimeFlag, tag, block)) return;

          nodeStats.reportIncomingRequestLocation(key.toNormalizedDouble());

          boolean needsPubKey = key instanceof NodeSSK && m.getBoolean(DMT.NEED_PUB_KEY);
          RequestHandler rh =
              new RequestHandler(source, id, node, htl, key, tag, block, realTimeFlag, needsPubKey);
          rh.receivedBytes(m.receivedByteCount());
          node.network()
              .executor()
              .execute(
                  rh, "RequestHandler for UID " + id + " on " + node.network().darknetPortNumber());
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
            rejectRequest(
                m,
                isSSK
                    ? node.network().stats().sskRequestCtr
                    : node.network().stats().chkRequestCtr);
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
          if (tracker.lockUID(id, isSSK, false, false, false, tag.realTimeFlag, tag)) {
            if (LOG.isDebugEnabled()) LOG.debug("Lock acquired for id {}", id);
            return false;
          }
          if (LOG.isDebugEnabled()) LOG.debug(LOG_ALREADY_RUNNING, id);
          Message rejected = DMT.createFNPRejectedLoop(id);
          try {
            source.transport().sendAsync(rejected, null, ctr);
          } catch (NotConnectedException e) {
            LOG.info(
                "Reject request; sendAsync failed (peer={}, error={})",
                source.getPeer(),
                e.toString());
          }
          node.routing().failureTable().onFinalFailure(key, null, htl, htl, -1, -1, source);
          return true;
        }

        private KeyBlock tryFetchBlock(Key key, RequestTag tag) {
          BlockMetadata meta = new BlockMetadata();
          KeyBlock block = node.storage().fetch(key, false, false, false, false, meta);
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
              nodeStats.shouldRejectRequest(
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
            source.transport().sendAsync(rejected, null, ctr);
          } catch (NotConnectedException e) {
            LOG.info(
                "Rejecting (overload) data request from {}: {}", source.getPeer(), e.toString());
          }
          tag.setRejected();
          tag.unlockHandler(rejectReason.soft());
          return true;
        }
      };

  private NodeStats nodeStats;

  NodeDataRequestHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  void start(NodeStats stats) {
    this.nodeStats = stats;
    node.network().executor().execute(queueRunner);
  }

  boolean handle(Message m, PeerNode source) {
    MessageType spec = m.getSpec();
    if (spec == DMT.FNPCHKDataRequest) {
      handleDataRequest(m, false);
      return true;
    } else if (spec == DMT.FNPSSKDataRequest) {
      handleDataRequest(m, true);
      return true;
    }
    return false;
  }

  private void handleDataRequest(Message m, boolean isSSK) {
    // Note: could check probablyInStore and handle inline when available.
    // This and DatastoreChecker would need support for that path.
    if (!requestQueue.offer(m)) {
      rejectRequest(
          m, isSSK ? node.network().stats().sskRequestCtr : node.network().stats().chkRequestCtr);
    }
  }

  private void rejectRequest(Message m, ByteCounter ctr) {
    long uid = m.getLong(DMT.UID);
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      m.getSource().transport().sendAsync(msg, null, ctr);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }
}
