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

/**
 * Coordinates acceptance and queued processing of incoming CHK/SSK data requests.
 *
 * <p>This handler is the narrow entry point for data request messages that arrive from peers. It
 * performs quick prechecks, enqueues accepted messages onto a bounded queue, and runs a dedicated
 * queue consumer to perform heavier processing off the message thread. Requests that fail early
 * admission or capacity checks are rejected with the appropriate wire-level responses, and accepted
 * requests are forwarded to {@link RequestHandler} instances for full processing.
 *
 * <p>Concurrency: the queue consumer runs on the node executor and blocks on the queue; it exits
 * when interrupted. The handler itself is not thread-safe for external mutation and is intended to
 * be owned by {@link NodeDispatcher}. Internal state is minimal and mostly immutable after
 * construction, aside from the swappable {@link NodeStats} reference used for admission decisions.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Queueing inbound request messages with bounded backpressure.
 *   <li>Performing fast prechecks and overload rejection.
 *   <li>Creating tracking tags and dispatching {@link RequestHandler} jobs.
 * </ul>
 *
 * @see NodeDispatcher
 * @see RequestHandler
 * @see RequestTracker
 */
final class NodeDataRequestHandler {

  /** Logger for request admission decisions and rejection diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeDataRequestHandler.class);

  /**
   * Message template for lock contention when a request UID is already running.
   *
   * <p>The template is used with SLF4J formatting and includes the UID as a parameter, ensuring
   * consistent log text without string concatenation in the hot path.
   */
  private static final String LOG_ALREADY_RUNNING =
      "Lock contention for id {}; reject (already running)";

  /** Owning node used for network, routing, and storage dependencies. */
  private final Node node;

  /**
   * Tracker for currently running request UIDs.
   *
   * <p>This reference is obtained from the routing subsystem during construction and used to
   * prevent duplicate request execution across concurrent messages.
   */
  private final RequestTracker tracker;

  /**
   * Bounded queue of incoming data request messages.
   *
   * <p>The queue limits in-flight admission work. When full, requests are rejected immediately to
   * provide backpressure instead of unbounded memory growth.
   */
  private final ArrayBlockingQueue<Message> requestQueue = new ArrayBlockingQueue<>(100);

  /**
   * Runnable that drains {@link #requestQueue} and processes messages off-thread.
   *
   * <p>The runnable blocks on {@link ArrayBlockingQueue#take()} and exits cleanly on interruption,
   * allowing the node executor to manage lifecycle.
   */
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

  /**
   * Current node statistics instance used for admission and counters.
   *
   * <p>This reference may be updated via {@link #start(NodeStats)} to bind the handler to the
   * active stats instance during node startup.
   */
  private NodeStats nodeStats;

  /**
   * Creates a data request handler for the given node.
   *
   * <p>The handler captures the routing tracker and initial stats reference from the node. It does
   * not start background processing; callers should invoke {@link #start(NodeStats)} after the node
   * executor and statistics subsystem are available.
   *
   * @param node owning node that provides routing, network, and storage subsystems; must be
   *     non-null
   */
  NodeDataRequestHandler(Node node) {
    this.node = node;
    this.tracker = node.routing().tracker();
    this.nodeStats = node.network().stats();
  }

  /**
   * Binds the handler to the active {@link NodeStats} and starts queue processing.
   *
   * <p>This method updates the stats reference used for admission decisions and submits the queue
   * runner to the node executor. It is safe to call once during startup; calling it multiple times
   * will resubmit the runner and is not intended for repeated use.
   *
   * @param stats active node statistics instance used for admission and counters; must be non-null
   */
  void start(NodeStats stats) {
    this.nodeStats = stats;
    node.network().executor().execute(queueRunner);
  }

  /**
   * Routes an inbound message to the data request handler when applicable.
   *
   * <p>Only CHK and SSK data request message types are accepted. Accepted messages are enqueued for
   * asynchronous processing, and rejection is handled later if the queue is full. For all other
   * message types, this method returns {@code false} without side effects.
   *
   * @param m inbound message to inspect; must be a fully decoded request message
   * @return {@code true} if the message was recognized as a data request type and queued
   */
  boolean handle(Message m) {
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

  /**
   * Enqueues a data request for asynchronous processing or rejects if the queue is full.
   *
   * <p>This method performs only lightweight admission by attempting to insert into the bounded
   * queue. If the queue is full, it immediately rejects the request with an overload response using
   * the appropriate byte counter for the request type.
   *
   * @param m data request message to enqueue; must not be null
   * @param isSSK {@code true} for SSK requests, {@code false} for CHK requests
   */
  private void handleDataRequest(Message m, boolean isSSK) {
    // Note: could check probablyInStore and handle inline when available.
    // This and DatastoreChecker would need support for that path.
    if (!requestQueue.offer(m)) {
      rejectRequest(
          m, isSSK ? node.network().stats().sskRequestCtr : node.network().stats().chkRequestCtr);
    }
  }

  /**
   * Sends an overload rejection response for a queued request that cannot be accepted.
   *
   * <p>The rejection is sent asynchronously to the message source. If the peer disconnects before
   * sending, the rejection is silently ignored as the request is already invalid.
   *
   * @param m request message being rejected; used to obtain UID and source peer
   * @param ctr byte counter used for accounting of the rejection message on the wire
   */
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
