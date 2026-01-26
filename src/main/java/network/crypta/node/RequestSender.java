package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import network.crypta.crypt.CryptFormatException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockReceiver.BlockReceiverCompletion;
import network.crypta.io.xfer.BlockReceiver.BlockReceiverTimeoutHandler;
import network.crypta.io.xfer.BlockTransferContext;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.FailureTable.BlockOffer;
import network.crypta.node.FailureTable.OfferList;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.node.OpennetNoderefWaiter.WaitedTooLongForOpennetNoderefException;
import network.crypta.node.subsystem.NodeRoutingSubsystem.RequestSenderOptions;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends a single CHK/SSK retrieval request, routing it through peers, handling offers, receiving
 * data, verifying it, and recording the terminal status.
 *
 * <p>This class is the sending counterpart of {@link RequestHandler}. A {@code RequestSender}
 * instance progresses through distinct phases: try offered blocks (if available), route the request
 * to progressively closer peers, await {@code Accepted}/rejection control messages, receive the
 * block if accepted, and finally verify and commit to caches/stores according to the configured
 * permissions.
 *
 * <p>Concurrency and lifecycle:
 *
 * <ul>
 *   <li>Instances are submitted to the node executor via {@link #start()} and run asynchronously.
 *   <li>Completion is reported via {@link #finish(int, PeerNode, boolean)} (inherited), after which
 *       {@link #getStatus()}, {@link #successFrom()}, and header/data accessors stabilize.
 *   <li>Listeners are notified on key milestones (e.g., transfer begins/ends, overloads).
 *   <li>Internal timeouts may trigger reassignment to self to avoid penalizing a downstream peer
 *       for cumulative per-peer deadlines.
 * </ul>
 *
 * <p>Side effects and external interactions: updates the {@link FailureTable}, accumulates
 * statistics via {@link network.crypta.node.NodeStats}, writes to client cache and/or datastore
 * when allowed, and may forward {@code RejectedOverload} to the originator.
 *
 * @author amphibian
 */
public final class RequestSender extends BaseSender implements PrioRunnable {
  private static final Logger LOG = LoggerFactory.getLogger(RequestSender.class);
  private static final String FOR_SEP = " for ";
  private static final String FROM_SEP = " from ";
  private static final String NODE_PREFIX = "Node ";
  private static final byte[] NO_REF = new byte[0];

  // Constants
  static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);
  // After a get-offered key fails, wait this long for two stage timeout. Probably we will
  // have disconnected by then.
  static final long GET_OFFER_LONG_TIMEOUT = SECONDS.toMillis(60);
  final long getOfferedTimeout;

  /** Wait up to this long to get a path folding reply */
  static final long OPENNET_TIMEOUT = MINUTES.toMillis(2);

  /**
   * One in this many successful requests is randomly reinserted. This is probably a good idea
   * anyway, but with the split store it's essential.
   */
  static final int RANDOM_REINSERT_INTERVAL = 200;

  // Basics
  final RequestTag origTag;
  private PartiallyReceivedBlock prb;
  private byte[] finalHeaders;
  private byte[] finalSskData;
  private DSAPublicKey pubKey;
  private SSKBlock block;
  private PeerNode transferringFrom;
  private boolean reassignedToSelfDueToMultipleTimeouts;
  private final boolean canWriteClientCache;
  private final boolean canWriteDatastore;

  /** If true, only try to fetch the key from nodes which have offered it */
  private final boolean tryOffersOnly;

  private final ArrayList<RequestSenderListener> listeners = new ArrayList<>();

  // Terminal status
  // Always set finished AFTER setting the reason flag

  private int status = -1;
  static final int NOT_FINISHED = -1;
  static final int SUCCESS = 0;
  static final int ROUTE_NOT_FOUND = 1;
  static final int DATA_NOT_FOUND = 3;
  static final int TRANSFER_FAILED = 4;
  static final int VERIFY_FAILURE = 5;
  static final int TIMED_OUT = 6;
  static final int GENERATED_REJECTED_OVERLOAD = 7;
  static final int INTERNAL_ERROR = 8;
  static final int RECENTLY_FAILED = 9;
  static final int GET_OFFER_VERIFY_FAILURE = 10;
  static final int GET_OFFER_TRANSFER_FAILED = 11;
  private PeerNode successFrom;

  static String getStatusString(int status) {
    return switch (status) {
      case NOT_FINISHED -> "NOT FINISHED";
      case SUCCESS -> "SUCCESS";
      case ROUTE_NOT_FOUND -> "ROUTE NOT FOUND";
      case DATA_NOT_FOUND -> "DATA NOT FOUND";
      case TRANSFER_FAILED -> "TRANSFER FAILED";
      case GET_OFFER_TRANSFER_FAILED -> "GET OFFER TRANSFER FAILED";
      case VERIFY_FAILURE -> "VERIFY FAILURE";
      case GET_OFFER_VERIFY_FAILURE -> "GET OFFER VERIFY FAILURE";
      case TIMED_OUT -> "TIMED OUT";
      case GENERATED_REJECTED_OVERLOAD -> "GENERATED REJECTED OVERLOAD";
      case INTERNAL_ERROR -> "INTERNAL ERROR";
      case RECENTLY_FAILED -> "RECENTLY FAILED";
      default -> "UNKNOWN STATUS CODE: " + status;
    };
  }

  String getStatusString() {
    return getStatusString(getStatus());
  }

  // No static initialization is required; static fields are constant configuration only.

  @Override
  public String toString() {
    return super.toString() + FOR_SEP + uid;
  }

  /**
   * Creates a new sender for a single key fetch.
   *
   * @param context Request metadata for the fetch, including key, HTL, UID, and tag references.
   * @param options Policy flags governing offers, cache handling, and realtime scheduling.
   * @param canWriteDatastore Whether verified data may be stored in the main datastore.
   */
  public RequestSender(
      RequestSenderContext context, RequestSenderOptions options, boolean canWriteDatastore) {
    super(
        context.key(),
        options.realTimeFlag(),
        context.source(),
        context.node(),
        context.htl(),
        context.uid());
    if (options.realTimeFlag()) {
      getOfferedTimeout = BlockReceiver.RECEIPT_TIMEOUT_REALTIME;
    } else {
      getOfferedTimeout = BlockReceiver.RECEIPT_TIMEOUT_BULK;
    }
    this.pubKey = context.pubKey();
    this.origTag = context.tag();
    this.tryOffersOnly = options.offersOnly();
    this.canWriteClientCache = options.canWriteClientCache();
    this.canWriteDatastore = canWriteDatastore;
  }

  /**
   * Submits this sender to the node's executor for asynchronous execution. Returns immediately. The
   * request lifecycle and terminal status are signaled via listeners and accessors.
   */
  public void start() {
    node.network()
        .executor()
        .execute(
            this, "RequestSender for UID " + uid + " on " + node.network().darknetPortNumber());
  }

  /**
   * Entry point for the request state machine. Coordinates routing, offer handling, transfer, and
   * completion. Any uncaught error results in {@link #finish(int, PeerNode, boolean)} with {@link
   * #INTERNAL_ERROR}.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    node.network()
        .ticker()
        .queueTimedJob(
            () -> {
              // We may reroute multiple times, applying the same per-peer timeout each time. The
              // aggregate can exceed the downstream peer’s patience. Reassign to self so the
              // immediate peer is not penalized for upstream delays.

              boolean fromOfferedKey;

              synchronized (RequestSender.this) {
                if (status != NOT_FINISHED) return;
                if (transferringFrom != null) return;
                reassignedToSelfDueToMultipleTimeouts = true;
                fromOfferedKey = (routeAttempts == 0);
              }

              // We are still routing, yet we have exceeded the per-peer timeout, probably due to
              // routing to multiple nodes e.g., RNFs and accepted timeouts.
              LOG.info("Reassigning to self on timeout: {}", RequestSender.this);

              reassignToSelfOnTimeout(fromOfferedKey);
            },
            incomingSearchTimeout);
    try {
      realRun();
    } catch (Throwable t) {
      LOG.error("RequestSender.run caught throwable: {}", t, t);
      finish(INTERNAL_ERROR, null, false);
    } finally {
      // LOCKING: Normally receivingAsync is set by this thread, so there is no need to synchronize.
      // If it is set by another thread, it will only be after it was set by this thread.
      if (status == NOT_FINISHED && !receivingAsync) {
        LOG.error("Not finished: {}", this);
        finish(INTERNAL_ERROR, null, false);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Leaving RequestSender.run() for {}", uid);
    }
  }

  static final int MAX_HIGH_HTL_FAILURES = 5;

  private void realRun() {
    if (isSSK && (pubKey == null)) {
      pubKey = ((NodeSSK) key).getPubKey();
    }

    // Prefer offered keys first; regular routing is the fallback.

    final OfferList offers = node.routing().failureTable().getOffers(key);

    if (offers != null) tryOffers(offers, null, null);
    else startRequests();
  }

  private void startRequests() {
    if (tryOffersOnly) {
      if (LOG.isDebugEnabled())
        LOG.debug("Tried all offers; not issuing a regular request for key");
      // Use DATA_NOT_FOUND to indicate the offer-only path is exhausted.
      finish(DATA_NOT_FOUND, null, true);
      return;
    }

    routeAttempts = 0;
    starting = true;
    // While in no-cache mode, do not decrement HTL on certain control responses (e.g.,
    // RejectedLoop). Cap the number of such failures before declaring ROUTE_NOT_FOUND.
    highHTLFailureCount = 0;
    routeRequests();
  }

  private boolean starting;
  private int highHTLFailureCount = 0;
  private boolean killedByRecentlyFailed = false;

  /**
   * Route requests. Method is responsible for its own completion, e.g., finish or chaining to
   * MainLoopCallback, i.e., the caller isn't going to do more stuff relevant to the request
   * afterward.
   */
  protected void routeRequests() {

    if (LOG.isDebugEnabled()) LOG.debug("Routing requests on {}", this);

    PeerNode next;
    boolean canWriteStorePrev = node.routing().canWriteDatastoreInsert(htl);
    if (adjustHTLOrFinish(canWriteStorePrev)) return;

    starting = false;

    if (LOG.isDebugEnabled()) LOG.debug("htl={}", htl);
    if (htl <= 0) {
      node.routing()
          .failureTable()
          .onFinalFailure(
              key,
              null,
              htl,
              origHTL,
              FailureTable.RECENTLY_FAILED_TIME,
              FailureTable.REJECT_TIME,
              source);
      finish(DATA_NOT_FOUND, null, false);
      return;
    }

    if (handleReassignTimeout()) return;

    if (origTag.shouldStop()) {
      finish(ROUTE_NOT_FOUND, null, false);
      return;
    }

    RecentlyFailedReturn r = new RecentlyFailedReturn();
    long now = System.currentTimeMillis();

    // Route it
    PeerRoutingSelectionParams params =
        new PeerRoutingSelectionParams(
            source,
            nodesRoutedTo,
            target,
            true,
            node.isAdvancedModeEnabled(),
            -1,
            null,
            2.0,
            key,
            htl,
            0L,
            source == null,
            realTimeFlag,
            r,
            false,
            now,
            newLoadManagement);
    next = node.network().peers().routingSelector().closerPeer(params);

    if (handleRecentlyFailedDecision(r, now)) return;

    if (next == null) {
      if (LOG.isDebugEnabled() && rejectOverloads > 0)
        LOG.debug(
            "no more peers, but overloads ({}/{} overloaded)", rejectOverloads, routeAttempts);
      finish(ROUTE_NOT_FOUND, null, false);
      node.routing().failureTable().onFinalFailure(key, null, htl, origHTL, -1, -1, source);
      return;
    }

    innerRouteRequests(next, origTag);
    // Will either chain back to routeRequests(), or call onAccepted().
  }

  private boolean adjustHTLOrFinish(boolean canWriteStorePrev) {
    if (dontDecrementHTLThisTime) {
      // NLM needs us to reroute.
      dontDecrementHTLThisTime = false;
      return false;
    }
    // See notes on when to decrement HTL in the original code.
    if ((!starting) && (!canWriteStorePrev)) {
      if (highHTLFailureCount++ >= MAX_HIGH_HTL_FAILURES) {
        if (LOG.isDebugEnabled()) LOG.debug("Too many failures at non-cacheable HTL");
        finish(ROUTE_NOT_FOUND, null, false);
        return true;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Allowing failure {} htl is still {}", highHTLFailureCount, htl);
      return false;
    }
    // Decrement at this point so we can DNF immediately on reaching HTL 0.
    htl = node.routing().decrementHTL((hasForwarded ? null : source), htl);
    if (LOG.isDebugEnabled()) LOG.debug("Decremented HTL to {}", htl);
    return false;
  }

  private boolean handleReassignTimeout() {
    boolean failed;
    synchronized (this) {
      failed = reassignedToSelfDueToMultipleTimeouts;
      if (!failed) routeAttempts++;
    }
    if (failed) {
      finish(TIMED_OUT, null, false);
      return true;
    }
    return false;
  }

  private boolean handleRecentlyFailedDecision(RecentlyFailedReturn r, long now) {
    long recentlyFailed = r.recentlyFailed();
    if (recentlyFailed > now) {
      synchronized (this) {
        recentlyFailedTimeLeft = (int) Math.min(Integer.MAX_VALUE, recentlyFailed - now);
      }
      finish(RECENTLY_FAILED, null, false);
      node.routing().failureTable().onFinalFailure(key, null, htl, origHTL, -1, -1, source);
      return true;
    }
    boolean rfAnyway;
    synchronized (this) {
      rfAnyway = killedByRecentlyFailed;
    }
    if (rfAnyway) {
      // See comment in the original code for rationale.
      synchronized (this) {
        recentlyFailedTimeLeft = 0;
      }
      finish(RECENTLY_FAILED, null, false);
      node.routing().failureTable().onFinalFailure(key, null, htl, origHTL, -1, -1, source);
      return true;
    }
    return false;
  }

  private class MainLoopCallback implements SlowAsyncMessageFilterCallback {

    // Needs to be a separate class so it can check whether the main loop has moved on to another
    // peer.
    // If it has

    private final PeerNode waitingFor;
    private final boolean noReroute;
    private final long deadline;
    private byte[] sskData;
    private byte[] headers;
    final long searchTimeout;

    public MainLoopCallback(PeerNode source, boolean noReroute, long searchTimeout) {
      waitingFor = source;
      this.noReroute = noReroute;
      this.searchTimeout = searchTimeout;
      deadline = System.currentTimeMillis() + searchTimeout;
    }

    private MessageFilter createMessageFilter(int timeout, PeerNode next) {
      MessageFilter mfDNF =
          MessageFilter.create()
              .setSource(next)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPDataNotFound);
      MessageFilter mfRF =
          MessageFilter.create()
              .setSource(next)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPRecentlyFailed);
      MessageFilter mfRouteNotFound =
          MessageFilter.create()
              .setSource(next)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPRouteNotFound);
      MessageFilter mfRejectedOverload =
          MessageFilter.create()
              .setSource(next)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPRejectedOverload);

      if (!isSSK) {
        MessageFilter mfRealDFCHK =
            MessageFilter.create()
                .setSource(next)
                .setField(DMT.UID, uid)
                .setTimeout(timeout)
                .setType(DMT.FNPCHKDataFound);
        return mfDNF.or(mfRF.or(mfRouteNotFound.or(mfRejectedOverload.or(mfRealDFCHK))));
      } else {
        MessageFilter mfPubKey =
            MessageFilter.create()
                .setSource(next)
                .setField(DMT.UID, uid)
                .setTimeout(timeout)
                .setType(DMT.FNPSSKPubKey);
        MessageFilter mfDFSSKHeaders =
            MessageFilter.create()
                .setSource(next)
                .setField(DMT.UID, uid)
                .setTimeout(timeout)
                .setType(DMT.FNPSSKDataFoundHeaders);
        MessageFilter mfDFSSKData =
            MessageFilter.create()
                .setSource(next)
                .setField(DMT.UID, uid)
                .setTimeout(timeout)
                .setType(DMT.FNPSSKDataFoundData);
        return mfDNF.or(
            mfRF.or(
                mfRouteNotFound.or(
                    mfRejectedOverload.or(mfPubKey.or(mfDFSSKHeaders.or(mfDFSSKData))))));
      }
    }

    private DO handleMessage(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      // For debugging purposes, remember the number of responses AFTER the insert and the last
      // message type we received.
      gotMessages++;
      lastMessage = msg.getSpec().getName();
      if (LOG.isDebugEnabled()) LOG.debug("Handling message {} on {}", msg, this);

      return dispatchByKind(msg, wasFork, source, waiter);
    }

    private DO handleControlMessage(Message msg, boolean wasFork, PeerNode source) {
      if (msg.getSpec() == DMT.FNPDataNotFound) {
        handleDataNotFound(wasFork, source);
        return DO.FINISHED;
      }
      if (msg.getSpec() == DMT.FNPRecentlyFailed) {
        handleRecentlyFailed(msg, source);
        return DO.NEXT_PEER;
      }
      if (msg.getSpec() == DMT.FNPRouteNotFound) {
        handleRouteNotFound(msg, source);
        return DO.NEXT_PEER;
      }
      if (msg.getSpec() == DMT.FNPRejectedOverload) {
        return handleRejectedOverload(msg, wasFork, source) ? DO.WAIT : DO.FINISHED;
      }
      return null;
    }

    private DO dispatchByKind(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      DO ctrl = handleControlMessage(msg, wasFork, source);
      if (ctrl != null) return ctrl;
      return isSSK
          ? handleSskMessage(msg, wasFork, source, waiter)
          : handleChkMessage(msg, wasFork, source, waiter);
    }

    private DO handleChkMessage(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      if (msg.getSpec() == DMT.FNPCHKDataFound) {
        handleCHKDataFound(msg, wasFork, source, waiter);
        return DO.FINISHED;
      }
      LOG.error("Unexpected CHK control message: {}", msg);
      int t = timeSinceSent();
      node.routing().failureTable().onFailed(key, source, htl, t, t);
      source.noLongerRoutingTo(origTag, false);
      return DO.NEXT_PEER;
    }

    private DO handleSskMessage(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      if (msg.getSpec() == DMT.FNPSSKPubKey) return onSskPubKey(msg, wasFork, source, waiter);
      if (msg.getSpec() == DMT.FNPSSKDataFoundData)
        return onSskDataFoundData(msg, wasFork, source, waiter);
      if (msg.getSpec() == DMT.FNPSSKDataFoundHeaders)
        return onSskDataFoundHeaders(msg, wasFork, source, waiter);
      LOG.error("Unexpected SSK control message: {}", msg);
      int t = timeSinceSent();
      node.routing().failureTable().onFailed(key, source, htl, t, t);
      source.noLongerRoutingTo(origTag, false);
      return DO.NEXT_PEER;
    }

    private DO onSskPubKey(Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      if (!handleSSKPubKey(msg, source)) return DO.NEXT_PEER;
      if (waiter.sskData != null && waiter.headers != null) {
        finishSSK(source, wasFork, waiter.headers, waiter.sskData);
        return DO.FINISHED;
      }
      return DO.WAIT;
    }

    private DO onSskDataFoundData(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      if (LOG.isDebugEnabled()) LOG.debug("Got data on {}", uid);
      waiter.sskData = ((ShortBuffer) msg.getObject(DMT.DATA)).getData();
      if (pubKey != null && waiter.headers != null) {
        finishSSK(source, wasFork, waiter.headers, waiter.sskData);
        return DO.FINISHED;
      }
      return DO.WAIT;
    }

    private DO onSskDataFoundHeaders(
        Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
      if (LOG.isDebugEnabled()) LOG.debug("Got headers on {}", uid);
      waiter.headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
      if (pubKey != null && waiter.sskData != null) {
        finishSSK(source, wasFork, waiter.headers, waiter.sskData);
        return DO.FINISHED;
      }
      return DO.WAIT;
    }

    private boolean handleSSKPubKey(Message msg, PeerNode next) {
      if (LOG.isDebugEnabled()) LOG.debug("Got pubkey on {}", uid);
      byte[] pubkeyAsBytes = ((ShortBuffer) msg.getObject(DMT.PUBKEY_AS_BYTES)).getData();
      try {
        if (pubKey == null) pubKey = DSAPublicKey.create(pubkeyAsBytes);
        ((NodeSSK) key).setPubKey(pubKey);
        return true;
      } catch (SSKVerifyException e) {
        pubKey = null;
        LOG.error("Invalid pubkey signature from {} on {} ({})", next, uid, e.getMessage(), e);
        int t = timeSinceSent();
        node.routing().failureTable().onFailed(key, next, htl, t, t);
        next.noLongerRoutingTo(origTag, false);
        return false; // try the next node
      } catch (CryptFormatException e) {
        LOG.error("Invalid pubkey format from {} on {} ({})", next, uid, e.getMessage(), e);
        int t = timeSinceSent();
        node.routing().failureTable().onFailed(key, next, htl, t, t);
        next.noLongerRoutingTo(origTag, false);
        return false; // try the next node
      }
    }

    @Override
    public void onMatched(Message msg) {

      if (waitingFor != msg.getSource()) {
        return;
      }

      DO action = handleMessage(msg, noReroute, waitingFor, this);

      Runnable followUp =
          switch (action) {
            case NEXT_PEER -> (noReroute ? (Runnable) () -> {} : RequestSender.this::routeRequests);
            case WAIT -> this::schedule;
            default -> () -> {};
          };
      followUp.run();
    }

    public void schedule() {
      long now = System.currentTimeMillis();
      int timeout = (int) (Math.min(Integer.MAX_VALUE, deadline - now));
      if (timeout >= 0) {
        MessageFilter mf = createMessageFilter(timeout, waitingFor);
        try {
          node.network().usm().addAsyncFilter(mf, this, RequestSender.this);
        } catch (DisconnectedException _) {
          onDisconnect(lastNode);
        }
      } else {
        onTimeout();
      }
    }

    @Override
    public boolean shouldTimeout() {
      return false;
    }

    @Override
    public void onTimeout() {
      // This is probably a downstream timeout.
      // It's not a serious problem until we have a second (fatal) timeout.
      LOG.info(
          "Timed out after waiting {} on {} from {} ({} messages; last={}) noReroute={}",
          searchTimeout,
          uid,
          waitingFor,
          gotMessages,
          lastMessage,
          noReroute);
      if (noReroute) {
        waitingFor.localRejectedOverload("FatalTimeoutForked", realTimeFlag);
      } else {
        // Fatal timeout
        waitingFor.localRejectedOverload("FatalTimeout", realTimeFlag);
        forwardRejectedOverload();
        node.routing()
            .failureTable()
            .onFinalFailure(
                key,
                waitingFor,
                htl,
                origHTL,
                FailureTable.RECENTLY_FAILED_TIME,
                FailureTable.REJECT_TIME,
                source);
        finish(TIMED_OUT, waitingFor, false);
      }

      // Wait for the second timeout synchronously.
      long secondDeadline = System.currentTimeMillis() + searchTimeout;
      while (true) {

        Message msg;
        try {
          int timeout =
              (int) (Math.min(Integer.MAX_VALUE, secondDeadline - System.currentTimeMillis()));
          msg =
              node.network()
                  .usm()
                  .waitFor(createMessageFilter(timeout, waitingFor), RequestSender.this);
        } catch (DisconnectedException _) {
          LOG.info("Disconnected from {} while waiting for reply on {}", waitingFor, this);
          waitingFor.noLongerRoutingTo(origTag, false);
          return;
        }

        if (msg == null) {
          // Second timeout.
          LOG.error(
              "Fatal timeout waiting for reply after Accepted on {}" + FROM_SEP + "{}",
              this,
              waitingFor);
          waitingFor.fatalTimeout(origTag, false);
          return;
        }

        DO action = handleMessage(msg, noReroute, waitingFor, this);

        if (action == DO.FINISHED) return;
        else if (action == DO.NEXT_PEER) {
          waitingFor.noLongerRoutingTo(origTag, false);
          return; // Don't try others
        }
      }
    }

    @Override
    public void onDisconnect(PeerContext ctx) {
      LOG.info("Disconnected from {} while waiting for data on {}", waitingFor, uid);
      waitingFor.noLongerRoutingTo(origTag, false);
      if (noReroute) return;
      // Try another peer.
      routeRequests();
    }

    @Override
    public void onRestarted(PeerContext ctx) {
      onDisconnect(ctx);
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.NORM_PRIORITY.value;
    }

    @Override
    public String toString() {
      return super.toString() + ":" + waitingFor + ":" + noReroute + ":" + RequestSender.this;
    }

    private synchronized long timeSinceSentForTimeout() {
      int time = RequestSender.this.timeSinceSent();
      if (time > FailureTable.REJECT_TIME) {
        if (time < searchTimeout + SECONDS.toMillis(10)) return FailureTable.REJECT_TIME;
        LOG.atError()
            .addArgument(time)
            .addArgument(() -> TimeUtil.formatTime(time, 2, true))
            .log("Very long time since sent: {} ({})");
        return FailureTable.REJECT_TIME;
      }
      return time;
    }

    private void handleRouteNotFound(Message msg, PeerNode next) {
      short newHtl = msg.getShort(DMT.HTL);
      if (newHtl < 0) newHtl = 0;
      if (newHtl < htl) htl = newHtl;
      next.successNotOverload(realTimeFlag);
      int t = timeSinceSent();
      node.routing().failureTable().onFailed(key, next, htl, t, t);
      next.noLongerRoutingTo(origTag, false);
    }

    private void handleDataNotFound(boolean wasFork, PeerNode next) {
      next.successNotOverload(realTimeFlag);
      node.routing()
          .failureTable()
          .onFinalFailure(
              key,
              next,
              htl,
              origHTL,
              FailureTable.RECENTLY_FAILED_TIME,
              FailureTable.REJECT_TIME,
              source);
      if (!wasFork) finish(DATA_NOT_FOUND, next, false);
      else next.noLongerRoutingTo(origTag, false);
    }

    private void handleRecentlyFailed(Message msg, PeerNode next) {
      next.successNotOverload(realTimeFlag);
      int timeLeft = msg.getInt(DMT.TIME_LEFT);
      int origTimeLeft = timeLeft;
      if (timeLeft <= 0) {
        if (timeLeft == 0) {
          if (LOG.isDebugEnabled())
            LOG.debug("RecentlyFailed: timeout already consumed on {}", RequestSender.this);
        } else {
          LOG.error("Impossible: timeLeft={}", timeLeft);
        }
        origTimeLeft = 0;
        timeLeft = 0;
      }
      int timeSinceSent = Math.max(0, timeSinceSent());
      timeLeft -= timeSinceSent;
      timeLeft -= origTimeLeft / 100; // clock skew cushion
      if (timeLeft < 0) timeLeft = 0;
      synchronized (RequestSender.this) {
        killedByRecentlyFailed = true;
      }
      node.routing()
          .failureTable()
          .onFinalFailure(key, next, htl, origHTL, timeLeft, FailureTable.REJECT_TIME, source);
      next.noLongerRoutingTo(origTag, false);
    }

    private boolean handleRejectedOverload(Message msg, boolean wasFork, PeerNode next) {
      forwardRejectedOverload();
      rejectOverloads++;
      if (msg.getBoolean(DMT.IS_LOCAL)) {
        long t = timeSinceSentForTimeout();
        node.routing().failureTable().onFailed(key, next, htl, t, t);
        next.localRejectedOverload("ForwardRejectedOverload2", realTimeFlag);
        LOG.info("Local RejectedOverload after Accepted, moving on to next peer");
        next.noLongerRoutingTo(origTag, false);
        node.routing()
            .failureTable()
            .onFinalFailure(
                key,
                next,
                htl,
                origHTL,
                FailureTable.RECENTLY_FAILED_TIME,
                FailureTable.REJECT_TIME,
                source);
        if (!wasFork) finish(TIMED_OUT, next, false);
        return false;
      }
      return true;
    }

    private void handleCHKDataFound(
        Message msg, final boolean wasFork, final PeerNode next, final MainLoopCallback waiter) {
      waiter.headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
      if (!wasFork) origTag.senderTransferBegins((NodeCHK) key, RequestSender.this);
      final PartiallyReceivedBlock localPrb =
          new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
      boolean failNow = false;
      synchronized (RequestSender.this) {
        finalHeaders = waiter.headers;
        if (status == SUCCESS || RequestSender.this.prb != null && transferringFrom != null)
          failNow = true;
        if ((!wasFork)
            && (RequestSender.this.prb == null
                || !RequestSender.this.prb.allReceivedAndNotAborted()))
          RequestSender.this.prb = localPrb;
        RequestSender.this.notifyAll();
      }
      if (!wasFork) fireCHKTransferBegins();
      final long tStart = System.currentTimeMillis();
      final BlockReceiver br =
          new BlockReceiver(
              new BlockTransferContext(
                  node.network().usm(),
                  node.network().ticker(),
                  next,
                  uid,
                  localPrb,
                  RequestSender.this,
                  realTimeFlag),
              myTimeoutHandler,
              true);
      if (failNow) {
        handleChkFailNow(br, localPrb, next, wasFork);
        return;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Receiving data");
      if (!wasFork) {
        synchronized (RequestSender.this) {
          transferringFrom = next;
        }
      } else if (LOG.isDebugEnabled()) LOG.debug("Receiving data from fork");
      receivingAsync = true;
      br.receive(
          new BlockReceiverCompletion() {
            @Override
            public void blockReceived(byte[] data) {
              onChkBlockReceived(data, wasFork, next, waiter, localPrb, tStart);
            }

            @Override
            public void blockReceiveFailed(RetrievalException e) {
              onChkBlockReceiveFailed(e, wasFork, next, br, localPrb);
            }
          });
    }

    private void handleChkFailNow(
        BlockReceiver br, PartiallyReceivedBlock prb, PeerNode next, boolean wasFork) {
      if (LOG.isDebugEnabled())
        LOG.debug("Terminating forked transfer on {}" + FROM_SEP + "{}", RequestSender.this, next);
      prb.abort(RetrievalException.CANCELLED_BY_RECEIVER, "Cancelling fork", true);
      br.receive(
          new BlockReceiverCompletion() {
            @Override
            public void blockReceived(byte[] buf) {
              if (!wasFork) origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
              next.noLongerRoutingTo(origTag, false);
            }

            @Override
            public void blockReceiveFailed(RetrievalException e) {
              if (!wasFork) origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
              next.noLongerRoutingTo(origTag, false);
            }
          });
    }

    private boolean tryVerifyAndCommit(
        byte[] headers, byte[] data, PeerNode next, boolean wasFork) {
      try {
        verifyAndCommit(headers, data);
        if (LOG.isDebugEnabled()) LOG.debug("Written to store");
        return true;
      } catch (KeyVerifyException e1) {
        LOG.info("Got data but verify failed during store: {}", e1, e1);
        node.routing()
            .failureTable()
            .onFinalFailure(
                key,
                next,
                htl,
                origHTL,
                FailureTable.RECENTLY_FAILED_TIME,
                FailureTable.REJECT_TIME,
                source);
        if (!wasFork) finish(VERIFY_FAILURE, next, false);
        else next.noLongerRoutingTo(origTag, false);
        return false;
      }
    }

    @SuppressWarnings("java:S1181")
    private void onChkBlockReceived(
        byte[] data,
        boolean wasFork,
        PeerNode next,
        MainLoopCallback waiter,
        PartiallyReceivedBlock prb,
        long tStart) {
      try {
        long tEnd = System.currentTimeMillis();
        transferTime = tEnd - tStart;
        boolean haveSetPRB = false;
        synchronized (RequestSender.this) {
          transferringFrom = null;
          if (RequestSender.this.prb == null
              || !RequestSender.this.prb.allReceivedAndNotAborted()) {
            RequestSender.this.prb = prb;
            haveSetPRB = true;
          }
        }
        if (!wasFork) origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
        next.transferSuccess(realTimeFlag);
        next.successNotOverload(realTimeFlag);
        node.network().stats().successfulBlockReceive(realTimeFlag, source == null);
        if (LOG.isDebugEnabled()) LOG.debug("Received data");
        if (!tryVerifyAndCommit(waiter.headers, data, next, wasFork)) return;
        if (haveSetPRB) fireCHKTransferBegins();
        finish(SUCCESS, next, false);
      } catch (Throwable t) {
        LOG.error("CHK block receive failed on {}", RequestSender.this, t);
        if (!wasFork) finish(INTERNAL_ERROR, next, true);
      } finally {
        if (wasFork) next.noLongerRoutingTo(origTag, false);
      }
    }

    @SuppressWarnings("java:S1181")
    private void onChkBlockReceiveFailed(
        RetrievalException e,
        boolean wasFork,
        PeerNode next,
        BlockReceiver br,
        PartiallyReceivedBlock prb) {
      try {
        synchronized (RequestSender.this) {
          transferringFrom = null;
        }
        origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
        if (e.getReason() == RetrievalException.SENDER_DISCONNECTED)
          LOG.info("Transfer failed (disconnect) during fetch: {}", e, e);
        else
          LOG.atInfo()
              .addArgument(e.getReason())
              .addArgument(() -> RetrievalException.getErrString(e.getReason()))
              .addArgument(e)
              .addArgument(next)
              .setCause(e)
              .log("Transfer failed ({}/{}): {}" + FROM_SEP + "{}");
        if (RequestSender.this.source == null)
          LOG.atInfo()
              .addArgument(e.getReason())
              .addArgument(() -> RetrievalException.getErrString(e.getReason()))
              .addArgument(e)
              .addArgument(next)
              .setCause(e)
              .log("Local transfer failed: {} : {}): {}" + FROM_SEP + "{}");
        if (!prb.abortedLocally())
          next.localRejectedOverload("TransferFailedRequest" + e.getReason(), realTimeFlag);
        node.routing()
            .failureTable()
            .onFinalFailure(
                key,
                next,
                htl,
                origHTL,
                FailureTable.RECENTLY_FAILED_TIME,
                FailureTable.REJECT_TIME,
                source);
        int reason = e.getReason();
        boolean timeout =
            (!br.senderAborted())
                && (reason == RetrievalException.SENDER_DIED
                    || reason == RetrievalException.RECEIVER_DIED
                    || reason == RetrievalException.TIMED_OUT
                    || reason == RetrievalException.UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT);
        if (timeout) {
          if (LOG.isDebugEnabled()) LOG.debug("Timeout transferring data : {}", e, e);
          next.transferFailed(e.getErrString(), realTimeFlag);
        } else {
          node.routing()
              .failureTable()
              .onFinalFailure(
                  key,
                  next,
                  htl,
                  origHTL,
                  FailureTable.RECENTLY_FAILED_TIME,
                  FailureTable.REJECT_TIME,
                  source);
        }
        if (!prb.abortedLocally())
          node.network().stats().failedBlockReceive(true, timeout, realTimeFlag, source == null);
      } catch (Throwable t) {
        LOG.error("CHK block receive handling failed on {}", RequestSender.this, t);
        if (!wasFork) finish(INTERNAL_ERROR, next, true);
      } finally {
        if (wasFork) next.noLongerRoutingTo(origTag, false);
      }
    }

    private void finishSSK(PeerNode next, boolean wasFork, byte[] headers, byte[] sskData) {
      try {
        block = new SSKBlock(sskData, headers, (NodeSSK) key, false);
        node.storage().storeShallow(block, canWriteClientCache, canWriteDatastore, false);
        if (node.bootstrap().random().nextInt(RANDOM_REINSERT_INTERVAL) == 0)
          node.services().clientCore().getTransfers().queueRandomReinsert(block);
        synchronized (RequestSender.this) {
          finalHeaders = headers;
          finalSskData = sskData;
        }
        finish(SUCCESS, next, false);
      } catch (SSKVerifyException e) {
        LOG.error("Failed to verify: {}" + FROM_SEP + "{}", e, next, e);
        if (!wasFork) finish(VERIFY_FAILURE, next, false);
        else next.noLongerRoutingTo(origTag, false);
      } catch (KeyCollisionException _) {
        LOG.info("SSK collision during finish on {}", RequestSender.this);
        block =
            node.storage()
                .fetch(
                    (NodeSSK) key,
                    false,
                    canWriteClientCache,
                    canWriteClientCache,
                    canWriteDatastore,
                    false,
                    null);
        if (block != null) {
          headers = block.getRawHeaders();
          sskData = block.getRawData();
        }
        synchronized (RequestSender.this) {
          if (finalHeaders == null || finalSskData == null) {
            finalHeaders = headers;
            finalSskData = sskData;
          }
        }
        finish(SUCCESS, next, false);
      }
    }
  }

  enum OFFER_STATUS {
    FETCHING, // Fetching asynchronously or already fetched.
    TWO_STAGE_TIMEOUT, // Waiting asynchronously for two stage timeout; remove the offer, but don't
    // unlock the tag.
    FATAL, // Fatal error, fail the whole request.
    TRY_ANOTHER, // Delete the offer and move on.
    KEEP // Keep the offer and move on.
  }

  /**
   * Tries offers. If we succeed or fatally fail, end the request. If an offer is being transferred
   * asynchronously, set the receivingAsync flag and return. Otherwise, we have run out of offers
   * without succeeding, so chain to startRequests().
   *
   * @param pn If this and status are non-null, we have just tried an offer, and these two contain
   *     its status. This should be handled before we try to do anymore.
   */
  private void tryOffers(final OfferList offers, PeerNode pn, OFFER_STATUS status) {
    while (true) {
      if (pn == null) {
        // Fetches valid offers, then expired ones. Expired offers don't count towards failures,
        // but they're still worth trying.
        BlockOffer offer = offers.getFirstOffer();
        if (offer == null) {
          if (LOG.isDebugEnabled()) LOG.debug("No more offers");
          startRequests();
          return;
        }
        pn = offer.getPeerNode();
        status = tryOffer(offer, pn, offers);
      }
      switch (status) {
        case FATAL:
          offers.deleteLastOffer();
          pn.noLongerRoutingTo(origTag, true);
          return;
        case TWO_STAGE_TIMEOUT:
          offers.deleteLastOffer();
          break;
        case FETCHING:
          return;
        case KEEP:
          offers.keepLastOffer();
          pn.noLongerRoutingTo(origTag, true);
          break;
        case TRY_ANOTHER:
          offers.deleteLastOffer();
          pn.noLongerRoutingTo(origTag, true);
          break;
      }
      pn = null;
      status = null;
    }
  }

  private OFFER_STATUS tryOffer(final BlockOffer offer, final PeerNode pn, final OfferList offers) {
    if (pn == null) return OFFER_STATUS.TRY_ANOTHER;
    if (pn.getBootID() != offer.bootID) return OFFER_STATUS.TRY_ANOTHER;
    origTag.addRoutedTo(pn, true);
    Message msg = DMT.createFNPGetOfferedKey(key, offer.authenticator, pubKey == null, uid);
    msg.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
    try {
      pn.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Offer request send disconnected: {} getting offer for {}", pn, key);
      return OFFER_STATUS.TRY_ANOTHER;
    } catch (SyncSendWaitedTooLongException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Offer request send timed out: {}" + FOR_SEP + "{}", pn, key);
      return OFFER_STATUS.TRY_ANOTHER;
    }
    // Wait asynchronously for a response.
    synchronized (this) {
      receivingAsync = true;
    }
    try {
      node.network()
          .usm()
          .addAsyncFilter(
              getOfferedKeyReplyFilter(pn, getOfferedTimeout),
              buildOfferReplyCallback(offer, pn, offers),
              this);
      return OFFER_STATUS.FETCHING;
    } catch (DisconnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Offer request send disconnected (async): {} getting offer for {}", pn, key);
      return OFFER_STATUS.TRY_ANOTHER;
    }
  }

  private SlowAsyncMessageFilterCallback buildOfferReplyCallback(
      final BlockOffer offer, final PeerNode pn, final OfferList offers) {
    return new SlowAsyncMessageFilterCallback() {
      @Override
      public void onMatched(Message m) {
        OFFER_STATUS offerStatus =
            isSSK ? handleSSKOfferReply(m, pn, offer) : handleCHKOfferReply(m, pn, offer, offers);
        tryOffers(offers, pn, offerStatus);
      }

      @Override
      public boolean shouldTimeout() {
        return false;
      }

      @Override
      public void onTimeout() {
        LOG.info("Timeout awaiting reply to offer request on {} to {}", this, pn);
        OFFER_STATUS offerStatus = handleOfferTimeout(offer, pn);
        tryOffers(offers, pn, offerStatus);
      }

      @Override
      public void onDisconnect(PeerContext ctx) {
        if (LOG.isDebugEnabled())
          LOG.debug("Offer reply wait disconnected: {} getting offer for {}", pn, key);
        tryOffers(offers, pn, OFFER_STATUS.TRY_ANOTHER);
      }

      @Override
      public void onRestarted(PeerContext ctx) {
        // Treat restart like a disconnect but record it distinctly for diagnostics.
        if (LOG.isDebugEnabled()) LOG.debug("Restarted: {} getting offer for {}", pn, key);
        tryOffers(offers, pn, OFFER_STATUS.TRY_ANOTHER);
      }

      @Override
      public int getPriority() {
        return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
      }
    };
  }

  private MessageFilter getOfferedKeyReplyFilter(final PeerNode pn, long timeout) {
    MessageFilter mfRO =
        MessageFilter.create()
            .setSource(pn)
            .setField(DMT.UID, uid)
            .setTimeout(timeout)
            .setType(DMT.FNPRejectedOverload);
    MessageFilter mfGetInvalid =
        MessageFilter.create()
            .setSource(pn)
            .setField(DMT.UID, uid)
            .setTimeout(timeout)
            .setType(DMT.FNPGetOfferedKeyInvalid);
    if (isSSK) {
      MessageFilter mfAltDF =
          MessageFilter.create()
              .setSource(pn)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPSSKDataFoundHeaders);
      return mfAltDF.or(mfRO.or(mfGetInvalid));
    } else {
      MessageFilter mfDF =
          MessageFilter.create()
              .setSource(pn)
              .setField(DMT.UID, uid)
              .setTimeout(timeout)
              .setType(DMT.FNPCHKDataFound);
      return mfDF.or(mfRO.or(mfGetInvalid));
    }
  }

  private OFFER_STATUS handleOfferTimeout(final BlockOffer offer, final PeerNode pn) {
    try {
      node.network()
          .usm()
          .addAsyncFilter(
              getOfferedKeyReplyFilter(pn, GET_OFFER_LONG_TIMEOUT),
              new SlowAsyncMessageFilterCallback() {

                @Override
                public void onMatched(Message m) {
                  OFFER_STATUS offerStatus2 =
                      isSSK
                          ? handleSSKOfferReply(m, pn, offer)
                          : handleCHKOfferReply(m, pn, offer, null);
                  if (offerStatus2 != OFFER_STATUS.FETCHING) pn.noLongerRoutingTo(origTag, true);
                  // If FETCHING, the block transfer will unlock it.
                  if (LOG.isDebugEnabled())
                    LOG.debug(
                        "Forked get offered key due to two stage timeout completed with status {}"
                            + " from message {}"
                            + FOR_SEP
                            + "{} to {}",
                        status,
                        m,
                        RequestSender.this,
                        pn);
                }

                @Override
                public boolean shouldTimeout() {
                  return false;
                }

                @Override
                public void onTimeout() {
                  LOG.error(
                      "Fatal timeout getting offered key from {}" + FOR_SEP + "{}",
                      pn,
                      RequestSender.this);
                  pn.fatalTimeout(origTag, true);
                }

                @Override
                public void onDisconnect(PeerContext ctx) {
                  // Ok.
                  pn.noLongerRoutingTo(origTag, true);
                }

                @Override
                public void onRestarted(PeerContext ctx) {
                  // Ok.
                  pn.noLongerRoutingTo(origTag, true);
                }

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
                }
              },
              this);
      return OFFER_STATUS.TWO_STAGE_TIMEOUT;
    } catch (DisconnectedException _) {
      // Okay.
      if (LOG.isDebugEnabled())
        LOG.debug("Offer reply wait disconnected (second stage): {} getting offer for {}", pn, key);
      return OFFER_STATUS.TRY_ANOTHER;
    }
  }

  private OFFER_STATUS handleSSKOfferReply(Message reply, PeerNode pn, BlockOffer offer) {
    if (reply.getSpec() == DMT.FNPRejectedOverload) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "SSK offer reply: " + NODE_PREFIX + "{} rejected FNPGetOfferedKey for {} (expired={}",
            pn,
            key,
            offer.isExpired());
      return OFFER_STATUS.KEEP;
    }
    if (reply.getSpec() == DMT.FNPGetOfferedKeyInvalid) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "SSK offer reply invalid: "
                + NODE_PREFIX
                + "{} rejected FNPGetOfferedKey as invalid with reason {}",
            pn,
            reply.getShort(DMT.REASON));
      return OFFER_STATUS.TRY_ANOTHER;
    }
    if (reply.getSpec() == DMT.FNPSSKDataFoundHeaders) {
      return processSskHeadersReply(
          pn, ((ShortBuffer) reply.getObject(DMT.BLOCK_HEADERS)).getData());
    }
    LOG.error("Unexpected SSK offer reply: {}", reply);
    return OFFER_STATUS.TRY_ANOTHER;
  }

  private OFFER_STATUS processSskHeadersReply(PeerNode pn, byte[] headers) {
    Message dataMessage = waitForOfferData(pn);
    if (dataMessage == null) return OFFER_STATUS.TRY_ANOTHER;
    byte[] sskData = ((ShortBuffer) dataMessage.getObject(DMT.DATA)).getData();
    if (!ensurePubKeyForOffer(pn)) return OFFER_STATUS.TRY_ANOTHER;
    if (finishSSKFromGetOffer(pn, headers, sskData)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Successfully fetched SSK from offer from {}" + FOR_SEP + "{}", pn, key);
      return OFFER_STATUS.FETCHING;
    }
    return OFFER_STATUS.TRY_ANOTHER;
  }

  private Message waitForOfferData(PeerNode pn) {
    MessageFilter mfData =
        MessageFilter.create()
            .setSource(pn)
            .setField(DMT.UID, uid)
            .setTimeout(getOfferedTimeout)
            .setType(DMT.FNPSSKDataFoundData);
    try {
      Message dataMessage = node.network().usm().waitFor(mfData, this);
      if (dataMessage == null) {
        LOG.error(
            "Offer headers arrived without data from {} for offer for {} on {}", pn, key, this);
      }
      return dataMessage;
    } catch (DisconnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Disconnected while fetching offer data from {} for {}", pn, key);
      return null;
    }
  }

  private boolean ensurePubKeyForOffer(PeerNode pn) {
    if (pubKey != null) return true;
    MessageFilter mfPK =
        MessageFilter.create()
            .setSource(pn)
            .setField(DMT.UID, uid)
            .setTimeout(getOfferedTimeout)
            .setType(DMT.FNPSSKPubKey);
    Message pk;
    try {
      pk = node.network().usm().waitFor(mfPK, this);
    } catch (DisconnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Disconnected while fetching offer pubkey from {} for {}", pn, key);
      return false;
    }
    if (pk == null) {
      LOG.error("Offer data arrived without pubkey from {} for offer for {} on {}", pn, key, this);
      return false;
    }
    try {
      pubKey = DSAPublicKey.create(((ShortBuffer) pk.getObject(DMT.PUBKEY_AS_BYTES)).getData());
      ((NodeSSK) key).setPubKey(pubKey);
      return true;
    } catch (CryptFormatException e) {
      LOG.error("Invalid pubkey for offer from {} for {} : {}", pn, key, e, e);
      return false;
    } catch (SSKVerifyException e) {
      LOG.error("Invalid SSK data for offer from {} for {} : {}", pn, key, e, e);
      return false;
    }
  }

  /**
   * @return True if we successfully received the offer or failed fatally, or we started to receive
   *     a block transfer asynchronously (in which case receivingAsync will be set, and if it fails,
   *     the whole request will fail). False if we should try the next offer and/or normal fetches.
   * @param offers The list of offered keys. Only used if we complete asynchronously. Null indicates
   *     this is a fork due to a two-stage timeout.
   */
  private OFFER_STATUS handleCHKOfferReply(
      Message reply, final PeerNode pn, final BlockOffer offer, final OfferList offers) {
    if (reply.getSpec() == DMT.FNPRejectedOverload) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "CHK offer reply: " + NODE_PREFIX + "{} rejected FNPGetOfferedKey for {} (expired={}",
            pn,
            key,
            offer.isExpired());
      return OFFER_STATUS.KEEP;
    }
    if (reply.getSpec() == DMT.FNPGetOfferedKeyInvalid) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "CHK offer reply invalid: "
                + NODE_PREFIX
                + "{} rejected FNPGetOfferedKey as invalid with reason {}",
            pn,
            reply.getShort(DMT.REASON));
      return OFFER_STATUS.TRY_ANOTHER;
    }
    if (reply.getSpec() == DMT.FNPCHKDataFound) {
      return processChkOfferReply(
          pn, offers, ((ShortBuffer) reply.getObject(DMT.BLOCK_HEADERS)).getData());
    }
    LOG.error("Unexpected CHK offer reply: {}", reply);
    return OFFER_STATUS.TRY_ANOTHER;
  }

  private OFFER_STATUS processChkOfferReply(
      final PeerNode pn, final OfferList offers, final byte[] headers) {
    finalHeaders = headers;
    origTag.senderTransferBegins((NodeCHK) key, this);
    try {
      prb = new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
      synchronized (this) {
        transferringFrom = pn;
        notifyAll();
      }
      fireCHKTransferBegins();
      BlockReceiver br =
          new BlockReceiver(
              new BlockTransferContext(
                  node.network().usm(), node.network().ticker(), pn, uid, prb, this, realTimeFlag),
              myTimeoutHandler,
              true);
      if (LOG.isDebugEnabled()) LOG.debug("Receiving data (for offer reply)");
      receivingAsync = true;
      br.receive(
          new BlockReceiverCompletion() {
            @Override
            public void blockReceived(byte[] data) {
              onChkOfferBlockReceived(pn, offers, finalHeaders, data);
            }

            @Override
            public void blockReceiveFailed(RetrievalException e) {
              onChkOfferBlockReceiveFailed(pn, offers, e);
            }
          });
      return OFFER_STATUS.FETCHING;
    } finally {
      origTag.senderTransferEnds((NodeCHK) key, this);
    }
  }

  @SuppressWarnings("java:S1181")
  private void onChkOfferBlockReceived(PeerNode pn, OfferList offers, byte[] headers, byte[] data) {
    synchronized (RequestSender.this) {
      transferringFrom = null;
    }
    origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
    try {
      pn.transferSuccess(realTimeFlag);
      if (LOG.isDebugEnabled()) LOG.debug("Received data from offer reply");
      verifyAndCommit(headers, data);
      finish(SUCCESS, pn, true);
      node.network().stats().successfulBlockReceive(realTimeFlag, source == null);
    } catch (KeyVerifyException e1) {
      LOG.info("Got data but verify failed during offer verify: {}", e1, e1);
      if (offers != null) {
        finish(GET_OFFER_VERIFY_FAILURE, pn, true);
        offers.deleteLastOffer();
      }
    } catch (Throwable t) {
      LOG.error("CHK offer block handling failed on {}", this, t);
      if (offers != null) finish(INTERNAL_ERROR, pn, true);
    } finally {
      pn.noLongerRoutingTo(origTag, true);
    }
  }

  @SuppressWarnings("java:S1181")
  private void onChkOfferBlockReceiveFailed(PeerNode pn, OfferList offers, RetrievalException e) {
    synchronized (RequestSender.this) {
      transferringFrom = null;
    }
    origTag.senderTransferEnds((NodeCHK) key, RequestSender.this);
    try {
      if (e.getReason() == RetrievalException.SENDER_DISCONNECTED)
        LOG.info("Transfer failed (disconnect) during offer fetch: {}", e, e);
      else
        LOG.atInfo()
            .addArgument(e.getReason())
            .addArgument(() -> RetrievalException.getErrString(e.getReason()))
            .addArgument(e)
            .addArgument(pn)
            .setCause(e)
            .log("Transfer for offer failed ({}/{}): {}" + FROM_SEP + "{}");
      if (offers != null) finish(GET_OFFER_TRANSFER_FAILED, pn, true);
      pn.transferFailed("RequestSenderGetOfferedTransferFailed", realTimeFlag);
      if (offers != null) offers.deleteLastOffer();
      if (!prb.abortedLocally())
        node.network().stats().failedBlockReceive(false, false, realTimeFlag, source == null);
    } catch (Throwable t) {
      LOG.error("CHK offer block receive failed on {}", this, t);
      if (offers != null) finish(INTERNAL_ERROR, pn, true);
    } finally {
      pn.noLongerRoutingTo(origTag, true);
    }
  }

  /**
   * Creates a composite filter that waits for {@code Accepted} or a rejection control message from
   * the selected downstream peer.
   *
   * @param next The downstream peer the request was sent to.
   * @param acceptedTimeout Timeout in milliseconds to await a control reply.
   * @param tag The UID tag associated with the request (used for assertions/diagnostics).
   * @return A filter matching {@code Accepted}, {@code RejectedLoop}, or {@code RejectedOverload}.
   */
  @Override
  protected MessageFilter makeAcceptedRejectedFilter(
      PeerNode next, long acceptedTimeout, UIDTag tag) {
    assert (tag == origTag);
    /*
     * What are we waiting for? FNPAccepted - continue FNPRejectedLoop - go to another node
     * FNPRejectedOverload - propagate back to source, go to another node if local
     */
    MessageFilter mfAccepted =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPAccepted);
    MessageFilter mfRejectedLoop =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPRejectedLoop);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(next)
            .setField(DMT.UID, uid)
            .setTimeout(acceptedTimeout)
            .setType(DMT.FNPRejectedOverload);

    // The order of these filters is performance-critical. The last or-filter is checked first.
    // So the last filter in the "or-chain" must be the filter that matches most frequently.
    return mfRejectedOverload.or(mfRejectedLoop.or(mfAccepted));
  }

  /**
   * Finish fetching an SSK. We must have received the data, the headers, and the pubkey by this
   * point.
   *
   * @param next The node we received the data from.
   * @return True if the request has completed. False if we need to look elsewhere.
   */
  private boolean finishSSKFromGetOffer(PeerNode next, byte[] headers, byte[] sskData) {
    try {
      block = new SSKBlock(sskData, headers, (NodeSSK) key, false);
      synchronized (this) {
        finalHeaders = headers;
        finalSskData = sskData;
      }
      node.storage().storeShallow(block, canWriteClientCache, canWriteDatastore, tryOffersOnly);
      if (node.bootstrap().random().nextInt(RANDOM_REINSERT_INTERVAL) == 0)
        node.services().clientCore().getTransfers().queueRandomReinsert(block);
      finish(SUCCESS, next, true);
      return true;
    } catch (SSKVerifyException e) {
      LOG.error("Failed to verify (from get offer): {} from {}", e, next, e);
      return false;
    } catch (KeyCollisionException _) {
      LOG.info("Collision (from get offer) on {}", this);
      finish(SUCCESS, next, true);
      return false;
    }
  }

  /**
   * Builds the protocol message that requests the data from a downstream peer.
   *
   * <p>For CHK requests, emits {@code FNPCHKDataRequest}. For SSK requests, emits {@code
   * FNPSSKDataRequest}, optionally asking for the public key when it is not yet known. In both
   * cases the real-time flag sub-message is attached to allow downstream policy to adapt.
   *
   * @return A fully populated request message including the real-time flag sub-message.
   */
  protected Message createDataRequest() {
    Message req;
    if (!isSSK) {
      req = DMT.createFNPCHKDataRequest(uid, htl, (NodeCHK) key);
    } else {
      req = DMT.createFNPSSKDataRequest(uid, htl, (NodeSSK) key, pubKey == null);
    }
    req.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
    return req;
  }

  private void verifyAndCommit(byte[] headers, byte[] data) throws KeyVerifyException {
    if (!isSSK) {
      CHKBlock chkBlock = new CHKBlock(data, headers, (NodeCHK) key);
      synchronized (this) {
        finalHeaders = headers;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Verified");
      // Cache only in the cache, not the store. The reason for this is that
      // requests don't go to the full distance, and therefore pollute the
      // store; simulations it is best to only include data from requests
      // which go all the way i.e., inserts.
      node.storage().storeShallow(chkBlock, canWriteClientCache, canWriteDatastore, tryOffersOnly);
      if (node.bootstrap().random().nextInt(RANDOM_REINSERT_INTERVAL) == 0)
        node.services().clientCore().getTransfers().queueRandomReinsert(chkBlock);
    } else {
      synchronized (this) {
        finalHeaders = headers;
        finalSskData = data;
      }
      try {
        SSKBlock sskBlock = new SSKBlock(data, headers, (NodeSSK) key, false);
        if (LOG.isDebugEnabled()) LOG.debug("Verified SSK");
        node.storage()
            .storeShallow(sskBlock, canWriteClientCache, canWriteDatastore, tryOffersOnly);
      } catch (KeyCollisionException _) {
        LOG.info("SSK collision during verify on {}", this);
      }
    }
  }

  private volatile boolean hasForwardedRejectedOverload;

  /**
   * Forwards a {@code RejectedOverload} signal to the request originator once per request.
   *
   * <p>Only the first call forwards; later calls are ignored. Wakes up any waiter blocked in {@link
   * #waitUntilStatusChange(short)} via {@link #notifyAll()}.
   */
  protected void forwardRejectedOverload() {
    synchronized (this) {
      if (hasForwardedRejectedOverload) return;
      hasForwardedRejectedOverload = true;
      notifyAll();
    }
    fireReceivedRejectOverload();
  }

  /**
   * Returns the current partially received block, if any.
   *
   * <p>The returned instance is mutable and updated as packets arrive. Callers should check {@link
   * PartiallyReceivedBlock#allReceivedAndNotAborted()} before assuming completeness.
   *
   * @return The shared {@link PartiallyReceivedBlock}, or {@code null} if a transfer has not
   *     started.
   */
  public PartiallyReceivedBlock getPRB() {
    return prb;
  }

  /**
   * Indicates whether a transfer has begun for this request.
   *
   * @return {@code true} if a {@link PartiallyReceivedBlock} has been allocated; otherwise {@code
   *     false}.
   */
  public boolean transferStarted() {
    return prb != null;
  }

  // these are bit-masks
  static final short WAIT_REJECTED_OVERLOAD = 1;
  static final short WAIT_TRANSFERRING_DATA = 2;
  static final short WAIT_FINISHED = 4;

  static final short WAIT_ALL = WAIT_REJECTED_OVERLOAD | WAIT_TRANSFERRING_DATA | WAIT_FINISHED;

  /**
   * Blocks until the transfer starts, a {@code RejectedOverload} is forwarded, or the request
   * reaches a terminal status.
   *
   * <p>The call does not time out; it logs defensively if there is no state change for an extended
   * period (approximately 5 minutes in real-time mode, 21 minutes in bulk mode), then continues to
   * wait.
   *
   * @param mask Bit mask describing states to ignore (i.e., those already observed by the caller).
   *     See {@link #WAIT_REJECTED_OVERLOAD}, {@link #WAIT_TRANSFERRING_DATA}, and {@link
   *     #WAIT_FINISHED}. Passing {@link #WAIT_ALL} is invalid.
   * @return A mask that includes any newly observed states; may be passed to a later call.
   * @throws IllegalArgumentException if {@code mask == WAIT_ALL}.
   */
  public synchronized short waitUntilStatusChange(short mask) {
    if (mask == WAIT_ALL) throw new IllegalArgumentException("Cannot ignore all!");
    while (true) {
      long now = System.currentTimeMillis();
      long deadline = now + (realTimeFlag ? MINUTES.toMillis(5) : MINUTES.toMillis(21));
      while (true) {
        short current = computeWaitCurrent(mask);
        if (current != mask) return current;
        try {
          if (isDeadlineExceeded(now, deadline, current)) break;
          logWaitingState(current);
          wait(deadline - now);
          now = System.currentTimeMillis();
          maybeLogMissedNotify(now, deadline, current);
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return mask;
        }
      }
    }
  }

  private short computeWaitCurrent(short mask) {
    short current = mask; // If any bits are set already, we ignore those states.
    if (hasForwardedRejectedOverload) current |= WAIT_REJECTED_OVERLOAD;
    if (prb != null) current |= WAIT_TRANSFERRING_DATA;
    if (status != NOT_FINISHED) current |= WAIT_FINISHED;
    return current;
  }

  private boolean isDeadlineExceeded(long now, long deadline, short current) {
    if (now >= deadline) {
      LOG.error(
          "Waited more than 5 minutes for status change on {} current = {} and there was no"
              + " change.",
          this,
          current);
      return true;
    }
    return false;
  }

  private void logWaitingState(short current) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Waiting for status change on {} current is {} status is {}", this, current, status);
  }

  private void maybeLogMissedNotify(long now, long deadline, short current) {
    if (now >= deadline) {
      LOG.error(
          "Waited more than 5 minutes for status change on {} current = {}, maybe nobody called"
              + " notify()",
          this,
          current);
      // Normally we would break; here, but we give the function a chance to
      // succeed in the next iteration and break in the above check if it did not.
    }
  }

  private static final RunningAverage avgTimeTaken = new TrivialRunningAverage();

  private static final RunningAverage avgTimeTakenTransfer = new TrivialRunningAverage();

  private long transferTime;

  /**
   * Complete the request. Note that if the request was forked (which unfortunately is possible
   * because of timeouts awaiting Accepted/Rejected), it is *possible* that there are other forks
   * still running; UIDTag will wait for them. Hence, a fork that fails should NOT call this method,
   * however, a fork that succeeds SHOULD call it.
   *
   * @param code The completion code.
   * @param next The node being routed to.
   * @param fromOfferedKey Whether this was the result of fetching an offered key.
   */
  private void finish(int code, PeerNode next, boolean fromOfferedKey) {
    if (LOG.isDebugEnabled()) LOG.debug("finish({}) on {} from {}", code, this, next);

    boolean doOpennet;

    synchronized (this) {
      if (status != NOT_FINISHED) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Status already set to {} - returning on {} would be setting {} from {}",
              status,
              this,
              code,
              next);
        if (next != null) next.noLongerRoutingTo(origTag, fromOfferedKey);
        return;
      }
      doOpennet = code == SUCCESS && !(fromOfferedKey || isSSK);
      if (doOpennet) origTag.waitingForOpennet(next); // Call this first so we don't unlock.
      if (next != null) next.noLongerRoutingTo(origTag, fromOfferedKey);
      // After calling both, THEN tell the handler.
      status = code;
      if (status == SUCCESS) successFrom = next;
      notifyAll();
    }

    boolean shouldUnlock = doOpennet;

    if (status == SUCCESS) {
      shouldUnlock = handleFinishSuccess(code, next, fromOfferedKey, doOpennet, shouldUnlock);
    } else {
      handleFinishFailure(code, fromOfferedKey);
    }

    if (shouldUnlock && next != null) next.noLongerRoutingTo(origTag, fromOfferedKey);

    synchronized (this) {
      opennetFinished = true;
      notifyAll();
    }
  }

  private boolean handleFinishSuccess(
      int code, PeerNode next, boolean fromOfferedKey, boolean doOpennet, boolean shouldUnlock) {
    if ((!isSSK) && transferTime > 0 && LOG.isDebugEnabled()) {
      logSuccessfulChkStats();
    }
    if (next != null) {
      next.onSuccess(false, isSSK);
    }
    node.network().stats().requestCompleted(true, source != null, isSSK);
    fireRequestSenderFinished(code, fromOfferedKey);
    if (doOpennet && finishOpennet(next)) shouldUnlock = false;
    return shouldUnlock;
  }

  private void handleFinishFailure(int code, boolean fromOfferedKey) {
    node.network().stats().requestCompleted(false, source != null, isSSK);
    fireRequestSenderFinished(code, fromOfferedKey);
  }

  private void logSuccessfulChkStats() {
    long timeTaken = System.currentTimeMillis() - startTime;
    avgTimeTaken.report(timeTaken);
    avgTimeTakenTransfer.report(transferTime);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Successful CHK request took {} average {}", timeTaken, avgTimeTaken.currentValue());
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Successful CHK request transfer {} average {}",
          transferTime,
          avgTimeTakenTransfer.currentValue());
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Search phase: mean {}ms",
          avgTimeTaken.currentValue() - avgTimeTakenTransfer.currentValue());
  }

  AsyncMessageCallback finishOpennetOnAck(final PeerNode next) {

    return new AsyncMessageCallback() {

      private boolean completed;

      private void completeOnce(String reason) {
        synchronized (this) {
          if (completed) return;
          completed = true;
        }
        if (LOG.isDebugEnabled()) LOG.debug("Opennet finish callback: {}", reason);
        origTag.finishedWaitingForOpennet(next);
      }

      @Override
      public void sent() {
        // Ignore
      }

      @Override
      public void acknowledged() {
        completeOnce("acknowledged");
      }

      @Override
      public void disconnected() {
        completeOnce("disconnected");
      }

      @Override
      public void fatalError() {
        completeOnce("fatalError");
      }
    };
  }

  /**
   * Acknowledge the opennet path folding attempt without sending a reference. Once the sending
   * completes (asynchronously), unlock everything.
   */
  void ackOpennet(final PeerNode next) {
    Message msg = DMT.createFNPOpennetCompletedAck(uid);
    // We probably should set opennetFinished after the sending completes.
    try {
      next.transport().sendAsync(msg, finishOpennetOnAck(next), this);
    } catch (NotConnectedException _) {
      // Ignore.
    }
  }

  /** Number of ping times to simulate */
  static final double PINGS = 3.0;

  /** Standard deviation in ping times */
  static final double PINGS_STDDEV = PINGS / 6.0;

  static final double MAX_PING_TIME = (double) RequestSender.OPENNET_TIMEOUT / 10;

  private long randomDelayFinishOpennetLocal() {
    double pingTime =
        // Noderefs are sent as real-time
        node.network().stats().getBwlimitDelayTimeRT()
            + node.network().stats().nodePinger.averagePingTime();
    pingTime = Math.min(pingTime, MAX_PING_TIME);
    double delay = ((node.bootstrap().random().nextGaussian() * PINGS_STDDEV) + PINGS) * pingTime;
    return Math.max((long) delay, 0L);
  }

  /**
   * Do path folding, maybe. Wait for either a CompletedAck or a ConnectDestination. If the former,
   * exit. If we want a connection, reply with a ConnectReply, otherwise send a ConnectRejected and
   * exit. Add the peer.
   *
   * @return True only if there was a fatal timeout and the caller should not unlock.
   */
  private boolean finishOpennet(final PeerNode next) {
    try {
      byte[] noderef = OpennetNoderefWaiter.waitForOpennetNoderef(false, next, uid, this, node);
      return handleNoderefResult(next, noderef);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not connected sending ConnectReply (finish) on {} to {}", this, next);
      origTag.finishedWaitingForOpennet(next);
    } catch (WaitedTooLongForOpennetNoderefException _) {
      return onOpennetTimeout(next);
    } finally {
      synchronized (this) {
        opennetFinished = true;
        notifyAll();
      }
    }
    return false;
  }

  private boolean handleNoderefResult(PeerNode next, byte[] noderef) throws NotConnectedException {
    if (noderef == null || noderef.length == 0) {
      ackOpennet(next);
      return false;
    }
    OpennetManager om = node.network().opennet();
    if (om == null) {
      ackOpennet(next);
      return false;
    }
    return processOpennetRef(next, noderef, om);
  }

  private boolean processOpennetRef(PeerNode next, byte[] noderef, OpennetManager om)
      throws NotConnectedException {
    SimpleFieldSet ref = OpennetNoderefValidator.validateNoderef(noderef, next, false);
    if (ref == null) {
      ackOpennet(next);
      return false;
    }
    if (!node.routing().canWriteDatastoreRequest(origHTL)) {
      ackOpennet(next);
      return false;
    }
    if (node.network().addNewOpennetNode(ref, ConnectionType.PATH_FOLDING) == null) {
      return handleUnwantedNoderef(next, noderef);
    }
    LOG.info("Added opennet noderef in {} from {}", this, next);
    om.sendOpennetRef(true, uid, next, om.getCrypto().myCompressedFullRef(), this);
    origTag.finishedWaitingForOpennet(next);
    return false;
  }

  private boolean handleUnwantedNoderef(PeerNode next, byte[] noderef) {
    if (LOG.isDebugEnabled()) LOG.debug("Don't want noderef on {}", this);
    synchronized (this) {
      opennetNoderef = noderef;
    }
    if (source == null) {
      long delay = randomDelayFinishOpennetLocal();
      if (LOG.isDebugEnabled()) {
        LOG.debug("Delaying opennet completion for {}", TimeUtil.formatTime(delay, 2, true));
      }
      node.network().ticker().queueTimedJob(() -> ackOpennet(next), delay);
    } else if (origTag.shouldStop()) {
      origTag.finishedWaitingForOpennet(next);
    }
    return false;
  }

  private boolean onOpennetTimeout(PeerNode next) {
    LOG.error("Opennet noderef wait timed out (error) from {}" + FOR_SEP + "{}", next, this);
    origTag.timedOutToHandlerButContinued();
    LOG.warn("Opennet noderef wait timed out (warn) from {}" + FOR_SEP + "{}", next, this);
    synchronized (this) {
      opennetTimedOut = true;
      opennetFinished = true;
      try {
        next.transport()
            .sendAsync(DMT.createFNPOpennetCompletedTimeout(uid), finishOpennetOnAck(next), this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Not connected sending ConnectReply (timeout) on {} to {}", this, next);
        }
        origTag.finishedWaitingForOpennet(next);
      }
      notifyAll();
    }
    try {
      OpennetNoderefWaiter.waitForOpennetNoderef(false, next, uid, this, node);
    } catch (WaitedTooLongForOpennetNoderefException _) {
      LOG.error("Opennet noderef wait fatal timeout from {}" + FOR_SEP + "{}", next, this);
      next.fatalTimeout(origTag, false);
      ackOpennet(next);
      return true;
    }
    ackOpennet(next);
    return false;
  }

  // Opennet stuff

  /** Have we finished all opennet-related activities? */
  private boolean opennetFinished;

  /** Did we time out when waiting for opennet noderef? */
  private boolean opennetTimedOut;

  /** Opennet noderef from next node */
  private byte[] opennetNoderef;

  byte[] waitForOpennetNoderef() throws WaitedTooLongForOpennetNoderefException {
    synchronized (this) {
      long startTime = System.currentTimeMillis();
      boolean wasInterrupted = false;
      try {
        while (true) {
          byte[] ref = takeNoderefIfFinished();
          if (ref != NO_REF) return ref;
          int waitTime = computeRemainingOpennetWait(startTime);
          if (waitTime <= 0) return tooLongWaitingForOpennet();
          try {
            wait(waitTime);
          } catch (InterruptedException _) {
            // In this code path, interrupts are used as signals; keep waiting
            // but remember to restore the interrupt status on exit.
            wasInterrupted = true;
          }
        }
      } finally {
        if (wasInterrupted) Thread.currentThread().interrupt();
      }
    }
  }

  private byte[] takeNoderefIfFinished() throws WaitedTooLongForOpennetNoderefException {
    if (opennetFinished) {
      if (opennetTimedOut) throw new WaitedTooLongForOpennetNoderefException();
      if (LOG.isDebugEnabled()) LOG.debug("Grabbing opennet noderef on {}", this);
      byte[] ref = opennetNoderef; // Only one RequestHandler may take the noderef
      opennetNoderef = null;
      return ref;
    }
    return NO_REF;
  }

  private int computeRemainingOpennetWait(long startTime) {
    return (int)
        Math.min(Integer.MAX_VALUE, OPENNET_TIMEOUT + startTime - System.currentTimeMillis());
  }

  private byte[] tooLongWaitingForOpennet() {
    if (LOG.isDebugEnabled()) LOG.debug("Took too long waiting for opennet ref on {}", this);
    return new byte[0];
  }

  /**
   * Returns the peer that successfully supplied the data for this request.
   *
   * @return The successful {@link PeerNode}, or {@code null} if unfinished or unsuccessful.
   */
  public synchronized PeerNode successFrom() {
    return successFrom;
  }

  /**
   * Returns the verified block headers associated with the fetched data.
   *
   * @return The header bytes, or {@code null} if unavailable.
   */
  public synchronized byte[] getHeaders() {
    return finalHeaders;
  }

  /**
   * Returns the terminal status code for this request.
   *
   * @return One of {@link #NOT_FINISHED}, {@link #SUCCESS}, {@link #ROUTE_NOT_FOUND}, {@link
   *     #DATA_NOT_FOUND}, {@link #TRANSFER_FAILED}, {@link #VERIFY_FAILURE}, {@link #TIMED_OUT},
   *     {@link #GENERATED_REJECTED_OVERLOAD}, {@link #INTERNAL_ERROR}, {@link #RECENTLY_FAILED},
   *     {@link #GET_OFFER_VERIFY_FAILURE}, or {@link #GET_OFFER_TRANSFER_FAILED}.
   */
  public int getStatus() {
    return status;
  }

  /**
   * Returns the current hop-to-live value. The value may decrease over time as routing proceeds.
   */
  public short getHTL() {
    return htl;
  }

  synchronized byte[] getSSKData() {
    return finalSskData;
  }

  /**
   * Returns the verified {@link SSKBlock} when an SSK request completes successfully.
   *
   * @return The block instance, or {@code null} when not applicable or not yet available.
   */
  public SSKBlock getSSKBlock() {
    return block;
  }

  private final Object totalBytesSync = new Object();
  private int totalBytesSent;

  /**
   * Accounts bytes sent for this request.
   *
   * @param x Number of bytes; units are raw bytes.
   */
  @Override
  public void sentBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesSent += x;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Sent bytes: {} for {} isSSK={}", x, this, isSSK);
    node.network().stats().requestSentBytes(isSSK, x);
  }

  /** Returns total bytes sent so far for this request. */
  public int getTotalSentBytes() {
    synchronized (totalBytesSync) {
      return totalBytesSent;
    }
  }

  private int totalBytesReceived;

  /**
   * Accounts bytes received for this request.
   *
   * @param x Number of bytes; units are raw bytes.
   */
  @Override
  public void receivedBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesReceived += x;
    }
    node.network().stats().requestReceivedBytes(isSSK, x);
  }

  /** Returns total bytes received so far for this request. */
  public int getTotalReceivedBytes() {
    synchronized (totalBytesSync) {
      return totalBytesReceived;
    }
  }

  /** Returns whether {@link #fireCHKTransferBegins()} has already notified listeners. */
  boolean hasSentChkTransferBegins() {
    synchronized (listeners) {
      return sentCHKTransferBegins;
    }
  }

  /** Returns {@code true} when the transfer is active with a peer. */
  boolean isTransferActive() {
    synchronized (this) {
      return transferringFrom != null;
    }
  }

  synchronized boolean hasForwarded() {
    return hasForwarded;
  }

  /**
   * Accounts payload bytes (as distinct from protocol overhead) and adjusts request statistics to
   * avoid double-counting.
   *
   * @param x Number of payload bytes.
   */
  @Override
  public void sentPayload(int x) {
    node.sentPayload(x);
    node.network().stats().requestSentBytes(isSSK, -x);
  }

  private int recentlyFailedTimeLeft;

  synchronized int getRecentlyFailedTimeLeft() {
    return recentlyFailedTimeLeft;
  }

  public void addListener(RequestSenderListener l) {
    // Only call here if we've already called for the other listeners.
    // Therefore, the callbacks will only be called once.
    boolean reject;
    boolean transfer;
    boolean sentFinished;
    boolean sentFinishedFromOfferedKey;
    int resultStatus;
    // LOCKING: We add the new listener. We check each notification.
    // If it has already been sent when we add the new listener, we need to send it here.
    // Otherwise, we don't, it will be called by the thread processing that event, even if it's
    // already happened.
    synchronized (listeners) {
      listeners.add(l);
      if (LOG.isDebugEnabled()) LOG.debug("Added listener {} to {}", l, this);
      reject = sentReceivedRejectOverload;
      transfer = sentCHKTransferBegins;
      sentFinished = sentRequestSenderFinished;
      sentFinishedFromOfferedKey = completedFromOfferedKey;
    }
    transfer = transfer && transferStarted();
    if (reject) l.onReceivedRejectOverload();
    if (transfer) l.onCHKTransferBegins();
    if (sentFinished) {
      // At the time when we added the listener, we had sent the status to the others.
      // Therefore, we need to send it to this one too.
      synchronized (this) {
        resultStatus = this.status;
      }
      if (resultStatus != NOT_FINISHED)
        l.onRequestSenderFinished(resultStatus, sentFinishedFromOfferedKey, this);
      else
        LOG.error(
            "sentFinished is true but status is still NOT_FINISHED?!?! on {}",
            this,
            new Exception("error"));
    }
  }

  private boolean sentReceivedRejectOverload;

  @SuppressWarnings("java:S1181")
  private void fireReceivedRejectOverload() {
    synchronized (listeners) {
      if (sentReceivedRejectOverload) return;
      sentReceivedRejectOverload = true;
      for (RequestSenderListener l : listeners) {
        try {
          l.onReceivedRejectOverload();
        } catch (Throwable t) {
          LOG.error("RejectOverload listener threw: {}", t, t);
        }
      }
    }
  }

  private boolean sentCHKTransferBegins;

  @SuppressWarnings("java:S1181")
  private void fireCHKTransferBegins() {
    synchronized (listeners) {
      if (sentCHKTransferBegins) return;
      sentCHKTransferBegins = true;
      for (RequestSenderListener l : listeners) {
        try {
          l.onCHKTransferBegins();
        } catch (Throwable t) {
          LOG.error("CHK transfer begin listener threw: {}", t, t);
        }
      }
    }
  }

  private boolean sentRequestSenderFinished;
  private boolean completedFromOfferedKey;

  @SuppressWarnings("java:S1181")
  private void fireRequestSenderFinished(int status, boolean fromOfferedKey) {
    origTag.setRequestSenderFinished(status);
    synchronized (listeners) {
      if (sentRequestSenderFinished) {
        LOG.error("Request sender finished twice: {}, {} on {}", status, fromOfferedKey, this);
        return;
      }
      sentRequestSenderFinished = true;
      completedFromOfferedKey = fromOfferedKey;
      if (LOG.isDebugEnabled())
        LOG.debug("Notifying {} listeners of status {}", listeners.size(), status);
      for (RequestSenderListener l : listeners) {
        try {
          l.onRequestSenderFinished(status, fromOfferedKey, this);
        } catch (Throwable t) {
          LOG.error("RequestSender finished listener threw: {}", t, t);
        }
      }
    }
  }

  private boolean receivingAsync;

  private void reassignToSelfOnTimeout(boolean fromOfferedKey) {
    RequestSenderListener[] list;
    boolean transferActive;
    synchronized (this) {
      transferActive = transferringFrom != null;
    }
    synchronized (listeners) {
      if (sentCHKTransferBegins && transferActive) {
        LOG.error(
            "Transfer started, not dumping listeners when reassigning to self on timeout (race"
                + " condition?) on {}",
            this);
        origTag.timedOutToHandlerButContinued();
        return;
      }
      list = listeners.toArray(new RequestSenderListener[0]);
      listeners.clear();
    }
    for (RequestSenderListener l : list) {
      l.onRequestSenderFinished(TIMED_OUT, fromOfferedKey, this);
    }
    origTag.timedOutToHandlerButContinued();
  }

  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  public long fetchTimeout() {
    return incomingSearchTimeout;
  }

  BlockReceiverTimeoutHandler myTimeoutHandler =
      new BlockReceiverTimeoutHandler() {

        /**
         * The data receiving has failed. A block timed out. The PRB will be canceled as soon as we
         * return, and that will cause the source node to consider the request finished. Meantime we
         * don't know whether the upstream node has finished or not. So we reassign the request to
         * ourselves and then wait for the second timeout.
         */
        @Override
        public void onFirstTimeout() {
          origTag.timedOutToHandlerButContinued();
        }

        /**
         * The timeout appears to have been caused by the node we are directly connected to. So we
         * need to disconnect the node or take other fairly strong sanctions to avoid load
         * management problems.
         */
        @Override
        public void onFatalTimeout(PeerContext receivingFrom) {
          LOG.error("Fatal timeout receiving requested block on {} from {}", this, receivingFrom);
          ((PeerNode) receivingFrom).fatalTimeout();
        }
      };

  // Note: This may be temporary; ideally, listeners would provide this information directly.
  // At present, NodeClientCore's realGetCHK and realGetSSK (blocking fetches) do not register a
  // RequestSenderListener. Future refactoring is expected to replace these usages.

  // Also consider whether a local RequestSenderListener added after the request starts should
  // impact
  // the decision; this may risk over-disclosure. Given existing signals, it is probably acceptable.
  // When starting the request locally, we still want to finish it even if incoming RequestHandler's
  // are coalesced with it, and they fail onward transfers.

  private boolean transferCoalesced;

  /**
   * Marks that this request's transfer is coalesced with other waiters.
   *
   * <p>Used by components that multiplex multiple requesters onto a single upstream transfer to
   * steer completion decisions.
   */
  public synchronized void setTransferCoalesced() {
    transferCoalesced = true;
  }

  /** Returns whether the transfer has been marked as coalesced. */
  public synchronized boolean isTransferCoalesced() {
    return transferCoalesced;
  }

  @Override
  protected void onAccepted(PeerNode next) {
    onAccepted(next, false, htl);
  }

  /** If we handled a timeout and forked, we need to know the original HTL. */
  private void onAccepted(PeerNode next, boolean forked, short htl) {
    MainLoopCallback cb;
    synchronized (this) {
      receivingAsync = true;
      int searchTimeoutLocal = calculateTimeout(htl);
      cb = new MainLoopCallback(next, forked, searchTimeoutLocal);
    }
    cb.schedule();
  }

  /** Returns the timeout (ms) to wait for {@code Accepted} after sending a request. */
  protected long getAcceptedTimeout() {
    return ACCEPTED_TIMEOUT;
  }

  /**
   * Handles timeouts while waiting for a downstream slot. Adjusts HTL heuristically, records the
   * terminal failure, and updates the failure table.
   */
  @Override
  protected void timedOutWhileWaiting(double load) {
    htl -= (short) Math.max(0, hopsForFatalTimeoutWaitingForPeer());
    if (htl < 0) htl = 0;
    // Timeouts while waiting for a slot are relatively normal.
    // That is, in an ideal world they wouldn't happen.
    // They happen when the network is very small or when there is a capacity bottleneck.
    // They are best considered statistically, see the stats page.
    // Individual timeouts are, therefore, not very interesting...
    if (LOG.isDebugEnabled()) {
      if (source != null) LOG.debug("Timed out while waiting for a slot on {}", this);
      else LOG.debug("Local request timed out while waiting for a slot on {}", this);
    }
    finish(ROUTE_NOT_FOUND, null, false);
    node.routing().failureTable().onFinalFailure(key, null, htl, origHTL, -1, -1, source);
  }

  /** This sender performs a retrieval, not an insert. */
  @Override
  protected boolean isInsert() {
    return false;
  }

  /**
   * Handles a timeout while waiting for {@code Accepted}/{@code Rejected} by installing a follow-up
   * filter that continues waiting and escalates to a fatal timeout if the peer stays silent.
   */
  @Override
  protected void handleAcceptedRejectedTimeout(final PeerNode next, final UIDTag origTag) {

    final short htl = this.htl;
    origTag.handlingTimeout(next);

    long timeout = MINUTES.toMillis(1);

    MessageFilter mf = makeAcceptedRejectedFilter(next, timeout, origTag);
    try {
      node.network()
          .usm()
          .addAsyncFilter(
              mf,
              new SlowAsyncMessageFilterCallback() {

                @Override
                public void onMatched(Message m) {
                  if (m.getSpec() == DMT.FNPRejectedLoop
                      || m.getSpec() == DMT.FNPRejectedOverload) {
                    // Ok.
                    next.noLongerRoutingTo(origTag, false);
                  } else {
                    // Accepted. May as well wait for the data, if any.
                    onAccepted(next, true, htl);
                  }
                }

                @Override
                public boolean shouldTimeout() {
                  return false;
                }

                @Override
                public void onTimeout() {
                  LOG.error(
                      "Fatal timeout waiting for Accepted/Rejected from {} on {}",
                      next,
                      RequestSender.this);
                  next.fatalTimeout(origTag, false);
                }

                @Override
                public void onDisconnect(PeerContext ctx) {
                  next.noLongerRoutingTo(origTag, false);
                }

                @Override
                public void onRestarted(PeerContext ctx) {
                  next.noLongerRoutingTo(origTag, false);
                }

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                }
              },
              this);
    } catch (DisconnectedException _) {
      next.noLongerRoutingTo(origTag, false);
    }
  }
}
