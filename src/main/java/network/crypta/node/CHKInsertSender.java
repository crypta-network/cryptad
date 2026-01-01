package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import java.util.List;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.io.xfer.AbortedException;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.io.xfer.BlockTransmitter.BlockTransmitterCompletion;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends a CHK insert request and streams the corresponding block to the selected peer while
 * managing asynchronous outcomes.
 *
 * <p>This sender performs routing, transmits the {@code DataInsert} payload, and then waits for a
 * terminal outcome from the next hop (e.g., {@code InsertReply}, {@code RouteNotFound}, {@code
 * RejectedOverload}, or {@code RejectedTimeout}). The data transfer proceeds in the background and
 * completion is tracked via a dedicated listener. A two‑stage timeout model is used: a first
 * timeout unlocks downstream routing and a second timeout is treated as fatal for the misbehaving
 * peer.
 *
 * <p>Thread-safety: routing and state transitions are coordinated using the inherited sender lock
 * and the {@code backgroundTransfers} monitor. Callbacks from the messaging subsystem may arrive at
 * different threads; this class confines observable state changes to synchronized sections.
 */
public final class CHKInsertSender extends BaseSender
    implements PrioRunnable, AnyInsertSender, ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(CHKInsertSender.class);
  private static final String FOR = " for ";

  private class BackgroundTransfer implements PrioRunnable, SlowAsyncMessageFilterCallback {
    private static final Logger LOG = LoggerFactory.getLogger(BackgroundTransfer.class);

    private final long uid;

    /** Node the transfer targets and from which completion is awaited. */
    final PeerNode pn;

    /** Transmitter used to stream the block to {@link #pn}. */
    BlockTransmitter bt;

    /**
     * Have we received notice of the downstream success or failure of dependant transfers from that
     * node? Includes timing out.
     */
    boolean receivedCompletionNotice;

    /** Set on fatal timeout or on any non-timeout completion. */
    boolean finishedWaiting;

    /** Was the notification of successful transfer? */
    boolean completionSucceeded;

    /** True once the payload stream to the peer finishes (success or failure). */
    boolean completedTransfer;

    /** Whether an {@code InsertReply}, RNF, or similar completion has been received. */
    boolean gotInsertReply;

    /** Guards that the post-transfer wait has been initiated only once. */
    private boolean startedWait;

    /** True when the background transfer was terminated early (e.g., disconnect). */
    private boolean killed;

    private final InsertTag thisTag;

    BackgroundTransfer(final PeerNode pn, PartiallyReceivedBlock prb, InsertTag thisTag) {
      this.pn = pn;
      this.uid = CHKInsertSender.this.uid;
      this.thisTag = thisTag;
      bt =
          new BlockTransmitter(
              node.getUSM(),
              node.getTicker(),
              pn,
              uid,
              prb,
              CHKInsertSender.this,
              BlockTransmitter.NEVER_CASCADE,
              new BlockTransmitterCompletion() {

                @Override
                public void blockTransferFinished(boolean success) {
                  if (LOG.isDebugEnabled())
                    LOG.debug("Transfer completed: {}" + FOR + "{}", success, this);
                  BackgroundTransfer.this.completedTransfer(success);
                  // Double-check that the node is still connected. Pointless to wait otherwise.
                  if (pn.isConnected() && success) {
                    synchronized (backgroundTransfers) {
                      if (!gotInsertReply) return;
                      if (startedWait) return;
                      startedWait = true;
                    }
                    startWait();
                  } else {
                    BackgroundTransfer.this.receivedNotice(false, false, false);
                    pn.localRejectedOverload("TransferFailedInsert", realTimeFlag);
                  }
                }
              },
              realTimeFlag,
              node.getNodeStats());
    }

    /**
     * Starts waiting for an acknowledgement or timeout.
     *
     * <p>Preconditions: the data transfer to the peer succeeded and an RNF/InsertReply (or
     * equivalent) has been observed. The timeout is relative to this point to avoid counting time
     * spent routing.
     */
    private void startWait() {
      if (LOG.isDebugEnabled()) LOG.debug("Waiting for completion notification from {}", this);
      // Add ourselves as a listener for the longterm completion message of this transfer, then
      // gracefully exit.
      try {
        node.getUSM()
            .addAsyncFilter(getNotificationMessageFilter(false), BackgroundTransfer.this, null);
      } catch (DisconnectedException _) {
        // Normal
        if (LOG.isDebugEnabled()) LOG.debug("Disconnected while adding filter");
        BackgroundTransfer.this.completedTransfer(false);
        BackgroundTransfer.this.receivedNotice(false, false, true);
      }
    }

    void start() {
      node.getExecutor()
          .execute(this, "CHKInsert-BackgroundTransfer" + FOR + uid + " to " + pn.getPeer());
    }

    @Override
    @SuppressWarnings("java:S1181")
    public void run() {
      try {
        this.realRun();
      } catch (Throwable t) {
        this.completedTransfer(false);
        this.receivedNotice(false, false, true);
        LOG.error("Caught {}", t, t);
      }
    }

    private void realRun() {
      bt.sendAsync();
      // REDFLAG: Load limiting — the transmitter does not provide a definitive end-of-processing
      // signal here and may continue beyond payload completion. Do not call
      // thisTag.removeRoutingTo(next); assume the route remains in use until the insert completes.
    }

    private void completedTransfer(boolean success) {
      synchronized (backgroundTransfers) {
        completedTransfer = true;
        backgroundTransfers.notifyAll();
      }
      if (!success) {
        setTransferTimedOut();
      }
    }

    /**
     * Processes a completion notice.
     *
     * @param timeout whether this completion resulted from a timeout
     * @return {@code true} to continue waiting (e.g., first-stage timeout), {@code false} otherwise
     */
    private boolean receivedNotice(boolean success, boolean timeout, boolean kill) {
      if (LOG.isDebugEnabled())
        LOG.debug("Received notice: {}{} on {}", success, timeout ? " (timeout)" : "", this);
      NoticeOutcome outcome;
      synchronized (backgroundTransfers) {
        outcome = processNoticeInLock(success, timeout, kill);
      }
      if (outcome == null) return false;
      if (!outcome.gotFatalTimeout && !success) setTransferTimedOut();
      if (!outcome.noUnlockPeer) pn.noLongerRoutingTo(thisTag, false);
      synchronized (backgroundTransfers) {
        if (!outcome.gotFatalTimeout) backgroundTransfers.notifyAll();
      }
      if (timeout && outcome.gotFatalTimeout) {
        LOG.error("Second timeout waiting for final ack from {} on {}", pn, this);
        pn.fatalTimeout(thisTag, false);
        return false;
      }
      return true;
    }

    private NoticeOutcome processNoticeInLock(boolean success, boolean timeout, boolean kill) {
      if (finishedWaiting) {
        if (!(killed || kill))
          LOG.error(
              "Finished waiting already yet receivedNotice({},{},{})",
              success,
              timeout,
              false,
              new Exception("error"));
        return null;
      }

      NoticeOutcome result;
      if (killed) {
        // Keep state; unlock handled below.
        result = new NoticeOutcome(false, false);
      } else if (kill) {
        result = outcomeForKill();
      } else if (receivedCompletionNotice) {
        result = outcomeForAlreadyCompleted(timeout, success);
      } else {
        result = outcomeForFirstCompletion(success, timeout);
      }

      if (!result.noUnlockPeer) startedWait = true; // Prevent further waits.
      return result;
    }

    private NoticeOutcome outcomeForKill() {
      killed = true;
      finishedWaiting = true;
      receivedCompletionNotice = true;
      completionSucceeded = false;
      return new NoticeOutcome(false, false);
    }

    private NoticeOutcome outcomeForAlreadyCompleted(boolean timeout, boolean success) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "receivedNotice({}), already had receivedNotice({})", success, completionSucceeded);
      }
      if (timeout) {
        // Fatal timeout on the second stage.
        finishedWaiting = true;
        return new NoticeOutcome(false, true);
      }
      return new NoticeOutcome(false, false);
    }

    private NoticeOutcome outcomeForFirstCompletion(boolean success, boolean timeout) {
      completionSucceeded = success;
      receivedCompletionNotice = true;
      if (!timeout) {
        // Any completion mode other than a timeout immediately sets finishedWaiting.
        finishedWaiting = true;
        return new NoticeOutcome(false, false);
      }
      // First timeout but not yet fatal: unlock downstream and wait for fatal timeout.
      // Safe to call the tag within the lock since UIDTag is taken last.
      thisTag.handlingTimeout(pn);
      return new NoticeOutcome(true, false);
    }

    private record NoticeOutcome(boolean noUnlockPeer, boolean gotFatalTimeout) {}

    @Override
    public void onMatched(Message m) {
      pn.successNotOverload(realTimeFlag);
      PeerNode msgPeer = (PeerNode) m.getSource();
      // pn cannot be null, because the filters will prevent garbage collection of the nodes

      if (this.pn.equals(msgPeer)) {
        boolean anyTimedOut = m.getBoolean(DMT.ANY_TIMED_OUT);
        if (anyTimedOut) {
          CHKInsertSender.this.setTransferTimedOut();
        }
        receivedNotice(!anyTimedOut, false, false);
      } else {
        LOG.error("received completion notice for wrong node: {} != {}", msgPeer, this.pn);
      }
    }

    @Override
    public boolean shouldTimeout() {
      // AFIACS, this will still let the filter timeout, but not call onMatched() twice.
      return finishedWaiting;
    }

    private MessageFilter getNotificationMessageFilter(boolean longTimeoutAnyway) {
      return MessageFilter.create()
          .setField(DMT.UID, uid)
          .setType(DMT.FNPInsertTransfersCompleted)
          .setSource(pn)
          .setTimeout(
              longTimeoutAnyway ? TRANSFER_COMPLETION_ACK_TIMEOUT_BULK : transferCompletionTimeout);
    }

    @Override
    public void onTimeout() {
      // NORMAL priority because it is normally caused by a transfer taking too long downstream, and
      // that doesn't usually indicate a bug.
      LOG.info(
          "Timed out waiting for a final ack from: {} on {}", pn, this, new Exception("debug"));
      if (receivedNotice(false, true, false)) {
        pn.localRejectedOverload("InsertTimeoutNoFinalAck", realTimeFlag);
        // First timeout. Wait for second timeout.
        try {
          node.getUSM()
              .addAsyncFilter(getNotificationMessageFilter(true), this, CHKInsertSender.this);
        } catch (DisconnectedException _) {
          // Normal
          if (LOG.isDebugEnabled())
            LOG.debug("Disconnected while adding filter after first timeout");
          pn.noLongerRoutingTo(thisTag, false);
        }
      }
    }

    @Override
    public void onDisconnect(PeerContext ctx) {
      LOG.info("Disconnected {}" + FOR + "{}", ctx, this);
      receivedNotice(true, false, true); // as far as we know
      pn.noLongerRoutingTo(thisTag, false);
    }

    @Override
    public void onRestarted(PeerContext ctx) {
      LOG.info("Restarted {}" + FOR + "{}", ctx, this);
      receivedNotice(true, false, true);
      pn.noLongerRoutingTo(thisTag, false);
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
    }

    @Override
    public String toString() {
      return super.toString() + ":" + uid + ":" + pn;
    }

    /** Signals that routing completed (e.g., InsertReply or RNF) for this transfer. */
    public void onCompleted() {
      synchronized (backgroundTransfers) {
        if (finishedWaiting) return;
        if (gotInsertReply) return;
        gotInsertReply = true;
        if (!completedTransfer) return;
        if (startedWait) return;
        startedWait = true;
      }
      startWait();
    }

    /** Terminates the background transfer due to a failure, such as DataInsertRejected. */
    public void kill() {
      LOG.info("Killed {}", this);
      receivedNotice(false, false, true); // as far as we know
      pn.noLongerRoutingTo(thisTag, false);
    }
  }

  CHKInsertSender(
      NodeCHK myKey,
      long uid,
      InsertTag tag,
      byte[] headers,
      short htl,
      PeerNode source,
      Node node,
      PartiallyReceivedBlock prb,
      boolean fromStore,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag) {
    super(myKey, realTimeFlag, source, node, htl, uid);
    this.origUID = uid;
    this.origTag = tag;
    this.headers = headers;
    this.prb = prb;
    this.fromStore = fromStore;
    this.backgroundTransfers = new ArrayList<>();
    this.forkOnCacheable = forkOnCacheable;
    this.preferInsert = preferInsert;
    this.ignoreLowBackoff = ignoreLowBackoff;
    if (realTimeFlag) {
      transferCompletionTimeout = TRANSFER_COMPLETION_ACK_TIMEOUT_REALTIME;
    } else {
      transferCompletionTimeout = TRANSFER_COMPLETION_ACK_TIMEOUT_BULK;
    }
  }

  /**
   * Schedules this sender on the node executor.
   *
   * <p>Non-blocking. The actual work is performed on a background thread.
   */
  void start() {
    node.getExecutor()
        .execute(
            this,
            "CHKInsertSender"
                + FOR
                + "UID "
                + uid
                + " on "
                + node.getDarknetPortNumber()
                + " at "
                + System.currentTimeMillis());
  }

  // Constants
  static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);
  static final long TRANSFER_COMPLETION_ACK_TIMEOUT_REALTIME = MINUTES.toMillis(1);
  static final long TRANSFER_COMPLETION_ACK_TIMEOUT_BULK = MINUTES.toMillis(5);

  final long transferCompletionTimeout;

  // Basics
  final long origUID;
  final InsertTag origTag;
  private InsertTag forkedRequestTag;
  final byte[] headers; // received BEFORE creation => we handle Accepted elsewhere
  final PartiallyReceivedBlock prb;
  final boolean fromStore;
  private boolean receiveFailed;
  private final boolean forkOnCacheable;
  private final boolean preferInsert;
  private final boolean ignoreLowBackoff;

  /**
   * List of nodes we are waiting for either a transfer completion notice or a transfer completion
   * from. Also used as a sync object for waiting for transfer completion.
   */
  private final List<BackgroundTransfer> backgroundTransfers;

  /** Have all transfers completed and all nodes reported completion status? */
  private boolean allTransfersCompleted;

  /** Has a transfer timed out, either directly or downstream? */
  private volatile boolean transferTimedOut;

  private int status = -1;

  /** Still running */
  static final int NOT_FINISHED = -1;

  /** Successful insert */
  static final int SUCCESS = 0;

  /** Route not found */
  static final int ROUTE_NOT_FOUND = 1;

  /** Internal error */
  static final int INTERNAL_ERROR = 3;

  /** Timed out waiting for response */
  static final int TIMED_OUT = 4;

  /** Locally Generated a RejectedOverload */
  static final int GENERATED_REJECTED_OVERLOAD = 5;

  /** Could not get off the node at all! */
  static final int ROUTE_REALLY_NOT_FOUND = 6;

  /** Receive failed. Not used internally; only used by CHKInsertHandler. */
  static final int RECEIVE_FAILED = 7;

  /**
   * Returns a short identifier including the request UID.
   *
   * @return human-readable identifier
   */
  @Override
  public String toString() {
    return super.toString() + FOR + uid;
  }

  /**
   * Executes the insert workflow on a background thread.
   *
   * <p>Invoked by the executor. This method drives routing and ensures a terminal {@link #finish}
   * call on exit.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    origTag.startedSender();
    try {
      routeRequests();
    } catch (Throwable t) {
      LOG.error("Caught {}", t, t);
    } finally {
      // Always check: we ALWAYS set status, even if receiveFailed.
      int myStatus;
      synchronized (this) {
        myStatus = status;
      }
      if (myStatus == NOT_FINISHED) finish(INTERNAL_ERROR, null);
      origTag.finishedSender();
      if (forkedRequestTag != null) forkedRequestTag.finishedSender();
    }
  }

  static final int MAX_HIGH_HTL_FAILURES = 5;

  /**
   * Performs routing and manages retries according to HTL and peer selection policy.
   *
   * <p>Preconditions: {@code origTag.startedSender()} has been called. This method may call {@link
   * #finish(int, PeerNode)} when a terminal state is reached.
   */
  @Override
  protected void routeRequests() {
    PeerNode next;
    int highHTLFailureCount = 0; // Limit trivial failures at high HTL
    boolean starting = true;

    if (failIfReceiveFailed(null, null)) return;
    if (origTag.shouldStop()) {
      finish(SUCCESS, null);
      return;
    }

    boolean canWriteStorePrev = node.canWriteDatastoreInsert(htl);
    HtlDecision dec = processHtlDecrement(starting, canWriteStorePrev, highHTLFailureCount);
    if (dec.finished) return;
    // dec.highHTLFailureCount is only relevant within this decision step; no reuse required here.

    if (checkImmediateSuccessAndFinish()) return;

    maybeForkOnCacheable(canWriteStorePrev);

    // Can backtrack: only route to peers closer to target
    next = findNextPeer();
    if (next == null) {
      if (!hasForwarded) origTag.setNotRoutedOnwards();
      finish(ROUTE_NOT_FOUND, null);
      return;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Routing insert to {}", next);
    nodesRoutedTo.add(next);

    InsertTag thisTag = (forkedRequestTag == null) ? origTag : forkedRequestTag;
    if (failIfReceiveFailed(thisTag, next)) {
      sendReceiveFailedNotice(next);
      return;
    }

    innerRouteRequests(next, thisTag);
  }

  private record HtlDecision(boolean starting, int highHTLFailureCount, boolean finished) {}

  private HtlDecision processHtlDecrement(
      boolean starting, boolean canWriteStorePrev, int highHTLFailureCount) {
    if (!starting && !canWriteStorePrev) {
      if (highHTLFailureCount++ >= MAX_HIGH_HTL_FAILURES) {
        if (LOG.isDebugEnabled()) LOG.debug("Too many failures at non-cacheable HTL");
        finish(ROUTE_NOT_FOUND, null);
        return new HtlDecision(false, highHTLFailureCount, true);
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Allowing failure {} htl is still {}", highHTLFailureCount, htl);
      return new HtlDecision(false, highHTLFailureCount, false);
    }
    htl = node.decrementHTL(hasForwarded ? lastNode : source, htl);
    if (LOG.isDebugEnabled()) LOG.debug("Decremented HTL to {}", htl);
    return new HtlDecision(false, highHTLFailureCount, false);
  }

  private boolean checkImmediateSuccessAndFinish() {
    boolean successNow = false;
    boolean noRequest = false;
    synchronized (this) {
      if (htl <= 0) {
        successNow = true;
        noRequest = !hasForwarded; // Send an InsertReply back
      }
    }
    if (successNow) {
      if (noRequest) origTag.setNotRoutedOnwards();
      finish(SUCCESS, null);
      return true;
    }
    return false;
  }

  private void maybeForkOnCacheable(boolean canWriteStorePrev) {
    if (node.canWriteDatastoreInsert(htl)
        && (!canWriteStorePrev)
        && forkOnCacheable
        && forkedRequestTag == null) {
      uid = node.getClientCore().makeUID();
      forkedRequestTag =
          new InsertTag(false, InsertTag.START.REMOTE, source, realTimeFlag, uid, node);
      forkedRequestTag.reassignToSelf();
      forkedRequestTag.startedSender();
      forkedRequestTag.unlockHandler();
      forkedRequestTag.setAccepted();
      LOG.info("FORKING CHK INSERT {} to {}", origUID, uid);
      nodesRoutedTo.clear();
      node.getTracker().lockUID(forkedRequestTag);
    }
  }

  private PeerNode findNextPeer() {
    return node.getPeers()
        .routingSelector()
        .closerPeer(
            forkedRequestTag == null ? source : null,
            nodesRoutedTo,
            target,
            true,
            node.isAdvancedModeEnabled(),
            -1,
            null,
            null,
            htl,
            ignoreLowBackoff ? Node.LOW_BACKOFF : 0,
            source == null,
            realTimeFlag,
            newLoadManagement);
  }

  private void sendReceiveFailedNotice(PeerNode next) {
    try {
      next.sendAsync(
          DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED),
          null,
          this);
    } catch (NotConnectedException _) {
      // Ignore
    }
  }

  private void handleRejectedTimeout(Message msg, PeerNode next) {
    // Some severe lag problem.
    // However, it is not fatal because we can be confident now that even if the DataInsert
    // is delivered late, it will not be acted on. I.e. we are certain how many requests
    // are running, which is what fatal timeouts are designed to deal with.
    LOG.warn(
        "Node timed out waiting for our DataInsert ({} from {}) after Accepted in insert - treating"
            + " as fatal timeout",
        msg,
        next);
    // Terminal overload
    // Try to propagate back to source
    next.localRejectedOverload("AfterInsertAcceptedRejectedTimeout", realTimeFlag);

    // We have always started the transfer by the time this is called, so we do NOT need to
    // removeRoutingTo().
    finish(TIMED_OUT, next);
  }

  /**
   * @return True if fatal i.e. we should try another node.
   */
  private boolean handleRejectedOverload(Message msg, PeerNode next) {
    // Probably non-fatal, if so, we have time left, can try next one
    if (msg.getBoolean(DMT.IS_LOCAL)) {
      next.localRejectedOverload("ForwardRejectedOverload6", realTimeFlag);
      if (LOG.isDebugEnabled()) LOG.debug("Local RejectedOverload, moving on to next peer");
      // Give up on this one, try another
      return true;
    } else {
      forwardRejectedOverload();
    }
    return false; // Wait for any further response
  }

  private void handleRNF(Message msg, PeerNode next) {
    if (LOG.isDebugEnabled()) LOG.debug("Rejected: RNF");
    short newHtl = msg.getShort(DMT.HTL);
    if (newHtl < 0) newHtl = 0;
    synchronized (this) {
      if (htl > newHtl) htl = newHtl;
    }
    // Finished as far as this node is concerned - except for the data transfer, which will continue
    // until it finishes.
    next.successNotOverload(realTimeFlag);
  }

  private void handleDataInsertRejected(Message msg, PeerNode next) {
    next.successNotOverload(realTimeFlag);
    short reason = msg.getShort(DMT.DATA_INSERT_REJECTED_REASON);
    if (LOG.isDebugEnabled()) LOG.debug("DataInsertRejected: {}", reason);
    if (reason == DMT.DATA_INSERT_REJECTED_VERIFY_FAILED) {
      handleVerifyFailed(next);
    } else if (reason == DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED) {
      handleReceiveFailed(next);
    }
    LOG.atError()
        .addArgument(() -> DMT.getDataInsertRejectedReason(reason))
        .log("DataInsert rejected! Reason={}");
  }

  private void handleVerifyFailed(PeerNode next) {
    if (fromStore) {
      // That's odd...
      LOG.error(
          "Verify failed on next node {} for DataInsert but we were sending from the store!", next);
      return;
    }
    try {
      if (!prb.allReceived()) {
        LOG.error("Did not receive all packets but next node says invalid anyway!");
      } else {
        // Check the data
        new CHKBlock(prb.getBlock(), headers, (NodeCHK) key);
        LOG.error("Verify failed on {} but data was valid!", next);
      }
    } catch (CHKVerifyException _) {
      LOG.info("Verify failed because data was invalid");
    } catch (AbortedException _) {
      onReceiveFailed();
    }
  }

  private void handleReceiveFailed(PeerNode next) {
    boolean recvFailed;
    synchronized (backgroundTransfers) {
      recvFailed = receiveFailed;
    }
    if (recvFailed) {
      if (LOG.isDebugEnabled()) LOG.debug("Failed to receive data, so failed to send data");
      return;
    }
    try {
      if (prb.allReceived()) {
        // Probably caused by transient connectivity problems.
        // Only fatal timeouts warrant ERROR's because they indicate something seriously wrong
        // that didn't result in a disconnection, and because they cause disconnections.
        LOG.warn("Received all data but send failed to {}", next);
      } else {
        if (prb.isAborted()) {
          LOG.info("Send failed: aborted: {}: {}", prb.getAbortReason(), prb.getAbortDescription());
        } else {
          LOG.info("Send failed; have not yet received all data but not aborted: {}", next);
        }
      }
    } catch (AbortedException _) {
      onReceiveFailed();
    }
  }

  /**
   * Builds a filter that matches the initial post-request outcome from {@code next}.
   *
   * <p>The filter waits for {@code Accepted}, {@code RejectedLoop}, or {@code RejectedOverload} for
   * the provided {@code uid} carried by {@code tag} and uses the specified timeout.
   *
   * @param next peer from which an early outcome is expected
   * @param acceptedTimeout timeout (ms) for awaiting the outcome
   * @param tag current routing tag carrying the UID; may differ when forking
   * @return a configured {@link MessageFilter}
   */
  @Override
  protected MessageFilter makeAcceptedRejectedFilter(
      PeerNode next, long acceptedTimeout, UIDTag tag) {
    // Use the right UID here, in case we fork on cacheable.
    final long uid = tag.uid;
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

    // mfRejectedOverload must be the last thing in the "or"
    // So its or pointer remains null
    // Otherwise we need to recreate it below
    mfRejectedOverload.clearOr();
    return mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload));
  }

  private static final long TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT = MINUTES.toMillis(1);

  /**
   * Handles a timeout while waiting for {@code Accepted}/{@code Rejected*} from {@code next}.
   *
   * <p>A first timeout unlocks the downstream route and installs a short follow-up wait to reduce
   * the chance of immediately escalating to a fatal timeout if the peer replies late.
   *
   * @param next the peer that did not respond in time
   * @param tag routing tag associated with the request
   */
  @Override
  protected void handleAcceptedRejectedTimeout(final PeerNode next, final UIDTag tag) {
    // It could still be running. So the timeout is fatal to the node.
    // This is a WARNING not an ERROR because it's possible that the problem is we simply haven't
    // been able to send the message yet, because we don't use sendSync().
    LOG.warn("Timeout awaiting Accepted/Rejected {} to {}", this, next);
    // Use the right UID here, in case we fork.
    final long uid = tag.uid;
    tag.handlingTimeout(next);
    // The node didn't accept the request. So we don't need to send them the data.
    // However, we do need to wait a bit longer to try to postpone the fatalTimeout().
    // Somewhat intricate logic to try to avoid fatalTimeout() if at all possible.
    MessageFilter mf =
        makeAcceptedRejectedFilter(next, TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT, tag);
    try {
      node.getUSM()
          .addAsyncFilter(
              mf,
              new SlowAsyncMessageFilterCallback() {

                @Override
                public void onMatched(Message m) {
                  if (m.getSpec() == DMT.FNPRejectedLoop
                      || m.getSpec() == DMT.FNPRejectedOverload) {
                    // Ok.
                    next.noLongerRoutingTo(tag, false);
                  } else if (m.getSpec() == DMT.FNPAccepted) {
                    if (LOG.isDebugEnabled())
                      LOG.debug(
                          "Accepted after timeout on {} - will not send DataInsert, waiting for"
                              + " RejectedTimeout",
                          CHKInsertSender.this);
                    // We are not going to send the DataInsert.
                    // We have moved on, and we don't want inserts to fork unnecessarily.
                    // However, we need to send a DataInsertRejected, or two-stage timeout will
                    // happen.
                    sendTimeoutRejectedAfterAccepted(next, tag, uid);
                  } else {
                    // Defensive: filter should only match Accepted/RejectedLoop/RejectedOverload
                    LOG.warn(
                        "Unexpected message {} while awaiting Accepted/Rejected on {}",
                        m,
                        CHKInsertSender.this);
                    next.noLongerRoutingTo(tag, false);
                  }
                }

                @Override
                public boolean shouldTimeout() {
                  return false;
                }

                @Override
                public void onTimeout() {
                  LOG.error("Fatal: No Accepted/Rejected" + FOR + "{}", CHKInsertSender.this);
                  next.fatalTimeout(tag, false);
                }

                @Override
                public void onDisconnect(PeerContext ctx) {
                  next.noLongerRoutingTo(tag, false);
                }

                @Override
                public void onRestarted(PeerContext ctx) {
                  next.noLongerRoutingTo(tag, false);
                }

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                }
              },
              this);
    } catch (DisconnectedException _) {
      next.noLongerRoutingTo(tag, false);
    }
  }

  private void sendTimeoutRejectedAfterAccepted(PeerNode next, UIDTag tag, long uid) {
    try {
      next.sendAsync(
          DMT.createFNPDataInsertRejected(
              uid, DMT.DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED),
          new AsyncMessageCallback() {
            @Override
            public void sent() {
              if (LOG.isDebugEnabled())
                LOG.debug(
                    "DataInsertRejected sent after accepted timeout on {}", CHKInsertSender.this);
            }

            @Override
            public void acknowledged() {
              if (LOG.isDebugEnabled())
                LOG.debug(
                    "DataInsertRejected acknowledged after accepted timeout on {}",
                    CHKInsertSender.this);
              next.noLongerRoutingTo(tag, false);
            }

            @Override
            public void disconnected() {
              if (LOG.isDebugEnabled())
                LOG.debug(
                    "DataInsertRejected peer disconnected after accepted timeout on  {}",
                    CHKInsertSender.this);
              next.noLongerRoutingTo(tag, false);
            }

            @Override
            public void fatalError() {
              if (LOG.isDebugEnabled())
                LOG.debug(
                    "DataInsertRejected fatal error after accepted timeout on {}",
                    CHKInsertSender.this);
              next.noLongerRoutingTo(tag, false);
            }
          },
          CHKInsertSender.this);
    } catch (NotConnectedException _) {
      next.noLongerRoutingTo(tag, false);
    }
  }

  private BackgroundTransfer startBackgroundTransfer(
      PeerNode node, PartiallyReceivedBlock prb, InsertTag tag) {
    BackgroundTransfer ac = new BackgroundTransfer(node, prb, tag);
    synchronized (backgroundTransfers) {
      backgroundTransfers.add(ac);
      backgroundTransfers.notifyAll();
    }
    ac.start();
    return ac;
  }

  private boolean hasForwardedRejectedOverload;

  synchronized boolean receivedRejectedOverload() {
    return hasForwardedRejectedOverload;
  }

  /**
   * Forward RejectedOverload to the request originator. DO NOT CALL if it has a *local*
   * RejectedOverload.
   */
  @Override
  protected synchronized void forwardRejectedOverload() {
    if (hasForwardedRejectedOverload) return;
    hasForwardedRejectedOverload = true;
    notifyAll();
  }

  private void setTransferTimedOut() {
    synchronized (this) {
      if (!transferTimedOut) {
        transferTimedOut = true;
        notifyAll();
      }
    }
  }

  /**
   * Finish the insert process. Will set status, wait for underlings to complete, and report success
   * if appropriate.
   *
   * @param code The status code to set.
   * @param next The node we successfully inserted to.
   */
  private void finish(int code, PeerNode next) {
    if (LOG.isDebugEnabled()) LOG.debug("Finished: {} on {}", code, this);
    // InsertReply always precedes transfer completion; do not removeRoutingTo().
    if (preFinishUpdateStatus(code)) return;

    boolean failedRecv;
    if (hasBackgroundTransfers()) {
      waitForBackgroundTransferCompletions();
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("No background transfers");
    }
    synchronized (backgroundTransfers) {
      failedRecv = receiveFailed;
    }

    completeAfterTransfers(failedRecv);

    if (status == SUCCESS && next != null) next.onSuccess(true, false);
    if (LOG.isDebugEnabled()) LOG.debug("Returning from finish()");
  }

  private boolean preFinishUpdateStatus(int code) {
    synchronized (this) {
      if (allTransfersCompleted) return true;
      if ((code == ROUTE_NOT_FOUND) && !hasForwarded) {
        status = ROUTE_REALLY_NOT_FOUND;
      } else if (status != NOT_FINISHED) {
        if (status == RECEIVE_FAILED) {
          if (code == SUCCESS) LOG.error("Request succeeded despite receive failed?! on {}", this);
        } else if (status != TIMED_OUT) {
          throw new IllegalStateException(
              "finish() called with " + code + " when was already " + status);
        }
      } else {
        status = code;
      }
      notifyAll();
      if (LOG.isDebugEnabled()) LOG.debug("Set status code: {} on {}", getStatusString(), uid);
    }
    return false;
  }

  private boolean hasBackgroundTransfers() {
    synchronized (backgroundTransfers) {
      return !backgroundTransfers.isEmpty();
    }
  }

  private void completeAfterTransfers(boolean failedRecv) {
    synchronized (this) {
      if (!allTransfersCompleted) {
        if (failedRecv) status = RECEIVE_FAILED;
        allTransfersCompleted = true;
        notifyAll();
      }
    }
  }

  @Override
  public synchronized int getStatus() {
    return status;
  }

  @Override
  public synchronized short getHTL() {
    return htl;
  }

  public boolean failIfReceiveFailed(InsertTag tag, PeerNode next) {
    synchronized (backgroundTransfers) {
      if (!receiveFailed) return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Failing because receive failed on {}", this);
    if (tag != null && next != null) {
      next.noLongerRoutingTo(tag, false);
    }
    return true;
  }

  /** Called by CHKInsertHandler to notify that the receive has failed. */
  public void onReceiveFailed() {
    if (LOG.isDebugEnabled()) LOG.debug("Receive failed on {}", this);
    synchronized (backgroundTransfers) {
      receiveFailed = true;
      backgroundTransfers.notifyAll();
      // Locking is safe as UIDTag always taken last.
      for (BackgroundTransfer t : backgroundTransfers) t.thisTag.handlingTimeout(t.pn);
    }
    // Set status immediately.
    // The code (e.g. waitForStatus()) relies on a status eventually being set,
    // so we may as well set it here. The alternative is to set it in realRun()
    // when we notice that receiveFailed = true.
    synchronized (this) {
      status = RECEIVE_FAILED;
      allTransfersCompleted = true;
      notifyAll();
    }
    // Do not call finish(), that can only be called on the main thread and it will block.
  }

  /**
   * @return The current status as a string
   */
  @Override
  public synchronized String getStatusString() {
    if (status == SUCCESS) return "SUCCESS";
    if (status == ROUTE_NOT_FOUND) return "ROUTE NOT FOUND";
    if (status == NOT_FINISHED) return "NOT FINISHED";
    if (status == INTERNAL_ERROR) return "INTERNAL ERROR";
    if (status == TIMED_OUT) return "TIMED OUT";
    if (status == GENERATED_REJECTED_OVERLOAD) return "GENERATED REJECTED OVERLOAD";
    if (status == ROUTE_REALLY_NOT_FOUND) return "ROUTE REALLY NOT FOUND";
    return "UNKNOWN STATUS CODE: " + status;
  }

  @Override
  public synchronized boolean sentRequest() {
    return hasForwarded;
  }

  private void waitForBackgroundTransferCompletions() {
    try {
      if (LOG.isDebugEnabled()) LOG.debug("Waiting for background transfer completions: {}", this);

      // We must presently be at such a stage that no more background transfers will be added.

      BackgroundTransfer[] transfers;
      synchronized (backgroundTransfers) {
        transfers = new BackgroundTransfer[backgroundTransfers.size()];
        transfers = backgroundTransfers.toArray(transfers);
      }

      // Wait for the outgoing transfers to complete.
      if (!waitForBackgroundTransfers(transfers)) {
        setTransferTimedOut();
      }
    } finally {
      synchronized (CHKInsertSender.this) {
        allTransfersCompleted = true;
        CHKInsertSender.this.notifyAll();
      }
    }
  }

  /**
   * Block until all transfers have reached a final-terminal state (success/failure). On success
   * this means that a successful 'received-notification' has been received.
   *
   * @return True if all background transfers were successful.
   */
  private boolean waitForBackgroundTransfers(BackgroundTransfer[] transfers) {
    long start = System.currentTimeMillis();
    long deadline = start + transferCompletionTimeout * 3;
    boolean interrupted = false;
    while (System.currentTimeMillis() <= deadline) {
      synchronized (backgroundTransfers) {
        int state = evaluateWaitState(transfers);
        if (state != 0) return state > 0;
        try {
          backgroundTransfers.wait(SECONDS.toMillis(100));
        } catch (InterruptedException _) {
          // Record and break out so higher-level shutdown paths can react promptly.
          // Re-assert interrupt here to satisfy static analysis and preserve signal.
          Thread.currentThread().interrupt();
          // We'll exit the loop and return promptly; callers can decide how to react.
          interrupted = true;
          break;
        }
      }
    }
    if (interrupted) {
      // Re‑assert interrupt so callers observe it (java:S2142) and return promptly.
      Thread.currentThread().interrupt();
      if (LOG.isDebugEnabled())
        LOG.debug("Interrupted while waiting for background transfers; exiting early: {}", this);
      return false;
    }
    LOG.info(
        "Timed out waiting for background transfers! Probably caused by async filter not"
            + " getting a timeout notification! DEBUG ME!");
    return false;
  }

  private int evaluateWaitState(BackgroundTransfer[] transfers) {
    if (receiveFailed) return -1; // failed
    boolean noneRoutable = true;
    boolean someFailed = false;
    for (BackgroundTransfer transfer : transfers) {
      if (!transfer.pn.isRoutable()) {
        LOG.debug("Ignoring transfer to {}" + FOR + "{} as not routable", transfer.pn, this);
        continue;
      }
      noneRoutable = false;
      if (!transfer.completedTransfer) {
        LOG.debug("Waiting for transfer completion to {} : {}", transfer.pn, transfer);
        return 0; // keep waiting
      }
      if (!transfer.receivedCompletionNotice) {
        LOG.debug("Waiting for completion notice from {} : {}", transfer.pn, transfer);
        return 0; // keep waiting
      }
      if (!transfer.completionSucceeded) someFailed = true;
    }
    if (noneRoutable) return -1;
    return someFailed ? -1 : 1;
  }

  /**
   * Returns whether all background transfers reached a terminal state.
   *
   * @return {@code true} when every background transfer reported completion
   */
  public synchronized boolean completed() {
    return allTransfersCompleted;
  }

  /**
   * Indicates that at least one transfer timed out (locally or downstream).
   *
   * @return {@code true} if any background transfer failed
   */
  public boolean anyTransfersFailed() {
    return transferTimedOut;
  }

  /**
   * Returns the header bytes that accompany the block; callers historically used this as a
   * public‑key hash.
   *
   * @return header bytes (non-null)
   */
  public byte[] getPubkeyHash() {
    return headers;
  }

  /**
   * Waits up to {@code millis} for the sender to transition out of {@link #NOT_FINISHED}.
   *
   * <p>Thread-safety: uses the sender's intrinsic monitor which is also used for notify/notifyAll
   * in this class. Callers should not synchronize on the sender instance directly; use this helper
   * instead to avoid synchronizing on parameters.
   */
  @SuppressWarnings(
      "java:S2142") // Intentionally ignore interrupts to avoid busy-spin of polling loops
  void waitIfNotFinished(long millis) {
    if (millis < 0) throw new IllegalArgumentException("timeout value is negative");
    synchronized (this) {
      if (millis == 0) {
        while (status == NOT_FINISHED) {
          try {
            this.wait(0); // indefinite wait
          } catch (InterruptedException _) {
            // See rationale above: ignore to avoid busy-spin in polling callers.
          }
        }
        return;
      }
      long deadlineNanos =
          System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis);
      long remainingNanos = deadlineNanos - System.nanoTime();
      while (status == NOT_FINISHED && remainingNanos > 0) {
        try {
          long waitMillis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(remainingNanos);
          int waitNanos =
              (int)
                  (remainingNanos - java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(waitMillis));
          if (waitMillis == 0L && waitNanos > 0) {
            this.wait(0L, waitNanos);
          } else {
            this.wait(waitMillis, waitNanos);
          }
        } catch (InterruptedException _) {
          // Intentionally swallow interrupts here so callers that poll using wait/notify
          // do not busy-spin with an already-set interrupt flag. Shutdown/cancellation paths
          // may interrupt these threads; we still prefer to wait for a terminal status.
        }
        remainingNanos = deadlineNanos - System.nanoTime();
      }
    }
  }

  /** Waits up to {@code millis} while background transfers are not fully completed. */
  @SuppressWarnings("java:S2142") // Intentionally ignore interrupts for the same reason as above
  void waitIfNotCompleted(long millis) {
    if (millis < 0) throw new IllegalArgumentException("timeout value is negative");
    synchronized (this) {
      if (millis == 0) {
        while (!completed()) {
          try {
            this.wait(0); // indefinite wait
          } catch (InterruptedException _) {
            // See comment in waitIfNotFinished(): ignore interrupts to avoid immediate
            // InterruptedException on subsequent wait() calls which would otherwise
            // cause tight-loop spinning in callers.
          }
        }
        return;
      }
      long deadlineNanos =
          System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(millis);
      long remainingNanos = deadlineNanos - System.nanoTime();
      while (!completed() && remainingNanos > 0) {
        try {
          long waitMillis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(remainingNanos);
          int waitNanos =
              (int)
                  (remainingNanos - java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(waitMillis));
          if (waitMillis == 0L && waitNanos > 0) {
            this.wait(0L, waitNanos);
          } else {
            this.wait(waitMillis, waitNanos);
          }
        } catch (InterruptedException _) {
          // See comment in waitIfNotFinished(): ignore interrupts to avoid immediate
          // InterruptedException on subsequent wait() calls which would otherwise
          // cause tight-loop spinning in callers.
        }
        remainingNanos = deadlineNanos - System.nanoTime();
      }
    }
  }

  /**
   * Returns the raw header bytes sent with {@code DataInsert}.
   *
   * @return header bytes (non-null)
   */
  public byte[] getHeaders() {
    return headers;
  }

  /**
   * Unique identifier for this request.
   *
   * @return UID matching the protocol {@code UID} field
   */
  @Override
  public long getUID() {
    return uid;
  }

  private final Object totalBytesSync = new Object();
  private int totalBytesSent;

  /**
   * Records the number of bytes sent for this transfer.
   *
   * @param x number of bytes
   */
  @Override
  public void sentBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesSent += x;
    }
    node.getNodeStats().insertSentBytes(false, x);
  }

  /**
   * Returns the total bytes sent so far for this sender.
   *
   * @return bytes sent
   */
  public int getTotalSentBytes() {
    synchronized (totalBytesSync) {
      return totalBytesSent;
    }
  }

  private int totalBytesReceived;

  /**
   * Records the number of bytes received for this transfer.
   *
   * @param x number of bytes
   */
  @Override
  public void receivedBytes(int x) {
    synchronized (totalBytesSync) {
      totalBytesReceived += x;
    }
    node.getNodeStats().insertReceivedBytes(false, x);
  }

  /**
   * Returns the total bytes received so far for this sender.
   *
   * @return bytes received
   */
  public int getTotalReceivedBytes() {
    synchronized (totalBytesSync) {
      return totalBytesReceived;
    }
  }

  /**
   * Records payload bytes (excludes protocol overhead) for statistics.
   *
   * @param x number of payload bytes
   */
  @Override
  public void sentPayload(int x) {
    node.sentPayload(x);
    node.getNodeStats().insertSentBytes(false, -x);
  }

  /**
   * Returns whether receiving the upstream block failed.
   *
   * @return {@code true} if upstream reception failed/aborted
   */
  public boolean failedReceive() {
    return receiveFailed;
  }

  /**
   * Returns {@code true} once at least one background transfer has started.
   *
   * @return {@code true} after first background transfer is scheduled
   */
  public boolean startedSendingData() {
    synchronized (backgroundTransfers) {
      return !backgroundTransfers.isEmpty();
    }
  }

  /**
   * Returns the scheduling priority for tasks spawned by this sender.
   *
   * @return numeric priority compatible with {@link NativeThread}
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  /**
   * Returns the peers this sender has routed to so far, in order.
   *
   * @return array of peers already contacted (may be empty)
   */
  public PeerNode[] getRoutedTo() {
    return this.nodesRoutedTo.toArray(new PeerNode[nodesRoutedTo.size()]);
  }

  /**
   * Creates the initial insert request message with optional routing hints.
   *
   * @return a fully populated {@link Message} ready to send to the next hop
   */
  @Override
  protected Message createDataRequest() {
    Message req;

    req = DMT.createFNPInsertRequest(uid, htl, key);
    if (forkOnCacheable != Node.FORK_ON_CACHEABLE_DEFAULT) {
      req.addSubMessage(DMT.createFNPSubInsertForkControl(forkOnCacheable));
    }
    if (ignoreLowBackoff != Node.IGNORE_LOW_BACKOFF_DEFAULT) {
      req.addSubMessage(DMT.createFNPSubInsertIgnoreLowBackoff(ignoreLowBackoff));
    }
    if (preferInsert != Node.PREFER_INSERT_DEFAULT) {
      req.addSubMessage(DMT.createFNPSubInsertPreferInsert(preferInsert));
    }
    req.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));

    return req;
  }

  /**
   * Timeout used when awaiting the early {@code Accepted}/{@code Rejected*} outcome.
   *
   * @return timeout in milliseconds
   */
  @Override
  protected long getAcceptedTimeout() {
    return ACCEPTED_TIMEOUT;
  }

  /**
   * Handles a fatal wait while contacting a peer. Decrements HTL and completes with RNF.
   *
   * @param load current measured load used by the routing policy
   */
  @Override
  protected void timedOutWhileWaiting(double load) {
    htl -= (short) Math.max(0, hopsForFatalTimeoutWaitingForPeer());
    if (htl < 0) htl = 0;
    // Backtrack, i.e. RNF.
    if (!hasForwarded) origTag.setNotRoutedOnwards();
    finish(ROUTE_NOT_FOUND, null);
  }

  /**
   * Called after the next peer accepts the request to begin the data transfer and outcome wait.
   *
   * @param next the accepting peer
   */
  @Override
  protected void onAccepted(PeerNode next) {
    // Send them the data.
    // Which might be the new data resulting from a collision...

    Message dataInsert;
    dataInsert = DMT.createFNPDataInsert(uid, headers);
    /*
     * What are we waiting for now??: - FNPRouteNotFound - couldn't exhaust HTL, but send us the
     * data anyway please - FNPInsertReply - used up all HTL, yay - FNPRejectOverload - propagating
     * an overload error :( - FNPRejectTimeout - we took too long to send the DataInsert -
     * FNPDataInsertRejected - the insert was invalid
     */
    int searchTimeout = calculateTimeout(htl);
    MessageFilter mf = buildInsertOutcomeFilter(next, uid, searchTimeout);

    InsertTag thisTag = forkedRequestTag;
    if (forkedRequestTag == null) thisTag = origTag;

    if (LOG.isDebugEnabled()) LOG.debug("Sending DataInsert");
    try {
      next.sendSync(dataInsert, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not connected sending DataInsert: {}" + FOR + "{}", next, uid);
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Unable to send {} to {} in a reasonable time", dataInsert, next);
      // Other side will fail. No need to do anything.
      next.noLongerRoutingTo(thisTag, false);
      routeRequests();
      return;
    }

    if (LOG.isDebugEnabled()) LOG.debug("Sending data");
    final BackgroundTransfer transfer = startBackgroundTransfer(next, prb, thisTag);
    // Once the transfer has started, we only unlock the tag after the transfer completes
    // (successfully or not).
    waitForInsertOutcomeLoop(next, thisTag, transfer, mf);
  }

  private void waitForInsertOutcomeLoop(
      PeerNode next, InsertTag thisTag, BackgroundTransfer transfer, MessageFilter mf) {
    while (true) {
      Message msg;
      if (failIfReceiveFailed(thisTag, next)) {
        // The transfer has started, it will be canceled.
        transfer.onCompleted();
        return;
      }
      try {
        msg = node.getUSM().waitFor(mf, this);
      } catch (DisconnectedException _) {
        LOG.info("Disconnected from {} while waiting for InsertReply on {}", next, this);
        transfer.onDisconnect(next);
        routeRequests();
        return;
      }
      if (failIfReceiveFailed(thisTag, next)) {
        // The transfer has started, it will be canceled.
        transfer.onCompleted();
        return;
      }
      if (msg == null) {
        LOG.warn("Timeout on insert {} to {}", this, next);
        handleFirstTimeout(next, thisTag, transfer, this.htl);
        return;
      }
      if (handleMessageAfterAcceptance(msg, next, transfer)) return;
    }
  }

  private MessageFilter buildInsertOutcomeFilter(PeerNode src, long uid, int searchTimeout) {
    MessageFilter mfInsertReply =
        MessageFilter.create()
            .setSource(src)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPInsertReply);
    MessageFilter mfRejectedOverload =
        MessageFilter.create()
            .setSource(src)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPRejectedOverload);
    MessageFilter mfRouteNotFound =
        MessageFilter.create()
            .setSource(src)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPRouteNotFound);
    MessageFilter mfDataInsertRejected =
        MessageFilter.create()
            .setSource(src)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPDataInsertRejected);
    MessageFilter mfTimeout =
        MessageFilter.create()
            .setSource(src)
            .setField(DMT.UID, uid)
            .setTimeout(searchTimeout)
            .setType(DMT.FNPRejectedTimeout);

    return mfInsertReply.or(
        mfRouteNotFound.or(mfDataInsertRejected.or(mfTimeout.or(mfRejectedOverload))));
  }

  private void handleFirstTimeout(
      PeerNode next, InsertTag thisTag, BackgroundTransfer transfer, short htlAtTimeout) {
    // First timeout. Could be caused by the next node, or downstream.
    next.localRejectedOverload("AfterInsertAcceptedTimeout2", realTimeFlag);
    forwardRejectedOverload();

    synchronized (this) {
      status = TIMED_OUT;
      notifyAll();
    }

    final InsertTag tag = thisTag;
    final PeerNode waitingFor = next;
    final short capturedHtl = htlAtTimeout;
    Runnable r = () -> runSecondTimeoutWait(waitingFor, tag, transfer, capturedHtl);
    node.getExecutor().execute(r);
    // Meanwhile, finish() to update allTransfersCompleted and let the handler proceed downstream.
    finish(TIMED_OUT, next);
  }

  private void runSecondTimeoutWait(
      PeerNode waitingFor, InsertTag tag, BackgroundTransfer transfer, short htlAtTimeout) {
    // Tag unlock happens in BackgroundTransfer after completion.
    int searchTimeout = calculateTimeout(htlAtTimeout);
    MessageFilter mf = buildInsertOutcomeFilter(waitingFor, uid, searchTimeout);
    while (true) {
      Message msg;
      if (failIfReceiveFailed(tag, waitingFor)) {
        transfer.onCompleted();
        return;
      }
      try {
        msg = node.getUSM().waitFor(mf, CHKInsertSender.this);
      } catch (DisconnectedException _) {
        LOG.info(
            "Disconnected from {} while waiting for InsertReply on {}",
            waitingFor,
            CHKInsertSender.this);
        transfer.onDisconnect(waitingFor);
        return;
      }
      if (failIfReceiveFailed(tag, waitingFor)) {
        transfer.onCompleted();
        return;
      }
      if (msg == null) {
        // Second timeout: definitely caused by the next node; fatal.
        LOG.error("Got second (local) timeout on {} from {}", CHKInsertSender.this, waitingFor);
        transfer.onCompleted();
        waitingFor.fatalTimeout();
        return;
      }
      if (handleSecondTimeoutOutcome(msg, waitingFor, transfer)) return;
    }
  }

  private boolean handleSecondTimeoutOutcome(
      Message msg, PeerNode waitingFor, BackgroundTransfer transfer) {
    if (msg.getSpec() == DMT.FNPRejectedTimeout) {
      handleRejectedTimeout(msg, waitingFor);
      transfer.kill();
      return true;
    }
    if (msg.getSpec() == DMT.FNPRejectedOverload) {
      if (handleRejectedOverload(msg, waitingFor)) {
        transfer.onCompleted();
        return true; // Don't try another node.
      }
      return false; // retry loop
    }
    if (msg.getSpec() == DMT.FNPRouteNotFound) {
      transfer.onCompleted();
      return true; // Don't try another node.
    }
    if (msg.getSpec() == DMT.FNPDataInsertRejected) {
      handleDataInsertRejected(msg, waitingFor);
      transfer.kill();
      return true; // Don't try another node.
    }
    if (msg.getSpec() != DMT.FNPInsertReply) {
      LOG.error("Unknown reply: {}", msg);
    }
    transfer.onCompleted();
    return true;
  }

  private boolean handleMessageAfterAcceptance(
      Message msg, PeerNode next, BackgroundTransfer transfer) {
    if (msg.getSpec() == DMT.FNPRejectedTimeout) {
      transfer.kill();
      handleRejectedTimeout(msg, next);
      return true;
    }
    if (msg.getSpec() == DMT.FNPRejectedOverload) {
      if (handleRejectedOverload(msg, next)) {
        transfer.onCompleted();
        routeRequests();
        return true;
      }
      return false; // try again on the next loop iteration
    }
    if (msg.getSpec() == DMT.FNPRouteNotFound) {
      handleRNF(msg, next);
      transfer.onCompleted();
      routeRequests();
      return true;
    }
    if (msg.getSpec() == DMT.FNPDataInsertRejected) {
      handleDataInsertRejected(msg, next);
      transfer.kill();
      routeRequests();
      return true;
    }
    if (msg.getSpec() != DMT.FNPInsertReply) {
      LOG.error("Unknown reply: {}", msg);
      transfer.onCompleted();
      finish(INTERNAL_ERROR, next);
    } else {
      transfer.onCompleted();
      finish(SUCCESS, next);
    }
    return true;
  }

  /**
   * Indicates that this sender performs an insert operation.
   *
   * @return always {@code true}
   */
  @Override
  protected boolean isInsert() {
    return true;
  }

  /**
   * Returns the source node for routing heuristics (null when forked).
   *
   * @return the originating peer or {@code null} if this is a forked request
   */
  @Override
  protected PeerNode sourceForRouting() {
    if (forkedRequestTag != null) return null;
    return source;
  }

  /**
   * Returns a non-zero value to ignore low-backoff peers when requested.
   *
   * @return {@code Node.LOW_BACKOFF} to ignore low-backoff peers; otherwise 0
   */
  @Override
  protected long ignoreLowBackoff() {
    return ignoreLowBackoff ? Node.LOW_BACKOFF : 0;
  }
}
