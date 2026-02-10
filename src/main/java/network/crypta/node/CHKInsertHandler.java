package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.io.xfer.AbortedException;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockReceiver.BlockReceiverCompletion;
import network.crypta.io.xfer.BlockReceiver.BlockReceiverTimeoutHandler;
import network.crypta.io.xfer.BlockTransferContext;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.NodeCHK;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.HexUtil;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles a CHK (Content-Hash Key) data insert received from an upstream peer.
 *
 * <p>This handler performs the upstream handshake (send {@code FNPAccepted}), waits for the
 * accompanying {@code FNPDataInsert} or {@code FNPDataInsertRejected}, sets up a {@link
 * BlockReceiver} to receive the block, coordinates a {@link CHKInsertSender} to forward the data
 * downstream when applicable, and finally replies to the source with the terminal result message.
 *
 * <p>Lifecycle and threading: - An instance is executed once via {@link #run()} on a worker thread
 * (implements {@link PrioRunnable}). - A separate {@code DataReceiver} task is posted to the node's
 * executor to receive the block in parallel with downstream routing progress. - Completion and
 * error paths synchronize on internal locks to avoid double-finishing and to ensure that the commit
 * happens only after downstream completion signals are observed.
 *
 * <p>Timeouts and retries: - Waits up to {@link #DATA_INSERT_TIMEOUT} milliseconds for the initial
 * {@code DataInsert}; absence triggers a two-stage timeout (soft notify, then fatal after an
 * extended grace period). - When downstream takes too long to acknowledge transfer completion, the
 * handler informs the source that it timed out locally but continues waiting until downstream
 * finishes to avoid protocol races.
 *
 * <p>Side effects: - Sends protocol messages to {@link #source} and updates node statistics via the
 * {@link ByteCounter} interface. - May commit verified blocks to the local datastore when allowed
 * by {@link #canWriteDatastore}.
 *
 * <p>Nullability and units: - All timeouts are expressed in milliseconds unless otherwise
 * documented. - {@code realTimeFlag} selects real-time vs. bulk timeouts for transfer completion.
 *
 * @author amphibian
 */
public class CHKInsertHandler implements PrioRunnable, ByteCounter {
  private static final Logger LOG = LoggerFactory.getLogger(CHKInsertHandler.class);

  private static final String FOR_STRING = " for ";
  private static final String FROM_STRING = " from ";

  // No explicit static initialization is required for this handler.

  static final long DATA_INSERT_TIMEOUT = SECONDS.toMillis(10);

  final Node node;
  final long uid;
  final PeerNode source;
  final NodeCHK key;
  final long startTime;
  private final short htl;
  private CHKInsertSender sender;
  private byte[] headers;
  private BlockReceiver br;
  private Thread runThread;
  PartiallyReceivedBlock prb;
  final InsertTag tag;
  private final boolean canWriteDatastore;
  private final boolean forkOnCacheable;
  private final boolean preferInsert;
  private final boolean ignoreLowBackoff;
  private final boolean realTimeFlag;

  CHKInsertHandler(NodeCHK key, short htl, InsertHandlerContext context) {
    this.node = context.node();
    this.uid = context.uid();
    this.source = context.source();
    this.startTime = context.startTime();
    this.tag = context.tag();
    this.key = key;
    this.htl = htl;
    canWriteDatastore = node.routing().canWriteDatastoreInsert(htl);
    InsertRoutingOptions options = context.routingOptions();
    this.forkOnCacheable = options.forkOnCacheable();
    this.preferInsert = options.preferInsert();
    this.ignoreLowBackoff = options.ignoreLowBackoff();
    this.realTimeFlag = context.realTimeFlag();
  }

  /**
   * Returns a short identifier suitable for logs and diagnostics.
   *
   * @return a string that includes the handler type and the request UID
   */
  @Override
  public String toString() {
    return super.toString() + FOR_STRING + uid;
  }

  /**
   * Entry point for the handler. Performs the upstream acceptance, waits for the data insert,
   * starts the receiver task, and drives downstream routing until a terminal status is reached.
   *
   * <p>All exceptions are caught and reported to the associated {@link InsertTag}; the tag is
   * unlocked in a {@code finally} block to avoid deadlocks on upstream cancellation.
   */
  @Override
  @SuppressWarnings({"java:S1181", "ResultOfMethodCallIgnored"})
  public void run() {
    try {
      realRun();
    } catch (Throwable t) {
      LOG.error("Caught in run() {}", t, t);
      tag.handlerThrew(t);
    } finally {
      if (LOG.isDebugEnabled()) LOG.debug("Exiting CHKInsertHandler.run() for {}", uid);
      // Clear any interrupt left set by DataReceiveCompletion to avoid leaking
      // interrupt status back into the executor thread pool.
      // Thread.interrupted() returns the current status and clears it.
      Thread.interrupted();
      tag.unlockHandler();
    }
  }

  private void realRun() {
    runThread = Thread.currentThread();
    if (!sendAccepted()) return;

    Message msg;
    try {
      msg = waitForDataInsert();
    } catch (DisconnectedException _) {
      // Peer disconnected while we were waiting; do not treat as timeout/overload.
      if (LOG.isInfoEnabled()) LOG.info("Disconnected while waiting for DataInsert on {}", uid);
      return;
    }
    if (msg == null) {
      handleNoDataInsert();
      return;
    }

    if (DMT.FNPDataInsertRejected.equals(msg.getSpec())) {
      forwardDataInsertRejected(msg);
      return;
    }

    setupForDataInsert(msg);
    processSenderStatuses();
  }

  private boolean sendAccepted() {
    // Consider inserting rate limiting here if the acceptance path requires backpressure.
    Message accepted = DMT.createFNPAccepted(uid);
    try {
      // Synchronous send here ensures the next message filter does not spuriously time out; we
      // either block here, or inside the filter, but we prefer to fail early on sending.
      source.transport().sendSync(accepted, this, realTimeFlag);
      return true;
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source while sending FNPAccepted");
      return false;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Unable to send {} in a reasonable time to {}", accepted, source);
      return false;
    }
  }

  private Message waitForDataInsert() throws DisconnectedException {
    MessageFilter mf = makeDataInsertFilter(DATA_INSERT_TIMEOUT);
    Message msg = node.network().usm().waitFor(mf, this);
    if (LOG.isDebugEnabled()) LOG.debug("Received DataInsert message: {}", msg);
    return msg;
  }

  private void forwardDataInsertRejected(Message msg) {
    try {
      source
          .transport()
          .sendAsync(
              DMT.createFNPDataInsertRejected(uid, msg.getShort(DMT.DATA_INSERT_REJECTED_REASON)),
              null,
              this);
    } catch (NotConnectedException _) {
      // Upstream disconnected while we were notifying it; nothing more to do here.
    }
  }

  private void setupForDataInsert(Message msg) {
    // A DataInsert was received; extract headers for the block.
    headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
    // Note: headers can be validated if needed.

    // Create a CHKInsertSender when HTL permits, otherwise we may end up storing locally.
    // From this point on, clean exits must flow through finish() to centralize commit and reply.
    prb = new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
    if (htl > 0)
      sender =
          node.routing()
              .makeInsertSender(
                  key,
                  htl,
                  uid,
                  tag,
                  source,
                  NodeRoutingSubsystem.ChkInsertOptions.of(headers, prb)
                      .withFromStore(false)
                      .withCanWriteClientCache(false)
                      .withForkOnCacheable(forkOnCacheable)
                      .withPreferInsert(preferInsert)
                      .withIgnoreLowBackoff(ignoreLowBackoff)
                      .withRealTimeFlag(realTimeFlag));
    br =
        new BlockReceiver(
            new BlockTransferContext(
                node.network().usm(),
                node.network().ticker(),
                source,
                uid,
                prb,
                this,
                realTimeFlag),
            myTimeoutHandler,
            false);

    // Receive the data off-thread so downstream routing can proceed concurrently.
    Runnable dataReceiver = new DataReceiver();
    synchronized (this) {
      receiveStarted = true;
    }
    node.network().executor().execute(dataReceiver, "CHKInsertHandler$DataReceiver for UID " + uid);
  }

  private void processSenderStatuses() {
    boolean receivedRejectedOverload = false;
    while (true) {
      waitOnSender();
      if (receiveFailed()) {
        finish(CHKInsertSender.RECEIVE_FAILED);
        return;
      }

      receivedRejectedOverload = forwardNonTerminalOverloadIfNeeded(receivedRejectedOverload);

      int status = sender.getStatus();
      if (status != CHKInsertSender.NOT_FINISHED) {
        handleTerminalStatus(status);
        return;
      }
    }
  }

  private boolean forwardNonTerminalOverloadIfNeeded(boolean alreadyForwarded) {
    if (!alreadyForwarded && sender.receivedRejectedOverload()) {
      try {
        source.transport().sendAsync(DMT.createFNPRejectedOverload(uid, false), null, this);
      } catch (NotConnectedException _) {
        if (LOG.isDebugEnabled())
          LOG.debug("Lost connection to source while forwarding non-terminal overload");
        return true; // Treat as forwarded to avoid retrying endlessly.
      }
      return true;
    }
    return alreadyForwarded;
  }

  private void waitOnSender() {
    final CHKInsertSender s = sender;
    synchronized (s) {
      try {
        long deadline = System.currentTimeMillis() + 5000L;
        long remaining = deadline - System.currentTimeMillis();
        while (s.getStatus() == CHKInsertSender.NOT_FINISHED && remaining > 0L) {
          s.wait(remaining);
          remaining = deadline - System.currentTimeMillis();
        }
      } catch (InterruptedException _) {
        // Restore interrupt status; likely set by receive failing.
        Thread.currentThread().interrupt();
      }
    }
  }

  private void handleTerminalStatus(int status) {
    switch (status) {
      case CHKInsertSender.TIMED_OUT,
          CHKInsertSender.GENERATED_REJECTED_OVERLOAD,
          CHKInsertSender.INTERNAL_ERROR ->
          handleFatalOverload(status);
      case CHKInsertSender.ROUTE_NOT_FOUND, CHKInsertSender.ROUTE_REALLY_NOT_FOUND ->
          handleRouteNotFound(status);
      case CHKInsertSender.RECEIVE_FAILED -> handleReceiveFailed();
      case CHKInsertSender.SUCCESS -> handleSuccess(status);
      default -> handleUnknownStatus();
    }
  }

  /**
   * Sends a fatal overload response upstream and finalizes the insert.
   *
   * <p>If the terminal status is {@link CHKInsertSender#TIMED_OUT} or {@link
   * CHKInsertSender#GENERATED_REJECTED_OVERLOAD}, the handler allows committing any locally stored
   * data after notifying upstream.
   */
  private void handleFatalOverload(int status) {
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Lost connection to source while sending fatal overload");
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Send timeout for fatal overload message: {} to {}", msg, source);
      return;
    }
    if ((status == CHKInsertSender.TIMED_OUT)
        || (status == CHKInsertSender.GENERATED_REJECTED_OVERLOAD)) canCommit = true;
    finish(status);
  }

  /** Sends a route-not-found response including the final HTL, then finalizes the insert. */
  private void handleRouteNotFound(int status) {
    Message msg = DMT.createFNPRouteNotFound(uid, sender.getHTL());
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Lost connection to source while sending route-not-found");
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Send timeout for route-not-found message: {} to {}", msg, source);
      return;
    }
    canCommit = true;
    finish(status);
  }

  /** Finalizes the insert as a receiving failure without sending additional messages. */
  private void handleReceiveFailed() {
    finish(CHKInsertSender.RECEIVE_FAILED);
  }

  /** Sends a success reply upstream and finalizes the insert. */
  private void handleSuccess(int status) {
    Message msg = DMT.createFNPInsertReply(uid);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException _) {
      LOG.debug("Lost connection to source while sending insert reply");
      return;
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Send timeout for insert reply: {} to {}", msg, source);
      return;
    }
    canCommit = true;
    finish(status);
  }

  /**
   * Defensive fallback for unexpected sender status codes: logs, notifies overload, and treats the
   * situation as an internal error.
   */
  private void handleUnknownStatus() {
    LOG.error("Unknown status code: {}", sender.getStatusString());
    Message msg = DMT.createFNPRejectedOverload(uid, true);
    try {
      source.transport().sendSync(msg, this, realTimeFlag);
    } catch (NotConnectedException | SyncSendWaitedTooLongException _) {
      // Ignore
    }
    finish(CHKInsertSender.INTERNAL_ERROR);
  }

  /**
   * Builds a filter that matches either {@code FNPDataInsert} or {@code FNPDataInsertRejected} from
   * the same source and UID.
   *
   * @param timeout timeout in milliseconds for the filter
   * @return a filter that matches the first relevant message
   */
  private MessageFilter makeDataInsertFilter(long timeout) {
    MessageFilter mfDataInsert =
        MessageFilter.create()
            .setType(DMT.FNPDataInsert)
            .setField(DMT.UID, uid)
            .setSource(source)
            .setTimeout(timeout);
    // DataInsertRejected means the transfer failed upstream so a DataInsert will not be sent.
    MessageFilter mfDataInsertRejected =
        MessageFilter.create()
            .setType(DMT.FNPDataInsertRejected)
            .setField(DMT.UID, uid)
            .setSource(source)
            .setTimeout(timeout);
    return mfDataInsert.or(mfDataInsertRejected);
  }

  /**
   * Handles the case where no data insert arrives within the initial timeout.
   *
   * <p>Notifies the source of a local timeout and sets up a two-stage timeout: a soft phase that
   * tolerates connectivity hiccups, followed by a fatal timeout which marks the peer at fault if no
   * message arrives within the extended grace period.
   */
  private void handleNoDataInsert() {
    try {
      // Nodes wait until they have the DataInsert before forwarding, so there is absolutely no
      // excuse: There is a local problem here!
      if (source.isConnected()
          && (startTime > (source.timeLastConnectionCompleted() + Node.HANDSHAKE_TIMEOUT * 4L)))
        LOG.warn("Did not receive DataInsert on {}" + FROM_STRING + "{} !", uid, source);
      Message tooSlow = DMT.createFNPRejectedTimeout(uid);
      source.transport().sendAsync(tooSlow, null, this);
      Message m = DMT.createFNPInsertTransfersCompleted(uid, true);
      source.transport().sendAsync(m, null, this);
      prb = new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
      br =
          new BlockReceiver(
              new BlockTransferContext(
                  node.network().usm(),
                  node.network().ticker(),
                  source,
                  uid,
                  prb,
                  this,
                  realTimeFlag),
              null,
              false);
      prb.abort(RetrievalException.NO_DATAINSERT, "No DataInsert", true);
      source.localRejectedOverload("TimedOutAwaitingDataInsert", realTimeFlag);

      // Two-stage timeout: do not go fatal unless no response arrives within 60 seconds.
      // This accommodates long connection timeouts; revisiting this approach would require careful
      // consideration of transport behavior and handshake timing.
      MessageFilter mf = makeDataInsertFilter(SECONDS.toMillis(60));
      node.network()
          .usm()
          .addAsyncFilter(
              mf,
              new SlowAsyncMessageFilterCallback() {

                @Override
                public void onMatched(Message m) {
                  // Either we got a DataInsert (the transfer was already aborted above) or a
                  // DataInsertRejected (transfer never started). We intentionally defer unlocking
                  // to
                  // the finally block in realRun(); early unlocking here risks minor races without
                  // a
                  // clear benefit.
                }

                @Override
                public boolean shouldTimeout() {
                  return false;
                }

                @Override
                public void onTimeout() {
                  LOG.error(
                      "No DataInsert for {}" + FROM_STRING + "{} ({})",
                      CHKInsertHandler.this,
                      source,
                      source.getBuildNumber());
                  // Fatal timeout. Something is seriously busted.
                  // We've waited long enough that we know it's not just a connectivity problem - if
                  // it was, we'd have disconnected by now.
                  source.fatalTimeout();
                }

                @Override
                public void onDisconnect(PeerContext ctx) {
                  // Okay. Somewhat expected, it was having problems.
                }

                @Override
                public void onRestarted(PeerContext ctx) {
                  // Okay.
                }

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                }
              },
              this);
    } catch (NotConnectedException | DisconnectedException _) {
      if (LOG.isDebugEnabled())
        LOG.debug("Lost connection to source while handling missing DataInsert");
    }
  }

  private volatile boolean canCommit = false;
  private boolean sentCompletion = false;
  private final Object sentCompletionLock = new Object();

  /**
   * Finalization path for the insert.
   *
   * <p>If {@code canCommit} is set, and a complete, verified block is available, the block is
   * committed to the local store. Completion messages are coordinated so that upstream notification
   * occurs only after all downstream transfers have finished to avoid protocol races.
   */
  private void finish(int code) {
    if (LOG.isDebugEnabled()) LOG.debug("Waiting for receive");
    long transferTimeout =
        realTimeFlag
            ? CHKInsertSender.TRANSFER_COMPLETION_ACK_TIMEOUT_REALTIME
            : CHKInsertSender.TRANSFER_COMPLETION_ACK_TIMEOUT_BULK;

    waitForReceiveToComplete();

    CHKBlock block = verify();

    boolean sentCompletionWasSet = markAndGetSentCompletion();

    Message m = awaitDownstreamAndBuildCompletionMsg(sentCompletionWasSet, transferTimeout);

    if (sender == null && !sentCompletionWasSet && canCommit) {
      // There are no downstream senders, but we stored the data locally, report successful
      // transfer. Note that this is done even if the verifying fails.
      m = DMT.createFNPInsertTransfersCompleted(uid, false /* no timeouts */);
    }

    // Don't commit until after we have received all the downstream transfer completion
    // notifications.
    // We don't want an attacker to see a ULPR notice from the inserter before he sees it from the
    // end of the chain (bug 3338).
    if (block != null) {
      commit(block);
    }

    // Be generous with unlocking incoming requests, and cautious with outgoing requests.
    tag.unlockHandler();

    if (m != null) sendCompletion(m);

    reportStatsIfNeeded(code);
  }

  private void waitForReceiveToComplete() {
    synchronized (this) {
      while (receiveStarted && !receiveCompleted) {
        try {
          wait(SECONDS.toMillis(100));
        } catch (InterruptedException _) {
          // Restore interrupted status
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  private boolean markAndGetSentCompletion() {
    synchronized (sentCompletionLock) {
      boolean wasSet = sentCompletion;
      sentCompletion = true;
      return wasSet;
    }
  }

  private Message awaitDownstreamAndBuildCompletionMsg(
      boolean sentCompletionAlreadySet, long transferTimeout) {
    if ((sender == null) || sentCompletionAlreadySet) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Waiting for completion");
    long deadline = System.currentTimeMillis() + transferTimeout;

    boolean routingTookTooLong = waitUntilSenderCompletedWithin(deadline);

    if (routingTookTooLong) {
      tag.timedOutToHandlerButContinued();
      try {
        source.transport().sendAsync(DMT.createFNPInsertTransfersCompleted(uid, true), null, this);
      } catch (NotConnectedException _) {
        // Ignore.
      }
      // Still waiting until downstream reports completed
      waitUntilSenderCompletedNoTimeout();
      if (LOG.isDebugEnabled()) LOG.debug("Completed after telling downstream on {}", this);
      return null; // already notified upstream
    }

    boolean failed = sender.anyTransfersFailed();
    return DMT.createFNPInsertTransfersCompleted(uid, failed);
  }

  private boolean waitUntilSenderCompletedWithin(long deadlineMillis) {
    final CHKInsertSender s = sender;
    while (true) {
      synchronized (s) {
        if (s.completed()) return false;
        try {
          long remaining = deadlineMillis - System.currentTimeMillis();
          int t = (int) Math.clamp(remaining, 0L, Integer.MAX_VALUE);
          if (t > 0) s.wait(t);
          else return true; // took too long
        } catch (InterruptedException _) {
          // Restore interrupted status and loop
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  private void waitUntilSenderCompletedNoTimeout() {
    final CHKInsertSender s = sender;
    while (true) {
      synchronized (s) {
        if (s.completed()) return;
        try {
          s.wait(SECONDS.toMillis(10));
        } catch (InterruptedException _) {
          // Restore interrupted status and loop
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  private void sendCompletion(Message m) {
    try {
      // We do need to sendSync here so we have accurate byte counter totals.
      source.transport().sendSync(m, this, realTimeFlag);
      if (LOG.isDebugEnabled()) LOG.debug("Sent completion: {}" + FOR_STRING + "{}", m, this);
    } catch (NotConnectedException _) {
      if (LOG.isDebugEnabled()) LOG.debug("Not connected: {}" + FOR_STRING + "{}", source, this);
      // May need to commit anyway...
    } catch (SyncSendWaitedTooLongException _) {
      LOG.error("Send timeout for completion message: {} to {}", m, source);
      // May need to commit anyway...
    }
  }

  private void reportStatsIfNeeded(int code) {
    if (code == CHKInsertSender.TIMED_OUT
        || code == CHKInsertSender.GENERATED_REJECTED_OVERLOAD
        || code == CHKInsertSender.INTERNAL_ERROR
        || code == CHKInsertSender.ROUTE_REALLY_NOT_FOUND
        || code == CHKInsertSender.RECEIVE_FAILED
        || receiveFailed()) {
      return;
    }
    int totalSent = getTotalSentBytes();
    int totalReceived = getTotalReceivedBytes();
    if (sender != null) {
      totalSent += sender.getTotalSentBytes();
      totalReceived += sender.getTotalReceivedBytes();
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Remote CHK insert cost {}/{} bytes ({}) receive failed = {}",
          totalSent,
          totalReceived,
          code,
          receiveFailed());
    node.network().stats().remoteChkInsertBytesSentAverage.report(totalSent);
    node.network().stats().remoteChkInsertBytesReceivedAverage.report(totalReceived);
    if (code == CHKInsertSender.SUCCESS) {
      // Report both sent and received because we have both a Handler and a Sender
      if (sender != null && sender.startedSendingData())
        node.network().stats().successfulChkInsertBytesSentAverage.report(totalSent);
      node.network().stats().successfulChkInsertBytesReceivedAverage.report(totalReceived);
    }
  }

  /** Verify data, or send DataInsertRejected. */
  private CHKBlock verify() {
    Message toSend = null;

    CHKBlock block = null;

    synchronized (this) {
      if ((prb == null) || prb.isAborted()) return null;
      try {
        if (!canCommit) return null;
        if (!prb.allReceived()) return null;
        block = new CHKBlock(prb.getBlock(), headers, key);
      } catch (CHKVerifyException e) {
        LOG.error(
            "Verify failed in CHKInsertHandler: {} - headers: {}",
            e,
            HexUtil.bytesToHex(headers),
            e);
        toSend = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_VERIFY_FAILED);
      } catch (AbortedException e) {
        LOG.error("Receive failed: {}", String.valueOf(e));
        // The receiver thread (below) will handle sending the failure notice
      }
    }
    if (toSend != null) {
      try {
        source.transport().sendAsync(toSend, null, this);
      } catch (NotConnectedException _) {
        // :(
        if (LOG.isDebugEnabled())
          LOG.debug("Lost connection in {} when sending FNPDataInsertRejected", this);
      }
    }
    return block;
  }

  private void commit(CHKBlock block) {
    try {
      node.storage()
          .store(
              block,
              node.routing()
                  .shouldStoreDeep(
                      key, source, sender == null ? new PeerNode[0] : sender.getRoutedTo()),
              false,
              canWriteDatastore,
              false);
    } catch (KeyCollisionException _) {
      // Impossible with CHKs.
    }
    if (LOG.isDebugEnabled()) LOG.debug("Committed");
  }

  /** Has the receiving failed? If so, there's not much more that can be done... */
  private boolean receiveFailed;

  private boolean receiveStarted;
  private boolean receiveCompleted;

  /**
   * Runnable that performs the actual block receiving for this insert. Executed on the node's
   * executor, so downstream routing can proceed concurrently on the caller thread.
   */
  public class DataReceiver implements PrioRunnable {

    @Override
    public void run() {
      if (LOG.isDebugEnabled()) LOG.debug("Receiving data for {}", CHKInsertHandler.this);
      // Don't log whether the transfer succeeded or failed as the source initiated the transfer,
      // therefore, could be unreliable evidence.
      br.receive(new DataReceiveCompletion());
    }

    @Override
    public String toString() {
      return super.toString() + FOR_STRING + uid;
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
    }
  }

  private final class DataReceiveCompletion implements BlockReceiverCompletion {
    @Override
    public void blockReceived(byte[] buf) {
      if (LOG.isDebugEnabled()) LOG.debug("Received data block for {}", CHKInsertHandler.this);
      synchronized (CHKInsertHandler.this) {
        receiveCompleted = true;
        CHKInsertHandler.this.notifyAll();
      }
      node.network().stats().successfulBlockReceive(realTimeFlag, false);
    }

    @Override
    public void blockReceiveFailed(RetrievalException e) {
      synchronized (CHKInsertHandler.this) {
        receiveCompleted = true;
        receiveFailed = true;
        CHKInsertHandler.this.notifyAll();
      }
      // Cancel the sender
      if (sender != null)
        sender.onReceiveFailed(); // tell it to stop if it hasn't already failed... unless
      // it's sending it from the store
      runThread.interrupt();
      tag.timedOutToHandlerButContinued(); // sender is finished or will be very soon; we
      // may, however, be waiting for the sendAborted downstream.
      Message msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED);
      try {
        source.transport().sendSync(msg, CHKInsertHandler.this, realTimeFlag);
      } catch (NotConnectedException ex) {
        // If they are not connected, that's probably why the receiving failed!
        if (LOG.isDebugEnabled()) LOG.debug("Can't send {} to {}: {}", msg, source, ex, ex);
      } catch (SyncSendWaitedTooLongException _) {
        LOG.error("Send timeout for receive-failed rejection: {} to {}", msg, source);
      }
      if (e.getReason() == RetrievalException.SENDER_DISCONNECTED)
        LOG.info(
            "Failed to retrieve (disconnect): {}" + FOR_STRING + "{}", e, CHKInsertHandler.this, e);
      else
        // Annoying, but we have stats for this; no need to call attention to it, it's unlikely to
        // be a bug.
        LOG.atInfo()
            .addArgument(e::getReason)
            .addArgument(() -> RetrievalException.getErrString(e.getReason()))
            .addArgument(e)
            .addArgument(CHKInsertHandler.this)
            .setCause(e)
            .log("Failed to retrieve ({}/{}): {}" + FOR_STRING + "{}");

      if (!prb.abortedLocally())
        node.network().stats().failedBlockReceive(false, false, realTimeFlag, false);
    }
  }

  private synchronized boolean receiveFailed() {
    return receiveFailed;
  }

  private final Object totalSync = new Object();
  private int totalSentBytes;
  private int totalReceivedBytes;

  /**
   * Records bytes sent for this insert and updates node statistics. Invoked by lower-level senders
   * as data flows out.
   *
   * @param x number of bytes sent
   */
  @Override
  public void sentBytes(int x) {
    synchronized (totalSync) {
      totalSentBytes += x;
    }
    node.network().stats().insertSentBytes(false, x);
  }

  /**
   * Records bytes received for this insert and updates node statistics. Invoked by lower-level
   * receivers as data arrives.
   *
   * @param x number of bytes received
   */
  @Override
  public void receivedBytes(int x) {
    synchronized (totalSync) {
      totalReceivedBytes += x;
    }
    node.network().stats().insertReceivedBytes(false, x);
  }

  /**
   * Returns the total number of bytes sent on behalf of this insert.
   *
   * <p>Reads are not synchronized; values may be slightly stale while transfers are in flight.
   *
   * @return cumulative sent byte count
   */
  public int getTotalSentBytes() {
    return totalSentBytes;
  }

  /**
   * Returns the total number of bytes received for this insert.
   *
   * <p>Reads are not synchronized; values may be slightly stale while transfers are in flight.
   *
   * @return cumulative received byte count
   */
  public int getTotalReceivedBytes() {
    return totalReceivedBytes;
  }

  /**
   * Records bytes sent over the wire for this insert and updates node-level statistics.
   *
   * @param x number of bytes sent (payload plus protocol overhead)
   */
  @Override
  public void sentPayload(int x) {
    node.sentPayload(x);
    node.network().stats().insertSentBytes(false, -x);
  }

  /**
   * Reports the scheduling priority for this runnable to the thread pool.
   *
   * @return a priority constant suitable for {@link NativeThread}
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  private final BlockReceiverTimeoutHandler myTimeoutHandler =
      new BlockReceiverTimeoutHandler() {

        /**
         * We timed-out waiting for a block from the request sender. We do not know whether it is
         * the fault of the request sender or that of some previous node. The PRB will be canceled,
         * resulting in all outgoing transfers for this insert being canceled quickly. If the
         * problem occurred on a previous node, we will receive a cancel. So we are consistent with
         * the nodes we routed to, and it is safe to wait for the node that routed to us to send an
         * explicit cancel. We do not need to do anything yet.
         */
        @Override
        public void onFirstTimeout() {
          // Do nothing.
        }

        /**
         * We timed out, and the sender did not send us a timeout message, even after we told it we
         * were cancelling. Hence, we know that it was at fault. We need to take action against it.
         */
        @Override
        public void onFatalTimeout(PeerContext receivingFrom) {
          LOG.error(
              "Fatal timeout receiving insert {}" + FROM_STRING + "{}",
              CHKInsertHandler.this,
              receivingFrom);
          ((PeerNode) receivingFrom).fatalTimeout();
        }
      };
}
