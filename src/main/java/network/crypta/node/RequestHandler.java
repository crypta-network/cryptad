package network.crypta.node;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.xfer.BlockTransferContext;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.io.xfer.BlockTransmitter.BlockTransmitterCompletion;
import network.crypta.io.xfer.BlockTransmitter.ReceiverAbortHandler;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.node.OpennetNoderefWaiter.NoderefCallback;
import network.crypta.node.OpennetNoderefWaiter.WaitedTooLongForOpennetNoderefException;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates handling of a single incoming request from an upstream peer.
 *
 * <p>This class orchestrates request lifecycle and messaging with the upstream peer and any
 * downstream work performed by {@link RequestSender}. Fetching and transfer are delegated to {@code
 * RequestSender} to enable transfer coalescing and accurate accounting, while the handler tracks
 * status, deadlines, and byte counters. It also manages opennet path folding (relaying or accepting
 * node references) and ensures final bookkeeping and slot release.
 *
 * <p>Threading: callbacks invoked by I/O subsystems may occur off the handler thread; methods that
 * record outcomes ensure idempotent cleanup.
 */
public class RequestHandler
    implements PrioRunnable, HighHtlAware, ByteCounter, RequestSenderListener {

  private static final Logger LOG = LoggerFactory.getLogger(RequestHandler.class);

  /**
   * Handles abort decisions during CHK transfer. Extracted to reduce complexity in {@link
   * #onCHKTransferBegins()}.
   */
  private final class CHKReceiverAbortHandler implements ReceiverAbortHandler {
    /**
     * Decide whether to abort the upstream CHK transfer.
     *
     * <p>Aborts only when no other consumer wants the data and the key is already present locally.
     * Keeps the transfer when coalesced or when peers/local consumers still need the block.
     *
     * @return {@code true} to abort receiving from upstream; {@code false} to continue.
     */
    @Override
    public boolean onAbort() {
      RequestSender current = RequestHandler.this.rs;
      if (current != null && current.uid != RequestHandler.this.uid) {
        if (LOG.isDebugEnabled())
          LOG.debug("Do not cancel transfer; coalesced on {}", RequestHandler.this);
        // No need to reassign the tag since this UID will end immediately; the RequestSender is on
        // different.
        return false;
      }
      if (node.storage().hasKey(key, false, false)) return true; // Don't want it
      if (current != null && current.isTransferCoalesced()) {
        if (LOG.isDebugEnabled())
          LOG.debug("Do not cancel transfer; other consumers want data on {}", RequestHandler.this);
        // We do need to reassign the tag because the RS has the same UID.
        node.routing().tracker().reassignTagToSelf(tag);
        return false;
      }
      if (node.routing().failureTable().peersWantKey(key, source)) {
        // This may indicate downstream is having trouble communicating with us.
        LOG.error(
            "Upstream transfer to {} failed after downstream success. Reassign tag to self for peer"
                + " demand on {}",
            source.shortToString(),
            RequestHandler.this);
        node.routing().tracker().reassignTagToSelf(tag);
        return false; // Want it
      }
      if (node.services().clientCore() != null && node.services().clientCore().wantKey(key)) {
        // See extensive security considerations in original code comments.
        LOG.error(
            "Upstream transfer to {} failed after downstream success. Reassign tag to self for"
                + " local demand on {}",
            source.shortToString(),
            RequestHandler.this);
        node.routing().tracker().reassignTagToSelf(tag);
        return false; // Want it
      }
      return true;
    }
  }

  /**
   * Completion callback for CHK transfer. Extracted to reduce complexity in {@link
   * #onCHKTransferBegins()}.
   */
  private final class CHKBlockTransmitterCompletion implements BlockTransmitterCompletion {
    /**
     * Mark CHK block transfer completion and trigger follow-up processing on the handler thread.
     *
     * @param success {@code true} if the downstream transfer succeeded.
     */
    @Override
    public void blockTransferFinished(boolean success) {
      synchronized (RequestHandler.this) {
        if (transferCompleted) {
          LOG.warn("Transfer already completed for {}", this);
          return;
        }
        transferCompleted = true;
        transferSuccess = success;
        if (!waitingForTransferSuccess) return;
      }
      transferFinished(success);
    }
  }

  final Node node;
  final long uid;
  private final short htl;
  final PeerNode source;
  private final boolean needsPubKey;
  final Key key;
  private boolean finalTransferFailed = false;

  /** Active {@link RequestSender} for this UID, or {@code null} if not yet created. */
  private RequestSender rs;

  private int status = RequestSender.NOT_FINISHED;
  private boolean appliedByteCounts = false;
  private boolean sentRejectedOverload = false;
  private long searchStartTime;
  private long responseDeadline;
  private BlockTransmitter bt;
  private final RequestTag tag;
  private final boolean realTimeFlag;
  KeyBlock passedInKeyBlock;

  @Override
  public String toString() {
    return super.toString() + " for " + uid;
  }

  /**
   * Creates a handler for a single incoming request.
   *
   * @param context request metadata including routing and accounting state
   * @param passedInKeyBlock if non-null, the block already fetched from the datastore to be
   *     returned locally; We ALWAYS look up in the datastore before starting a request. SECURITY:
   *     Do not pass messages into handler constructors. See the note at the top of NodeDispatcher.
   * @param needsPubKey whether an SSK response should include the publisher's public key
   */
  public RequestHandler(
      RequestHandlerContext context, KeyBlock passedInKeyBlock, boolean needsPubKey) {
    node = context.node();
    uid = context.uid();
    this.realTimeFlag = context.realTimeFlag();
    this.source = context.source();
    this.htl = context.htl();
    this.tag = context.tag();
    this.key = context.key();
    this.passedInKeyBlock = passedInKeyBlock;
    this.needsPubKey = needsPubKey;
  }

  /**
   * Entry point executed on the handler thread.
   *
   * <p>Initializes processing and hands off to {@link #realRun()} while capturing disconnection and
   * unexpected failures. Any uncaught exception is reported to the tag and ends the handler.
   */
  @Override
  @SuppressWarnings("java:S1181")
  public void run() {
    try {
      realRun();
      // The last thing that realRun() does is register as a request-sender listener, so any
      // exception here is the end.
    } catch (NotConnectedException e) {
      LOG.info(
          "event=handler_wait_setup_disconnected Request source disconnected; handler wait setup"
              + " aborted");
      tag.handlerThrew(e);
    } catch (Throwable t) {
      LOG.error("Caught throwable {}", t, t);
      tag.handlerThrew(t);
    }
  }

  private void applyByteCounts() {
    synchronized (this) {
      if (disconnected) {
        LOG.info("Skip byte accounting; request source disconnected during receive");
        return;
      }
      if (appliedByteCounts) {
        return;
      }
      appliedByteCounts = true;
      if (!(!finalTransferFailed
          && rs != null
          && status != RequestSender.TIMED_OUT
          && status != RequestSender.GENERATED_REJECTED_OVERLOAD
          && status != RequestSender.INTERNAL_ERROR)) return;
    }
    int sent;
    int rcvd;
    synchronized (bytesSync) {
      sent = sentBytes;
      rcvd = receivedBytes;
    }
    sent += rs.getTotalSentBytes();
    rcvd += rs.getTotalReceivedBytes();
    if (key instanceof NodeSSK) {
      if (LOG.isDebugEnabled())
        LOG.debug("Remote SSK fetch bytes sent/received: {}/{} (status={})", sent, rcvd, status);
      node.network().stats().remoteSskFetchBytesSentAverage.report(sent);
      node.network().stats().remoteSskFetchBytesReceivedAverage.report(rcvd);
      if (status == RequestSender.SUCCESS) {
        // Can report both parts, because we had both a Handler and a Sender
        node.network().stats().successfulSskFetchBytesSentAverage.report(sent);
        node.network().stats().successfulSskFetchBytesReceivedAverage.report(rcvd);
      }
    } else {
      if (LOG.isDebugEnabled())
        LOG.debug("Remote CHK fetch bytes sent/received: {}/{} (status={})", sent, rcvd, status);
      node.network().stats().remoteChkFetchBytesSentAverage.report(sent);
      node.network().stats().remoteChkFetchBytesReceivedAverage.report(rcvd);
      if (status == RequestSender.SUCCESS) {
        // Can report both parts, because we had both a Handler and a Sender
        node.network().stats().successfulChkFetchBytesSentAverage.report(sent);
        node.network().stats().successfulChkFetchBytesReceivedAverage.report(rcvd);
      }
    }
  }

  private void realRun() throws NotConnectedException {
    if (LOG.isDebugEnabled()) LOG.debug("Handle request uid={}", uid);

    Message accepted = DMT.createFNPAccepted(uid);
    source.transport().sendAsync(accepted, null, this);

    Object o;
    if (passedInKeyBlock != null) {
      tag.setServedFromDatastore();
      returnLocalData(passedInKeyBlock);
      passedInKeyBlock = null; // For GC
      return;
    } else
      o =
          node.routing()
              .makeRequestSender(
                  key,
                  htl,
                  uid,
                  tag,
                  source,
                  NodeRoutingSubsystem.RequestSenderOptions.of(
                      false, // localOnly
                      true, // ignoreStore
                      false, // offersOnly
                      false, // canReadClientCache
                      false, // canWriteClientCache
                      realTimeFlag));

    if (o == null) { // ran out of htl?
      Message dnf = DMT.createFNPDataNotFound(uid);
      status = RequestSender.DATA_NOT_FOUND; // for byte logging
      node.routing()
          .failureTable()
          .onFinalFailure(
              key,
              null,
              htl,
              htl,
              FailureTable.RECENTLY_FAILED_TIME,
              FailureTable.REJECT_TIME,
              source);
      sendTerminal(dnf);
      node.network()
          .stats()
          .remoteRequest(
              key instanceof NodeSSK,
              false,
              false,
              htl,
              key.toNormalizedDouble(),
              realTimeFlag,
              false);
    } else {
      long queueTime = source.getProbableSendQueueTime();
      synchronized (this) {
        rs = (RequestSender) o;
        // If we cannot respond before this time, the 'source' node has already fatally timed out
        // (and we need not return packets which will not be claimed)
        searchStartTime = System.currentTimeMillis();
        responseDeadline = searchStartTime + rs.fetchTimeout() + queueTime;
      }
      rs.addListener(this);
    }
  }

  /**
   * Propagate a local overload decision upstream.
   *
   * <p>Sends a non-terminal {@code FNPRejectedOverload} to the request source when not already
   * sent, signaling backpressure. If the source disconnects, the event is logged and ignored.
   */
  @Override
  public void onReceivedRejectOverload() {
    try {
      if (!sentRejectedOverload) {
        if (LOG.isDebugEnabled()) LOG.debug("Propagate RejectedOverload on {}", this);
        // Forward RejectedOverload
        // Note: This message is only discernible from the terminal messages by the IS_LOCAL flag
        // being false. (!IS_LOCAL)->!Terminal
        Message msg = DMT.createFNPRejectedOverload(uid, false);
        source.transport().sendAsync(msg, null, this);
        // If the status changes (e.g., to SUCCESS), there is little need to send yet another reject
        // overload.
        sentRejectedOverload = true;
      }
    } catch (NotConnectedException _) {
      LOG.info(
          "event=reject_overload_forward_disconnected Request source disconnected;"
              + " rejected-overload not forwarded");
    }
  }

  private boolean disconnected = false;

  /**
   * Start a CHK transfer to the upstream peer and set up accounting.
   *
   * <p>Sends {@code FNPCHKDataFound} headers, streams the block via {@link BlockTransmitter}, and
   * notifies the tag when the transfer begins. On disconnection, marks the handler as disconnected
   * and logs the event.
   */
  @Override
  public void onCHKTransferBegins() {
    if (tag.hasSourceReallyRestarted()) {
      LOG.info(
          "event=chk_transfer_skip_terminal_restart Request source restarted; skip terminal reply"
              + " before CHK transfer");
      applyByteCounts();
      unregisterRequestHandlerWithNode();
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Start CHK transfer for {}", this);
    try {
      // Is a CHK.
      Message df = DMT.createFNPCHKDataFound(uid, rs.getHeaders());
      source.transport().sendAsync(df, null, this);

      PartiallyReceivedBlock prb = rs.getPRB();
      bt =
          new BlockTransmitter(
              new BlockTransferContext(
                  node.network().usm(),
                  node.network().ticker(),
                  source,
                  uid,
                  prb,
                  this,
                  realTimeFlag),
              new CHKReceiverAbortHandler(),
              new CHKBlockTransmitterCompletion(),
              node.network().stats());
      tag.handlerTransferBegins();
      bt.sendAsync();
    } catch (NotConnectedException _) {
      synchronized (this) {
        disconnected = true;
      }
      tag.handlerDisconnected();
      LOG.info(
          "event=chk_transfer_start_disconnected Request source disconnected; CHK transfer start"
              + " aborted");
    }
  }

  /** Has the transfer completed? */
  boolean transferCompleted;

  /** Did it succeed? */
  boolean transferSuccess;

  /** Are we waiting for the transfer to complete? */
  boolean waitingForTransferSuccess;

  /**
   * Complete processing after the CHK transfer finishes and a final status is available.
   *
   * <p>On success, schedules opennet finishing on a high-priority worker; on failure, records the
   * status for later accounting.
   *
   * @param success whether the block transfer succeeded
   */
  protected void transferFinished(boolean success) {
    if (LOG.isDebugEnabled()) LOG.debug("Transfer finished (success={})", success);
    if (success) {
      status = rs.getStatus();
      // Run off-thread because, on the onRequestSenderFinished path, RequestSender won't start to
      // wait for the noderef until we return!
      // Make waitForOpennetNoderef asynchronous (tracked)
      node.network()
          .executor()
          .execute(
              new PrioRunnable() {

                @Override
                public void run() {
                  // Successful CHK transfer, maybe path fold
                  finishOpennetChecked();
                }

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
                }
              });
    } else {
      finalTransferFailed = true;
      status = rs.getStatus();
      // for byte logging, since the block is the 'terminal' message.
      applyByteCounts();
      unregisterRequestHandlerWithNode();
    }
  }

  /**
   * Record that the request reached a terminal status and, if the transfer already finished, allow
   * immediate completion.
   *
   * @return {@code true} if the transfer is also finished and the caller should proceed to {@link
   *     #transferFinished(boolean)}
   */
  private synchronized boolean readyToFinishTransfer() {
    if (waitingForTransferSuccess) {
      LOG.error("readyToFinishTransfer called twice on {}", this);
      return false;
    }
    waitingForTransferSuccess = true;
    if (!transferCompleted) {
      if (LOG.isDebugEnabled()) LOG.debug("Wait for transfer to finish on {}", this);
      return false; // Wait
    }
    return true;
  }

  /**
   * Finalize processing when {@link RequestSender} reports completion.
   *
   * <p>Updates status, records metrics, handles late responses, and emits a terminal message
   * appropriate for the outcome. Disconnections are treated as terminal.
   */
  @Override
  public void onRequestSenderFinished(int status, boolean fromOfferedKey, RequestSender rs) {
    if (tag.hasSourceReallyRestarted()) {
      LOG.info(
          "event=terminal_skip_sender_restart Request source restarted; skip terminal reply after"
              + " sender finish");
      applyByteCounts();
      unregisterRequestHandlerWithNode();
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("onRequestSenderFinished status={} on {}", status, this);
    long now = System.currentTimeMillis();

    boolean tooLate;
    synchronized (this) {
      if (this.status == RequestSender.NOT_FINISHED) this.status = status;
      else {
        if (LOG.isDebugEnabled())
          LOG.debug("Ignore onRequestSenderFinished; status already {}", this.status);
        return;
      }
      tooLate = responseDeadline > 0 && now > responseDeadline;
    }

    node.network()
        .stats()
        .remoteRequest(
            key instanceof NodeSSK,
            status == RequestSender.SUCCESS,
            false,
            htl,
            key.toNormalizedDouble(),
            realTimeFlag,
            fromOfferedKey);

    if (tooLate) handleTooLate(rs, now);

    if (status == RequestSender.NOT_FINISHED)
      LOG.error("onRequestSenderFinished invoked but NOT_FINISHED status");

    try {
      processFinishedStatus(status, rs);
    } catch (NotConnectedException _) {
      LOG.info(
          "event=terminal_send_disconnected Request source disconnected while sending terminal"
              + " reply");
      applyByteCounts();
      unregisterRequestHandlerWithNode();
    }
  }

  private void handleTooLate(RequestSender rs, long now) {
    LOG.atDebug().log("Response arrived after deadline");
    // Offer the data if there is any.
    node.routing().failureTable().onFinalFailure(key, null, htl, htl, -1, -1, source);
    // A certain number of these are normal.
    LOG.atInfo()
        .setMessage("RequestSender responded after {} (status={}) routedLast={}")
        .addArgument(() -> TimeUtil.formatTime((now - searchStartTime), 2, true))
        .addArgument(() -> rs == null ? "null" : rs.getStatusString())
        .addArgument(
            () -> {
              PeerNode rl = (rs == null ? null : rs.routedLast());
              return rl == null ? "null" : rl.shortToString();
            })
        .log();
    // We need to send the RejectedOverload (or whatever) anyway, for a two-stage timeout.
    // Otherwise, the downstream node will assume it's our fault.
  }

  private void processFinishedStatus(int status, RequestSender rs) throws NotConnectedException {
    if (processStatusSimpleCases(status, rs)) return;
    if (processStatusSuccessOrFailures(status, rs)) return;
    // Treat as internal error
    Message reject = DMT.createFNPRejectedOverload(uid, true);
    sendTerminal(reject);
    throw new IllegalStateException("Unknown status code " + status);
  }

  @SuppressWarnings("StatementSwitchToExpressionSwitch")
  private boolean processStatusSimpleCases(int status, RequestSender rs) {
    switch (status) {
      case RequestSender.NOT_FINISHED, RequestSender.DATA_NOT_FOUND:
        {
          Message dnf = DMT.createFNPDataNotFound(uid);
          sendTerminal(dnf);
          return true;
        }
      case RequestSender.RECENTLY_FAILED:
        {
          Message rf = DMT.createFNPRecentlyFailed(uid, rs.getRecentlyFailedTimeLeft());
          sendTerminal(rf);
          return true;
        }
      case RequestSender.GENERATED_REJECTED_OVERLOAD,
      RequestSender.TIMED_OUT,
      RequestSender.INTERNAL_ERROR:
        {
          // Locally generated. Propagate back to the source who needs to reduce send rate
          // @bug: we may not want to translate fatal timeouts into non-fatal timeouts.
          Message reject = DMT.createFNPRejectedOverload(uid, true);
          sendTerminal(reject);
          return true;
        }
      case RequestSender.ROUTE_NOT_FOUND:
        {
          // Tell source
          Message rnf = DMT.createFNPRouteNotFound(uid, rs.getHTL());
          sendTerminal(rnf);
          return true;
        }
      default:
        return false;
    }
  }

  private boolean processStatusSuccessOrFailures(int status, RequestSender rs)
      throws NotConnectedException {
    return handleSuccess(status, rs)
        || handleVerifyFailureGroup(status)
        || handleTransferFailedGroup(status);
  }

  private boolean handleSuccess(int status, RequestSender rs) throws NotConnectedException {
    if (status != RequestSender.SUCCESS) return false;
    if (key instanceof NodeSSK) {
      sendSSK(rs.getHeaders(), rs.getSSKData(), rs.getSSKBlock().getKey().getPubKey());
    } else {
      maybeCompleteTransfer();
    }
    return true;
  }

  private boolean handleVerifyFailureGroup(int status) {
    if (!isVerifyFailure(status)) return false;
    if (key instanceof NodeCHK) {
      maybeCompleteTransfer();
    } else {
      Message reject = DMT.createFNPRejectedOverload(uid, true);
      sendTerminal(reject);
    }
    return true;
  }

  private boolean handleTransferFailedGroup(int status) {
    if (!isTransferFailure(status)) return false;
    if (key instanceof NodeCHK) {
      maybeCompleteTransfer();
    } else {
      LOG.error("Unexpected TRANSFER_FAILED on SSK", new Exception("error"));
    }
    return true;
  }

  private static boolean isVerifyFailure(int status) {
    return status == RequestSender.VERIFY_FAILURE
        || status == RequestSender.GET_OFFER_VERIFY_FAILURE;
  }

  private static boolean isTransferFailure(int status) {
    return status == RequestSender.TRANSFER_FAILED
        || status == RequestSender.GET_OFFER_TRANSFER_FAILED;
  }

  /**
   * After reaching a terminal status that might involve a transfer (success, transfer failure, or
   * verify failure), check for disconnection and confirm the transfer was started. If the transfer
   * is already completed, finish immediately; otherwise set a flag so completion happens when it
   * does.
   */
  private void maybeCompleteTransfer() {
    Message reject = null;
    boolean disconn = false;
    boolean xferFinished = false;
    boolean xferSuccess = false;
    synchronized (this) {
      if (disconnected) disconn = true;
      else if (bt == null) {
        // Bug! This is impossible!
        LOG.error("Status {} but no transfer started for {}", status, uid);
        // Obviously, this node is confused, send a terminal reject to make sure the requestor is
        // not
        // waiting forever.
        reject = DMT.createFNPRejectedOverload(uid, true);
      } else {
        xferFinished = readyToFinishTransfer();
        xferSuccess = transferSuccess;
      }
    }
    if (disconn) unregisterRequestHandlerWithNode();
    else if (reject != null) sendTerminal(reject);
    else if (xferFinished) transferFinished(xferSuccess);
  }

  private void sendSSK(byte[] headers, final byte[] data, DSAPublicKey pubKey)
      throws NotConnectedException {
    // SUCCESS requires that BOTH the pubkey AND the data/headers have been received.
    // The pubKey will have been set on the SSK key, and the SSKBlock will have been constructed.
    MultiMessageCallback mcb;
    mcb =
        new MultiMessageCallback() {
          @Override
          public void finish(boolean success) {
            // Reporting note: ideally record when the data message is acked for more accuracy.
            sentPayload(data.length);
            applyByteCounts();
            // Will call unlockHandler.
            // This is okay, it can be called twice safely, and it ensures that even if sent() is
            // not called it will still be unlocked.
            unregisterRequestHandlerWithNode();
          }

          @Override
          void sent(boolean success) {
            // As soon as the originator receives the messages, he can reuse the slot.
            // Unlocking on sent is a reasonable compromise between:
            // 1. Unlocking immediately avoids problems with the recipient reusing the slot when
            // he's received the data, therefore, us rejecting the request and getting a mandatory
            // backoff, and
            // 2. However, we do want SSK requests from the datastore to be counted towards the
            // total when accepting requests.
            // This is safe, however.
            // We have already done the request, so there is no outgoing request.
            // A node might be able to get a few more slots in flight by not acking the SSK
            // messages, but it would quickly stall.
            // Furthermore, we would start sending hard rejections when the sending queue gets past
            // a
            // certain point.
            // So it is neither beneficial for the node nor a viable DoS.
            // An alternative solution would be to wait until the pubkey and data have been acked
            // before unlocking and sending the headers, but this appears not to be necessary.
            tag.unlockHandler();
          }
        };
    Message headersMsg = DMT.createFNPSSKDataFoundHeaders(uid, headers, realTimeFlag);
    source.transport().sendAsync(headersMsg, mcb.make(), this);
    final Message dataMsg = DMT.createFNPSSKDataFoundData(uid, data, realTimeFlag);
    if (needsPubKey) {
      Message pk = DMT.createFNPSSKPubKey(uid, pubKey, realTimeFlag);
      source.transport().sendAsync(pk, mcb.make(), this);
    }
    source.transport().sendAsync(dataMsg, mcb.make(), this);
    mcb.arm();
  }

  static void sendSSK(
      byte[] headers,
      byte[] data,
      final PeerNode source,
      long uid,
      ByteCounter ctr,
      boolean realTimeFlag)
      throws NotConnectedException {
    // SUCCESS requires that BOTH the pubkey AND the data/headers have been received.
    // The pubKey will have been set on the SSK key, and the SSKBlock will have been constructed.
    WaitingMultiMessageCallback mcb = new WaitingMultiMessageCallback();
    Message headersMsg = DMT.createFNPSSKDataFoundHeaders(uid, headers, realTimeFlag);
    source.transport().sendAsync(headersMsg, mcb.make(), ctr);
    final Message dataMsg = DMT.createFNPSSKDataFoundData(uid, data, realTimeFlag);
    source.transport().sendAsync(dataMsg, mcb.make(), ctr);

    mcb.arm();
    mcb.waitFor();
    ctr.sentPayload(data.length);
  }

  /**
   * Return data from the datastore.
   *
   * @param block The block we found in the datastore.
   * @throws NotConnectedException If we lose the connected to the request source.
   */
  private void returnLocalData(KeyBlock block) throws NotConnectedException {
    if (key instanceof NodeSSK) {
      sendSSK(block.getRawHeaders(), block.getRawData(), ((SSKBlock) block).getPubKey());
      status = RequestSender.SUCCESS; // for byte logging
      // Assume local SSK sending will succeed?
      node.network()
          .stats()
          .remoteRequest(true, true, true, htl, key.toNormalizedDouble(), realTimeFlag, false);
    } else if (block instanceof CHKBlock) {
      Message df = DMT.createFNPCHKDataFound(uid, block.getRawHeaders());
      PartiallyReceivedBlock prb =
          new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, block.getRawData());
      BlockTransmitter localBt =
          new BlockTransmitter(
              new BlockTransferContext(
                  node.network().usm(),
                  node.network().ticker(),
                  source,
                  uid,
                  prb,
                  this,
                  realTimeFlag),
              BlockTransmitter.NEVER_CASCADE,
              success -> {
                if (success) {
                  // for byte logging
                  status = RequestSender.SUCCESS;
                  // We've fetched it from our datastore, so there won't be a downstream noderef.
                  // But we want to send at least an FNPOpennetCompletedAck, otherwise the request
                  // source
                  // may have to timeout waiting for one. That will be the terminal message.
                  finishOpennetNoRelay();
                } else {
                  // also for byte logging, since the block is the 'terminal' message.
                  applyByteCounts();
                  unregisterRequestHandlerWithNode();
                }
                node.network()
                    .stats()
                    .remoteRequest(
                        false, success, true, htl, key.toNormalizedDouble(), realTimeFlag, false);
              },
              node.network().stats());
      tag.handlerTransferBegins();
      source.transport().sendAsync(df, null, this);
      localBt.sendAsync();
    } else throw new IllegalStateException();
  }

  private void unregisterRequestHandlerWithNode() {
    RequestSender r;
    synchronized (this) {
      r = rs;
    }
    if (r != null) {
      PeerNode p = r.successFrom();
      if (p != null) tag.finishedWaitingForOpennet(p);
    }
    tag.unlockHandler();
  }

  /**
   * Sends the 'final' packet of a request in such a way that the thread can be freed (made
   * non-runnable/exit) and the byte counter will still be accurate.
   */
  private void sendTerminal(Message msg) {
    if (LOG.isDebugEnabled()) LOG.debug("Send terminal message {}", msg);
    if (sendTerminalCalled)
      throw new IllegalStateException("sendTerminal should only be called once");
    else sendTerminalCalled = true;

    // Unlock the handler immediately.
    // Otherwise, the request sender will think the slot is free as soon as it
    // receives it, but we won't, so we may reject his requests and get a mandatory backoff.
    tag.unlockHandler();
    try {
      source.transport().sendAsync(msg, new TerminalMessageByteCountCollector(), this);
    } catch (NotConnectedException _) {
      // Will have called the callback, so the caller doesn't need to worry about it.
    }
  }

  boolean sendTerminalCalled = false;

  @Override
  public boolean isHighHtl() {
    return this.htl >= (node.maxHTL() - 1);
  }

  /** Note well! These functions are not executed on the RequestHandler thread. */
  private class TerminalMessageByteCountCollector implements AsyncMessageCallback {
    private static final Logger LOG =
        LoggerFactory.getLogger(TerminalMessageByteCountCollector.class);

    private boolean completed = false;

    @Override
    public void acknowledged() {
      if (LOG.isDebugEnabled()) LOG.debug("Terminal message acknowledged: {}", RequestHandler.this);
      // terminalMessage ack'd by remote peer
      complete();
    }

    @Override
    public void disconnected() {
      if (LOG.isDebugEnabled())
        LOG.debug("Peer disconnected before terminal message was sent for {}", RequestHandler.this);
      complete();
    }

    @Override
    public void fatalError() {
      LOG.error("Error sending terminal message for {}", RequestHandler.this);
      complete();
    }

    @Override
    public void sent() {
      if (LOG.isDebugEnabled()) LOG.debug("Terminal message sent: {}", RequestHandler.this);
      complete();
    }

    private void complete() {
      synchronized (this) {
        if (completed) return;
        completed = true;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Complete terminal flow for {}", RequestHandler.this);
      // For byte counting, this relies on the fact that the callback is executed once.
      applyByteCounts();
      unregisterRequestHandlerWithNode();
    }
  }

  /**
   * Either send an ack indicating we've finished and aren't interested in opennet, or wait for a
   * noderef and relay it along with the response. If no relay happens, send our own noderef, wait
   * for a response, and add it.
   *
   * <p>One way or another this method must call applyByteCounts; unregisterRequestHandlerWithNode.
   * This happens asynchronously via ackOpennet() if we are unable to send a noderef. It happens
   * explicitly otherwise.
   */
  private void finishOpennetChecked() {
    OpennetManager om = node.network().opennet();
    if (om != null && (node.passOpennetRefsThroughDarknet() || source.isOpennet())) {
      finishOpennetInner(om);
    } else {
      ackOpennet();
    }
  }

  /**
   * There is no noderef to pass downstream. If we want a connection, send our noderef and wait for
   * a reply, otherwise send an ack.
   */
  private void finishOpennetNoRelay() {
    OpennetManager om = node.network().opennet();

    if (om != null && (source.isOpennet() || node.passOpennetRefsThroughDarknet())) {
      finishOpennetNoRelayInner(om);
    } else {
      ackOpennet();
    }
  }

  /**
   * Acknowledge the opennet path folding attempt without sending a reference. Once the sending
   * completes (asynchronously), unlock everything.
   */
  private void ackOpennet() {
    Message msg = DMT.createFNPOpennetCompletedAck(uid);
    sendTerminal(msg);
  }

  /**
   * @param om Completion: Will either call ackOpennet(), sending an ack downstream and then
   *     unlocking after this has been sent (asynchronously), or will unlock itself if we sent a
   *     noderef (after we have handled the incoming noderef / ack / timeout).
   */
  private void finishOpennetInner(OpennetManager om) {
    if (LOG.isDebugEnabled()) LOG.debug("Finish opennet for {}", this);
    byte[] noderef;
    try {
      noderef = rs.waitForOpennetNoderef();
    } catch (WaitedTooLongForOpennetNoderefException _) {
      // Send the timeout info upstream (towards higher HTL)
      sendTerminal(DMT.createFNPOpennetCompletedTimeout(uid));
      return;
    }
    if (noderef == null || noderef.length == 0) {
      if (LOG.isDebugEnabled()) LOG.debug("Do not relay; no noderef for {}", this);
      finishOpennetNoRelayInner(om);
      return;
    }
    if (node.bootstrap().random().nextInt(OpennetManager.RESET_PATH_FOLDING_PROB) == 0) {

      // Check whether it is actually the noderef of the peer.
      // If so, we need to relay it anyway.

      SimpleFieldSet ref = OpennetNoderefValidator.validateNoderef(noderef, source, false);

      if (ref != null && !om.alreadyHaveOpennetNode(ref)) {
        if (LOG.isDebugEnabled()) LOG.debug("Reset path folding for {}", this);
        // Reset path folding.
        // We need to tell the source of the noderef that we are not going to use it.
        // RequestSender didn't because it expected us to use the ref.
        rs.ackOpennet(rs.successFrom());
        finishOpennetNoRelayInner(om);
        return;
      }
    }

    finishOpennetRelay(noderef, om);
  }

  /**
   * Send our noderef to the request source, wait for a reply, if we get one add it. Called when
   * either the request wasn't routed, or the node it was routed to didn't return a noderef.
   *
   * <p>Completion: Will ack downstream if necessary (if we didn't send a noderef), and will in any
   * case call applyByteCounts(); unregisterRequestHandlerWithNode() asynchronously, either after
   * receiving the noderef, or after sending the ack.
   *
   * <p>In all cases we do not interact with dataSource. The caller must have already sent an ack to
   * dataSource if necessary (but in most cases dataSource has timed out or something similar has
   * happened).
   */
  private void finishOpennetNoRelayInner(final OpennetManager om) {
    if (LOG.isDebugEnabled()) LOG.debug("Finish opennet: send own reference for {}", this);
    if (!om.wantPeer(null, false, false, false, ConnectionType.PATH_FOLDING)) {
      ackOpennet();
      return; // Don't want a reference
    }

    try {
      om.sendOpennetRef(false, uid, source, om.getCrypto().myCompressedFullRef(), this);
    } catch (NotConnectedException _) {
      LOG.info("Cannot send opennet ref; node disconnected for {}", this);
      // Oh well...
      applyByteCounts();
      unregisterRequestHandlerWithNode();
      return;
    }

    // Wait for response

    OpennetNoderefWaiter.waitForOpennetNoderef(
        true,
        source,
        uid,
        this,
        new NoderefCallback() {

          // We have already sent ours, so we don't need to worry about timeouts.

          @Override
          public void gotNoderef(byte[] noderef) {
            // We have sent a noderef. It is not appropriate for the caller to call ackOpennet():
            // in all cases he should unlock.
            if (LOG.isDebugEnabled()) LOG.debug("Got noderef for {}", RequestHandler.this);
            finishOpennetNoRelayInner(noderef);
            applyByteCounts();
            unregisterRequestHandlerWithNode();
          }

          @Override
          public void timedOut() {
            if (LOG.isDebugEnabled())
              LOG.debug("Timed out waiting for noderef from {} on {}", source, RequestHandler.this);
            gotNoderef(null);
          }

          @Override
          public void acked(boolean timedOutMessage) {
            if (LOG.isDebugEnabled())
              LOG.debug("Noderef ack from {} on {}", source, RequestHandler.this);
            gotNoderef(null);
          }
        },
        node);
  }

  private void finishOpennetNoRelayInner(byte[] noderef) {
    if (noderef == null || noderef.length == 0) return;

    SimpleFieldSet ref = OpennetNoderefValidator.validateNoderef(noderef, source, false);

    if (ref == null) return;

    if (node.network().addNewOpennetNode(ref, ConnectionType.PATH_FOLDING) == null) {
      LOG.info("Asked for opennet ref but did not want it for {} :\n{}", this, ref);
    } else {
      LOG.info("Added opennet noderef for {}", this);
    }
  }

  /**
   * Called when the node we routed the request to return a valid noderef, and we don't want it. So
   * we relay it downstream to somebody who does, and wait to relay the response back upstream.
   *
   * <p>Completion: Will call applyByteCounts(); unregisterRequestHandlerWithNode() asynchronously
   * after this method returns.
   *
   * @param noderef the opennet node reference bytes to be relayed to the requester
   * @param om the {@link OpennetManager} used to validate and send opennet references
   */
  private void finishOpennetRelay(byte[] noderef, final OpennetManager om) {
    final PeerNode dataSource = rs.successFrom();
    if (LOG.isDebugEnabled())
      LOG.debug("Finish opennet: relay reference from {} on {}", dataSource, this);
    // Send it back to the handler, then wait for the ConnectReply

    try {
      om.sendOpennetRef(false, uid, source, noderef, this);
    } catch (NotConnectedException _) {
      rs.ackOpennet(dataSource);
      // Lost contact with the request source, nothing we can do
      applyByteCounts();
      unregisterRequestHandlerWithNode();
      return;
    }

    // Now wait for a reply from the request source.

    // We do not need to worry about timeouts here, because we have already sent our noderef.

    // We have sent a noderef. Therefore, we must unlock, not ack.

    OpennetNoderefWaiter.waitForOpennetNoderef(
        true, source, uid, this, new FinishOpennetRelayCallback(om, dataSource), node);
  }

  private final class FinishOpennetRelayCallback implements NoderefCallback {
    private final OpennetManager om;
    private final PeerNode dataSource;

    FinishOpennetRelayCallback(OpennetManager om, PeerNode dataSource) {
      this.om = om;
      this.dataSource = dataSource;
    }

    @Override
    public void gotNoderef(byte[] newNoderef) {
      if (newNoderef == null) {
        // Null reply: acknowledge upstream but still finish bookkeeping below.
        rs.ackOpennet(dataSource);
      } else {
        // Send it forward to the data source if it is valid.
        if (OpennetNoderefValidator.validateNoderef(newNoderef, source, false) != null) {
          try {
            if (LOG.isDebugEnabled())
              LOG.debug("Relay noderef from source to data source for {}", RequestHandler.this);
            om.sendOpennetRef(
                true,
                uid,
                dataSource,
                newNoderef,
                RequestHandler.this,
                _ -> {
                  // As soon as the originator receives the three blocks, he can reuse the slot.
                  tag.finishedWaitingForOpennet(dataSource);
                  tag.unlockHandler();
                  applyByteCounts();
                  // Note that sendOpennetRef() does not wait for an acknowledgement or even for
                  // the blocks to have been sent! So this will be called well after gotNoderef()
                  // exits.
                });
          } catch (NotConnectedException _) {
            // How sad
          }
        }
      }
      tag.finishedWaitingForOpennet(dataSource);
      tag.unlockHandler();
      applyByteCounts();
    }

    @Override
    public void timedOut() {
      tag.unlockHandler();
      try {
        dataSource
            .transport()
            .sendAsync(
                DMT.createFNPOpennetCompletedTimeout(uid),
                rs.finishOpennetOnAck(dataSource),
                RequestHandler.this);
      } catch (NotConnectedException _) {
        // Ignore
      }
      rs.ackOpennet(rs.successFrom());
      applyByteCounts();
    }

    @Override
    public void acked(boolean timedOutMessage) {
      tag.unlockHandler(); // will remove transfer
      rs.ackOpennet(dataSource);
      applyByteCounts();
    }
  }

  private int sentBytes;
  private int receivedBytes;
  private final Object bytesSync = new Object();

  /**
   * Record bytes sent to the peer for this request.
   *
   * @param x number of bytes sent
   */
  @Override
  public void sentBytes(int x) {
    synchronized (bytesSync) {
      sentBytes += x;
    }
    node.network().stats().requestSentBytes(key instanceof NodeSSK, x);
    if (LOG.isDebugEnabled()) LOG.debug("sentBytes={} on {}", x, this);
  }

  /**
   * Record bytes received from the peer for this request.
   *
   * @param x number of bytes received
   */
  @Override
  public void receivedBytes(int x) {
    synchronized (bytesSync) {
      receivedBytes += x;
    }
    node.network().stats().requestReceivedBytes(key instanceof NodeSSK, x);
  }

  /**
   * Record payload bytes and adjust per-request counters.
   *
   * @param x payload byte count
   */
  @Override
  public void sentPayload(int x) {
    /*
     * Do not add payload to sentBytes. sentBytes() is called with the actual sent bytes,
     * and we do not deduct the alreadyReportedBytes, which are only used for accounting
     * for the bandwidth throttle.
     */
    node.sentPayload(x);
    node.network().stats().requestSentBytes(key instanceof NodeSSK, -x);
    if (LOG.isDebugEnabled()) LOG.debug("sentPayload={} on {}", x, this);
  }

  /**
   * Priority used by {@link NativeThread} when scheduling this handler.
   *
   * @return The high priority scheduling value
   */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This event is not expected for this handler.
   */
  @Override
  public void onNotStarted(boolean internalError) {
    // Impossible
    assert false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This event is not expected for this handler.
   */
  @Override
  public void onDataFoundLocally() {
    // Can't happen.
    assert false;
  }
}
