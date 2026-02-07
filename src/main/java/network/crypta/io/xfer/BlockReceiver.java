package network.crypta.io.xfer;

import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.io.comm.SlowAsyncMessageFilterCallback;
import network.crypta.node.SyncSendWaitedTooLongException;
import network.crypta.support.BitArray;
import network.crypta.support.Buffer;
import network.crypta.support.Ticker;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Receives a block from a peer by assembling incoming packets and coordinating acknowledgements.
 *
 * <p>The receiver is allowed to cancel the incoming transfer. Depending on the caller, this may or
 * may not cancel the underlying {@link PartiallyReceivedBlock} (PRB) and propagate back to the
 * originator. Allowing receiver‑side cancellation introduces a potential, but limited, DoS vector:
 * a node can start a request and then cancel it, wasting some upstream bandwidth. This behavior is
 * detectable. If receiver cancels did not propagate, a more serious DoS would be possible; if
 * receiver cancels were disallowed, turtles and transfer timeouts would have to be tightened
 * considerably.
 *
 * <p>In particular, an attacker might connect, saturate the link with transfers, then disconnect to
 * avoid receiving the data, reconnect later with a new identity (on opennet), and rely on the
 * transfers having been canceled. Downstream bandwidth is comparatively inexpensive for small
 * attackers, so this can act as a multiplier if not mitigated.
 *
 * <p>Keeping receiver cancels does increase code complexity (e.g., around {@code
 * ReceiverAbortHandler}), but improves reliability of transfers when applied carefully with
 * two‑stage timeouts and explicit acknowledgment of failure.
 *
 * @author ian
 */
public class BlockReceiver implements AsyncMessageFilterCallback {
  private static final Logger LOG = LoggerFactory.getLogger(BlockReceiver.class);
  private static final String LOG_FROM = " from ";
  private static final String LOG_ABORTED_QUESTION = "Aborted?";

  //

  public interface BlockReceiverTimeoutHandler {

    /**
     * Called after the first inactivity timeout for this transfer.
     *
     * <p>After this returns, the receiver cancels the PRB and waits for either an explicit cancel
     * from the sender (a {@code sendAborted} message) or a second, fatal timeout. If the upstream
     * path is the cause, only the first timeout is typically observed; if the sender is at fault,
     * the second timeout is likely to occur as well.
     */
    void onFirstTimeout();

    /**
     * Called if the sender does not acknowledge cancellation within {@link
     * #ACK_TRANSFER_FAILED_TIMEOUT} and the second timeout elapses.
     *
     * <p>This likely indicates a fault at the sender. Implementations may take corrective action
     * because the remote may still believe the transfer is active, which would skew load accounting
     * on both sides.
     *
     * @param source the peer that failed to acknowledge cancellation
     */
    void onFatalTimeout(PeerContext source);
  }

  /*
   * Must be < 60s because BlockTransmitter times out after 60s without hearing from us. Without
   * contact from the transmitter, we periodically send missing‑packet reports to recover.
   */
  public final long receiptTimeout;
  public static final long RECEIPT_TIMEOUT_REALTIME = SECONDS.toMillis(10);
  public static final long RECEIPT_TIMEOUT_BULK = SECONDS.toMillis(30);
  // Should ideally be proportional to the measured round‑trip time, not a fixed constant.
  public final long maxRoundTripTime;
  public static final long CLEANUP_TIMEOUT = SECONDS.toMillis(5);

  /**
   * Timeout for acknowledging a failed transfer (milliseconds).
   *
   * <p>{@code sendAborted} is not exchanged at realtime/bulk priority. Two‑stage timeout flows use
   * roughly 60 seconds by convention.
   */
  public static final long ACK_TRANSFER_FAILED_TIMEOUT = SECONDS.toMillis(60);

  private final PartiallyReceivedBlock prb;
  PeerContext sender;
  long uid;
  MessageCore usm;
  ByteCounter ctr;
  Ticker ticker;
  boolean sentAborted;
  private MessageFilter discardFilter;
  private long discardEndTime;
  private boolean senderAborted;
  private final boolean realTime;

  private final BlockReceiverTimeoutHandler timeoutHandler;
  private final boolean completeAfterAckedAllReceived;

  /**
   * Creates a receiver for one block transfer.
   *
   * @param transferContext shared transfer context (message core, peer, uid, PRB, accounting, and
   *     timing settings)
   * @param timeoutHandler callback invoked on first and fatal timeouts; may be {@code null}
   * @param completeAfterAckedAllReceived if true, complete only after the sender acknowledges
   *     {@code allReceived}; if false, complete as soon as all data is present locally. Handlers
   *     typically prefer early completion (free the slot); senders prefer late completion to avoid
   *     reusing a slot before the handler finishes.
   */
  public BlockReceiver(
      BlockTransferContext transferContext,
      BlockReceiverTimeoutHandler timeoutHandler,
      boolean completeAfterAckedAllReceived) {
    BlockReceiverTimeoutHandler nullTimeoutHandler =
        new BlockReceiverTimeoutHandler() {

          @Override
          public void onFirstTimeout() {
            // Default: no action.
          }

          @Override
          public void onFatalTimeout(PeerContext source) {
            // Default: no action.
          }
        };
    this.timeoutHandler = timeoutHandler == null ? nullTimeoutHandler : timeoutHandler;
    this.sender = transferContext.peer();
    this.prb = transferContext.block();
    this.uid = transferContext.uid();
    this.usm = transferContext.messageCore();
    this.ctr = transferContext.byteCounter();
    this.ticker = transferContext.ticker();
    this.realTime = transferContext.realTime();
    this.completeAfterAckedAllReceived = completeAfterAckedAllReceived;
    receiptTimeout = this.realTime ? RECEIPT_TIMEOUT_REALTIME : RECEIPT_TIMEOUT_BULK;
    maxRoundTripTime = receiptTimeout;
  }

  private void sendAborted(int reason, String desc) throws NotConnectedException {
    synchronized (this) {
      if (sentAborted) return;
      sentAborted = true;
    }
    usm.send(sender, DMT.createSendAborted(uid, reason, desc), ctr);
  }

  public interface BlockReceiverCompletion {

    /**
     * Invoked when the complete block has been received and assembled.
     *
     * @param buf full block bytes; never {@code null}
     */
    void blockReceived(byte[] buf);

    /**
     * Invoked when the block transfer fails.
     *
     * @param e describes the failure reason
     */
    void blockReceiveFailed(RetrievalException e);
  }

  private BlockReceiverCompletion callback;

  private long startTime;

  // If false, do not check for duplicate packets from the sender.
  // Can be disabled when the PRB is already partially received at the start. Dupe checks prevent
  // malicious or broken nodes from trickling forever by resending the same packets.
  static final boolean CHECK_DUPES = true;

  private boolean gotAllSent;

  private final AsyncMessageFilterCallback notificationWaiter =
      new SlowAsyncMessageFilterCallback() {

        @Override
        public void onMatched(Message m1) {
          if (LOG.isDebugEnabled()) LOG.debug("Received {}", m1);
          if (isSendAborted(m1)) {
            handleSendAborted(m1);
            return;
          }

          boolean truncateTimeout = false;
          if (isPacketTransmit(m1)) {
            truncateTimeout = handlePacketTransmit(m1);
            synchronized (BlockReceiver.this) {
              if (completed) return;
            }
          } else if (isAllSent(m1)) {
            truncateTimeout = handleAllSent();
            synchronized (BlockReceiver.this) {
              if (completed) return;
            }
          }

          if (finalizeIfAllReceived()) return;

          try {
            // Add the filter even with timeout <= 0 to drain any messages already buffered
            // before the timeout fires.
            waitNotification(truncateTimeout);
          } catch (DisconnectedException _) {
            onDisconnect(null);
          }
        }

        private boolean isSendAborted(Message m) {
          return m != null && m.getSpec().equals(DMT.sendAborted);
        }

        private boolean isPacketTransmit(Message m) {
          return m != null && m.getSpec().equals(DMT.packetTransmit);
        }

        private boolean isAllSent(Message m) {
          return m != null && m.getSpec().equals(DMT.allSent);
        }

        private void handleSendAborted(Message m) {
          String desc = m.getString(DMT.DESCRIPTION);
          if (!desc.contains("Upstream")) desc = "Upstream transmit error: " + desc;
          prb.abort(m.getInt(DMT.REASON), desc, false);
          synchronized (BlockReceiver.this) {
            senderAborted = true;
          }
          complete(m.getInt(DMT.REASON), desc);
        }

        private boolean handlePacketTransmit(Message m) {
          int packetNo = m.getInt(DMT.PACKET_NO);
          BitArray sent = (BitArray) m.getObject(DMT.SENT);
          Buffer data = (Buffer) m.getObject(DMT.DATA);
          try {
            synchronized (BlockReceiver.this) {
              if (completed) return false;
            }
            if (CHECK_DUPES && prb.isReceived(packetNo)) {
              LOG.error(
                  "Already received the packet - DoS??? on {} uid {}" + LOG_FROM + "{}",
                  this,
                  uid,
                  sender);
              return true; // truncate timeout, don't extend
            }

            prb.addPacket(packetNo, data);
            if (LOG.isDebugEnabled()) logPacketInterval();
            if (LOG.isDebugEnabled()) logMissingSentButNotReceived(sent);
            return false;
          } catch (AbortedException e) {
            LOG.error("Receiver aborted while handling packet transmit: {}", e, e);
            complete(RetrievalException.UNKNOWN, LOG_ABORTED_QUESTION);
            return false;
          }
        }

        private boolean handleAllSent() {
          synchronized (BlockReceiver.this) {
            boolean wasSeen = gotAllSent;
            gotAllSent = true;
            return wasSeen; // truncate when duplicate
          }
        }

        private boolean finalizeIfAllReceived() {
          try {
            if (!prb.allReceived()) return false;
            Message m = DMT.createAllReceived(uid);
            sendAllReceived(m);
            discardEndTime = System.currentTimeMillis() + CLEANUP_TIMEOUT;
            discardFilter = relevantMessages(CLEANUP_TIMEOUT);
            maybeResetDiscardFilter();
            long transferTime = System.currentTimeMillis() - startTime;
            if (LOG.isDebugEnabled()) {
              avgTimeTaken.report(transferTime);
              LOG.debug(
                  "Block transfer took {}ms - average is {}",
                  transferTime,
                  avgTimeTaken.currentValue());
            }
            completeBytes(prb.getBlock());
            return true;
          } catch (AbortedException e) {
            LOG.error("Receiver aborted while finalizing block receipt: {}", e, e);
            complete(RetrievalException.UNKNOWN, LOG_ABORTED_QUESTION);
            return true;
          }
        }

        private void logPacketInterval() {
          synchronized (BlockReceiver.this) {
            long interval = System.currentTimeMillis() - timeStartedWaiting;
            if (LOG.isDebugEnabled()) {
              LOG.debug(
                  "Packet interval: {} = {}" + LOG_FROM + "{}",
                  interval,
                  TimeUtil.formatTime(interval, 2, true),
                  sender);
            }
          }
        }

        private void logMissingSentButNotReceived(BitArray sent) throws AbortedException {
          int missing = 0;
          for (int x = 0; x < sent.getSize(); x++) {
            if (sent.bitAt(x) && !prb.isReceived(x)) missing++;
          }
          if (missing != 0)
            LOG.debug(
                "Packets which the sender says it has sent but we have not received: {}", missing);
        }

        @Override
        public boolean shouldTimeout() {
          return completed;
        }

        @Override
        public void onTimeout() {
          synchronized (this) {
            if (completed) return;
          }
          try {
            if (prb.allReceived()) return;
            prb.abort(
                RetrievalException.SENDER_DIED, "Sender unresponsive to resend requests", false);
            complete(RetrievalException.SENDER_DIED, "Sender unresponsive to resend requests");

            timeoutHandler.onFirstTimeout();
            // If upstream caused the problem, then the sender will itself timeout
            // and will tell us. So wait for a timeout.
            // It is important for load management that the two sides agree on the number of
            // transfers happening.
            // Therefore, we need to not complete until the other side has acknowledged that the
            // transfer has been canceled.
            MessageFilter mfSendAborted =
                MessageFilter.create()
                    .setTimeout(ACK_TRANSFER_FAILED_TIMEOUT)
                    .setType(DMT.sendAborted)
                    .setField(DMT.UID, uid)
                    .setSource(sender);
            addAckFailureFilter(mfSendAborted);

          } catch (AbortedException e) {
            // Unexpected: PRB aborted elsewhere during timeout processing.
            LOG.error("Receiver aborted during timeout handling: {}", e, e);
            complete(RetrievalException.UNKNOWN, LOG_ABORTED_QUESTION);
          }
        }

        @Override
        public void onDisconnect(PeerContext ctx) {
          complete(
              RetrievalException.SENDER_DISCONNECTED,
              RetrievalException.getErrString(RetrievalException.SENDER_DISCONNECTED));
        }

        @Override
        public void onRestarted(PeerContext ctx) {
          complete(
              RetrievalException.SENDER_DISCONNECTED,
              RetrievalException.getErrString(RetrievalException.SENDER_DISCONNECTED));
        }

        @Override
        public int getPriority() {
          return NativeThread.PriorityLevel.NORM_PRIORITY.value;
        }

        private void sendAllReceivedSync(Message m) throws NotConnectedException {
          try {
            sender.transport().sendSync(m, ctr, realTime);
          } catch (SyncSendWaitedTooLongException _) {
            // Synchronous send exceeded the wait threshold; proceed with completion regardless.
          }
        }

        private void sendAllReceived(Message m) {
          try {
            if (completeAfterAckedAllReceived) {
              sendAllReceivedSync(m);
            } else {
              usm.send(sender, m, ctr);
            }
          } catch (NotConnectedException _) {
            // Ignore: data already present locally.
            if (LOG.isDebugEnabled())
              LOG.debug("Got data but can't send allReceived to {} as is disconnected", sender);
          }
        }

        private void addAckFailureFilter(MessageFilter mfSendAborted) {
          try {
            usm.addAsyncFilter(
                mfSendAborted,
                new SlowAsyncMessageFilterCallback() {

                  @Override
                  public void onMatched(Message m) {
                    // Acknowledged by the other side.
                    if (LOG.isDebugEnabled()) LOG.debug("Transfer cancel acknowledged");
                  }

                  @Override
                  public boolean shouldTimeout() {
                    return false;
                  }

                  @Override
                  public void onTimeout() {
                    LOG.error(
                        "Other side did not acknowledge transfer failure on {}",
                        BlockReceiver.this);
                    timeoutHandler.onFatalTimeout(sender);
                  }

                  @Override
                  public void onDisconnect(PeerContext ctx) {
                    // No action needed.
                  }

                  @Override
                  public void onRestarted(PeerContext ctx) {
                    // No action needed.
                  }

                  @Override
                  public int getPriority() {
                    return NativeThread.PriorityLevel.NORM_PRIORITY.value;
                  }
                },
                ctr);
          } catch (DisconnectedException _) {
            // Ignore
          }
        }

        private void completeBytes(byte[] ret) {
          synchronized (BlockReceiver.this) {
            if (completed) {
              if (LOG.isDebugEnabled()) LOG.debug("Block receive already completed (success path)");
              return;
            }
            completed = true;
          }
          prb.removeListener(myListener);
          callback.blockReceived(ret);
          BlockReceiver.this.decRunningBlockReceives();
        }
      };

  private boolean completed;

  private void complete(int reason, String description) {
    synchronized (this) {
      if (completed) {
        if (LOG.isDebugEnabled()) LOG.debug("Block receive already completed (failure path)");
        return;
      }
      completed = true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Transfer failed: ({}) {} : {} on {}" + LOG_FROM + "{}",
          realTime ? "realtime" : "bulk",
          reason,
          description,
          uid,
          sender);
    prb.removeListener(myListener);
    byte[] block = prb.abort(reason, description, false);
    if (block == null) {
      // Expected behavior.
      // Send the abort whether we have received one or not.
      // If we are cancelling due to failing to turtle, we need to tell the sender
      // this otherwise he will keep sending, wasting a lot of bandwidth on packets
      // that we will ignore. If we are cancelling because the sender has told us
      // to, we need to acknowledge that.
      try {
        sendAborted(prb.abortReason, prb.abortDescription);
      } catch (NotConnectedException _) {
        // Ignore at this point.
      }
      callback.blockReceiveFailed(new RetrievalException(reason, description));
    } else {
      LOG.error(
          "Succeeded in complete({},{}) on {}", reason, description, this, new Exception("error"));
      callback.blockReceived(block);
    }
    decRunningBlockReceives();
  }

  // Moved into the anonymous callback below per SonarLint S3398

  private long timeStartedWaiting = -1;

  private void waitNotification(boolean truncateTimeout) throws DisconnectedException {
    long timeout;
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (truncateTimeout) {
        timeout = (int) Math.min(timeStartedWaiting + receiptTimeout - now, receiptTimeout);
      } else {
        timeStartedWaiting = now;
        timeout = receiptTimeout;
      }
    }
    usm.addAsyncFilter(relevantMessages(timeout), notificationWaiter, ctr);
  }

  private MessageFilter relevantMessages(long timeout) {
    MessageFilter mfPacketTransmit =
        MessageFilter.create()
            .setTimeout(timeout)
            .setType(DMT.packetTransmit)
            .setField(DMT.UID, uid)
            .setSource(sender);
    MessageFilter mfAllSent =
        MessageFilter.create()
            .setTimeout(timeout)
            .setType(DMT.allSent)
            .setField(DMT.UID, uid)
            .setSource(sender);
    MessageFilter mfSendAborted =
        MessageFilter.create()
            .setTimeout(timeout)
            .setType(DMT.sendAborted)
            .setField(DMT.UID, uid)
            .setSource(sender);
    return mfSendAborted.or(mfAllSent.or(mfPacketTransmit));
  }

  PartiallyReceivedBlock.PacketReceivedListener myListener;

  /**
   * Starts the asynchronous receiving flow for this transfer.
   *
   * <p>Registers a listener on the {@link PartiallyReceivedBlock}, installs message filters, and
   * begins waiting for packets. The callback is invoked on success with the full block, or on
   * failure with a {@link RetrievalException}. If the PRB is already complete or aborted when this
   * is called, the callback may be invoked synchronously before the method returns.
   *
   * <p>Threading: completion callbacks may run on internal I/O or timer threads.
   *
   * @param callback completion callback receiving the outcome
   */
  public void receive(BlockReceiverCompletion callback) {
    startTime = System.currentTimeMillis();
    this.callback = callback;
    synchronized (prb) {
      try {
        myListener =
            new PartiallyReceivedBlock.PacketReceivedListener() {

              @Override
              public void packetReceived(int packetNo) {
                // Ignore
              }

              @Override
              public void receiveAborted(int reason, String description) {
                complete(reason, description);
              }
            };
        prb.addListener(myListener);
      } catch (AbortedException _) {
        try {
          callback.blockReceived(prb.getBlock());
          return;
        } catch (AbortedException _) {
          // Intentionally ignored: PRB aborted between attempts to get the block
        }
        callback.blockReceiveFailed(new RetrievalException(prb.abortReason, prb.abortDescription));
        return;
      }
    }
    incRunningBlockReceives();
    try {
      waitNotification(false);
    } catch (DisconnectedException _) {
      RetrievalException retrievalException =
          new RetrievalException(RetrievalException.SENDER_DISCONNECTED);
      prb.abort(
          retrievalException.getReason(),
          retrievalException.toString(),
          true /* kind of, it shouldn't count towards the stats anyway */);
      callback.blockReceiveFailed(retrievalException);
      decRunningBlockReceives();
    } catch (RuntimeException e) {
      decRunningBlockReceives();
      throw e;
    }
  }

  private static final RunningAverage avgTimeTaken = new TrivialRunningAverage();

  private void maybeResetDiscardFilter() {
    long timeleft = discardEndTime - System.currentTimeMillis();
    if (timeleft > 0) {
      try {
        discardFilter.setTimeout(timeleft);
        usm.addAsyncFilter(discardFilter, this, ctr);
      } catch (DisconnectedException _) {
        // ignore
      }
    }
  }

  /**
   * Discards leftover messages after completion.
   *
   * <p>Most commonly drops {@code allSent} (receive() often exits immediately after the last
   * packet) and occasionally {@code packetTransmit} for reordered packets requested as “missing”.
   */
  @Override
  public void onMatched(Message m) {
    if (LOG.isDebugEnabled()) LOG.debug("discarding message post-receive: {}", m);
    maybeResetDiscardFilter();
  }

  @Override
  public boolean shouldTimeout() {
    return false;
  }

  @Override
  public void onTimeout() {
    // ignore
  }

  @Override
  public void onDisconnect(PeerContext ctx) {
    // Ignore
  }

  @Override
  public void onRestarted(PeerContext ctx) {
    // Ignore
  }

  /**
   * Returns whether a {@code sendAborted} from the sender was observed for this transfer.
   *
   * @return true if the remote peer sent an abort for this UID
   */
  public synchronized boolean senderAborted() {
    return senderAborted;
  }

  static int runningBlockReceives = 0;

  private void incRunningBlockReceives() {
    if (LOG.isDebugEnabled()) LOG.debug("Starting block receive {}", uid);
    synchronized (BlockReceiver.class) {
      runningBlockReceives++;
      if (LOG.isDebugEnabled())
        LOG.debug("Started a block receive, running: {}", runningBlockReceives);
    }
  }

  private void decRunningBlockReceives() {
    if (LOG.isDebugEnabled()) LOG.debug("Stopping block receive {}", uid);
    synchronized (BlockReceiver.class) {
      runningBlockReceives--;
      if (LOG.isDebugEnabled())
        LOG.debug("Finished a block receive, running: {}", runningBlockReceives);
    }
  }

  /**
   * Returns the number of {@code BlockReceiver} instances that are actively receiving.
   *
   * <p>Intended for diagnostics and monitoring.
   *
   * @return active receive count
   */
  public static synchronized int getRunningReceives() {
    return runningBlockReceives;
  }

  @Override
  public String toString() {
    return super.toString() + ":" + uid + ":" + sender.shortToString();
  }
}
