package network.crypta.io.xfer;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.node.PrioRunnable;
import network.crypta.support.BitArray;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends large, file-like payloads to a single peer using the bulk transfer protocol. The
 * transmitter assumes the data is locally available and is not persisted across node restarts.
 *
 * <p>It streams block-sized packets, tracks in-flight packets, and—unless {@code noWait} is
 * true—waits for the final {@code FNPBulkReceivedAll} acknowledgement before reporting success.
 * Local aborts or remote cancellations unblock the sending loop promptly.
 *
 * <p>Threading: state transitions synchronize on {@code this}. Instances are notified by {@link
 * PartiallyReceivedBulk} (new blocks or abort) and by asynchronous message filters registered on
 * {@link network.crypta.io.comm.MessageCore}. Public methods may block until progress, completion,
 * cancellation, or timeout.
 *
 * @author toad
 */
public class BulkTransmitter {
  private static final Logger LOG = LoggerFactory.getLogger(BulkTransmitter.class);

  /**
   * Callback invoked when all packets have been queued and their sending callbacks have fired.
   *
   * <p>The callback is invoked at most once, asynchronously on the message executor.
   */
  public interface AllSentCallback {

    /**
     * Notifies that all packets were queued and observed as {@code sent}.
     *
     * @param bulkTransmitter the transmitter reporting completion of queuing
     * @param anyFailed {@code true} if any packet failed to send; {@code false} otherwise
     */
    void allSent(BulkTransmitter bulkTransmitter, boolean anyFailed);
  }

  /** Maximum time without progress before the transfer is considered failed. Unit: milliseconds. */
  static final long TIMEOUT = MINUTES.toMillis(5);

  /**
   * Grace period to keep listening for the final {@code FNPBulkReceivedAll} after finishing. Unit:
   * milliseconds.
   */
  static final long FINAL_ACK_TIMEOUT = SECONDS.toMillis(10);

  final AllSentCallback allSentCallback;

  /** Available blocks. Provided by the associated {@link PartiallyReceivedBulk}. */
  final PartiallyReceivedBulk prb;

  /** Peer receiving the data. */
  final PeerContext peer;

  /** Transfer UID used in all protocol messages. */
  final long uid;

  /**
   * Tracks blocks present but not yet sent. Bit semantics: 0 = sent or not present; 1 = present and
   * pending.
   */
  final BitArray blocksNotSentButPresent;

  private boolean cancelled;

  /** Peer boot identifier observed when the transfer started; used to detect restarts. */
  final long peerBootID;

  private boolean sentCancel;
  private boolean finished;

  /** When {@code true}, do not wait for the final acknowledgement after sending. */
  final boolean noWait;

  private long finishTime = -1;
  private String cancelReason;
  private final ByteCounter ctr;

  // 'realTime' parameter is accepted in the constructor for API compatibility, but no field is
  // needed here.
  /**
   * Whether an {@link InterruptedException} was observed inside internal waits. Interrupt status is
   * restored when {@link #send()} returns to allow callers to observe it (see java:S2142).
   */
  private volatile boolean interruptedDuringWait = false;

  private static long transfersCompleted;
  private static long transfersSucceeded;

  // No static initialization required.

  public BulkTransmitter(
      PartiallyReceivedBulk prb,
      PeerContext peer,
      long uid,
      boolean noWait,
      ByteCounter ctr,
      boolean realTime)
      throws DisconnectedException {
    this(prb, peer, uid, noWait, ctr, realTime, null);
  }

  /**
   * Creates a bulk transmitter.
   *
   * <p>The constructor registers asynchronous filters for abort and final-ack messages on the
   * underlying message core and associates the transmitter with the supplied {@link
   * PartiallyReceivedBulk}.
   *
   * @param prb the data source that exposes available blocks and notifies of new blocks/aborts
   * @param peer the destination peer
   * @param uid a unique transfer identifier used in protocol messages
   * @param noWait when {@code true}, return after sending all available data without waiting for
   *     {@code FNPBulkReceivedAll}
   * @param ctr byte counter to record payload accounting; must not be {@code null}
   * @param realTime accepted for API compatibility; does not alter scheduling semantics here
   * @throws DisconnectedException if the peer disconnects while registering filters
   */
  public BulkTransmitter(
      PartiallyReceivedBulk prb,
      PeerContext peer,
      long uid,
      boolean noWait,
      ByteCounter ctr,
      boolean realTime,
      AllSentCallback cb)
      throws DisconnectedException {
    this.prb = prb;
    this.peer = peer;
    this.uid = uid;
    this.noWait = noWait;
    this.ctr = ctr;
    // Touch the flag to make the intent explicit without changing behavior.
    if (realTime && LOG.isTraceEnabled()) {
      LOG.trace("Real-time flag set for {}", this);
    }
    this.allSentCallback = cb;
    if (ctr == null) throw new NullPointerException();
    peerBootID = peer.getBootID();
    // Synchronize on PRB while cloning and registering to avoid seeing block updates before the
    // bitmap snapshot is initialized.
    synchronized (this.prb) {
      // We can just clone it.
      blocksNotSentButPresent = prb.cloneBlocksReceived();
      prb.add(this);
    }
    try {
      prb.usm.addAsyncFilter(
          MessageFilter.create()
              .setNoTimeout()
              .setSource(peer)
              .setType(DMT.FNPBulkReceiveAborted)
              .setField(DMT.UID, uid),
          new AsyncMessageFilterCallback() {
            @Override
            public void onMatched(Message m) {
              cancel("Other side sent FNPBulkReceiveAborted");
            }

            @Override
            public boolean shouldTimeout() {
              synchronized (BulkTransmitter.this) {
                if (cancelled || finished) return true;
              }
              return BulkTransmitter.this.prb.isAborted();
            }

            @Override
            public void onTimeout() {
              // No-op: the filter is removed by cancellation/completion.
            }

            @Override
            public void onDisconnect(PeerContext ctx) {
              // No-op: cancellation paths handle disconnects.
            }

            @Override
            public void onRestarted(PeerContext ctx) {
              // No-op: peer restarts are detected via boot ID in the send loop.
            }
          },
          ctr);
      prb.usm.addAsyncFilter(
          MessageFilter.create()
              .setNoTimeout()
              .setSource(peer)
              .setType(DMT.FNPBulkReceivedAll)
              .setField(DMT.UID, uid),
          new AsyncMessageFilterCallback() {
            @Override
            public void onMatched(Message m) {
              // send() will terminate, so must call setAllQueued().
              setAllQueued();
              completed();
            }

            @Override
            public boolean shouldTimeout() {
              synchronized (BulkTransmitter.this) {
                if (cancelled) return true;
                if (finished) return (System.currentTimeMillis() - finishTime > FINAL_ACK_TIMEOUT);
              }
              return BulkTransmitter.this.prb.isAborted();
            }

            @Override
            public void onTimeout() {
              // No-op: the filter is removed by cancellation/completion.
            }

            @Override
            public void onDisconnect(PeerContext ctx) {
              // No-op: cancellation paths handle disconnects.
            }

            @Override
            public void onRestarted(PeerContext ctx) {
              // No-op: peer restarts are detected via boot ID in the send loop.
            }
          },
          ctr);
    } catch (DisconnectedException e) {
      cancel("Disconnected");
      throw e;
    }
  }

  /**
   * Received a block. Set the relevant bit to 1 to indicate that we have the block but haven't sent
   * it yet. **Only called by PartiallyReceivedBulk.**
   *
   * @param block The block number that has been received.
   */
  synchronized void blockReceived(int block) {
    blocksNotSentButPresent.setBit(block, true);
    notifyAll();
  }

  /**
   * Notifies the transmitter that the associated {@link PartiallyReceivedBulk} aborted.
   *
   * <p>Sends a best-effort {@code FNPBulkSendAborted} to the peer and wakes any waiting threads.
   * Idempotent.
   */
  public void onAborted() {
    sendAbortedMessage();
    synchronized (this) {
      notifyAll();
    }
  }

  /** Sends {@code FNPBulkSendAborted} once. Subsequent calls are no-ops. */
  private void sendAbortedMessage() {
    synchronized (this) {
      if (sentCancel) return;
      sentCancel = true;
    }
    try {
      peer.transport().sendAsync(DMT.createFNPBulkSendAborted(uid), null, ctr);
    } catch (NotConnectedException _) {
      // Best-effort notification only; ignore if not connected.
    }
  }

  public void cancel(String reason) {
    if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
    sendAbortedMessage();
    synchronized (this) {
      if (cancelled || finished) return;
      cancelled = true;
      cancelReason = reason;
      notifyAll();
    }
    prb.remove(this);
    synchronized (BulkTransmitter.class) {
      transfersCompleted++;
    }
    // Call AllSentCallback if necessary.
    // If packets are still in flight, the callback is invoked after they complete or fail.
    setAllQueued();
  }

  /**
   * Marks the transfer successful, updates counters, and notifies waiting threads and the optional
   * callback.
   *
   * <p>Like cancel(), but without the negative overtones: The client says it's got everything, we
   * believe them (even if we haven't sent everything; maybe they had a partial).
   */
  public void completed() {
    synchronized (this) {
      if (cancelled || finished) return;
      finished = true;
      finishTime = System.currentTimeMillis();
      notifyAll();
    }
    prb.remove(this);
    synchronized (BulkTransmitter.class) {
      transfersCompleted++;
      transfersSucceeded++;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Completed transfer successfully {}", this);
  }

  /**
   * Runs the sending loop until success, failure, or cancellation.
   *
   * <p>When {@code noWait} is {@code true} and the full file is already present locally, this
   * method completes after enqueueing all packets without waiting for the final acknowledgement.
   *
   * @return {@code true} if the peer acknowledged receipt (or {@code noWait} short-circuited after
   *     enqueueing); {@code false} if canceled, aborted, or timed out
   * @throws DisconnectedException if the peer disconnects or restarts during the transfer
   */
  public boolean send() throws DisconnectedException {
    try {
      long lastSentPacket = System.currentTimeMillis();
      while (true) {
        IterationResult r = doOneSendIteration(lastSentPacket);
        if (r.outcome == Outcome.SUCCEEDED) return true;
        if (r.outcome == Outcome.FAILED) return false;
        lastSentPacket = r.lastSentPacket;
      }
    } finally {
      // Restore interrupt status if we swallowed any InterruptedException during internal waits.
      if (interruptedDuringWait) Thread.currentThread().interrupt();
    }
  }

  private record IterationResult(Outcome outcome, long lastSentPacket) {

    static IterationResult cont(long ts) {
      return new IterationResult(Outcome.CONTINUE, ts);
    }

    static IterationResult success(long ts) {
      return new IterationResult(Outcome.SUCCEEDED, ts);
    }

    static IterationResult fail(long ts) {
      return new IterationResult(Outcome.FAILED, ts);
    }
  }

  private IterationResult doOneSendIteration(long lastSentPacket) throws DisconnectedException {
    int max = computeMaxInFlight();

    if (prb.isAborted()) {
      if (LOG.isDebugEnabled()) LOG.debug("Aborted {}", this);
      return IterationResult.fail(lastSentPacket);
    }

    ensurePeerNotRestarted();

    int blockNo = nextBlockOrStatus();
    if (blockNo == FINISHED_SENTINEL) return IterationResult.success(lastSentPacket);
    if (blockNo == CANCELLED_SENTINEL) return IterationResult.fail(lastSentPacket);

    if (blockNo < 0) {
      Outcome outcome = handleNoBlockAvailable(lastSentPacket);
      if (outcome == Outcome.SUCCEEDED) return IterationResult.success(lastSentPacket);
      if (outcome == Outcome.FAILED) return IterationResult.fail(lastSentPacket);
      return IterationResult.cont(lastSentPacket);
    }

    long ts = sendPacket(blockNo, max);
    if (ts < 0) return IterationResult.fail(lastSentPacket); // Already canceled, quit
    return IterationResult.cont(ts);
  }

  private int computeMaxInFlight() {
    int max = prb.blocks;
    max = Math.min(max, peer.getThrottleWindowSize());
    // Note: A global limiter of [code]max[/code] for memory management may be desirable
    // instead of hard-coding per use.
    max = Math.min(max, 100);
    if (max < 1) max = 1;
    return max;
  }

  private void ensurePeerNotRestarted() throws DisconnectedException {
    if (peer.getBootID() != peerBootID) {
      synchronized (this) {
        cancelled = true;
        notifyAll();
      }
      prb.remove(BulkTransmitter.this);
      if (LOG.isDebugEnabled()) LOG.debug("Failed to send {}: peer restarted: {}", uid, peer);
      throw new DisconnectedException();
    }
  }

  private static final int FINISHED_SENTINEL = Integer.MIN_VALUE;
  private static final int CANCELLED_SENTINEL = Integer.MAX_VALUE;

  private int nextBlockOrStatus() {
    synchronized (this) {
      if (finished) return FINISHED_SENTINEL;
      if (cancelled) return CANCELLED_SENTINEL;
      return blocksNotSentButPresent.firstOne();
    }
  }

  private enum Outcome {
    CONTINUE,
    SUCCEEDED,
    FAILED
  }

  private Outcome handleNoBlockAvailable(long lastSentPacket) {
    setAllQueued();
    Outcome early = fastCompleteIfNoWait();
    if (early != null) return early;
    Outcome drained = waitForInFlightToDrainOrContinue();
    if (drained != null) return drained;
    return waitForAckOrAbort(lastSentPacket);
  }

  private Outcome fastCompleteIfNoWait() {
    if (noWait && prb.hasWholeFile()) {
      completed();
      return Outcome.SUCCEEDED;
    }
    return null;
  }

  /**
   * Wait while there are packets in flight, but wake opportunistically.
   *
   * <p>When the transmitter temporarily runs out of locally available blocks, we do not want to
   * stall until every outstanding packet completes. New blocks may arrive (via {@link
   * #blockReceived(int)}) while there are still packets in flight; in that case, we should return
   * to the outer sending loop as soon as we are woken so the new block can be queued the moment the
   * congestion window permits.
   *
   * <p>Return semantics: - {@code Outcome.FAILED}: a packet failed while waiting. - {@code
   * Outcome.CONTINUE}: woke before fully draining; re-check availability and possibly send. -
   * {@code null}: in-flight packets fully drained; caller may proceed to ACK/abort the wait path.
   */
  @SuppressWarnings("java:S2142")
  private Outcome waitForInFlightToDrainOrContinue() {
    synchronized (this) {
      if (failedPacket) {
        cancel("Packet send failed");
        return Outcome.FAILED;
      }
      if (inFlightPackets == 0) return null; // Already drained; fall through to ACK wait.

      if (LOG.isDebugEnabled())
        LOG.debug("Waiting for packets (opportunistic wake): remaining: {}", inFlightPackets);

      // Guard against spurious wakeup; wake early only when a new block is available or when
      // in-flight packets drain to zero.
      while (!failedPacket && inFlightPackets != 0 && blocksNotSentButPresent.firstOne() < 0) {
        try {
          wait();
        } catch (InterruptedException _) {
          // Ignore and continue waiting; do not reassert the interrupt flag (see java:S2142).
          // We must not exit early here, or further waits will spin and bypass throttling.
          interruptedDuringWait = true; // restored by send() finally block
        }
      }

      if (failedPacket) {
        cancel("Packet send failed");
        return Outcome.FAILED;
      }
      if (inFlightPackets == 0) return null; // Fully drained, proceed to ACK the wait path.
      // A new block is now available; give control back to the outer loop to enqueue it
      // (congestion control still enforced in waitWhileCongested()).
      return Outcome.CONTINUE;
    }
  }

  @SuppressWarnings("java:S2142")
  private Outcome waitForAckOrAbort(long lastSentPacket) {
    // When there are no packets in flight, we may be waiting for the final
    // FNPBulkReceivedAll. However, new blocks can become available at any time
    // (blockReceived()), so we must also wake and return to the outer loop
    // immediately to queue them instead of stalling for up to 60 seconds.
    synchronized (this) {
      long deadline = System.currentTimeMillis() + SECONDS.toMillis(60);
      while (!failedPacket
          && !finished
          && !cancelled
          && !prb.isAborted()
          && inFlightPackets == 0
          && blocksNotSentButPresent.firstOne() < 0) { // break early when a new block appears
        long remaining = deadline - System.currentTimeMillis();
        if (remaining <= 0) break;
        try {
          wait(remaining);
        } catch (InterruptedException _) {
          // Ignore and loop; we restore the interrupt in send() finally.
          interruptedDuringWait = true;
        }
      }
      // If we observed completion/cancellation while waiting, return immediately so the outer
      // loop can see FINISHED/CANCELLED without stalling for the full deadline.
      // Also return promptly if the local PRB aborted while we were waiting; the outer loop
      // checks prb.isAborted() at the start of the iteration and will fail fast.
      if (finished || cancelled || prb.isAborted()) return Outcome.CONTINUE;
    }
    long end = System.currentTimeMillis();
    if (end - lastSentPacket > TIMEOUT) {
      LOG.error("Send timed out on {}", this);
      cancel("Timeout awaiting BulkReceivedAll");
      return Outcome.FAILED;
    }
    return Outcome.CONTINUE;
  }

  private long sendPacket(int blockNo, int max) throws DisconnectedException {
    // Send a packet
    byte[] buf = prb.getBlockData(blockNo);
    if (buf == null) {
      if (LOG.isDebugEnabled())
        LOG.debug("Block {} is null, presumably the send is cancelled: {}", blockNo, this);
      // Already canceled, quit
      return -1L;
    }

    // Congestion control and bandwidth limiting
    try {
      if (LOG.isDebugEnabled()) LOG.debug("Sending packet {}", blockNo);
      Message msg = DMT.createFNPBulkPacketSend(uid, blockNo, buf);
      UnsentPacketTag tag = new UnsentPacketTag();
      peer.transport().sendAsync(msg, tag, ctr);
      waitWhileCongested(max);
      synchronized (this) {
        blocksNotSentButPresent.setBit(blockNo, false);
      }
      return System.currentTimeMillis();
    } catch (NotConnectedException _) {
      cancel("Disconnected");
      if (LOG.isDebugEnabled()) LOG.debug("Cancelled: not connected {}", this);
      throw new DisconnectedException();
    }
  }

  @SuppressWarnings("java:S2142")
  private void waitWhileCongested(int max) {
    synchronized (this) {
      while (inFlightPackets >= max && !failedPacket) {
        try {
          wait(1000);
        } catch (InterruptedException _) {
          // Ignore and continue waiting; keep honoring congestion/throttle semantics.
          // We restore the interrupt when send() returns to avoid spinning here.
          interruptedDuringWait = true;
        }
      }
    }
  }

  private void setAllQueued() {
    if (allSentCallback != null) {
      boolean callAllSent = false;
      boolean anyFailed = false;
      synchronized (this) {
        allQueued = true;
        if (unsentPackets == 0 && !calledAllSent) {
          if (LOG.isDebugEnabled())
            LOG.debug("All packets queued; invoking all-sent callback for {}", this);
          callAllSent = true;
          calledAllSent = true;
          anyFailed = failedPacket;
        } else if (!calledAllSent && LOG.isDebugEnabled()) {
          LOG.debug("Still waiting for {}", unsentPackets);
        }
      }
      if (callAllSent) {
        callAllSentCallbackInner(anyFailed);
      }
    }
  }

  private void callAllSentCallbackInner(final boolean anyFailed) {
    prb.usm
        .getExecutor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                allSentCallback.allSent(BulkTransmitter.this, anyFailed);
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
              }
            });
  }

  private int inFlightPackets = 0;
  private int unsentPackets = 0;
  private boolean failedPacket = false;
  private boolean allQueued = false;
  private boolean calledAllSent = false;

  private class UnsentPacketTag implements AsyncMessageCallback {

    private boolean finished;
    private boolean sent;

    private UnsentPacketTag() {
      synchronized (BulkTransmitter.this) {
        inFlightPackets++;
        unsentPackets++;
      }
    }

    @Override
    public void acknowledged() {
      complete(false);
    }

    private void complete(boolean failed) {
      synchronized (this) {
        if (finished) return;
        finished = true;
        notifyAll();
      }
      if (!failed) ctr.sentPayload(prb.blockSize);
      synchronized (BulkTransmitter.this) {
        if (failed) {
          failedPacket = true;
          BulkTransmitter.this.notifyAll();
          if (LOG.isDebugEnabled()) LOG.debug("Packet failed for {}", BulkTransmitter.this);
        } else {
          inFlightPackets--;
          BulkTransmitter.this.notifyAll();
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Packet sent {} remaining in flight: {}", BulkTransmitter.this, inFlightPackets);
        }
      }
      sent(true);
    }

    @Override
    public void disconnected() {
      complete(true);
    }

    @Override
    public void fatalError() {
      complete(true);
    }

    @Override
    public void sent() {
      sent(false);
    }

    public void sent(boolean ignoreFinished) {
      if (allSentCallback == null) return;
      synchronized (this) {
        if (finished && !ignoreFinished) return;
        if (sent) return;
        sent = true;
        notifyAll();
      }
      final boolean anyFailed;
      synchronized (BulkTransmitter.this) {
        unsentPackets--;
        if (unsentPackets > 0) return;
        if (!allQueued) return;
        if (calledAllSent) return;
        calledAllSent = true;
        anyFailed = failedPacket;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("All packets sent; invoking all-sent callback for {}", this);
      callAllSentCallbackInner(anyFailed);
    }
  }

  /** Returns a short, human-readable identifier containing the UID and peer. */
  @Override
  public String toString() {
    return "BulkTransmitter:" + uid + ":" + peer.shortToString();
  }

  /** Returns the cancellation reason, or {@code null} if not canceled. */
  public String getCancelReason() {
    return cancelReason;
  }

  /**
   * Returns aggregate counters for completed and successful transfers.
   *
   * <p>Index {@code 0} = total completed, index {@code 1} = total succeeded.
   *
   * @return a two-element array {@code [completed, succeeded]}
   */
  public static synchronized long[] transferSuccess() {
    return new long[] {transfersCompleted, transfersSucceeded};
  }
}
