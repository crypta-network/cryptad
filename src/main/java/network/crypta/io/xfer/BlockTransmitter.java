package network.crypta.io.xfer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.io.comm.AsyncMessageCallback;
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
import network.crypta.node.FastRunnable;
import network.crypta.node.HighHtlAware;
import network.crypta.node.MessageItem;
import network.crypta.node.Node;
import network.crypta.node.PrioRunnable;
import network.crypta.support.BitArray;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.NativeThread;
import network.crypta.support.math.RunningAverage;
import network.crypta.support.math.TrivialRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transmits a partially received block to a peer, packet by packet, and tracks completion.
 *
 * <p>This class streams packets from a {@link PartiallyReceivedBlock} to a destination peer where
 * they are reconstructed by {@code BlockReceiver}. A single {@code PartiallyReceivedBlock} may be
 * transmitted concurrently to multiple peers; therefore, this class must never call {@code
 * prb.abort()}.
 *
 * <p>Security and fairness: transmission continues even when the inter-packet interval grows beyond
 * what the receiver can accept. Otherwise, a malicious receiver could waste disproportionate
 * inbound bandwidth on our side and on upstream nodes by issuing many requests but only accepting a
 * few bytes per second. Such situations should be handled by higher-level load limiting (accurate
 * bandwidth limits at the originator, or a cap on packets in flight).
 *
 * <p>Thread safety: internal transfer state ({@code unsent}, {@code sentPackets}, completion flags
 * and counters) is guarded by the {@code senderThread} monitor. Callers must respect the locking
 * notes in the method Javadoc.
 */
public class BlockTransmitter {
  private static final Logger LOG = LoggerFactory.getLogger(BlockTransmitter.class);

  /**
   * Upper bound (ms) for the random delay applied between the final two packets (30→31 and 31→32)
   * when operating at high HTL. The intent is to avoid bursty tail delivery.
   *
   * <p>Note: {@code 1000} ms increases average insert latency by about 2.5 s; adjust with care.
   */
  private static final int MAX_ARTIFICIAL_FINAL_PACKETS_DELAY = 1000;

  // Used only for scheduling small non-security delays; SecureRandom satisfies Sonar rule S2245.
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  // Shared log string fragments to avoid duplication warnings.
  private static final String LOG_FOR = " for ";
  private static final String LOG_UNSENT_IS = " unsent is ";
  private static final String ERROR_TEXT = "error";
  private static final String LOG_TIME_BETWEEN = "Time between packets on ";
  private static final String LOG_MS_REALTIME = "ms) realtime=";
  private static final String LOG_TIME_FMT_CORE = "{} : {} ( {}";

  /**
   * Timeout (ms) after the last packet is sent before abandoning the transfer if the receiver does
   * not acknowledge completion. Starts counting from {@code timeAllSent}.
   */
  public static final int SEND_TIMEOUT = 60000;

  final MessageCore messageCore;
  final PeerContext destination;
  private volatile boolean sentSendAborted;
  final long uid;
  private final boolean realTime;
  final PartiallyReceivedBlock prb;
  private Deque<Integer> unsent;
  private final BlockSenderJob senderThread = new BlockSenderJob();
  private BitArray sentPackets;
  private long timeAllSent = -1;
  final ByteCounter ctr;
  final int packetSize;
  private final ReceiverAbortHandler abortHandler;
  private final HashSet<MessageItem> itemsPending = new HashSet<>();

  private final Ticker ticker;
  private final PriorityAwareExecutor executor;
  private final BlockTransmitterCompletion callback;

  /** Reports the observed inter-packet interval for metrics/telemetry. */
  public interface BlockTimeCallback {
    /**
     * Called with the measured interval between consecutive packet sending.
     *
     * @param interval time in milliseconds since the previous packet was sent; negative when not
     *     applicable (e.g., for the first packet).
     * @param realTime {@code true} if the transfer runs in realtime mode, {@code false} for bulk.
     */
    void blockTime(long interval, boolean realTime);
  }

  private final BlockTimeCallback blockTimeCallback;

  /**
   * Have we received a completion acknowledgement from the other side - either a sendAborted or
   * allReceived?
   */
  private boolean receivedSendCompletion;

  /** Was it allReceived? */
  private boolean receivedSendSuccess;

  /** Have we completed i.e., called the callback? */
  private volatile boolean completed;

  /** Have we failed e.g., due to PRB abort, disconnection? */
  private volatile boolean failed;

  static int runningBlockTransmits = 0;

  class BlockSenderJob implements PrioRunnable {
    private static final int STATE_IDLE = 0; // not running
    private static final int STATE_RUNNING = 1; // currently running
    private static final int STATE_WAITING = 2; // waiting for a scheduled delay

    private final AtomicInteger state = new AtomicInteger();
    private int count = 0;

    @Override
    public void run() {
      if (!state.compareAndSet(STATE_IDLE, STATE_RUNNING)) {
        return;
      }
      try {
        while (state.get() == STATE_RUNNING) {
          int packetNo;
          BitArray copy;
          synchronized (senderThread) {
            if (failed || receivedSendCompletion || completed) return;
            if (unsent.isEmpty()) {
              // Wait for PRB callback to tell us we have more packets.
              return;
            }
            packetNo = unsent.removeFirst();
            if (sentPackets.bitAt(packetNo)) {
              LOG.error(
                  "Already sent packet in run(): {}"
                      + LOG_FOR
                      + "{}"
                      + LOG_UNSENT_IS
                      + "{} sent is {}",
                  packetNo,
                  this,
                  unsent,
                  sentPackets,
                  new Exception(ERROR_TEXT));
              continue;
            }
            copy = sentPackets.copy();
            sentPackets.setBit(packetNo, true);
            // Apply a small random delay before the final two packets at high HTL.
            // Uses 'count' to detect the last two sending (packets 31 and 32 of the block).
            count++;
            if (isHighHtl() && count >= (Node.PACKETS_IN_BLOCK - 2)) {
              state.set(STATE_WAITING);
              long delayMillis = SECURE_RANDOM.nextInt(MAX_ARTIFICIAL_FINAL_PACKETS_DELAY);
              ticker.queueTimedJob((FastRunnable) this::schedule, delayMillis);
            }
          }
          if (!innerRun(packetNo, copy)) return;
        }
      } finally {
        state.compareAndSet(STATE_RUNNING, STATE_IDLE);
      }
    }

    void schedule() {
      state.compareAndSet(STATE_WAITING, STATE_IDLE);
      if (failed || receivedSendCompletion || completed) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not scheduling for {} to {} :{}{}{}",
              uid,
              destination,
              failed ? "(failed) " : "",
              receivedSendCompletion ? "(receivedSendCompletion) " : "",
              completed ? "(completed) " : "");
        return;
      }
      executor.execute(this, "BlockTransmitter block sender for " + uid + " to " + destination);
    }

    /**
     * @return True .
     */
    private boolean innerRun(int packetNo, BitArray copied) {
      try {
        Message msg =
            DMT.createPacketTransmit(uid, packetNo, copied, prb.getPacket(packetNo), realTime);
        MyAsyncMessageCallback cb = new MyAsyncMessageCallback();
        MessageItem item;
        // All sending are throttled via the shared ByteCounter.
        item = destination.transport().sendAsync(msg, cb, ctr);
        synchronized (itemsPending) {
          itemsPending.add(item);
        }
      } catch (NotConnectedException _) {
        onDisconnect();
        return false;
      } catch (AbortedException e) {
        LOG.info("Terminating send due to abort: {}", String.valueOf(e));
        // The PRB callback will deal with this.
        return false;
      }
      boolean success = false;
      boolean complete = false;
      synchronized (senderThread) {
        if (unsent.isEmpty() && getNumSent() == prb.packets) {
          // No unsent packets, no unreceived packets
          sendAllSentNotification();
          if (maybeAllSent()) {
            if (maybeComplete()) {
              complete = true;
              success = receivedSendSuccess;
            } else return false;
          } else {
            return false;
          }
        }
      }
      if (complete) {
        callCallback(success);
        return false; // No more blocks to send.
      }
      return true; // More blocks to send.
    }

    private void sendAllSentNotification() {
      try {
        messageCore.send(destination, DMT.createAllSent(uid), ctr);
      } catch (NotConnectedException _) {
        LOG.info("disconnected for allSent()");
      }
    }

    @Override
    public int getPriority() {
      return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
    }
  }

  /**
   * Creates a new transmitter for sending a partially received block to a specific peer.
   *
   * @param transferContext shared transfer context (message core, peer, uid, PRB, accounting, and
   *     timing settings)
   * @param abortHandler callback invoked when the receiver cancels; determines whether to cascade
   *     the cancel to the {@code PartiallyReceivedBlock}.
   * @param callback completion callback invoked once per transfer with success status.
   * @param blockTimes optional callback for inter-packet timing metrics; may be {@code null}.
   */
  public BlockTransmitter(
      BlockTransferContext transferContext,
      ReceiverAbortHandler abortHandler,
      BlockTransmitterCompletion callback,
      BlockTimeCallback blockTimes) {
    this.realTime = transferContext.realTime();
    this.ticker = transferContext.ticker();
    this.executor = this.ticker.getExecutor();
    this.callback = callback;
    this.abortHandler = abortHandler;
    messageCore = transferContext.messageCore();
    this.destination = transferContext.peer();
    this.uid = transferContext.uid();
    prb = transferContext.block();
    this.ctr = transferContext.byteCounter();
    if (this.ctr == null) throw new NullPointerException();
    packetSize = DMT.packetTransmitSize(prb.packetSize, prb.packets);
    try {
      sentPackets = new BitArray(prb.getNumPackets());
    } catch (AbortedException _) {
      LOG.error("Aborted during setup");
      // Will throw on running
    }
    this.blockTimeCallback = blockTimes;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Starting block transmit for {} to {} realtime={}",
          uid,
          destination.shortToString(),
          this.realTime);
  }

  private Runnable timeoutJob;

  /**
   * Schedules a timeout to trigger after all packets have been sent, if no acknowledgement arrives.
   * A no-op if an acknowledgement was already received or a timeout is already scheduled.
   */
  public void scheduleTimeoutAfterBlockSends() {
    synchronized (senderThread) {
      if (receivedSendCompletion) return;
      if (timeoutJob != null) return;
      if (LOG.isDebugEnabled()) LOG.debug("Scheduling timeout on {}", this);
      timeoutJob =
          new PrioRunnable() {
            @Override
            public void run() {
              runTimeoutJobInner();
            }

            @Override
            public int getPriority() {
              return NativeThread.PriorityLevel.NORM_PRIORITY.value;
            }
          };
      ticker.queueTimedJob(timeoutJob, "Timeout for " + this, SEND_TIMEOUT, false, false);
    }
  }

  private void runTimeoutJobInner() {
    String timeString;
    String abortReason;
    Future fail;
    synchronized (senderThread) {
      if (completed) return;
      boolean hadSendCompletion = receivedSendCompletion;
      if (!receivedSendCompletion) {
        receivedSendCompletion = true;
        receivedSendSuccess = false;
      }
      // SEND_TIMEOUT (one minute) after all packets have been transmitted, terminate the sending.
      if (failed) {
        // Already failed, we were just waiting for the acknowledgement sendAborted.
        if (!hadSendCompletion) {
          LOG.warn("Terminating send after failure on {}", this);
          abortReason = "Already failed and no acknowledgement";
        } else {
          // Waiting for transfers maybe???
          if (LOG.isDebugEnabled()) LOG.debug("Trying to terminate send after timeout");
          abortReason = "Already failed";
        }
      } else {
        timeString = TimeUtil.formatTime((System.currentTimeMillis() - timeAllSent), 2, true);
        LOG.warn(
            "Terminating send {} to {} from {} as we haven't heard from receiver in {}.",
            uid,
            destination,
            destination.transport().getSocketHandler(),
            timeString);
        abortReason = "Haven't heard from you (receiver) in " + timeString;
      }
      fail = maybeFail(RetrievalException.RECEIVER_DIED, abortReason);
    }
    fail.execute();
  }

  /**
   * Determines whether all packets have been sent and records the time if so.
   *
   * <p>LOCKING: Must be called with the {@code senderThread} monitor held.
   *
   * @return {@code true} when there are no unsent packets and no pending sends (or when a failure
   *     has already been recorded), meaning the sender is now waiting for either an acknowledgement
   *     or a timeout; {@code false} otherwise.
   */
  public boolean maybeAllSent() {
    if (blockSendsPending == 0 && unsent.isEmpty() && getNumSent() == prb.packets) {
      timeAllSent = System.currentTimeMillis();
      if (LOG.isDebugEnabled()) LOG.debug("Sent all blocks, none unsent on {}", this);
      senderThread.schedule();
      return true;
    }
    if (blockSendsPending == 0 && failed) {
      timeAllSent = System.currentTimeMillis();
      if (LOG.isDebugEnabled()) LOG.debug("Sent blocks and failed on {}", this);
      return true;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "maybeAllSent: block sends pending = {} unsent = {} sent = {} on {}",
          blockSendsPending,
          unsent.size(),
          getNumSent(),
          this);
    return false;
  }

  /**
   * Finalizes the transfer once an acknowledgement (success or abort) has been received.
   *
   * <p>Precondition: {@link #maybeAllSent()} returned {@code true} for the current state.
   *
   * <p>LOCKING: Must be called with the {@code senderThread} monitor held. The caller must invoke
   * the completion callback outside the lock when this method returns {@code true}.
   *
   * @return {@code true} if the transfer transitioned to the completed state; {@code false} if we
   *     are still waiting for the receiver or were already completed.
   */
  public boolean maybeComplete() {
    if (!receivedSendCompletion) {
      if (LOG.isDebugEnabled())
        LOG.debug("maybeComplete() not completing because send not completed on {}", this);
      // All the block sending have completed, wait for the other side to acknowledge or timeout.
      scheduleTimeoutAfterBlockSends();
      return false;
    }
    if (completed) {
      if (LOG.isDebugEnabled()) LOG.debug("maybeComplete() already completed on {}", this);
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("maybeComplete() completing on {}", this);
    completed = true;
    decRunningBlockTransmits();
    return true;
  }

  /** A tiny executable used to defer actions that must run outside the sender lock. */
  public interface Future {
    /** Executes the deferred action outside the {@code senderThread} monitor. */
    void execute();
  }

  private static final Future nullFuture =
      () -> {
        // Do nothing.
      };

  /**
   * Transitions the transfer into a failed state exactly once and returns work to run afterward.
   *
   * <p>On failure, this method determines whether to send a {@code sendAborted} message immediately
   * or wait for pending sends/acknowledgements, and returns a {@link Future} that performs any
   * required I/O outside the lock.
   *
   * <p>LOCKING: Must be called with the {@code senderThread} monitor held.
   *
   * @param reason reason code (see {@link DMT} constants).
   * @param description human-readable cause.
   * @return a {@link Future} that must be {@link Future#execute() executed} after releasing the
   *     lock.
   */
  public Future maybeFail(final int reason, final String description) {
    if (completed) {
      if (LOG.isDebugEnabled()) LOG.debug("maybeFail() already completed on {}", this);
      return nullFuture;
    }
    failed = true;
    if (!receivedSendCompletion) {
      return handleFailBeforeAck(reason, description);
    }
    if (blockSendsPending != 0) {
      return handleFailWithPending(reason, description);
    }
    return handleFailComplete(reason, description);
  }

  private Future handleFailBeforeAck(final int reason, final String description) {
    // Don't time out until after we have an acknowledgement of the transfer cancel.
    // This is important for keeping track of how many transfers are actually running, which will be
    // important for load management later on.
    // The caller will immediately call prepareSendAbort() then innerSendAborted().
    if (LOG.isDebugEnabled()) LOG.debug("maybeFail() waiting for acknowledgement on {}", this);
    if (sentSendAborted) {
      scheduleTimeoutAfterBlockSends();
      return nullFuture; // Do nothing, waiting for timeout.
    }
    sentSendAborted = true;
    // Send the aborted, then wait.
    return () -> {
      try {
        innerSendAborted(reason, description);
        scheduleTimeoutAfterBlockSends();
      } catch (NotConnectedException _) {
        onDisconnect();
      }
    };
  }

  private Future handleFailWithPending(final int reason, final String description) {
    if (LOG.isDebugEnabled())
      LOG.debug("maybeFail() waiting for {} block sends on {}", blockSendsPending, this);
    if (sentSendAborted) return nullFuture; // Wait for blockSendsPending to reach 0
    sentSendAborted = true;
    // They have sent us a cancel, but we still need to send them an ack, or they will do a fatal
    // timeout.
    return () -> {
      try {
        innerSendAborted(reason, description);
      } catch (NotConnectedException _) {
        onDisconnect();
      }
    };
  }

  private Future handleFailComplete(final int reason, final String description) {
    if (LOG.isDebugEnabled()) LOG.debug("maybeFail() completing on {}", this);
    completed = true;
    decRunningBlockTransmits();
    final boolean sendAborted = sentSendAborted;
    sentSendAborted = true;
    return () -> {
      if (!sendAborted) {
        try {
          innerSendAborted(reason, description);
        } catch (NotConnectedException _) {
          onDisconnect();
        }
      }
      callCallback(false);
    };
  }

  /**
   * Sends a {@code sendAborted} message to the receiver.
   *
   * @param reason reason code (see {@link DMT}).
   * @param desc human-readable description.
   * @throws NotConnectedException if the peer is not currently connected.
   */
  public void innerSendAborted(int reason, String desc) throws NotConnectedException {
    messageCore.send(destination, DMT.createSendAborted(uid, reason, desc), ctr);
  }

  /** Decides whether a receiver-side cancel should be cascaded to the source block. */
  public interface ReceiverAbortHandler {

    /**
     * Returns true to cancel the PRB and cascade to downstream transfer.
     *
     * @return true to cancel the PRB and thus cascade the cancel to the downstream transfer, false
     *     otherwise.
     */
    boolean onAbort();
  }

  /** Never cascades receiver aborts to the source block. */
  public static final ReceiverAbortHandler NEVER_CASCADE = () -> false;

  /** Completion callback invoked once when the transfer finishes (success or failure). */
  public interface BlockTransmitterCompletion {

    /**
     * Called exactly once per transfer when it terminates.
     *
     * @param success {@code true} if the receiver acknowledged {@code allReceived}; {@code false}
     *     if the transfer aborted or failed.
     */
    void blockTransferFinished(boolean success);
  }

  private PartiallyReceivedBlock.PacketReceivedListener myListener = null;

  private final AsyncMessageFilterCallback cbAllReceived =
      new SlowAsyncMessageFilterCallback() {

        @Override
        public void onMatched(Message m) {
          if (LOG.isDebugEnabled()) {
            long endTime = System.currentTimeMillis();
            long transferTime = (endTime - startTime);
            avgTimeTaken.report(transferTime);
            LOG.debug(
                "Block send took {} : average {} on {}",
                transferTime,
                avgTimeTaken.currentValue(),
                BlockTransmitter.this);
          }
          synchronized (senderThread) {
            receivedSendCompletion = true;
            receivedSendSuccess = true;
            if (!maybeAllSent()) return;
            if (!maybeComplete()) return;
          }
          callCallback(true);
        }

        @Override
        public boolean shouldTimeout() {
          synchronized (senderThread) {
            // We are waiting for the sending completion, which is set on timeout as well as on
            // receiving a message.
            // In some corner cases we might want to get the allReceived after setting _failed, so
            // don't time out on _failed.
            // We do want to timeout on _completed because that means everything is finished - it is
            // only set in maybeComplete() and maybeFail().
            if (receivedSendCompletion || completed) return true;
          }
          return false;
        }

        @Override
        public void onTimeout() {
          // Do nothing
        }

        @Override
        public void onDisconnect(PeerContext ctx) {
          BlockTransmitter.this.onDisconnect();
        }

        @Override
        public void onRestarted(PeerContext ctx) {
          BlockTransmitter.this.onDisconnect();
        }

        @Override
        public int getPriority() {
          return NativeThread.PriorityLevel.NORM_PRIORITY.value;
        }
      };

  private final AsyncMessageFilterCallback cbSendAborted =
      new SlowAsyncMessageFilterCallback() {

        @Override
        public void onMatched(Message msg) {
          if (!prb.isAborted() && abortHandler.onAbort())
            prb.abort(
                RetrievalException.CANCELLED_BY_RECEIVER, "Cascading cancel from receiver", true);
          Future fail;
          synchronized (senderThread) {
            receivedSendCompletion = true;
            receivedSendSuccess = false;
            fail = maybeFail(msg.getInt(DMT.REASON), msg.getString(DMT.DESCRIPTION));
            if (LOG.isDebugEnabled())
              LOG.debug("Transfer got sendAborted on {}", BlockTransmitter.this);
          }
          fail.execute();
          cancelItemsPending();
        }

        @Override
        public boolean shouldTimeout() {
          synchronized (senderThread) {
            // We are waiting for the sending completion, which is set on timeout as well as on
            // receiving a message.
            // We don't want to timeout on _failed because we can set _failed, send sendAborted, and
            // then wait for the acknowledging sendAborted.
            // We do want to timeout on _completed because that means everything is finished - it is
            // only set in maybeComplete() and maybeFail().
            if (receivedSendCompletion || completed) return true;
          }
          return false;
        }

        @Override
        public void onTimeout() {
          // Do nothing
        }

        @Override
        public void onDisconnect(PeerContext ctx) {
          BlockTransmitter.this.onDisconnect();
        }

        @Override
        public void onRestarted(PeerContext ctx) {
          BlockTransmitter.this.onDisconnect();
        }

        @Override
        public int getPriority() {
          return NativeThread.PriorityLevel.NORM_PRIORITY.value;
        }
      };

  private void onDisconnect() {
    LOG.info(
        "Terminating send {} to {} from {} because node disconnected while waiting",
        uid,
        destination,
        destination.transport().getSocketHandler());
    // Peer disconnected; an abort/ack cannot be sent back to them.
    Future fail;
    synchronized (senderThread) {
      receivedSendCompletion = true; // effectively
      blockSendsPending = 0; // effectively
      sentSendAborted = true; // effectively
      fail = maybeFail(RetrievalException.SENDER_DISCONNECTED, "Sender disconnected");
    }
    fail.execute();
    // Sometimes disconnect doesn't clear the message queue.
    // Since we are cancelling the transfer, we need to unqueue the messages.
    cancelItemsPending();
  }

  private void onAborted(int reason, String description) {
    if (LOG.isDebugEnabled()) LOG.debug("Aborting on {}", this);
    Future fail;
    synchronized (senderThread) {
      timeAllSent = -1;
      failed = true;
      senderThread.schedule();
      fail = maybeFail(reason, description);
    }
    fail.execute();
    cancelItemsPending();
  }

  private long startTime;

  /**
   * Starts the transfer asynchronously.
   *
   * <p>Registers a packet listener on the source block, shuffles packets under high HTL, and
   * installs asynchronous message filters for {@code allReceived} and {@code sendAborted}. The
   * actual sending runs on the executor.
   */
  public void sendAsync() {
    startTime = System.currentTimeMillis();

    if (LOG.isDebugEnabled()) LOG.debug("Starting async send on {}", this);
    incRunningBlockTransmits();

    try {
      synchronized (prb) {
        myListener =
            new PartiallyReceivedBlock.PacketReceivedListener() {

              @Override
              public void packetReceived(int packetNo) {
                synchronized (senderThread) {
                  if (LOG.isDebugEnabled())
                    LOG.debug("Got packet {}" + LOG_FOR + "{} to {}", packetNo, uid, destination);
                  if (unsent.contains(packetNo)) {
                    LOG.error(
                        "Already in unsent: {}" + LOG_FOR + "{}" + LOG_UNSENT_IS + "{}",
                        packetNo,
                        this,
                        unsent,
                        new Exception(ERROR_TEXT));
                    return;
                  }
                  if (sentPackets.bitAt(packetNo)) {
                    LOG.error(
                        "Already sent packet in packetReceived: {}"
                            + LOG_FOR
                            + "{}"
                            + LOG_UNSENT_IS
                            + "{} sent is {}",
                        packetNo,
                        this,
                        unsent,
                        sentPackets,
                        new Exception(ERROR_TEXT));
                    return;
                  }
                  unsent.addLast(packetNo);
                  timeAllSent = -1;
                  senderThread.schedule();
                }
              }

              @Override
              public void receiveAborted(int reason, String description) {
                onAborted(reason, description);
              }
            };
        unsent = prb.addListener(myListener);
      }
      // If all 32 packets are ready at once and HTL is high, shuffle to mix the sending order.
      if (isHighHtl() && unsent.size() == Node.PACKETS_IN_BLOCK) {
        List<Integer> temp = new ArrayList<>(unsent);
        unsent.clear();
        Collections.shuffle(temp);
        unsent.addAll(temp);
      }
      senderThread.schedule();

      MessageFilter mfAllReceived =
          MessageFilter.create()
              .setType(DMT.allReceived)
              .setField(DMT.UID, uid)
              .setSource(destination)
              .setNoTimeout();
      MessageFilter mfSendAborted =
          MessageFilter.create()
              .setType(DMT.sendAborted)
              .setField(DMT.UID, uid)
              .setSource(destination)
              .setNoTimeout();

      registerAsyncFilters(mfAllReceived, mfSendAborted);

    } catch (AbortedException _) {
      onAborted(prb.getAbortReason(), prb.getAbortDescription());
    }
  }

  private void registerAsyncFilters(MessageFilter mfAllReceived, MessageFilter mfSendAborted) {
    try {
      messageCore.addAsyncFilter(mfAllReceived, cbAllReceived, ctr);
      messageCore.addAsyncFilter(mfSendAborted, cbSendAborted, ctr);
    } catch (DisconnectedException _) {
      onDisconnect();
    }
  }

  private void cancelItemsPending() {
    MessageItem[] items;
    synchronized (itemsPending) {
      items = itemsPending.toArray(new MessageItem[0]);
      itemsPending.clear();
    }
    for (MessageItem item : items) {
      if (!destination.unqueueMessage(item) && LOG.isDebugEnabled())
        // Benign race: the item may already have been dequeued.
        LOG.debug("Message not queued ?!?!?!? on {} : {}", this, item);
    }
  }

  private static synchronized void incRunningBlockTransmits() {
    runningBlockTransmits++;
    if (LOG.isDebugEnabled())
      LOG.debug("Started a block transmit, running: {}", runningBlockTransmits);
  }

  private static synchronized void decRunningBlockTransmits() {
    runningBlockTransmits--;
    if (LOG.isDebugEnabled())
      LOG.debug("Finished a block transmit, running: {}", runningBlockTransmits);
  }

  private void cleanup() {
    // Async filters expire via shouldTimeout(); explicit removal is intentionally avoided.
    if (myListener != null) prb.removeListener(myListener);
  }

  private class MyAsyncMessageCallback implements AsyncMessageCallback {

    MyAsyncMessageCallback() {
      synchronized (senderThread) {
        blockSendsPending++;
      }
    }

    private boolean completed = false;

    @Override
    public void sent() {
      if (LOG.isDebugEnabled()) LOG.debug("Sent block on {}", BlockTransmitter.this);
      // Wait for acknowledgement
    }

    @Override
    public void acknowledged() {
      complete(false);
    }

    @Override
    public void disconnected() {
      complete(true);
    }

    @Override
    public void fatalError() {
      complete(true);
    }

    private void complete(boolean failed) {
      if (LOG.isDebugEnabled())
        LOG.debug("Completed send on a block for {}", BlockTransmitter.this);
      boolean success = false;
      long now = System.currentTimeMillis();
      boolean callCallback = false;
      long delta;
      synchronized (senderThread) {
        if (completed) return;
        completed = true;
        delta = logInterPacketTime(now);
        blockSendsPending--;
        if (LOG.isDebugEnabled()) LOG.debug("Pending: {}", blockSendsPending);
        if (maybeAllSent() && maybeComplete()) {
          callCallback = true;
          success = receivedSendSuccess;
        }
      }
      if (!failed)
        // Everything is throttled, but the payload is not reported.
        ctr.sentPayload(packetSize);
      if (callCallback) {
        callCallback(success);
      }
      if (delta > 0 && blockTimeCallback != null) {
        blockTimeCallback.blockTime(delta, realTime);
      }
    }

    private long logInterPacketTime(long now) {
      long deltaLocal = -1;
      if (lastSentPacket > 0) {
        deltaLocal = now - lastSentPacket;
        long threshold =
            (realTime
                ? BlockReceiver.RECEIPT_TIMEOUT_REALTIME
                : BlockReceiver.RECEIPT_TIMEOUT_BULK);
        if (deltaLocal > threshold) {
          if (LOG.isWarnEnabled()) {
            LOG.warn(
                LOG_TIME_BETWEEN + LOG_TIME_FMT_CORE + LOG_MS_REALTIME + "{}",
                BlockTransmitter.this,
                TimeUtil.formatTime(deltaLocal, 2, true),
                deltaLocal,
                realTime);
          }
        } else if (deltaLocal > threshold / 5) {
          if (LOG.isInfoEnabled()) {
            LOG.info(
                LOG_TIME_BETWEEN + LOG_TIME_FMT_CORE + LOG_MS_REALTIME + "{}",
                BlockTransmitter.this,
                TimeUtil.formatTime(deltaLocal, 2, true),
                deltaLocal,
                realTime);
          }
        } else if (LOG.isDebugEnabled())
          LOG.debug(
              LOG_TIME_BETWEEN + LOG_TIME_FMT_CORE + LOG_MS_REALTIME + "{}",
              BlockTransmitter.this,
              TimeUtil.formatTime(deltaLocal, 2, true),
              deltaLocal,
              realTime);
      }
      lastSentPacket = now;
      return deltaLocal;
    }
  }

  private int blockSendsPending = 0;

  private long lastSentPacket = -1;

  private static final RunningAverage avgTimeTaken = new TrivialRunningAverage();

  /** LOCKING: Must be called with _senderThread held. */
  private int getNumSent() {
    int ret = 0;
    for (int x = 0; x < sentPackets.getSize(); x++) {
      if (sentPackets.bitAt(x)) {
        ret++;
      }
    }
    return ret;
  }

  /**
   * Invokes the completion callback asynchronously on the executor and then performs cleanup. If no
   * callback is set, only cleanup runs.
   *
   * @param success {@code true} on receiver acknowledgement; {@code false} on failure/abort.
   */
  public void callCallback(final boolean success) {
    if (callback != null) {
      executor.execute(
          () -> {
            try {
              callback.blockTransferFinished(success);
            } finally {
              cleanup();
            }
          },
          "BlockTransmitter completion callback for " + this);
    } else {
      cleanup();
    }
  }

  /** Returns the destination peer for this transfer. */
  public PeerContext getDestination() {
    return destination;
  }

  @Override
  public String toString() {
    return "BlockTransmitter for " + uid + " to " + destination.shortToString();
  }

  /**
   * Returns the number of block transfers currently running across the process.
   *
   * <p>Thread-safe.
   */
  public static synchronized int getRunningSends() {
    return runningBlockTransmits;
  }

  private boolean isHighHtl() {
    if (ctr instanceof HighHtlAware aware) {
      return aware.isHighHtl();
    }
    return false;
  }
}
