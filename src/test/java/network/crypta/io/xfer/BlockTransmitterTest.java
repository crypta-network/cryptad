package network.crypta.io.xfer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.AsyncMessageFilterCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.node.HighHtlAware;
import network.crypta.node.MessageItem;
import network.crypta.support.BitArray;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BlockTransmitterTest {

  // Minimal inline executor that runs tasks immediately on the caller thread
  static final class InlineExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  // Immediate ticker: schedules tasks to run inline without delay
  static final class ImmediateTicker implements Ticker {
    private final PriorityAwareExecutor exec;
    private final boolean runNamedDelayedImmediately;

    ImmediateTicker(PriorityAwareExecutor exec) {
      this(exec, false);
    }

    ImmediateTicker(PriorityAwareExecutor exec, boolean runNamedDelayedImmediately) {
      this.exec = exec;
      this.runNamedDelayedImmediately = runNamedDelayedImmediately;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      // run immediately to keep tests deterministic
      exec.execute(job);
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      if (offset <= 0 || runNamedDelayedImmediately) {
        exec.execute(job, name);
      }
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op for tests
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(runner, name);
    }
  }

  // ByteCounter that records payload sends and exposes high-HTL flag
  static final class TestCounter implements ByteCounter, HighHtlAware {
    final AtomicInteger payloadBytes = new AtomicInteger();
    volatile boolean highHtl;

    @Override
    public void sentBytes(int x) {
      // Intentional no-op in tests: assertions only care about payload bytes
      // via sentPayload(x). Counting raw bytes would add noise without value.
    }

    @Override
    public void receivedBytes(int x) {
      // Intentional no-op in tests: inbound link byte accounting is irrelevant
      // for these scenarios; we exercise completion paths using payload accounting.
    }

    @Override
    public void sentPayload(int x) {
      payloadBytes.addAndGet(x);
    }

    @Override
    public boolean isHighHtl() {
      return highHtl;
    }
  }

  private final PriorityAwareExecutor executor = new InlineExecutor();
  private final Ticker ticker = new ImmediateTicker(executor);
  private MessageCore usm;

  @Mock private PeerContext peer;

  @BeforeEach
  void setupCore() {
    usm = new MessageCore(executor);
  }

  private static PartiallyReceivedBlock prbWithAllData(int packets, int packetSize) {
    byte[] data = new byte[packets * packetSize];
    // bytes default to 0; PRB will mark all entries as received when constructed with data[]
    return new PartiallyReceivedBlock(packets, packetSize, data);
  }

  private static Message messageFromPeer(Message m, PeerContext src) {
    // Re-encode and decode to set the source on the Message, so MessageFilter#match can compare it
    byte[] packet = m.encodeToPacket();
    return Message.decodeMessageLax(packet, src, 0);
  }

  @Test
  @DisplayName("maybeComplete_whenAllSentAndAllReceived_completesSuccessfully")
  @SuppressWarnings({"java:S100", "java:S3011"})
  void maybeComplete_whenAllSentAndAllReceived_completesSuccessfully() throws Exception {
    // Arrange
    int packets = 3;
    int packetSize = 4;
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(packets, packetSize);
    TestCounter counter = new TestCounter();
    counter.highHtl = false;

    when(peer.getBootID()).thenReturn(1L);
    when(peer.getWeakRef()).thenAnswer(inv -> new WeakReference<PeerContext>(peer));
    when(peer.shortToString()).thenReturn("peer#manual");
    when(peer.isConnected()).thenReturn(true);

    AtomicInteger callback = new AtomicInteger(-1);
    BlockTransmitter.BlockTransmitterCompletion completion =
        success -> callback.set(success ? 1 : 0);

    long uid = 100L;
    BlockTransmitter tx =
        new BlockTransmitter(
            usm,
            ticker,
            peer,
            uid,
            prb,
            counter,
            BlockTransmitter.NEVER_CASCADE,
            completion,
            false,
            null);

    // Force internal state to "all sent" and "completion acknowledged"
    var senderThreadField = BlockTransmitter.class.getDeclaredField("senderThread");
    senderThreadField.setAccessible(true);
    Object senderThread = senderThreadField.get(tx);

    var unsentField = BlockTransmitter.class.getDeclaredField("unsent");
    unsentField.setAccessible(true);
    var sentPacketsField = BlockTransmitter.class.getDeclaredField("sentPackets");
    sentPacketsField.setAccessible(true);
    var rcvdCompletionField = BlockTransmitter.class.getDeclaredField("receivedSendCompletion");
    rcvdCompletionField.setAccessible(true);
    var rcvdSuccessField = BlockTransmitter.class.getDeclaredField("receivedSendSuccess");
    rcvdSuccessField.setAccessible(true);
    var pendingField = BlockTransmitter.class.getDeclaredField("blockSendsPending");
    pendingField.setAccessible(true);

    synchronized (senderThread) {
      // no unsent
      unsentField.set(tx, new ArrayDeque<Integer>());
      // all bits set to true
      BitArray bits = new BitArray(prb.packets);
      for (int i = 0; i < prb.packets; i++) bits.setBit(i, true);
      sentPacketsField.set(tx, bits);
      // no pending sends and completion acked with success
      pendingField.setInt(tx, 0);
      rcvdCompletionField.setBoolean(tx, true);
      rcvdSuccessField.setBoolean(tx, true);

      assertTrue(tx.maybeAllSent(), "All sent should be detected");
      assertTrue(tx.maybeComplete(), "maybeComplete should return true when ready");
    }
    // Act: caller must invoke callback outside the lock per contract
    tx.callCallback(true);

    // Assert
    assertEquals(1, callback.get(), "Completion should indicate success");
  }

  @Test
  @DisplayName("receiveSendAborted_whenReceiverCancels_cascadesAbortAndCallsCallbackFalse")
  @SuppressWarnings("java:S100")
  void receiveSendAborted_whenReceiverCancels_cascadesAbortAndCallsCallbackFalse()
      throws Exception {
    // Arrange
    int packets = 2;
    int packetSize = 8;
    PartiallyReceivedBlock prb = prbWithAllData(packets, packetSize);
    TestCounter counter = new TestCounter();
    counter.highHtl = false;

    when(peer.getBootID()).thenReturn(1L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getWeakRef()).thenAnswer(inv -> new WeakReference<PeerContext>(peer));
    when(peer.shortToString()).thenReturn("peer#sendAborted");

    // Accumulate pending items so cancelItemsPending() will attempt to unqueue them on abort
    Deque<MessageItem> queued = new ArrayDeque<>();
    doAnswer(
            inv -> {
              Message msg = inv.getArgument(0, Message.class);
              AsyncMessageCallback c = inv.getArgument(1, AsyncMessageCallback.class);
              // Acknowledge immediately so blockSendsPending reaches 0 and completion can fire
              if (c != null) {
                c.sent();
                c.acknowledged();
              }
              MessageItem item = new MessageItem(msg, new AsyncMessageCallback[] {c}, counter);
              queued.add(item);
              return item;
            })
        .when(peer)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(counter));
    when(peer.unqueueMessage(any()))
        .thenAnswer(inv -> queued.remove(inv.getArgument(0, MessageItem.class)));

    AtomicInteger callback = new AtomicInteger(-1);
    BlockTransmitter.BlockTransmitterCompletion completion =
        success -> callback.set(success ? 1 : 0);

    // Spy the MessageCore to capture the sendAborted filter callback
    MessageCore usmSpy = Mockito.spy(new MessageCore(executor));
    final AsyncMessageFilterCallback[] capturedAbortCb = new AsyncMessageFilterCallback[1];
    Mockito.doAnswer(
            inv -> {
              MessageFilter f = inv.getArgument(0, MessageFilter.class);
              AsyncMessageFilterCallback cb = inv.getArgument(1, AsyncMessageFilterCallback.class);
              // Capture callback for sendAborted filters
              if (f.toString().endsWith(":sendAborted")) {
                capturedAbortCb[0] = cb;
              }
              return null;
            })
        .when(usmSpy)
        .addAsyncFilter(any(MessageFilter.class), any(AsyncMessageFilterCallback.class), any());

    long uid = 7L;
    BlockTransmitter tx =
        new BlockTransmitter(
            usmSpy,
            ticker,
            peer,
            uid,
            prb,
            counter,
            BlockTransmitter.ALWAYS_CASCADE,
            completion,
            /*realTime*/ false,
            null);

    // Act
    tx.sendAsync();
    // Fire the captured cb directly with a fabricated sendAborted message
    Message aborted = messageFromPeer(DMT.createSendAborted(uid, 123, "Receiver cancelled"), peer);
    capturedAbortCb[0].onMatched(aborted);

    // Assert
    assertEquals(0, callback.get(), "Completion should indicate failure");
  }

  @Test
  @DisplayName("sendAsync_whenPeerDisconnects_triggersFailureAndCallbackFalse")
  @SuppressWarnings("java:S100")
  void sendAsync_whenPeerDisconnects_triggersFailureAndCallbackFalse() throws Exception {
    // Arrange
    int packets = 2;
    int packetSize = 4;
    PartiallyReceivedBlock prb = prbWithAllData(packets, packetSize);
    TestCounter counter = new TestCounter();

    when(peer.getBootID()).thenReturn(1L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getWeakRef()).thenAnswer(inv -> new WeakReference<PeerContext>(peer));
    when(peer.shortToString()).thenReturn("peer#disc");

    // Let the first send succeed, then immediately simulate a disconnect on filters
    doAnswer(
            inv -> {
              Message msg = inv.getArgument(0, Message.class);
              AsyncMessageCallback c = inv.getArgument(1, AsyncMessageCallback.class);
              return new MessageItem(msg, new AsyncMessageCallback[] {c}, counter);
            })
        .when(peer)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(counter));

    AtomicInteger callback = new AtomicInteger(-1);
    BlockTransmitter.BlockTransmitterCompletion completion =
        success -> callback.set(success ? 1 : 0);

    long uid = 999L;
    BlockTransmitter tx =
        new BlockTransmitter(
            usm,
            new ImmediateTicker(executor, true),
            peer,
            uid,
            prb,
            counter,
            BlockTransmitter.NEVER_CASCADE,
            completion,
            false,
            null);

    // Act
    tx.sendAsync();
    // Simulate transport layer disconnect while waiting
    usm.onDisconnect(peer);

    // Assert
    assertEquals(0, callback.get(), "Completion should indicate failure after disconnect");
  }

  @Test
  @DisplayName("timeoutAfterAllSent_whenNoAllReceived_callsCallbackFalse")
  @SuppressWarnings("java:S100")
  void timeoutAfterAllSent_whenNoAllReceived_callsCallbackFalse() throws Exception {
    // Arrange
    int packets = 2;
    int packetSize = 16;
    PartiallyReceivedBlock prb = prbWithAllData(packets, packetSize);
    TestCounter counter = new TestCounter();

    when(peer.getBootID()).thenReturn(1L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getWeakRef()).thenAnswer(inv -> new WeakReference<PeerContext>(peer));
    when(peer.shortToString()).thenReturn("peer#timeout");

    // Immediately acknowledge each send, but do NOT send allReceived
    doAnswer(
            inv -> {
              Message msg = inv.getArgument(0, Message.class);
              AsyncMessageCallback c = inv.getArgument(1, AsyncMessageCallback.class);
              if (c != null) {
                c.sent();
                c.acknowledged();
              }
              return new MessageItem(msg, new AsyncMessageCallback[] {c}, counter);
            })
        .when(peer)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(counter));

    AtomicInteger callback = new AtomicInteger(-1);
    BlockTransmitter.BlockTransmitterCompletion completion =
        success -> callback.set(success ? 1 : 0);

    long uid = 2024L;
    BlockTransmitter tx =
        new BlockTransmitter(
            usm,
            ticker,
            peer,
            uid,
            prb,
            counter,
            BlockTransmitter.NEVER_CASCADE,
            completion,
            false,
            null);

    // Act
    tx.sendAsync();
    // Ensure a timeout is enqueued even if completion path didn't check yet
    tx.scheduleTimeoutAfterBlockSends();
    // The transmitter will send a sendAborted; now simulate the receiver's acknowledging
    // sendAborted so completion can finalize immediately.
    Message ackAbort =
        messageFromPeer(
            DMT.createSendAborted(uid, RetrievalException.RECEIVER_DIED, "timeout"), peer);
    usm.checkFilters(ackAbort, null);
    // Assert
    assertEquals(0, callback.get(), "Completion should indicate failure after timeout");
    // sanity: still no success path
    assertFalse(prb.isAborted(), "PRB is not necessarily aborted on sender-side timeout");
  }
}
