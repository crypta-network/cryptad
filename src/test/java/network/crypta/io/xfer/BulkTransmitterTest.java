package network.crypta.io.xfer;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PacketSocketHandler;
import network.crypta.io.comm.PeerContext;
import network.crypta.node.MessageItem;
import network.crypta.node.PeerTransport;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class BulkTransmitterTest {

  private static final int BLOCK_SIZE = 1024;
  private static final int BLOCKS = 3;
  private static final long UID = 123L;

  @Mock ByteCounter ctr;

  // Inline executor used by MessageCore (runs tasks on the calling thread deterministically).
  private static final class InlineExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
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

  /**
   * Buffer that can block one write offset to force a deterministic ordering in race-condition
   * tests.
   */
  private static final class BlockingWriteBuffer extends ByteArrayRandomAccessBuffer {
    private final long blockedOffset;
    private final CountDownLatch writeStarted = new CountDownLatch(1);
    private final CountDownLatch releaseWrite = new CountDownLatch(1);

    BlockingWriteBuffer(byte[] initialData, long blockedOffset) {
      super(initialData);
      this.blockedOffset = blockedOffset;
    }

    @Override
    public synchronized void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
        throws IOException {
      if (fileOffset == blockedOffset) {
        writeStarted.countDown();
        try {
          if (!releaseWrite.await(10, TimeUnit.SECONDS)) {
            throw new IOException("Timed out waiting to release blocked write");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IOException("Interrupted while waiting to release blocked write", e);
        }
      }
      super.pwrite(fileOffset, buf, bufOffset, length);
    }

    boolean awaitWriteStarted(long timeout, TimeUnit unit) throws InterruptedException {
      return writeStarted.await(timeout, unit);
    }

    void releaseBlockedWrite() {
      releaseWrite.countDown();
    }
  }

  private MessageCore usm;

  @BeforeEach
  void setUp() {
    usm = new MessageCore(new InlineExecutor());
  }

  private PartiallyReceivedBulk newPrb() {
    int size = BLOCKS * BLOCK_SIZE;
    ByteArrayRandomAccessBuffer rab = new ByteArrayRandomAccessBuffer(size);
    // Fill deterministic content; the transmitter does not inspect it but PRB reads it back.
    byte[] pattern = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) pattern[i] = (byte) (i & 0xFF);
    for (int b = 0; b < BLOCKS; b++) {
      try {
        rab.pwrite((long) b * BLOCK_SIZE, pattern, 0, BLOCK_SIZE);
      } catch (Exception _) {
        // ByteArrayRandomAccessBuffer bounds are correct for our input; no exception expected.
      }
    }
    return new PartiallyReceivedBulk(usm, size, BLOCK_SIZE, rab, true);
  }

  @Test
  void send_whenAllBlocksPresentAndNoWait_expectSuccessAndAllSentCallback() throws Exception {
    PartiallyReceivedBulk prb = newPrb();

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(42L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(2);
    when(peer.shortToString()).thenReturn("peerX");
    // getWeakRef() is not used by BulkTransmitter; no need to stub.

    // Ack every packet immediately and report payload via ByteCounter
    doAnswer(
            inv -> {
              AsyncMessageCallback cb = inv.getArgument(1);
              if (cb != null) {
                cb.sent();
                cb.acknowledged();
              }
              return mock(MessageItem.class);
            })
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));

    // Capture baseline success counters
    long[] before = BulkTransmitter.transferSuccess();

    BulkTransmitter.AllSentCallback allSent = mock(BulkTransmitter.AllSentCallback.class);
    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, allSent);

    boolean ok = bt.send();
    assertTrue(ok, "send() should return true on successful no-wait transfer");

    // ByteCounter should be notified once per block with the configured block size
    verify(ctr, times(BLOCKS)).sentPayload(BLOCK_SIZE);

    // All-sent callback should be invoked exactly once with anyFailed=false
    ArgumentCaptor<Boolean> anyFailed = ArgumentCaptor.forClass(Boolean.class);
    verify(allSent, times(1)).allSent(eq(bt), anyFailed.capture());
    assertEquals(Boolean.FALSE, anyFailed.getValue(), "allSent should report no failures");

    long[] after = BulkTransmitter.transferSuccess();
    assertEquals(before[0] + 1, after[0], "transfersCompleted should increase by 1");
    assertEquals(before[1] + 1, after[1], "transfersSucceeded should increase by 1");
  }

  @Test
  void send_whenPeerNotConnected_expectDisconnectedAndCancelReasonSet() throws Exception {
    PartiallyReceivedBulk prb = newPrb();

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(7L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(1);
    when(peer.shortToString()).thenReturn("peerY");
    // getWeakRef() not needed here

    // Throw on any sendAsync to simulate immediate disconnect.
    doAnswer(
            inv -> {
              throw new NotConnectedException();
            })
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    assertThrows(DisconnectedException.class, bt::send, "send() should rethrow as Disconnected");
    assertEquals("Disconnected", bt.getCancelReason());

    // A best-effort aborted notification is attempted; it may also throw and is ignored.
    verify(transport, times(1))
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));
  }

  @Test
  void onAborted_whenCalledTwice_expectSendAbortedOnlyOnce() throws Exception {
    PartiallyReceivedBulk prb = newPrb();

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(9L);
    when(peer.isConnected()).thenReturn(true);

    // For data packets (not used in this test) we would ack immediately. Here the callback is
    // null for the aborted message, so just accept the call.
    doAnswer(inv -> mock(MessageItem.class))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    bt.onAborted();
    bt.onAborted();

    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCaptor.capture(), isNull(), eq(ctr));
    assertEquals(DMT.FNPBulkSendAborted, msgCaptor.getValue().getSpec());
    assertEquals(UID, msgCaptor.getValue().getLong(DMT.UID));
    // Constructor interactions (e.g., getBootID) are expected; nothing else to assert here.
  }

  @Test
  void filters_whenReceiveAbortedMessage_expectCancelAndAllSent() throws Exception {
    PartiallyReceivedBulk prb = newPrb();

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(111L);
    when(peer.isConnected()).thenReturn(true);
    // Only the null-callback variant is exercised by cancel()'s aborted notify in this test.
    doAnswer(inv -> mock(MessageItem.class))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), eq(ctr));

    BulkTransmitter.AllSentCallback allSent = mock(BulkTransmitter.AllSentCallback.class);
    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, allSent);

    // Craft a mocked inbound message that matches the registered filter: type + source + UID.
    Message aborted = mock(Message.class);
    when(aborted.getSpec()).thenReturn(DMT.FNPBulkReceiveAborted);
    when(aborted.getSource()).thenReturn(peer);
    when(aborted.isSet(DMT.UID)).thenReturn(true);
    when(aborted.getFromPayload(DMT.UID)).thenReturn(UID);

    // Deliver to MessageCore; onMatched() cancels the transmitter.
    prb.usm.checkFilters(aborted, mock(PacketSocketHandler.class));

    assertEquals(
        "Other side sent FNPBulkReceiveAborted", bt.getCancelReason(), "cancel reason should set");
    verify(allSent, times(1)).allSent(bt, false);
  }

  @Test
  void send_whenNewBlockArrivesWithPacketsInFlight_expectOpportunisticSecondSend()
      throws Exception {
    // Prepare a PRB with two blocks but no initial data available.
    int blocks = 2;
    int size = blocks * BLOCK_SIZE;
    ByteArrayRandomAccessBuffer rab = new ByteArrayRandomAccessBuffer(size);
    byte[] pattern = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) pattern[i] = (byte) (i & 0xFF);
    for (int b = 0; b < blocks; b++) rab.pwrite((long) b * BLOCK_SIZE, pattern, 0, BLOCK_SIZE);
    PartiallyReceivedBulk prb = new PartiallyReceivedBulk(usm, size, BLOCK_SIZE, rab, false);

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(222L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(2); // Window allows 2 in flight
    when(peer.shortToString()).thenReturn("peerZ");

    // Control acknowledgements to keep the first packet in flight while the second is queued.
    CountDownLatch firstSent = new CountDownLatch(1);
    CountDownLatch secondSent = new CountDownLatch(1);
    AtomicReference<AsyncMessageCallback> cb0 = new AtomicReference<>();
    AtomicInteger calls = new AtomicInteger();

    doAnswer(
            inv -> {
              AsyncMessageCallback cb = inv.getArgument(1);
              int idx = calls.getAndIncrement();
              if (idx == 0) {
                cb0.set(cb);
                cb.sent(); // Mark as sent but deliberately do not ack yet
                firstSent.countDown();
              } else if (idx == 1) {
                cb.sent();
                // Ack the second immediately to let the send loop progress to completion.
                cb.acknowledged();
                secondSent.countDown();
              }
              return mock(MessageItem.class);
            })
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    // Start sending in the background; initially there are no blocks, so it will wait.
    CompletableFuture<Boolean> result =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return bt.send();
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            });

    // Deliver the first block; the transmitter should send it and keep it in flight.
    prb.received(0, pattern, 0, BLOCK_SIZE);
    assertTrue(firstSent.await(5, TimeUnit.SECONDS), "first packet sent");

    // While the first remains in-flight, deliver the second block. The new logic should wake and
    // queue it immediately, without waiting for inFlight=0.
    prb.received(1, pattern, 0, BLOCK_SIZE);
    assertTrue(secondSent.await(10, TimeUnit.SECONDS), "second packet sent opportunistically");

    // Now allow the first packet to complete so send() can finish.
    cb0.get().acknowledged();

    assertTrue(result.get(10, TimeUnit.SECONDS), "send() should succeed");
    // Verify both payloads were accounted for.
    verify(ctr, times(2)).sentPayload(BLOCK_SIZE);
  }

  @Test
  void send_whenNoWaitAndWholeFileSetBeforeNotification_expectNoPrematureCompletion()
      throws Exception {
    // Prepare a PRB with two blocks but no initial data available.
    int blocks = 2;
    int size = blocks * BLOCK_SIZE;
    byte[] backing = new byte[size];
    byte[] pattern = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) pattern[i] = (byte) (i & 0xFF);
    System.arraycopy(pattern, 0, backing, 0, BLOCK_SIZE);
    System.arraycopy(pattern, 0, backing, BLOCK_SIZE, BLOCK_SIZE);
    BlockingWriteBuffer rab = new BlockingWriteBuffer(backing, BLOCK_SIZE);
    PartiallyReceivedBulk prb = new PartiallyReceivedBulk(usm, size, BLOCK_SIZE, rab, false);

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(223L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(2);
    when(peer.shortToString()).thenReturn("peerRace");

    CountDownLatch firstSent = new CountDownLatch(1);
    CountDownLatch allowFirstSendReturn = new CountDownLatch(1);
    CountDownLatch secondSent = new CountDownLatch(1);
    AtomicReference<AsyncMessageCallback> firstCallback = new AtomicReference<>();
    AtomicInteger calls = new AtomicInteger();

    doAnswer(
            inv -> {
              AsyncMessageCallback cb = inv.getArgument(1);
              int idx = calls.getAndIncrement();
              if (idx == 0) {
                firstCallback.set(cb);
                cb.sent();
                firstSent.countDown();
                if (!allowFirstSendReturn.await(10, TimeUnit.SECONDS)) {
                  throw new AssertionError("first send did not get release signal");
                }
              } else if (idx == 1) {
                cb.sent();
                cb.acknowledged();
                secondSent.countDown();
              }
              return mock(MessageItem.class);
            })
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    CompletableFuture<Boolean> result =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return bt.send();
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            });

    // Send the first block and hold sendAsync return to control sender progress.
    prb.received(0, pattern, 0, BLOCK_SIZE);
    assertTrue(firstSent.await(5, TimeUnit.SECONDS), "first packet sent");

    // Receive block 1 on another thread; this sets hasWholeFile=true but blocks before notifying
    // transmitter.blockReceived(), creating the historical race window.
    Thread receiveSecond =
        Thread.ofPlatform()
            .name("bt-race-receive-second")
            .start(() -> prb.received(1, pattern, 0, BLOCK_SIZE));
    assertTrue(
        rab.awaitWriteStarted(5, TimeUnit.SECONDS), "second block write reached blocked section");

    // Let the first send return and give the sender a chance to evaluate no-wait completion.
    allowFirstSendReturn.countDown();
    assertThrows(
        TimeoutException.class,
        () -> result.get(300, TimeUnit.MILLISECONDS),
        "sender must not complete before it has observed block 1");

    // Now release block 1 write so PartiallyReceivedBulk can notify transmitter.blockReceived().
    rab.releaseBlockedWrite();
    receiveSecond.join(5_000);

    assertTrue(secondSent.await(10, TimeUnit.SECONDS), "second packet sent after notification");
    firstCallback.get().acknowledged();
    assertTrue(result.get(10, TimeUnit.SECONDS), "send() should succeed");
    verify(ctr, times(2)).sentPayload(BLOCK_SIZE);
  }

  @Test
  void send_whenQueueEmpty_thenNewBlockArrives_expectWakeFromAckWait() throws Exception {
    // Prepare a PRB with one block but initially no data available.
    int blocks = 1;
    int size = blocks * BLOCK_SIZE;
    ByteArrayRandomAccessBuffer rab = new ByteArrayRandomAccessBuffer(size);
    byte[] pattern = new byte[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) pattern[i] = (byte) (i & 0xFF);
    PartiallyReceivedBulk prb = new PartiallyReceivedBulk(usm, size, BLOCK_SIZE, rab, false);

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(333L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(1);
    when(peer.shortToString()).thenReturn("peerAckWait");

    CountDownLatch sent = new CountDownLatch(1);
    doAnswer(
            inv -> {
              AsyncMessageCallback cb = inv.getArgument(1);
              cb.sent();
              cb.acknowledged();
              sent.countDown();
              return mock(MessageItem.class);
            })
        .when(transport)
        .sendAsync(any(Message.class), any(AsyncMessageCallback.class), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    // Start sending in the background; with no blocks and no in-flight packets, the sender enters
    // the ack-wait path. When a block arrives, it should wake immediately and send it.
    CompletableFuture<Boolean> result =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return bt.send();
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            });

    // No fixed sleep: rely on the latch below to await the async send.
    prb.received(0, pattern, 0, BLOCK_SIZE);

    assertTrue(sent.await(5, TimeUnit.SECONDS), "packet sent after wake");
    assertTrue(result.get(5, TimeUnit.SECONDS), "send() should succeed fast");
    verify(ctr, times(1)).sentPayload(BLOCK_SIZE);
  }

  @Test
  void send_whenAbortedDuringAckWait_expectImmediateReturn() throws Exception {
    // PRB with no initial data so sender enters the ACK-wait path (no in-flight, nothing to send).
    int blocks = 1;
    int size = blocks * BLOCK_SIZE;
    ByteArrayRandomAccessBuffer rab = new ByteArrayRandomAccessBuffer(size);
    PartiallyReceivedBulk prb = new PartiallyReceivedBulk(usm, size, BLOCK_SIZE, rab, false);

    PeerContext peer = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(peer.transport()).thenReturn(transport);
    when(peer.getBootID()).thenReturn(444L);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getThrottleWindowSize()).thenReturn(1);
    when(peer.shortToString()).thenReturn("peerAbortAckWait");

    // For the aborted notification, BulkTransmitter sends FNPBulkSendAborted with a null callback.
    doAnswer(inv -> mock(MessageItem.class))
        .when(transport)
        .sendAsync(any(Message.class), isNull(), eq(ctr));

    BulkTransmitter bt = new BulkTransmitter(prb, peer, UID, true, ctr, false, null);

    // Run send() in the background; with no blocks available, it will enter waitForAckOrAbort().
    CompletableFuture<Boolean> result =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return bt.send();
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            });

    // Abort locally; the transmitter should break its wait loop immediately and return false.
    prb.abort(42, "test-abort");

    assertEquals(false, result.get(2, TimeUnit.SECONDS), "send() should fail promptly on abort");

    // Verify the sender attempted to notify the peer once about the aborted send.
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCaptor.capture(), isNull(), eq(ctr));
    Message aborted = msgCaptor.getValue();
    assertEquals(DMT.FNPBulkSendAborted, aborted.getSpec());
    assertEquals(UID, aborted.getLong(DMT.UID));
  }
}
