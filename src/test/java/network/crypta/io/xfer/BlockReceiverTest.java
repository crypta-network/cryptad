package network.crypta.io.xfer;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.node.MessageItem;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTransport;
import network.crypta.node.SyncSendWaitedTooLongException;
import network.crypta.support.BitArray;
import network.crypta.support.Buffer;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class BlockReceiverTest {

  private static final long UID = 42L;

  // Inline executor: run callbacks synchronously on the caller thread for determinism.
  private final PriorityAwareExecutor inlineExecutor =
      new PriorityAwareExecutor() {
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
      };

  private MessageCore messageCore;

  @Mock private Ticker ticker; // not used by BlockReceiver paths under test

  @Mock private ByteCounter byteCounter; // optional accounting

  @BeforeEach
  void setUp() {
    messageCore = new MessageCore(inlineExecutor);
  }

  private static final class ConnectedPeer {
    private final PeerContext peer;
    private final PeerTransport transport;

    private ConnectedPeer(PeerContext peer, PeerTransport transport) {
      this.peer = peer;
      this.transport = transport;
    }
  }

  @Test
  void receive_whenAllPacketsArrive_expectCompleteAndAllReceivedSent() throws Exception {
    // Arrange
    ConnectedPeer sender = mockConnectedPeerContext();
    PeerContext senderPeer = sender.peer;
    PeerTransport transport = sender.transport;

    int packets = 3;
    int packetSize = 4;
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(packets, packetSize);

    BlockReceiver receiver = newRealtimeReceiver(senderPeer, prb, false);

    AtomicReference<byte[]> received = new AtomicReference<>();
    AtomicReference<RetrievalException> failed = new AtomicReference<>();

    // Capture sendAsync to verify that allReceived was emitted.
    doAnswer(
            inv -> {
              Message msg = inv.getArgument(0, Message.class);
              assertEquals(DMT.allReceived, msg.getSpec());
              assertEquals(UID, msg.getLong(DMT.UID));
              // Return a minimal MessageItem to satisfy callers.
              return new MessageItem(msg, null, byteCounter);
            })
        .when(transport)
        .sendAsync(any(Message.class), eq(null), eq(byteCounter));

    // Act: start to receive
    receiver.receive(
        new BlockReceiver.BlockReceiverCompletion() {
          @Override
          public void blockReceived(byte[] buf) {
            received.set(buf);
          }

          @Override
          public void blockReceiveFailed(RetrievalException e) {
            failed.set(e);
          }
        });

    // Feed packets synchronously via MessageCore so the installed filter matches by UID+source.
    byte[] data = new byte[packets * packetSize];
    for (int i = 0; i < data.length; i++) data[i] = (byte) i;
    for (int packetNo = 0; packetNo < packets; packetNo++) {
      BitArray sent = new BitArray(packets);
      sent.setBit(packetNo, true);
      Buffer chunk = new Buffer(data, packetNo * packetSize, packetSize);
      Message tx = DMT.createPacketTransmit(UID, packetNo, sent, chunk, true);
      deliverFrom(senderPeer, tx);
    }

    // Assert
    assertNull(failed.get(), "Should not have failed the receive");
    assertNotNull(received.get(), "Expected the full block to be delivered");
    assertArrayEquals(data, received.get(), "Assembled block mismatch");
    // allReceived must be sent exactly once on completion
    verify(transport, times(1)).sendAsync(any(Message.class), eq(null), eq(byteCounter));
    // Running receives counter is diagnostic-only and may be decremented by both
    // the immediate failure path and the listener-triggered completion; avoid asserting it.
  }

  @Test
  void receive_whenSenderAborts_expectFailureAndAckSentAndFlagTrue() throws Exception {
    // Arrange
    ConnectedPeer sender = mockConnectedPeerContext();
    PeerContext senderPeer = sender.peer;
    PeerTransport transport = sender.transport;

    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 3);
    BlockReceiver receiver =
        new BlockReceiver(
            new BlockTransferContext(messageCore, ticker, senderPeer, UID, prb, byteCounter, false),
            new NoopTimeoutHandler(),
            false);

    AtomicReference<byte[]> received = new AtomicReference<>();
    AtomicReference<RetrievalException> failed = new AtomicReference<>();

    // Capture the acknowledgment sendAborted that BlockReceiver should emit on failure.
    final AtomicReference<Message> ackMessage = new AtomicReference<>();
    doAnswer(
            inv -> {
              Message msg = inv.getArgument(0, Message.class);
              ackMessage.set(msg);
              return new MessageItem(msg, null, byteCounter);
            })
        .when(transport)
        .sendAsync(any(Message.class), eq(null), eq(byteCounter));

    receiver.receive(
        new BlockReceiver.BlockReceiverCompletion() {
          @Override
          public void blockReceived(byte[] buf) {
            received.set(buf);
          }

          @Override
          public void blockReceiveFailed(RetrievalException e) {
            failed.set(e);
          }
        });

    int reason = RetrievalException.IO_ERROR;
    String description = "disk full";
    Message abort = DMT.createSendAborted(UID, reason, description);
    deliverFrom(senderPeer, abort);

    // Assert
    assertNull(received.get(), "Should not have received a block");
    assertNotNull(failed.get(), "Expected a RetrievalException on abort");
    assertEquals(reason, failed.get().getReason());
    assertTrue(receiver.senderAborted());

    // The receiver must acknowledge with a sendAborted echo using the same UID and reason
    Message ack = ackMessage.get();
    assertNotNull(ack, "Expected an acknowledgment sendAborted");
    assertEquals(DMT.sendAborted, ack.getSpec());
    assertEquals(UID, ack.getLong(DMT.UID));
    assertEquals(reason, ack.getInt(DMT.REASON));
    // Description is prefixed by the receiver code if it doesn't contain "Upstream"
    assertTrue(ack.getString(DMT.DESCRIPTION).contains("Upstream transmit error:"));
    // Diagnostic counter isn't asserted; see the note above.
  }

  @Test
  void receive_whenNotConnected_expectImmediateFailure() {
    // Arrange: simulate a disconnected peer so addAsyncFilter throws DisconnectedException
    PeerContext sender = mockDisconnectedPeerContext();
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(1, 1);

    BlockReceiver receiver =
        new BlockReceiver(
            new BlockTransferContext(messageCore, ticker, sender, UID, prb, byteCounter, true),
            new NoopTimeoutHandler(),
            false);

    AtomicReference<RetrievalException> failed = receiveAndCaptureFailure(receiver);

    // Assert
    assertNotNull(failed.get(), "Expected immediate failure due to disconnection");
    assertEquals(RetrievalException.SENDER_DISCONNECTED, failed.get().getReason());
    // Diagnostic counter isn't asserted; see the note above.
  }

  @Test
  void receive_whenCompleteAfterAckedAllReceivedTrue_sendSyncAttemptedAndCompletes()
      throws Exception {
    // Arrange: use a PeerNode (not just PeerContext) so the receiver uses sendSync
    PeerNode sender = org.mockito.Mockito.mock(PeerNode.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    org.mockito.Mockito.lenient().when(sender.isConnected()).thenReturn(true);
    org.mockito.Mockito.lenient().when(sender.getBootID()).thenReturn(7L);
    org.mockito.Mockito.lenient().when(sender.shortToString()).thenReturn("peer");
    org.mockito.Mockito.lenient().when(sender.transport()).thenReturn(transport);
    WeakReference<PeerContext> ref = new WeakReference<>(sender);
    org.mockito.Mockito.lenient().when(sender.getWeakRef()).thenReturn(ref);

    // For all sending that happen outside sendSync (none expected here), return a MessageItem

    // Make sendSync throw the timeout to exercise the catch path; completion should still occur
    org.mockito.Mockito.doThrow(new SyncSendWaitedTooLongException())
        .when(transport)
        .sendSync(any(Message.class), eq(byteCounter), eq(true));

    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 2);
    BlockReceiver receiver = newRealtimeReceiver(sender, prb, true);

    AtomicReference<byte[]> received = new AtomicReference<>();
    receiver.receive(
        new BlockReceiver.BlockReceiverCompletion() {
          @Override
          public void blockReceived(byte[] buf) {
            received.set(buf);
          }

          @Override
          public void blockReceiveFailed(RetrievalException e) {
            // not expected
          }
        });

    // Act: deliver both packets
    byte[] data = new byte[] {1, 2, 3, 4};
    for (int packetNo = 0; packetNo < 2; packetNo++) {
      BitArray sent = new BitArray(2);
      sent.setBit(packetNo, true);
      Buffer chunk = new Buffer(data, packetNo * 2, 2);
      Message tx = DMT.createPacketTransmit(UID, packetNo, sent, chunk, true);
      deliverFrom(sender, tx);
    }

    // Assert: full block delivered and sendSync attempted once with allReceived
    assertNotNull(received.get(), "Expected block completion");
    assertArrayEquals(data, received.get());
    verify(transport, times(1)).sendSync(any(Message.class), eq(byteCounter), eq(true));
    // Diagnostic counter isn't asserted; see the note above.
  }

  // --- helpers ---

  /**
   * Helper that constructs a realtime BlockReceiver for tests.
   *
   * <p>Extraction keeps test methods concise and focused while centralizing the wiring of
   * frequently repeated constructor arguments. It returns only the created receiver (single output)
   * and requires just two inputs plus a flag, keeping the parameter count low.
   */
  private BlockReceiver newRealtimeReceiver(
      PeerContext sender, PartiallyReceivedBlock prb, boolean completeAfterAcked) {
    return new BlockReceiver(
        new BlockTransferContext(messageCore, ticker, sender, UID, prb, byteCounter, true),
        new NoopTimeoutHandler(),
        completeAfterAcked);
  }

  private ConnectedPeer mockConnectedPeerContext() throws NotConnectedException {
    PeerContext sender = org.mockito.Mockito.mock(PeerContext.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    org.mockito.Mockito.lenient().when(sender.isConnected()).thenReturn(true);
    org.mockito.Mockito.lenient().when(sender.getBootID()).thenReturn(1L);
    org.mockito.Mockito.lenient().when(sender.shortToString()).thenReturn("peer");
    org.mockito.Mockito.lenient().when(sender.transport()).thenReturn(transport);
    WeakReference<PeerContext> ref = new WeakReference<>(sender);
    org.mockito.Mockito.doReturn(ref).when(sender).getWeakRef();
    org.mockito.Mockito.lenient()
        .doAnswer(inv -> new MessageItem(inv.getArgument(0, Message.class), null, byteCounter))
        .when(transport)
        .sendAsync(any(Message.class), eq(null), eq(byteCounter));
    return new ConnectedPeer(sender, transport);
  }

  private PeerContext mockDisconnectedPeerContext() {
    PeerContext sender = org.mockito.Mockito.mock(PeerContext.class);
    PeerTransport transport = org.mockito.Mockito.mock(PeerTransport.class);
    org.mockito.Mockito.lenient().when(sender.isConnected()).thenReturn(false);
    org.mockito.Mockito.lenient().when(sender.shortToString()).thenReturn("peer");
    org.mockito.Mockito.lenient().when(sender.transport()).thenReturn(transport);
    return sender;
  }

  private void deliverFrom(PeerContext source, Message toSend) {
    byte[] enc = toSend.encodeToPacket();
    Message decoded = messageCore.decodeSingleMessage(enc, 0, enc.length, source, 0);
    // No packet socket handler semantics needed for this test; null is fine.
    messageCore.checkFilters(decoded, null);
  }

  /**
   * Starts receiving and returns a reference that will be set on failure.
   *
   * <p>This extracts the repeated callback wiring used by tests that only care about failure
   * outcomes, keeping the calling methods concise. The returned {@link AtomicReference} is the sole
   * output of this helper, matching the test assertions that follow.
   */
  private AtomicReference<RetrievalException> receiveAndCaptureFailure(BlockReceiver receiver) {
    AtomicReference<RetrievalException> failed = new AtomicReference<>();
    receiver.receive(
        new BlockReceiver.BlockReceiverCompletion() {
          @Override
          public void blockReceived(byte[] buf) {
            // not expected in failure-only tests
          }

          @Override
          public void blockReceiveFailed(RetrievalException e) {
            failed.set(e);
          }
        });
    return failed;
  }

  private static final class NoopTimeoutHandler
      implements BlockReceiver.BlockReceiverTimeoutHandler {
    @Override
    public void onFirstTimeout() {
      // Intentionally empty: this test double does not exercise timeout behavior.
      // BlockReceiverTest asserts happy-path and explicit abort flows only.
    }

    @Override
    public void onFatalTimeout(PeerContext source) {
      // Intentionally empty: fatal timeout handling is out of scope for these unit tests.
      // Using a no-op keeps the focus on receive/abort logic without adding side effects.
    }
  }
}
