package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.SocketHandler;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeTransportTest {

  private static final ByteCounter NOOP_COUNTER =
      new ByteCounter() {
        @Override
        public void receivedBytes(int x) {
          // no-op
        }

        @Override
        public void sentBytes(int x) {
          // no-op
        }

        @Override
        public void sentPayload(int x) {
          // no-op
        }
      };

  @Test
  void sendAsync_whenNotConnected_invokesDisconnectedAndThrows() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);
    when(peer.isConnected()).thenReturn(false);

    Message msg = DMT.createFNPPing(1);

    AsyncMessageCallback cb = Mockito.mock(AsyncMessageCallback.class);
    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act + Assert
    assertThrows(NotConnectedException.class, () -> transport.sendAsync(msg, cb, null));
    verify(cb).disconnected();
    verify(peer, never()).incrementSentMessageType(ArgumentMatchers.anyString());
  }

  @Test
  void sendAsync_whenQueueExceedsMax_wakesSender() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getMaxPacketSize()).thenReturn(100);

    PeerMessageQueue queue = Mockito.mock(PeerMessageQueue.class);
    when(peer.getMessageQueue()).thenReturn(queue);
    when(queue.queueAndEstimateSize(
            ArgumentMatchers.any(MessageItem.class), ArgumentMatchers.eq(100)))
        .thenReturn(150);

    Message msg = DMT.createFNPPing(2);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    MessageItem item = transport.sendAsync(msg, null, NOOP_COUNTER);

    // Assert
    assertNotNull(item);
    verify(peer).incrementSentMessageType(msg.getSpec().getName());
    verify(peer).wakeUpSender();
  }

  @Test
  void sendAsync_whenQueueWithinMaxAndCoalescingEnabled_doesNotWakeSender() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);
    when(node.isEnablePacketCoalescing()).thenReturn(true);
    when(peer.isConnected()).thenReturn(true);
    when(peer.getMaxPacketSize()).thenReturn(100);

    PeerMessageQueue queue = Mockito.mock(PeerMessageQueue.class);
    when(peer.getMessageQueue()).thenReturn(queue);
    when(queue.queueAndEstimateSize(
            ArgumentMatchers.any(MessageItem.class), ArgumentMatchers.eq(100)))
        .thenReturn(50);

    Message msg = DMT.createFNPPing(3);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    MessageItem item = transport.sendAsync(msg, null, NOOP_COUNTER);

    // Assert
    assertNotNull(item);
    verify(peer, never()).wakeUpSender();
  }

  @Test
  void sendSync_whenNotConnected_propagatesNotConnectedException() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);
    when(peer.isConnected()).thenReturn(false);

    Message msg = DMT.createFNPPing(4);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act + Assert
    assertThrows(NotConnectedException.class, () -> transport.sendSync(msg, NOOP_COUNTER, false));
  }

  @Test
  void ping_whenWaitForReturnsMessage_returnsTrue() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);

    MessageCore usm = Mockito.mock(MessageCore.class);
    NodeDispatcher dispatcher = Mockito.mock(NodeDispatcher.class);
    ByteCounter pingCounter = new CountingByteCounter();
    setField(dispatcher, NodeDispatcher.class, "pingCounter", pingCounter);

    when(node.getUSM()).thenReturn(usm);
    when(node.getDispatcher()).thenReturn(dispatcher);
    when(usm.waitFor(ArgumentMatchers.any(MessageFilter.class), ArgumentMatchers.isNull()))
        .thenReturn(new Message(DMT.FNPPong));

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    boolean result = transport.ping(42);

    // Assert
    assertTrue(result);
    ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
    verify(usm)
        .send(ArgumentMatchers.eq(peer), msgCaptor.capture(), ArgumentMatchers.eq(pingCounter));
    assertSame(DMT.FNPPing, msgCaptor.getValue().getSpec());
  }

  @Test
  void ping_whenWaitForReturnsNull_returnsFalse() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);

    MessageCore usm = Mockito.mock(MessageCore.class);
    NodeDispatcher dispatcher = Mockito.mock(NodeDispatcher.class);
    ByteCounter pingCounter = new CountingByteCounter();
    setField(dispatcher, NodeDispatcher.class, "pingCounter", pingCounter);

    when(node.getUSM()).thenReturn(usm);
    when(node.getDispatcher()).thenReturn(dispatcher);
    when(usm.waitFor(ArgumentMatchers.any(MessageFilter.class), ArgumentMatchers.isNull()))
        .thenReturn(null);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    boolean result = transport.ping(1);

    // Assert
    assertFalse(result);
  }

  @Test
  void ping_whenDisconnectedException_throwsNotConnectedException() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);

    MessageCore usm = Mockito.mock(MessageCore.class);
    NodeDispatcher dispatcher = Mockito.mock(NodeDispatcher.class);
    ByteCounter pingCounter = new CountingByteCounter();
    setField(dispatcher, NodeDispatcher.class, "pingCounter", pingCounter);

    when(node.getUSM()).thenReturn(usm);
    when(node.getDispatcher()).thenReturn(dispatcher);
    when(usm.waitFor(ArgumentMatchers.any(MessageFilter.class), ArgumentMatchers.isNull()))
        .thenThrow(new DisconnectedException());

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act + Assert
    assertThrows(NotConnectedException.class, () -> transport.ping(9));
  }

  @Test
  void getThrottle_whenCalled_returnsStableInstance() {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    PacketThrottle first = transport.getThrottle();
    PacketThrottle second = transport.getThrottle();

    // Assert
    assertNotNull(first);
    assertSame(first, second);
  }

  @Test
  void getSocketHandler_whenCalled_returnsOutgoingManglerSocketHandler() {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    OutgoingPacketMangler mangler = Mockito.mock(OutgoingPacketMangler.class);
    SocketHandler socketHandler = Mockito.mock(SocketHandler.class);
    when(peer.getOutgoingMangler()).thenReturn(mangler);
    when(mangler.getSocketHandler()).thenReturn(socketHandler);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    SocketHandler result = transport.getSocketHandler();

    // Assert
    assertSame(socketHandler, result);
  }

  @Test
  void handleMessage_whenCalled_delegatesToUsmCheckFilters() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeCrypto crypto = Mockito.mock(NodeCrypto.class);
    setField(peer, PeerNode.class, "node", node);
    setField(peer, PeerNode.class, "crypto", crypto);

    MessageCore usm = Mockito.mock(MessageCore.class);
    UdpSocketHandler socket = Mockito.mock(UdpSocketHandler.class);
    when(node.getUSM()).thenReturn(usm);
    when(crypto.getSocket()).thenReturn(socket);

    Message msg = Mockito.mock(Message.class);
    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    transport.handleMessage(msg);

    // Assert
    verify(usm).checkFilters(msg, socket);
  }

  @Test
  void startProcessingDecryptedMessages_whenDecodeReturnsNull_doesNotHandle() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    setField(peer, PeerNode.class, "node", node);

    MessageCore usm = Mockito.mock(MessageCore.class);
    when(node.getUSM()).thenReturn(usm);
    when(usm.decodeSingleMessage(
            ArgumentMatchers.any(byte[].class),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.eq(peer),
            ArgumentMatchers.anyInt()))
        .thenReturn(null);

    PeerNodeTransport transport = new PeerNodeTransport(peer);
    DecodingMessageGroup group = transport.startProcessingDecryptedMessages(1);

    // Act
    group.processDecryptedMessage(new byte[] {1, 2, 3}, 0, 3, 0);
    group.complete();

    // Assert
    verify(usm, never()).checkFilters(ArgumentMatchers.any(Message.class), ArgumentMatchers.any());
  }

  @Test
  void startProcessingDecryptedMessages_whenPeerLoadStatus_handlesImmediately() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeCrypto crypto = Mockito.mock(NodeCrypto.class);
    setField(peer, PeerNode.class, "node", node);
    setField(peer, PeerNode.class, "crypto", crypto);

    MessageCore usm = Mockito.mock(MessageCore.class);
    UdpSocketHandler socket = Mockito.mock(UdpSocketHandler.class);
    when(node.getUSM()).thenReturn(usm);
    when(crypto.getSocket()).thenReturn(socket);
    when(usm.decodeSingleMessage(
            ArgumentMatchers.any(byte[].class),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.eq(peer),
            ArgumentMatchers.anyInt()))
        .thenReturn(new Message(DMT.FNPPeerLoadStatusInt));

    PeerNodeTransport transport = new PeerNodeTransport(peer);
    DecodingMessageGroup group = transport.startProcessingDecryptedMessages(1);

    // Act
    group.processDecryptedMessage(new byte[] {4, 5, 6}, 0, 3, 1);
    group.complete();

    // Assert
    verify(usm, times(1))
        .checkFilters(ArgumentMatchers.any(Message.class), ArgumentMatchers.eq(socket));
  }

  @Test
  void complete_whenNormalAndLoadLimited_expectNormalHandledBeforeLoadLimited() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeCrypto crypto = Mockito.mock(NodeCrypto.class);
    setField(peer, PeerNode.class, "node", node);
    setField(peer, PeerNode.class, "crypto", crypto);

    MessageCore usm = Mockito.mock(MessageCore.class);
    UdpSocketHandler socket = Mockito.mock(UdpSocketHandler.class);
    when(node.getUSM()).thenReturn(usm);
    when(crypto.getSocket()).thenReturn(socket);

    Message normal = new Message(DMT.FNPRejectedLoop);
    Message loadLimited = new Message(DMT.FNPCHKDataRequest);
    when(usm.decodeSingleMessage(
            ArgumentMatchers.any(byte[].class),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.anyInt(),
            ArgumentMatchers.eq(peer),
            ArgumentMatchers.anyInt()))
        .thenReturn(normal, loadLimited);

    PeerNodeTransport transport = new PeerNodeTransport(peer);
    DecodingMessageGroup group = transport.startProcessingDecryptedMessages(2);

    // Act
    group.processDecryptedMessage(new byte[] {1}, 0, 1, 0);
    group.processDecryptedMessage(new byte[] {2}, 0, 1, 0);
    group.complete();

    // Assert
    InOrder inOrder = Mockito.inOrder(usm);
    inOrder.verify(usm).checkFilters(normal, socket);
    inOrder.verify(usm).checkFilters(loadLimited, socket);
  }

  @Test
  void sendNodeToNodeMessage_whenNotConnected_removesSentTime() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeStats stats = Mockito.mock(NodeStats.class);
    setField(peer, PeerNode.class, "node", node);
    setField(stats, NodeStats.class, "nodeToNodeCounter", NOOP_COUNTER);
    when(node.getNodeStats()).thenReturn(stats);
    when(peer.isDarknet()).thenReturn(false);

    PeerNodeTransport transport = Mockito.spy(new PeerNodeTransport(peer));
    doThrow(new NotConnectedException())
        .when(transport)
        .sendAsync(
            ArgumentMatchers.any(Message.class),
            ArgumentMatchers.isNull(),
            ArgumentMatchers.any(ByteCounter.class));

    SimpleFieldSet fs = new SimpleFieldSet(true);

    // Act
    transport.sendNodeToNodeMessage(fs, 7, true, 12345L, true);

    // Assert
    assertEquals("7", fs.get("n2nType"));
    assertNull(fs.get("sentTime"));
  }

  @Test
  void sendInitialMessages_whenRealConnection_sendsFiveMessagesAndConnectedDiff() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeStats stats = Mockito.mock(NodeStats.class);
    LocationManager locationManager = Mockito.mock(LocationManager.class);
    PeerManager peerManager = Mockito.mock(PeerManager.class);
    UptimeEstimator uptimeEstimator = Mockito.mock(UptimeEstimator.class);
    network.crypta.io.comm.Peer peerRef = Mockito.mock(network.crypta.io.comm.Peer.class);

    setField(peer, PeerNode.class, "node", node);
    setField(stats, NodeStats.class, "initialMessagesCtr", NOOP_COUNTER);

    when(peer.isRealConnection()).thenReturn(true);
    when(peer.getPeer()).thenReturn(peerRef);
    when(node.getLocationManager()).thenReturn(locationManager);
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getUptimeEstimator()).thenReturn(uptimeEstimator);
    when(node.getNodeStats()).thenReturn(stats);
    when(locationManager.getLocation()).thenReturn(0.25);
    when(peerManager.getPeerLocationDoubles(true)).thenReturn(new double[] {0.1, 0.2});
    when(uptimeEstimator.getUptime()).thenReturn(0.5d);

    PeerNodeTransport transport = Mockito.spy(new PeerNodeTransport(peer));
    doReturn(Mockito.mock(MessageItem.class))
        .when(transport)
        .sendAsync(
            ArgumentMatchers.any(Message.class),
            ArgumentMatchers.isNull(),
            ArgumentMatchers.any(ByteCounter.class));

    // Act
    transport.sendInitialMessages();

    // Assert
    verify(transport, times(5))
        .sendAsync(
            ArgumentMatchers.any(Message.class),
            ArgumentMatchers.isNull(),
            ArgumentMatchers.any(ByteCounter.class));
    verify(peer).sendConnectedDiffNoderef();
  }

  @Test
  void sendInitialMessages_whenNotRealConnection_skipsLocationMessage() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeStats stats = Mockito.mock(NodeStats.class);
    LocationManager locationManager = Mockito.mock(LocationManager.class);
    PeerManager peerManager = Mockito.mock(PeerManager.class);
    UptimeEstimator uptimeEstimator = Mockito.mock(UptimeEstimator.class);
    network.crypta.io.comm.Peer peerRef = Mockito.mock(network.crypta.io.comm.Peer.class);

    setField(peer, PeerNode.class, "node", node);
    setField(stats, NodeStats.class, "initialMessagesCtr", NOOP_COUNTER);

    when(peer.isRealConnection()).thenReturn(false);
    when(peer.getPeer()).thenReturn(peerRef);
    when(node.getLocationManager()).thenReturn(locationManager);
    when(node.getPeers()).thenReturn(peerManager);
    when(node.getUptimeEstimator()).thenReturn(uptimeEstimator);
    when(node.getNodeStats()).thenReturn(stats);
    when(locationManager.getLocation()).thenReturn(0.25);
    when(peerManager.getPeerLocationDoubles(true)).thenReturn(new double[] {0.1, 0.2});
    when(uptimeEstimator.getUptime()).thenReturn(0.5d);

    PeerNodeTransport transport = Mockito.spy(new PeerNodeTransport(peer));
    doReturn(Mockito.mock(MessageItem.class))
        .when(transport)
        .sendAsync(
            ArgumentMatchers.any(Message.class),
            ArgumentMatchers.isNull(),
            ArgumentMatchers.any(ByteCounter.class));

    // Act
    transport.sendInitialMessages();

    // Assert
    verify(transport, times(4))
        .sendAsync(
            ArgumentMatchers.any(Message.class),
            ArgumentMatchers.isNull(),
            ArgumentMatchers.any(ByteCounter.class));
    verify(peer).sendConnectedDiffNoderef();
  }

  @Test
  void resendBytes_whenCalled_incrementsCounters() throws Exception {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Node node = Mockito.mock(Node.class);
    NodeStats stats = Mockito.mock(NodeStats.class);
    CountingByteCounter counter = new CountingByteCounter();

    setField(peer, PeerNode.class, "node", node);
    setField(stats, NodeStats.class, "resendByteCounter", counter);
    when(node.getNodeStats()).thenReturn(stats);

    PeerNodeTransport transport = new PeerNodeTransport(peer);

    // Act
    transport.resendBytes(12);

    // Assert
    assertEquals(12L, transport.getResendBytesSent());
    assertEquals(12, counter.getSentBytes());
  }

  private static void setField(Object target, Class<?> declaringClass, String name, Object value)
      throws Exception {
    Field field = declaringClass.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static final class CountingByteCounter implements ByteCounter {
    private int sentBytes;

    @Override
    public void receivedBytes(int x) {
      // no-op
    }

    @Override
    public void sentBytes(int x) {
      sentBytes += x;
    }

    @Override
    public void sentPayload(int x) {
      // no-op
    }

    private int getSentBytes() {
      return sentBytes;
    }
  }
}
