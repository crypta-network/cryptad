package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.support.OutputThrottle;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
@SuppressWarnings({"java:S100"})
class PacketSenderTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peerManager;
  @Mock private NodeCrypto darknetCrypto;
  @Mock private UdpSocketHandler udpSocket;

  @BeforeEach
  void setupCommonNodeMocks() {
    // Common node wiring used by tests; specific behavior tuned per-test as needed.
    when(node.network().darknetPortNumber()).thenReturn(12345);
    when(node.bootstrap().createRandom()).thenReturn(new MersenneTwister(1234));
    when(node.network().peers()).thenReturn(peerManager);
    when(node.network().darknetCrypto()).thenReturn(darknetCrypto);
    when(darknetCrypto.getSocket()).thenReturn(udpSocket);
    when(udpSocket.getMaxPacketSize()).thenReturn(1200);

    // Real throttle instance (Kotlin class) to avoid mocking final types.
    /* nanosPerTick= */
    /* initialTokens= */ OutputThrottle outputThrottle =
        new OutputThrottle(10_000, /* nanosPerTick= */ 1_000_000L, /* initialTokens= */ 0);
    when(node.network().outputThrottle()).thenReturn(outputThrottle);

    // Avoid triggering the "no packets received" alarm path.
    when(node.getStartupTime()).thenReturn(System.currentTimeMillis());
    when(node.network().opennet()).thenReturn(null);
  }

  // Helper to run one iteration of the internal send loop deterministically.
  @SuppressWarnings("java:S3011")
  private static void invokeRealRun(PacketSender ps) throws Exception {
    var m = PacketSender.class.getDeclaredMethod("realRun");
    m.setAccessible(true);
    m.invoke(ps);
  }

  @Test
  @DisplayName("realRun_whenUrgentPacketDue_callsMaybeSendPacketWithAckFalse")
  void realRun_whenUrgentPacketDue_callsMaybeSendPacketWithAckFalse() throws Exception {
    // Arrange
    PeerNode pn = mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {pn});

    when(pn.isConnected()).thenReturn(true);
    when(pn.shouldThrottle()).thenReturn(false);
    when(pn.getNextUrgentTime(anyLong())).thenReturn(0L); // <= now: urgent
    when(pn.fullPacketQueued()).thenReturn(false);

    // Keep connectivity checks satisfied
    when(pn.lastReceivedDataPacketTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedPackets()).thenReturn(Long.MAX_VALUE);
    when(pn.lastReceivedAckTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedAcks()).thenReturn(Long.MAX_VALUE);
    when(pn.isRoutable()).thenReturn(false);

    when(pn.maybeSendPacket(anyLong(), anyBoolean())).thenReturn(true);

    PacketSender ps = new PacketSender(node);

    // Act
    invokeRealRun(ps);

    // Assert
    verify(pn, times(1)).maybeSendPacket(anyLong(), eq(false));
  }

  @Test
  @DisplayName("realRun_whenAckOnlyAndThrottled_callsMaybeSendPacketWithAckTrue")
  void realRun_whenAckOnlyAndThrottled_callsMaybeSendPacketWithAckTrue() throws Exception {
    // Arrange
    PeerNode pn = mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {pn});

    when(pn.isConnected()).thenReturn(true);
    when(pn.shouldThrottle()).thenReturn(true);
    when(pn.getNextUrgentTime(anyLong())).thenReturn(Long.MAX_VALUE); // no urgent payload
    when(pn.timeSendAcks()).thenReturn(0L); // acks due now

    // Connectivity thresholds not violated
    when(pn.lastReceivedDataPacketTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedPackets()).thenReturn(Long.MAX_VALUE);
    when(pn.lastReceivedAckTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedAcks()).thenReturn(Long.MAX_VALUE);
    when(pn.isRoutable()).thenReturn(false);

    when(pn.maybeSendPacket(anyLong(), anyBoolean())).thenReturn(true);

    PacketSender ps = new PacketSender(node);

    // Act
    invokeRealRun(ps);

    // Assert
    verify(pn, times(1)).maybeSendPacket(anyLong(), eq(true));
  }

  @Test
  @DisplayName("realRun_whenNotConnectedAndHandshakeDue_sendsHandshakeWithNotRegisteredFalse")
  void realRun_whenNotConnectedAndHandshakeDue_sendsHandshakeWithNotRegisteredFalse()
      throws Exception {
    // Arrange
    PeerNode pn = mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {pn});

    OutgoingPacketMangler mangler = mock(OutgoingPacketMangler.class);

    when(pn.isConnected()).thenReturn(false);
    when(pn.noContactDetails()).thenReturn(false);
    when(pn.timeSendHandshake(anyLong())).thenReturn(0L); // handshake due now
    when(pn.getOutgoingMangler()).thenReturn(mangler);

    PacketSender ps = new PacketSender(node);

    // Act
    invokeRealRun(ps);

    // Assert
    verify(mangler, times(1)).sendHandshake(pn, false);
  }

  @Test
  @DisplayName("realRun_whenPacketNumberBlockedTooLong_forcesDisconnectOnPeer")
  void realRun_whenPacketNumberBlockedTooLong_forcesDisconnectOnPeer() throws Exception {
    // Arrange
    PeerNode pn = mock(PeerNode.class);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {pn});

    when(pn.isConnected()).thenReturn(true);
    when(pn.shouldThrottle()).thenReturn(false);
    when(pn.getNextUrgentTime(anyLong())).thenReturn(0L); // urgent now

    when(pn.lastReceivedDataPacketTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedPackets()).thenReturn(Long.MAX_VALUE);
    when(pn.lastReceivedAckTime()).thenReturn(System.currentTimeMillis());
    when(pn.maxTimeBetweenReceivedAcks()).thenReturn(Long.MAX_VALUE);
    when(pn.isRoutable()).thenReturn(false);

    doAnswer(
            inv -> {
              pn.forceDisconnect();
              return false;
            })
        .when(pn)
        .maybeSendPacket(anyLong(), anyBoolean());

    PacketSender ps = new PacketSender(node);

    // Act
    invokeRealRun(ps);

    // Assert
    verify(pn, times(1)).forceDisconnect();
  }

  @Test
  @DisplayName("realRun_whenOldOpennetPeerWantsHandshake_sendsHandshakeWithNotRegisteredTrue")
  void realRun_whenOldOpennetPeerWantsHandshake_sendsHandshakeWithNotRegisteredTrue()
      throws Exception {
    // Arrange
    // No regular peers in the main loop to avoid unrelated branches.
    when(peerManager.myPeers()).thenReturn(new PeerNode[0]);

    OpennetManager om = mock(OpennetManager.class);
    when(node.network().opennet()).thenReturn(om);
    when(node.network().uptime()).thenReturn(60_000L); // > 30s gate

    OpennetPeerNode opn = mock(OpennetPeerNode.class);
    OutgoingPacketMangler mangler = mock(OutgoingPacketMangler.class);
    when(opn.getOutgoingMangler()).thenReturn(mangler);

    // Fresh enough to not be purged
    when(opn.isConnected()).thenReturn(false);
    when(opn.noContactDetails()).thenReturn(false);
    when(opn.shouldSendHandshake()).thenReturn(true);
    when(opn.timeLastConnected(anyLong())).thenAnswer(inv -> ((Long) inv.getArgument(0)) - 1_000L);

    when(om.getOldPeers()).thenReturn(new OpennetPeerNode[] {opn});

    PacketSender ps = new PacketSender(node);

    // Act
    invokeRealRun(ps);

    // Assert
    verify(mangler, times(1)).sendHandshake(opn, true);
  }

  @Test
  @DisplayName("wakeUp_notifiesWaiters_withoutException")
  void wakeUp_notifiesWaiters_withoutException() {
    // Arrange
    PacketSender ps = new PacketSender(node);
    // Act + Assert
    assertDoesNotThrow(ps::wakeUp);
  }
}
