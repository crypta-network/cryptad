package network.crypta.node;

import java.util.Arrays;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.Peer;
import network.crypta.node.subsystem.NodeMessagingSubsystem;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.UpdateOverMandatoryManager;
import network.crypta.support.Fields;
import network.crypta.support.ShortBuffer;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeControlMessageHandlerTest {
  @Mock private Node node;
  @Mock private ByteCounter pingCounter;
  @Mock private Message message;
  @Mock private PeerNode peerNode;
  @Mock private PeerTransport transport;
  @Mock private NodeNetworkSubsystem networkSubsystem;
  @Mock private NodeIPDetector ipDetector;
  @Mock private NodeMessagingSubsystem messagingSubsystem;
  @Mock private NodeServicesSubsystem servicesSubsystem;
  @Mock private NodeUpdateManager nodeUpdateManager;
  @Mock private UpdateOverMandatoryManager uomManager;
  @Mock private Ticker ticker;
  @Mock private PeerManager peerManager;
  @Mock private PeerMessenger peerMessenger;
  @Mock private OpennetManager opennetManager;

  private NodeControlMessageHandler handler;

  @BeforeEach
  void setUp() {
    handler = new NodeControlMessageHandler(node, pingCounter);
  }

  @Test
  void handle_whenPingReceived_sendsPongAndReturnsTrue() throws Exception {
    when(message.getSpec()).thenReturn(DMT.FNPPing);
    when(message.getInt(DMT.PING_SEQNO)).thenReturn(7);
    when(peerNode.transport()).thenReturn(transport);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Message> messageCaptor = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(messageCaptor.capture(), eq(null), eq(pingCounter));

    Message reply = messageCaptor.getValue();
    assertEquals(DMT.FNPPong, reply.getSpec());
    assertEquals(7, reply.getInt(DMT.PING_SEQNO));
  }

  @Test
  void handle_whenPingReplyNotConnected_stillReturnsTrue() throws Exception {
    when(message.getSpec()).thenReturn(DMT.FNPPing);
    when(message.getInt(DMT.PING_SEQNO)).thenReturn(3);
    when(peerNode.transport()).thenReturn(transport);
    doThrow(new NotConnectedException("test"))
        .when(transport)
        .sendAsync(any(Message.class), eq(null), eq(pingCounter));

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(transport).sendAsync(any(Message.class), eq(null), eq(pingCounter));
  }

  @Test
  void handle_whenDetectedIPAddress_updatesPeerAndTriggersRedetect() {
    Peer external = org.mockito.Mockito.mock(Peer.class);
    when(message.getSpec()).thenReturn(DMT.FNPDetectedIPAddress);
    when(message.getObject(DMT.EXTERNAL_ADDRESS)).thenReturn(external);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.ipDetector()).thenReturn(ipDetector);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(peerNode).setRemoteDetectedPeer(external);
    verify(ipDetector).redetectAddress();
  }

  @Test
  void handle_whenTimeMessage_setsTimeDeltaDeterministically() {
    long before = System.currentTimeMillis();
    long remoteTime = before + 5_000L;
    when(message.getSpec()).thenReturn(DMT.FNPTime);
    when(message.getLong(DMT.TIME)).thenReturn(remoteTime);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Long> deltaCaptor = ArgumentCaptor.forClass(Long.class);
    verify(peerNode).setTimeDelta(deltaCaptor.capture());
    long after = System.currentTimeMillis();
    long observed = deltaCaptor.getValue();
    assertTrue(observed <= remoteTime - before);
    assertTrue(observed >= remoteTime - after);
  }

  @Test
  void handle_whenUptimeMessage_setsUptime() {
    when(message.getSpec()).thenReturn(DMT.FNPUptime);
    when(message.getByte(DMT.UPTIME_PERCENT_48H)).thenReturn((byte) 81);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(peerNode).setUptime((byte) 81);
  }

  @Test
  void handle_whenVisibilityFromDarknetPeer_invokesHandler() {
    DarknetPeerNode darknetPeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    when(message.getSpec()).thenReturn(DMT.FNPVisibility);

    boolean handled = handler.handle(message, darknetPeer);

    assertTrue(handled);
    verify(darknetPeer).handleVisibility(message);
  }

  @Test
  void handle_whenVisibilityFromNonDarknet_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.FNPVisibility);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verify(peerNode).isRealConnection();
    verifyNoMoreInteractions(peerNode);
  }

  @Test
  void handle_whenVoidMessage_returnsTrue() {
    when(message.getSpec()).thenReturn(DMT.FNPVoid);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verifyNoInteractions(peerNode);
  }

  @Test
  void handle_whenNodeToNodeMessage_dispatchesToMessagingSubsystem() {
    when(message.getSpec()).thenReturn(DMT.nodeToNodeMessage);
    when(node.messaging()).thenReturn(messagingSubsystem);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(messagingSubsystem).receivedNodeToNodeMessage(message, peerNode);
  }

  @Test
  void handle_whenUomAnnouncementFromRealConnection_delegatesAndReturnsResult() {
    when(message.getSpec()).thenReturn(DMT.CryptadUOMAnnouncement);
    when(peerNode.isRealConnection()).thenReturn(true);
    when(node.services()).thenReturn(servicesSubsystem);
    when(servicesSubsystem.nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getUpdateOverMandatory()).thenReturn(uomManager);
    when(uomManager.handleAnnounce(message, peerNode)).thenReturn(true);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(uomManager).handleAnnounce(message, peerNode);
  }

  @Test
  void handle_whenUomAnnouncementFromNonRealConnection_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.CryptadUOMAnnouncement);
    when(peerNode.isRealConnection()).thenReturn(false);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verifyNoInteractions(node);
  }

  @Test
  void handle_whenUomRequestMainJarUnsupported_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.CryptadUOMRequestMainJar);
    when(peerNode.isRealConnection()).thenReturn(true);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verifyNoInteractions(node);
  }

  @Test
  void handle_whenUomSendingMainJar_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.CryptadUOMSendingMainJar);
    when(peerNode.isRealConnection()).thenReturn(true);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verifyNoInteractions(node);
  }

  @Test
  void handle_whenRoutingStatusFromDarknetPeer_setsRouting() {
    DarknetPeerNode darknetPeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    when(message.getSpec()).thenReturn(DMT.FNPRoutingStatus);
    when(message.getBoolean(DMT.ROUTING_ENABLED)).thenReturn(true);

    boolean handled = handler.handle(message, darknetPeer);

    assertTrue(handled);
    verify(darknetPeer).setRoutingStatus(true, false);
  }

  @Test
  void handle_whenRoutingStatusFromNonDarknet_returnsTrueWithoutCalls() {
    when(message.getSpec()).thenReturn(DMT.FNPRoutingStatus);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verifyNoInteractions(peerNode);
  }

  @Test
  void handle_whenLocationChangeWithRealConnection_updatesLocation() {
    double newLocation = 0.25;
    double[] locations = {0.1, 0.2, 0.3};
    when(message.getSpec()).thenReturn(DMT.FNPLocChangeNotificationNew);
    when(peerNode.isRealConnection()).thenReturn(true);
    when(message.getDouble(DMT.LOCATION)).thenReturn(newLocation);
    when(message.getObject(DMT.PEER_LOCATIONS))
        .thenReturn(new ShortBuffer(Fields.doublesToBytes(locations)));

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<double[]> locationsCaptor = ArgumentCaptor.forClass(double[].class);
    verify(peerNode).updateLocation(eq(newLocation), locationsCaptor.capture());
    assertArrayEquals(locations, locationsCaptor.getValue());
  }

  @Test
  void handle_whenLocationChangeOpennetTooManyPeers_truncatesLocations() {
    double newLocation = 0.5;
    int oversized = OpennetManager.MAX_PEERS_FOR_SCALING + 5;
    double[] locations = new double[oversized];
    Arrays.fill(locations, 0.1);
    when(message.getSpec()).thenReturn(DMT.FNPLocChangeNotificationNew);
    when(peerNode.isRealConnection()).thenReturn(true);
    when(peerNode.isOpennet()).thenReturn(true);
    when(message.getDouble(DMT.LOCATION)).thenReturn(newLocation);
    when(message.getObject(DMT.PEER_LOCATIONS))
        .thenReturn(new ShortBuffer(Fields.doublesToBytes(locations)));

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<double[]> locationsCaptor = ArgumentCaptor.forClass(double[].class);
    verify(peerNode).updateLocation(eq(newLocation), locationsCaptor.capture());
    assertEquals(OpennetManager.MAX_PEERS_FOR_SCALING, locationsCaptor.getValue().length);
  }

  @Test
  void handle_whenLocationChangeOpennetPanic_disconnects() {
    double newLocation = 0.75;
    int oversized = OpennetManager.PANIC_MAX_PEERS + 1;
    double[] locations = new double[oversized];
    when(message.getSpec()).thenReturn(DMT.FNPLocChangeNotificationNew);
    when(peerNode.isRealConnection()).thenReturn(true);
    when(peerNode.isOpennet()).thenReturn(true);
    when(message.getDouble(DMT.LOCATION)).thenReturn(newLocation);
    when(message.getObject(DMT.PEER_LOCATIONS))
        .thenReturn(new ShortBuffer(Fields.doublesToBytes(locations)));

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(peerNode).forceDisconnect();
    verify(peerNode, never()).updateLocation(any(double.class), any(double[].class));
  }

  @Test
  void handle_whenLocationChangeWithoutRealConnection_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.FNPLocChangeNotificationNew);
    when(peerNode.isRealConnection()).thenReturn(false);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
    verify(peerNode, never()).updateLocation(any(double.class), any(double[].class));
  }

  @Test
  void handle_whenPeerLoadStatus_reportsLoadStatus() {
    when(message.getSpec()).thenReturn(DMT.FNPPeerLoadStatusByte);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    verify(peerNode).reportLoadStatus(any(PeerLoadStats.class));
  }

  @Test
  void handle_whenDisconnectMessage_queuesDelayedDisconnectAndProcessesFlags() {
    OpennetPeerNode opennetPeer = org.mockito.Mockito.mock(OpennetPeerNode.class);
    ShortBuffer messageData = new ShortBuffer(new byte[] {1, 2});
    when(message.getSpec()).thenReturn(DMT.FNPDisconnect);
    when(message.getBoolean(DMT.REMOVE)).thenReturn(true);
    when(message.getBoolean(DMT.PURGE)).thenReturn(true);
    when(message.getInt(DMT.NODE_TO_NODE_MESSAGE_TYPE)).thenReturn(42);
    when(message.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA)).thenReturn(messageData);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.ticker()).thenReturn(ticker);
    when(networkSubsystem.peers()).thenReturn(peerManager);
    when(peerManager.messenger()).thenReturn(peerMessenger);
    when(networkSubsystem.opennet()).thenReturn(opennetManager);
    when(node.messaging()).thenReturn(messagingSubsystem);

    boolean handled = handler.handle(message, opennetPeer);

    assertTrue(handled);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(1000L));

    runnableCaptor.getValue().run();

    verify(opennetPeer).disconnected(true, true);
    verify(peerMessenger).disconnectAndRemove(opennetPeer, false, false, false);
    verify(opennetManager).purgeOldOpennetPeer(opennetPeer);
    verify(messagingSubsystem).receivedNodeToNodeMessage(opennetPeer, 42, messageData, true);
  }

  @Test
  void handle_whenDisconnectWithEmptyPartingMessage_skipsDispatch() {
    ShortBuffer messageData = new ShortBuffer();
    when(message.getSpec()).thenReturn(DMT.FNPDisconnect);
    when(message.getBoolean(DMT.REMOVE)).thenReturn(false);
    when(message.getBoolean(DMT.PURGE)).thenReturn(false);
    when(message.getInt(DMT.NODE_TO_NODE_MESSAGE_TYPE)).thenReturn(7);
    when(message.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA)).thenReturn(messageData);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.ticker()).thenReturn(ticker);

    boolean handled = handler.handle(message, peerNode);

    assertTrue(handled);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(1000L));

    runnableCaptor.getValue().run();

    verify(peerNode).disconnected(true, true);
    verify(messagingSubsystem, never()).receivedNodeToNodeMessage(peerNode, 7, messageData, true);
  }

  @Test
  void handle_whenUnknownMessage_returnsFalse() {
    when(message.getSpec()).thenReturn(DMT.FNPAccepted);

    boolean handled = handler.handle(message, peerNode);

    assertFalse(handled);
  }
}
