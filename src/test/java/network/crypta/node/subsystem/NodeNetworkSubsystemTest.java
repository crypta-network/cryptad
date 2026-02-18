package network.crypta.node.subsystem;

import java.lang.reflect.Field;
import java.util.Set;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.node.Announcer;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.NodeStats;
import network.crypta.node.OpennetManager;
import network.crypta.node.OpennetPeerNode;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.pluginmanager.ForwardPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeNetworkSubsystemTest {
  private static final String FIELD_DARKNET_CRYPTO = "darknetCrypto";
  private static final String FIELD_NODE_STATS = "nodeStats";
  private static final String FIELD_IP_DETECTOR = "ipDetector";
  private static final String FIELD_PEERS = "peers";
  private static final String FIELD_ACCEPT_SEED_CONNECTIONS = "acceptSeedConnections";
  private static final String FIELD_OPENNET = "opennet";
  private static final String FIELD_PASS_OPENNET_REFS = "passOpennetRefsThroughDarknet";
  private static final String FIELD_USM = "usm";

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, String name, Object value) {
    try {
      Field field = NodeNetworkSubsystem.class.getDeclaredField(name);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set field: " + name, e);
    }
  }

  private static NodeNetworkSubsystem newSubsystem() {
    return new NodeNetworkSubsystem(mock(Node.class));
  }

  @Test
  void enableNewLoadManagement_whenNodeStatsNull_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    boolean result = subsystem.enableNewLoadManagement(true);

    assertFalse(result);
  }

  @Test
  void enableNewLoadManagement_whenNodeStatsPresent_expectDelegates() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeStats nodeStats = mock(NodeStats.class);
    when(nodeStats.enableNewLoadManagement(false)).thenReturn(true);
    setField(subsystem, FIELD_NODE_STATS, nodeStats);

    boolean result = subsystem.enableNewLoadManagement(false);

    assertTrue(result);
    verify(nodeStats).enableNewLoadManagement(false);
  }

  @Test
  void minimumDetectedMtu_whenIpDetectorNull_expectMaxValue() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    int result = subsystem.minimumDetectedMtu();

    assertEquals(Integer.MAX_VALUE, result);
  }

  @Test
  void minimumDetectedMtu_whenIpDetectorPresent_expectDelegates() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeIPDetector detector = mock(NodeIPDetector.class);
    when(detector.getMinimumDetectedMTU()).thenReturn(1234);
    setField(subsystem, FIELD_IP_DETECTOR, detector);

    int result = subsystem.minimumDetectedMtu();

    assertEquals(1234, result);
  }

  @Test
  void peerStatus_whenPeersNull_expectFallbackText() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    String status = subsystem.peerStatus();

    assertEquals("No peers yet", status);
  }

  @Test
  void tmciPeerList_whenPeersNull_expectEmptyString() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    String list = subsystem.tmciPeerList();

    assertEquals("", list);
  }

  @Test
  void peerStatus_whenPeersPresent_expectDelegates() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    when(peers.getStatus()).thenReturn("ok");
    setField(subsystem, FIELD_PEERS, peers);

    String status = subsystem.peerStatus();

    assertEquals("ok", status);
  }

  @Test
  void tmciPeerList_whenPeersPresent_expectDelegates() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    when(peers.getTMCIPeerList()).thenReturn(FIELD_PEERS);
    setField(subsystem, FIELD_PEERS, peers);

    String list = subsystem.tmciPeerList();

    assertEquals(FIELD_PEERS, list);
  }

  @Test
  void numArkFetchers_whenPeersFetching_expectCount() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    PeerNode fetching = mock(PeerNode.class);
    PeerNode notFetching = mock(PeerNode.class);
    when(fetching.isFetchingARK()).thenReturn(true);
    when(notFetching.isFetchingARK()).thenReturn(false);
    when(peers.myPeers()).thenReturn(new PeerNode[] {fetching, notFetching, fetching});
    setField(subsystem, FIELD_PEERS, peers);

    int count = subsystem.numArkFetchers();

    assertEquals(2, count);
  }

  @Test
  void getPeerNode_whenIdentifierMatchesDarknetName_expectPeer() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    DarknetPeerNode darknetPeer = mock(DarknetPeerNode.class);
    when(darknetPeer.getName()).thenReturn("alice");
    when(darknetPeer.getIdentityString()).thenReturn("id-1");
    when(peers.myPeers()).thenReturn(new PeerNode[] {darknetPeer});
    setField(subsystem, FIELD_PEERS, peers);

    PeerNode result = subsystem.getPeerNode("alice");

    assertSame(darknetPeer, result);
  }

  @Test
  void getPeerNode_whenIdentifierMatchesIdentity_expectPeer() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    PeerNode peer = mock(PeerNode.class);
    when(peer.getIdentityString()).thenReturn("id-2");
    when(peers.myPeers()).thenReturn(new PeerNode[] {peer});
    setField(subsystem, FIELD_PEERS, peers);

    PeerNode result = subsystem.getPeerNode("id-2");

    assertSame(peer, result);
  }

  @Test
  void getPeerNode_whenIdentifierMatchesPeerString_expectPeer() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    PeerNode peer = mock(OpennetPeerNode.class);
    Peer peerAddress = mock(Peer.class);
    when(peerAddress.toString()).thenReturn("127.0.0.1:1234");
    when(peer.getPeer()).thenReturn(peerAddress);
    when(peer.getIdentityString()).thenReturn("id-3");
    when(peers.myPeers()).thenReturn(new PeerNode[] {peer});
    setField(subsystem, FIELD_PEERS, peers);

    PeerNode result = subsystem.getPeerNode("127.0.0.1:1234");

    assertSame(peer, result);
  }

  @Test
  void getPeerNode_whenIdentifierUnknown_expectNull() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    PeerNode peer = mock(PeerNode.class);
    when(peer.getIdentityString()).thenReturn("id-4");
    when(peers.myPeers()).thenReturn(new PeerNode[] {peer});
    setField(subsystem, FIELD_PEERS, peers);

    PeerNode result = subsystem.getPeerNode("missing");

    assertNull(result);
  }

  @Test
  void wantAnonAuth_whenOpennetDisabled_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    setField(subsystem, FIELD_ACCEPT_SEED_CONNECTIONS, true);

    boolean result = subsystem.wantAnonAuth(true);

    assertFalse(result);
  }

  @Test
  void wantAnonAuth_whenOpennetEnabledAndSeedConnectionsEnabled_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    setField(subsystem, FIELD_ACCEPT_SEED_CONNECTIONS, true);
    setField(subsystem, FIELD_OPENNET, mock(OpennetManager.class));

    boolean result = subsystem.wantAnonAuth(true);

    assertTrue(result);
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void wantAnonAuthChangeIP_whenOpennet_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    boolean result = subsystem.wantAnonAuthChangeIP(true);

    assertFalse(result);
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void wantAnonAuthChangeIP_whenDarknet_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    boolean result = subsystem.wantAnonAuthChangeIP(false);

    assertTrue(result);
  }

  @Test
  void opennetFnpPort_whenOpennetDisabled_expectMinusOne() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    int port = subsystem.opennetFnpPort();

    assertEquals(-1, port);
  }

  @Test
  void opennetFnpPort_whenOpennetEnabled_expectPort() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    OpennetManager opennet = mock(OpennetManager.class);
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.getPortNumber()).thenReturn(2048);
    when(opennet.getCrypto()).thenReturn(crypto);
    setField(subsystem, FIELD_OPENNET, opennet);

    int port = subsystem.opennetFnpPort();

    assertEquals(2048, port);
  }

  @Test
  void passOpennetRefsThroughDarknet_whenSet_expectValue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    setField(subsystem, FIELD_PASS_OPENNET_REFS, true);

    boolean value = subsystem.passOpennetRefsThroughDarknet();

    assertTrue(value);
  }

  @Test
  void publicInterfacePorts_whenNoOpennet_expectOnlyDarknetPort() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.getPortNumber()).thenReturn(1111);
    setField(subsystem, FIELD_DARKNET_CRYPTO, crypto);

    Set<ForwardPort> ports = subsystem.publicInterfacePorts();

    assertEquals(1, ports.size());
    assertTrue(
        ports.contains(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, 1111)));
  }

  @Test
  void publicInterfacePorts_whenOpennetEnabled_expectBothPorts() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    NodeCrypto opennetCrypto = mock(NodeCrypto.class);
    OpennetManager opennet = mock(OpennetManager.class);
    when(darknet.getPortNumber()).thenReturn(1111);
    when(opennetCrypto.getPortNumber()).thenReturn(2222);
    when(opennet.getCrypto()).thenReturn(opennetCrypto);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);
    setField(subsystem, FIELD_OPENNET, opennet);

    Set<ForwardPort> ports = subsystem.publicInterfacePorts();

    assertEquals(2, ports.size());
    assertTrue(
        ports.contains(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, 1111)));
    assertTrue(
        ports.contains(new ForwardPort(FIELD_OPENNET, false, ForwardPort.PROTOCOL_UDP_IPV4, 2222)));
  }

  @Test
  void packetSocketHandlers_whenOpennetDisabled_expectSingleSocket() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    UdpSocketHandler socket = mock(UdpSocketHandler.class);
    when(darknet.getSocket()).thenReturn(socket);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);

    UdpSocketHandler[] handlers = subsystem.packetSocketHandlers();

    assertEquals(1, handlers.length);
    assertSame(socket, handlers[0]);
  }

  @Test
  void packetSocketHandlers_whenOpennetEnabled_expectBothSockets() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    NodeCrypto opennetCrypto = mock(NodeCrypto.class);
    OpennetManager opennet = mock(OpennetManager.class);
    UdpSocketHandler darknetSocket = mock(UdpSocketHandler.class);
    UdpSocketHandler opennetSocket = mock(UdpSocketHandler.class);
    when(darknet.getSocket()).thenReturn(darknetSocket);
    when(opennetCrypto.getSocket()).thenReturn(opennetSocket);
    when(opennet.getCrypto()).thenReturn(opennetCrypto);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);
    setField(subsystem, FIELD_OPENNET, opennet);

    UdpSocketHandler[] handlers = subsystem.packetSocketHandlers();

    assertEquals(2, handlers.length);
    assertSame(darknetSocket, handlers[0]);
    assertSame(opennetSocket, handlers[1]);
  }

  @Test
  void dontDetect_whenDarknetNotRealInternet_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    FreenetInetAddress darknetBind = mock(FreenetInetAddress.class);
    when(darknetBind.isRealInternetAddress(false, true, false)).thenReturn(false);
    when(darknet.getBindTo()).thenReturn(darknetBind);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);

    boolean result = subsystem.dontDetect();

    assertFalse(result);
  }

  @Test
  void dontDetect_whenOpennetBindNotRealInternet_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    NodeCrypto opennetCrypto = mock(NodeCrypto.class);
    OpennetManager opennet = mock(OpennetManager.class);
    FreenetInetAddress darknetBind = mock(FreenetInetAddress.class);
    FreenetInetAddress opennetBind = mock(FreenetInetAddress.class);
    when(darknetBind.isRealInternetAddress(false, true, false)).thenReturn(true);
    when(opennetBind.isRealInternetAddress(false, true, false)).thenReturn(false);
    when(darknet.getBindTo()).thenReturn(darknetBind);
    when(opennetCrypto.getBindTo()).thenReturn(opennetBind);
    when(opennet.getCrypto()).thenReturn(opennetCrypto);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);
    setField(subsystem, FIELD_OPENNET, opennet);

    boolean result = subsystem.dontDetect();

    assertTrue(result);
  }

  @Test
  void dontDetect_whenOnlyDarknetRealInternet_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto darknet = mock(NodeCrypto.class);
    FreenetInetAddress darknetBind = mock(FreenetInetAddress.class);
    when(darknetBind.isRealInternetAddress(false, true, false)).thenReturn(true);
    when(darknet.getBindTo()).thenReturn(darknetBind);
    setField(subsystem, FIELD_DARKNET_CRYPTO, darknet);

    boolean result = subsystem.dontDetect();

    assertTrue(result);
  }

  @Test
  void opennetDefinitelyPortForwarded_whenOpennetNull_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    boolean result = subsystem.opennetDefinitelyPortForwarded();

    assertFalse(result);
  }

  @Test
  void opennetDefinitelyPortForwarded_whenCryptoNull_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    OpennetManager opennet = mock(OpennetManager.class);
    when(opennet.getCrypto()).thenReturn(null);
    setField(subsystem, FIELD_OPENNET, opennet);

    boolean result = subsystem.opennetDefinitelyPortForwarded();

    assertFalse(result);
  }

  @Test
  void opennetDefinitelyPortForwarded_whenCryptoReportsForwarded_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    OpennetManager opennet = mock(OpennetManager.class);
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.definitelyPortForwarded()).thenReturn(true);
    when(opennet.getCrypto()).thenReturn(crypto);
    setField(subsystem, FIELD_OPENNET, opennet);

    boolean result = subsystem.opennetDefinitelyPortForwarded();

    assertTrue(result);
  }

  @Test
  void darknetDefinitelyPortForwarded_whenCryptoNull_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();

    boolean result = subsystem.darknetDefinitelyPortForwarded();

    assertFalse(result);
  }

  @Test
  void darknetDefinitelyPortForwarded_whenCryptoReportsForwarded_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    NodeCrypto crypto = mock(NodeCrypto.class);
    when(crypto.definitelyPortForwarded()).thenReturn(true);
    setField(subsystem, FIELD_DARKNET_CRYPTO, crypto);

    boolean result = subsystem.darknetDefinitelyPortForwarded();

    assertTrue(result);
  }

  @Test
  void updateIsUrgent_whenAnnouncerWaitingForUpdater_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    OpennetManager opennet = mock(OpennetManager.class);
    Announcer announcer = mock(Announcer.class);
    when(announcer.isWaitingForUpdater()).thenReturn(true);
    when(opennet.getAnnouncer()).thenReturn(announcer);
    setField(subsystem, FIELD_OPENNET, opennet);

    boolean result = subsystem.updateIsUrgent();

    assertTrue(result);
  }

  @Test
  void updateIsUrgent_whenTooManyTooNewDarknetPeers_expectTrue() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    when(peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true))
        .thenReturn(PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET + 1);
    setField(subsystem, FIELD_PEERS, peers);

    boolean result = subsystem.updateIsUrgent();

    assertTrue(result);
  }

  @Test
  void updateIsUrgent_whenNoTriggers_expectFalse() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    PeerManager peers = mock(PeerManager.class);
    when(peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true))
        .thenReturn(PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET);
    setField(subsystem, FIELD_PEERS, peers);

    boolean result = subsystem.updateIsUrgent();

    assertFalse(result);
  }

  @Test
  void arkFetcherContext_whenSet_expectSameInstance() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    network.crypta.client.FetchContext context = mock(network.crypta.client.FetchContext.class);

    subsystem.setArkFetcherContext(context);

    assertSame(context, subsystem.arkFetcherContext());
  }

  @Test
  void unclaimedFifoSize_whenUsmConfigured_expectDelegates() {
    NodeNetworkSubsystem subsystem = newSubsystem();
    MessageCore core = mock(MessageCore.class);
    when(core.getUnclaimedFIFOSize()).thenReturn(42);
    setField(subsystem, FIELD_USM, core);

    int size = subsystem.unclaimedFifoSize();

    assertEquals(42, size);
  }
}
