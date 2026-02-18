package network.crypta.node;

import java.lang.reflect.Field;
import java.net.InetAddress;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SeedServerPeerNodeTest {

  // Helper: set the (possibly final/private) 'node' field on PeerNode for controlled testing
  private static void setNodeField(PeerNode target, Object value) {
    try {
      Field f = PeerNode.class.getDeclaredField("node");
      f.setAccessible(true);
      f.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed to set field 'node'", e);
    }
  }

  @Test
  @DisplayName("flags_and_capabilities_constants_are_as_expected")
  void flags_and_capabilities_constants_are_as_expected() {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);

    // Act & Assert (simple constant returns)
    assertFalse(seed.isDarknet());
    assertFalse(seed.isOpennet());
    assertTrue(seed.isSeed());
    assertFalse(seed.isRealConnection());
    assertTrue(seed.handshakeUnknownInitiator());
    assertEquals(FNPPacketMangler.SETUP_OPENNET_SEEDNODE, seed.handshakeSetupType());
    assertFalse(seed.isRoutingCompatible());
    assertFalse(seed.recordStatus());
    assertFalse(seed.dontKeepFullFieldSet());
    assertTrue(seed.isOpennetForNoderef());
    assertFalse(seed.canAcceptAnnouncements());
    assertFalse(seed.shallWeRouteAccordingToOurPeersLocation(10));
  }

  @Test
  @DisplayName("equals_whenComparedToOtherType_returnsFalse_and_self_isTrue")
  void equals_whenComparedToOtherType_returnsFalse_and_self_isTrue() {
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);

    //noinspection EqualsWithItself
    assertEquals(seed, seed); // self
    assertNotEquals(new Object(), seed); // different type
  }

  @Test
  @DisplayName("getInetAddresses_deduplicates_and_keeps_first_seen_order")
  void getInetAddresses_deduplicates_and_keeps_first_seen_order() throws Exception {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);
    InetAddress a = InetAddress.getAllByName("192.0.2.1")[0]; // TEST-NET-1
    InetAddress b = InetAddress.getAllByName("2001:db8::1")[0]; // documentation IPv6

    Peer p1 = new Peer(a, 1234);
    Peer p2 = new Peer(new FreenetInetAddress(a), 2345); // same IP, different port
    Peer p3 = new Peer(b, 3456);

    doReturn(new Peer[] {p1, p2, p3}).when(seed).getHandshakeIPs();

    // Act
    InetAddress[] inetAddresses = seed.getInetAddresses();

    // Assert
    assertNotNull(inetAddresses);
    assertEquals(2, inetAddresses.length, "duplicate InetAddress must be removed");
    assertArrayEquals(new InetAddress[] {a, b}, inetAddresses, "preserve first-seen order");
  }

  @Test
  @DisplayName("getInetAddresses_skips_unresolved_hostname_entries_and_can_return_empty")
  void getInetAddresses_skips_unresolved_hostname_entries_and_can_return_empty() throws Exception {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);

    // Unresolved hostname (dropHostname() -> null)
    Peer unresolved = new Peer("unresolvable.invalid:4242", true);
    doReturn(new Peer[] {unresolved}).when(seed).getHandshakeIPs();

    // Act
    InetAddress[] inetAddresses = seed.getInetAddresses();

    // Assert
    assertNotNull(inetAddresses);
    assertEquals(0, inetAddresses.length, "all-unresolved peers should yield empty result");
  }

  @Test
  @DisplayName("shouldDisconnectAndRemoveNow_whenOpennetNull_returnsTrue")
  void shouldDisconnectAndRemoveNow_whenOpennetNull_returnsTrue() {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(null).when(network).opennet();
    setNodeField(seed, node);

    // Act & Assert
    assertTrue(seed.shouldDisconnectAndRemoveNow());
  }

  @Test
  @DisplayName("shouldDisconnectAndRemoveNow_whenNotEnoughPeers_returnsFalse")
  void shouldDisconnectAndRemoveNow_whenNotEnoughPeers_returnsFalse() {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager om = mock(OpennetManager.class);
    Announcer announcer = mock(Announcer.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(om).when(network).opennet();
    doReturn(announcer).when(om).getAnnouncer();
    doReturn(false).when(announcer).enoughPeers();
    setNodeField(seed, node);

    // Act & Assert
    assertFalse(seed.shouldDisconnectAndRemoveNow());
  }

  @Test
  @DisplayName("shouldDisconnectAndRemoveNow_whenEnoughPeersForOver5min_returnsTrue")
  void shouldDisconnectAndRemoveNow_whenEnoughPeersForOver5min_returnsTrue() {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager om = mock(OpennetManager.class);
    Announcer announcer = mock(Announcer.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    doReturn(om).when(network).opennet();
    doReturn(announcer).when(om).getAnnouncer();
    doReturn(true).when(announcer).enoughPeers();
    long past = System.currentTimeMillis() - java.util.concurrent.TimeUnit.MINUTES.toMillis(6);
    doReturn(past).when(announcer).timeGotEnoughPeers();
    setNodeField(seed, node);

    // Act & Assert
    assertTrue(seed.shouldDisconnectAndRemoveNow());
  }

  @Test
  @DisplayName("fatalTimeout_invokes_forceDisconnect")
  void fatalTimeout_invokes_forceDisconnect() {
    // Arrange
    SeedServerPeerNode seed = mock(SeedServerPeerNode.class, CALLS_REAL_METHODS);
    doNothing().when(seed).forceDisconnect();

    // Act
    seed.fatalTimeout();

    // Assert
    verify(seed).forceDisconnect();
  }
}
