package network.crypta.node;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.io.xfer.PacketThrottle;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PeerNodeStatusTest {

  private <T extends PeerNode> T basePeerNodeMock(Class<T> type) {
    // Common, safe defaults to avoid NPEs in the PeerNodeStatus constructor
    T pn = mock(type);

    // Address chain default: no peer by default
    when(pn.getPeer()).thenReturn(null);

    // Status strings/values
    when(pn.getPeerNodeStatus()).thenReturn(1);
    when(pn.getPeerNodeStatusString()).thenReturn("CONNECTED");
    when(pn.getPeerNodeStatusCSSClassName()).thenReturn("connected");

    // Locations / versioning
    when(pn.getLocation()).thenReturn(0.25);
    when(pn.getPeersLocationArray()).thenReturn(new double[] {0.1, 0.2, 0.3});
    when(pn.getVersion()).thenReturn("1.2.3");
    when(pn.getSimpleVersion()).thenReturn(10203);

    // Backoff lengths and deadlines
    when(pn.getRoutingBackoffLength(true)).thenReturn(1000L);
    when(pn.getRoutingBackoffLength(false)).thenReturn(2000L);
    when(pn.getRoutingBackedOffUntil(true)).thenReturn(0L);
    when(pn.getRoutingBackedOffUntil(false)).thenReturn(0L);

    // Connectivity
    when(pn.isConnected()).thenReturn(true);
    when(pn.isRoutable()).thenReturn(true);
    when(pn.isFetchingARK()).thenReturn(false);
    when(pn.isOpennet()).thenReturn(false);
    when(pn.isRealConnection()).thenReturn(true);

    // Ping / versions
    when(pn.averagePingTime()).thenReturn(123.0);
    when(pn.averagePingTimeCorrected()).thenReturn(100.0);
    when(pn.publicInvalidVersion()).thenReturn(false);
    when(pn.publicReverseInvalidVersion()).thenReturn(false);

    // Backoff percentages
    when(pn.getBackedOffPercentRT()).thenReturn(0.1);
    when(pn.getBackedOffPercentBulk()).thenReturn(0.2);

    // Backoff reasons
    when(pn.getLastBackoffReason(true)).thenReturn("reason-rt");
    when(pn.getLastBackoffReason(false)).thenReturn("reason-bulk");

    PeerTransport transport = mock(PeerTransport.class);
    when(transport.getThrottle()).thenReturn(mock(PacketThrottle.class));
    when(pn.transport()).thenReturn(transport);

    // Times
    when(pn.timeLastRoutable()).thenReturn(111L);
    when(pn.timeLastConnectionCompleted()).thenReturn(222L);
    when(pn.getPeerAddedTime()).thenReturn(333L);

    // Traffic / throttle / other
    when(pn.getPRejected()).thenReturn(0.05);
    when(pn.getTotalInputBytes()).thenReturn(11L);
    when(pn.getTotalOutputBytes()).thenReturn(22L);
    when(pn.getTotalInputSinceStartup()).thenReturn(33L);
    when(pn.getTotalOutputSinceStartup()).thenReturn(44L);
    when(pn.getPercentTimeRoutableConnection()).thenReturn(0.9);
    when(pn.getClockDelta()).thenReturn(9L);
    when(pn.recordStatus()).thenReturn(true);
    when(pn.getResendBytesSent()).thenReturn(777L);
    when(pn.getUptime()).thenReturn((short) 88);
    when(pn.getMessageQueueLengthBytes()).thenReturn(999L);
    when(pn.getProbableSendQueueTime()).thenReturn(555L);
    when(pn.getIncomingLoadStats(true))
        .thenReturn(
            new PeerNodeLoadTracker.IncomingLoadSummaryStats(
                1,
                new PeerNodeLoadTracker.Limits(2, 3, 4, 5),
                new PeerNodeLoadTracker.Usage(6, 7),
                new PeerNodeLoadTracker.Usage(8, 9)));
    when(pn.getIncomingLoadStats(false))
        .thenReturn(
            new PeerNodeLoadTracker.IncomingLoadSummaryStats(
                10,
                new PeerNodeLoadTracker.Limits(20, 30, 40, 50),
                new PeerNodeLoadTracker.Usage(60, 70),
                new PeerNodeLoadTracker.Usage(80, 90)));
    when(pn.hasFullNoderef()).thenReturn(true);
    when(pn.selectionRate()).thenReturn(0.123);

    return pn;
  }

  @Test
  @DisplayName("getPeerStatusCount counts only matching statuses")
  void getPeerStatusCount_whenMixedStatuses_countsOnlyMatches() {
    PeerNode a = basePeerNodeMock(SeedClientPeerNode.class);
    PeerNode b = basePeerNodeMock(SeedServerPeerNode.class);
    PeerNode c = basePeerNodeMock(SeedClientPeerNode.class);

    when(a.getPeerNodeStatus()).thenReturn(1);
    when(b.getPeerNodeStatus()).thenReturn(2);
    when(c.getPeerNodeStatus()).thenReturn(1);

    PeerNodeStatus s1 = new PeerNodeStatus(a, true);
    PeerNodeStatus s2 = new PeerNodeStatus(b, true);
    PeerNodeStatus s3 = new PeerNodeStatus(c, true);

    int count = PeerNodeStatus.getPeerStatusCount(new PeerNodeStatus[] {s1, s2, s3}, 1);
    assertEquals(2, count);
  }

  @Test
  void getPeerAddressAndPort_whenIPv4_expectNoBrackets() throws Exception {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);

    // Mock underlying Peer and FreenetInetAddress for IPv4
    Peer peer = mock(Peer.class);
    FreenetInetAddress faddr = mock(FreenetInetAddress.class);
    InetAddress inet = InetAddress.getAllByName("203.0.113.10")[0];

    when(pn.getPeer()).thenReturn(peer);
    when(peer.getFreenetAddress()).thenReturn(faddr);
    when(peer.getPort()).thenReturn(12345);
    when(faddr.toString()).thenReturn("node.example");
    when(faddr.getAddress(false)).thenReturn(inet);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertEquals("node.example", status.getPeerAddress());
    assertEquals("203.0.113.10", status.getPeerAddressNumerical());
    assertArrayEquals(inet.getAddress(), status.getPeerAddressBytes());
    assertEquals(12345, status.getPeerPort());
    assertEquals("node.example:12345", status.getPeerAddressAndPort());
  }

  @Test
  void getPeerAddressAndPort_whenIPv6_expectBrackets() throws Exception {
    SeedClientPeerNode pn = basePeerNodeMock(SeedClientPeerNode.class);

    // Mock underlying Peer and FreenetInetAddress for IPv6
    Peer peer = mock(Peer.class);
    FreenetInetAddress faddr = mock(FreenetInetAddress.class);
    // Use a documentation prefix address (RFC 3849)
    InetAddress inet6 = InetAddress.getAllByName("2001:db8::1")[0];

    when(pn.getPeer()).thenReturn(peer);
    when(peer.getFreenetAddress()).thenReturn(faddr);
    when(peer.getPort()).thenReturn(23456);
    when(faddr.toString()).thenReturn("2001:db8::1");
    when(faddr.getAddress(false)).thenReturn(inet6);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertEquals("2001:db8::1", status.getPeerAddress());
    // Numerical form is provided by JDK; format may be expanded or compressed
    assertNotNull(status.getPeerAddressNumerical());
    assertEquals(16, status.getPeerAddressBytes().length);
    assertEquals(23456, status.getPeerPort());
    assertEquals("[2001:db8::1]:23456", status.getPeerAddressAndPort());
  }

  @Test
  void constructor_whenNoPeer_setsNullAddressAndMinusOnePort() {
    SeedClientPeerNode pn = basePeerNodeMock(SeedClientPeerNode.class);
    // Ensure getPeer() returns null (already default in base stub)
    when(pn.getPeer()).thenReturn(null);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertNull(status.getPeerAddress());
    assertNull(status.getPeerAddressNumerical());
    assertNull(status.getPeerAddressBytes());
    assertEquals(-1, status.getPeerPort());
    // getPeerAddressAndPort falls back to string concatenation with "null"
    assertEquals("null:-1", status.getPeerAddressAndPort());
  }

  @Test
  void constructor_whenNoHeavy_true_localMessageStatsAreNull() {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);
    PeerNodeStatus status = new PeerNodeStatus(pn, true);
    assertNull(status.getLocalMessagesReceived());
    assertNull(status.getLocalMessagesSent());
  }

  @Test
  void constructor_whenNoHeavy_false_localMessageStatsCopied() {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);
    LinkedHashMap<String, Long> recv = new LinkedHashMap<>();
    LinkedHashMap<String, Long> sent = new LinkedHashMap<>();
    recv.put("Foo", 1L);
    sent.put("Bar", 2L);
    when(pn.getLocalNodeReceivedMessagesFromStatistic()).thenReturn(recv);
    when(pn.getLocalNodeSentMessagesToStatistic()).thenReturn(sent);

    PeerNodeStatus status = new PeerNodeStatus(pn, false);
    assertEquals(recv, status.getLocalMessagesReceived());
    assertEquals(sent, status.getLocalMessagesSent());
  }

  @Test
  void toString_whenBackoffUntilZero_containsExpectedFieldsAndZeros() {
    SeedClientPeerNode pn = basePeerNodeMock(SeedClientPeerNode.class);

    // Provide a concrete peer so the address appears in toString
    Peer peer = mock(Peer.class);
    FreenetInetAddress faddr = mock(FreenetInetAddress.class);
    when(pn.getPeer()).thenReturn(peer);
    when(peer.getFreenetAddress()).thenReturn(faddr);
    when(peer.getPort()).thenReturn(1010);
    when(faddr.toString()).thenReturn("node");
    when(faddr.getAddress(false)).thenReturn(null); // numerical unknown is fine

    when(pn.getRoutingBackoffLength(true)).thenReturn(100L);
    when(pn.getRoutingBackoffLength(false)).thenReturn(200L);
    when(pn.getRoutingBackedOffUntil(true)).thenReturn(0L);
    when(pn.getRoutingBackedOffUntil(false)).thenReturn(0L);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);
    String s = status.toString();

    assertTrue(s.contains("CONNECTED"));
    assertTrue(s.contains("node:1010"));
    assertTrue(s.contains(" RT backoff: 100 (0 ) bulk backoff: 200 (0)"));
  }

  @Test
  void getters_locationVersionAndBackoff_reflectPeerNodeValues() {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);
    when(pn.getRoutingBackoffLength(true)).thenReturn(111L);
    when(pn.getRoutingBackoffLength(false)).thenReturn(222L);
    when(pn.getRoutingBackedOffUntil(true)).thenReturn(999_000L);
    when(pn.getRoutingBackedOffUntil(false)).thenReturn(888_000L);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertEquals(0.25, status.getLocation());
    assertArrayEquals(new double[] {0.1, 0.2, 0.3}, status.getPeersLocation());
    assertEquals("1.2.3", status.getVersion());
    assertEquals(10203, status.getSimpleVersion());
    assertEquals(111L, status.getRoutingBackoffLength(true));
    assertEquals(222L, status.getRoutingBackoffLength(false));
    assertEquals(999_000L, status.getRoutingBackedOffUntil(true));
    assertEquals(888_000L, status.getRoutingBackedOffUntil(false));
  }

  @Test
  void getters_pingBackoffReasonsAndTimes_reflectPeerNodeValues() {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);
    when(pn.getRoutingBackedOffUntil(true)).thenReturn(999_000L);
    when(pn.getRoutingBackedOffUntil(false)).thenReturn(888_000L);

    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertEquals(123.0, status.getAveragePingTime());
    assertEquals(100.0, status.getAveragePingTimeCorrected());
    assertEquals(0.1, status.getBackedOffPercent(true));
    assertEquals(0.2, status.getBackedOffPercent(false));
    assertEquals("reason-rt", status.getLastBackoffReason(true));
    assertEquals("reason-bulk", status.getLastBackoffReason(false));
    assertEquals(111L, status.getTimeLastRoutable());
    assertEquals(222L, status.getTimeLastConnectionCompleted());
    assertEquals(333L, status.getPeerAddedTime());
  }

  @Test
  void getters_trafficConnectionQueuesAndRates_reflectPeerNodeValues() {
    SeedServerPeerNode pn = basePeerNodeMock(SeedServerPeerNode.class);
    PeerNodeStatus status = new PeerNodeStatus(pn, true);

    assertEquals(0.05, status.getPReject());
    assertEquals(11L, status.getTotalInputBytes());
    assertEquals(22L, status.getTotalOutputBytes());
    assertEquals(33L, status.getTotalInputSinceStartup());
    assertEquals(44L, status.getTotalOutputSinceStartup());
    assertEquals(0.9, status.getPercentTimeRoutableConnection());
    assertNotNull(status.getThrottle());
    assertEquals(9L, status.getClockDelta());
    assertTrue(status.recordStatus());
    assertTrue(status.isConnected());
    assertTrue(status.isRoutable());
    assertEquals(777L, status.getResendBytesSent());
    assertEquals(88, status.getReportedUptimePercentage());
    assertEquals(999L, status.getMessageQueueLengthBytes());
    assertEquals(555L, status.getMessageQueueLengthTime());
    assertEquals(0.123, status.getSelectionRate());
  }

  @Test
  void seedFlags_whenSeedServer_detectTrueFalse() {
    SeedServerPeerNode server = basePeerNodeMock(SeedServerPeerNode.class);

    PeerNodeStatus status = new PeerNodeStatus(server, true);
    assertTrue(status.isSeedServer());
    assertFalse(status.isSeedClient());
  }

  @Test
  void seedFlags_whenSeedClient_detectFalseTrue() {
    SeedClientPeerNode client = basePeerNodeMock(SeedClientPeerNode.class);

    PeerNodeStatus status = new PeerNodeStatus(client, true);
    assertTrue(status.isSeedClient());
    assertFalse(status.isSeedServer());
  }

  @Test
  @DisplayName("equals(): different 32-byte pubkey hash but same 32-bit hashCode -> not equal")
  void equals_whenSameIntHash_butDifferentPubKeyHash_notEqual() {
    SeedServerPeerNode a = basePeerNodeMock(SeedServerPeerNode.class);
    SeedServerPeerNode b = basePeerNodeMock(SeedServerPeerNode.class);

    // Simulate two different peers with distinct public key hashes
    byte[] hashA = new byte[32];
    byte[] hashB = new byte[32];
    for (int i = 0; i < 32; i++) hashA[i] = (byte) i;
    for (int i = 0; i < 32; i++) hashB[i] = (byte) (255 - i);

    // Both mocks will likely have the same cached 32-bit field (default 0) on the underlying
    // PeerNode, but equals must ignore that and compare the full 32-byte hashes.
    when(a.getPubKeyHash()).thenReturn(hashA);
    when(b.getPubKeyHash()).thenReturn(hashB);

    PeerNodeStatus sa = new PeerNodeStatus(a, true);
    PeerNodeStatus sb = new PeerNodeStatus(b, true);

    assertNotEquals(sa, sb, "Status objects with different pubkey hashes must not be equal");
  }

  @Test
  @DisplayName("equals(): same 32-byte pubkey hash -> equal (hashCode contract holds)")
  void equals_whenSamePubKeyHash_equalAndHashMatches() {
    SeedClientPeerNode a = basePeerNodeMock(SeedClientPeerNode.class);
    SeedClientPeerNode b = basePeerNodeMock(SeedClientPeerNode.class);

    byte[] hash = new byte[32];
    for (int i = 0; i < 32; i++) hash[i] = (byte) (i * 3 + 7);

    when(a.getPubKeyHash()).thenReturn(hash);
    when(b.getPubKeyHash()).thenReturn(hash);

    PeerNodeStatus sa = new PeerNodeStatus(a, true);
    PeerNodeStatus sb = new PeerNodeStatus(b, true);

    assertEquals(sa, sb, "Status objects with same pubkey hash should be equal");
    // If equal, their hashCode values should match (our implementation uses cached 32-bit field)
    assertEquals(sa.hashCode(), sb.hashCode());
  }
}
