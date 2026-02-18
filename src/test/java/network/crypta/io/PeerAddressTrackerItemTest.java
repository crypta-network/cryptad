package network.crypta.io;

import java.net.InetAddress;
import network.crypta.io.comm.Peer;
import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class PeerAddressTrackerItemTest {

  // Convenience: threshold used by AddressTrackerItem when deciding whether to record a gap
  private static final long GAP_THRESHOLD = AddressTracker.MAYBE_TUNNEL_LENGTH;

  @Test
  @DisplayName("toFieldSet round-trips for IPv4 and preserves super fields")
  void toFieldSet_roundTrip_whenIPv4_expectPeerEqualAndAddressNumeric() throws Exception {
    long noRecv = 1_000L;
    long noSent = 2_000L;
    Peer peer = new Peer(InetAddress.getAllByName("127.0.0.1")[0], 3333);

    PeerAddressTrackerItem item = new PeerAddressTrackerItem(noRecv, noSent, peer);

    // Exercise parent behavior so state is non-trivial and gaps are populated
    long base = 50_000L;
    long s1 = base + 10_000L;
    long r1 = s1 + GAP_THRESHOLD + 2_000L;
    item.sentPacket(s1);
    item.receivedPacket(r1);

    long s2 = r1 + 500L;
    long r2 = s2 + GAP_THRESHOLD + 5_000L;
    item.sentPacket(s2);
    item.receivedPacket(r2);

    SimpleFieldSet fs = item.toFieldSet();
    assertNotNull(fs);
    assertEquals(peer.toStringPrefNumeric(), fs.getString("Address"));

    PeerAddressTrackerItem restored = new PeerAddressTrackerItem(fs);

    // Peer equality and numeric address field
    assertEquals(peer, restored.peer);
    assertEquals(peer.toStringPrefNumeric(), restored.peer.toStringPrefNumeric());

    // Parent fields preserved
    assertEquals(item.firstSentPacket(), restored.firstSentPacket());
    assertEquals(item.lastSentPacket(), restored.lastSentPacket());
    assertEquals(item.firstReceivedPacket(), restored.firstReceivedPacket());
    assertEquals(item.lastReceivedPacket(), restored.lastReceivedPacket());
    assertEquals(item.packetsSent(), restored.packetsSent());
    assertEquals(item.packetsReceived(), restored.packetsReceived());
    assertEquals(item.timeDefinitelyNoPacketsSent(), restored.timeDefinitelyNoPacketsSent());
    assertEquals(
        item.timeDefinitelyNoPacketsReceived(), restored.timeDefinitelyNoPacketsReceived());
  }

  @Test
  @DisplayName("toFieldSet round-trips for IPv6 and preserves peer")
  void toFieldSet_roundTrip_whenIPv6_expectPeerEqual() throws Exception {
    long noRecv = 10L;
    long noSent = 20L;

    // IPv6 documentation prefix ensures determinism; no DNS is performed for numeric IPs
    InetAddress v6 = InetAddress.getAllByName("2001:db8::1")[0];
    Peer peer = new Peer(v6, 65000);

    PeerAddressTrackerItem item = new PeerAddressTrackerItem(noRecv, noSent, peer);

    long s = 100_000L;
    long r = s + GAP_THRESHOLD + 1_000L;
    item.sentPacket(s);
    item.receivedPacket(r);

    SimpleFieldSet fs = item.toFieldSet();
    assertNotNull(fs);

    PeerAddressTrackerItem restored = new PeerAddressTrackerItem(fs);
    // Exact IPv6 textual form may be normalized by InetAddress; compare via Peer equality
    assertEquals(peer, restored.peer);
    assertEquals(peer.toStringPrefNumeric(), fs.getString("Address"));
  }

  @Test
  @DisplayName("FS constructor throws when address has invalid port")
  void fsConstructor_whenInvalidPort_expectFSParseException() {
    // Build a valid base FS for the parent from a fresh AddressTrackerItem, then inject Address
    SimpleFieldSet fs = new AddressTrackerItem(0L, 0L).toFieldSet();
    fs.putOverwrite("Address", "127.0.0.1:999999"); // invalid port triggers PeerParseException

    assertThrows(FSParseException.class, () -> new PeerAddressTrackerItem(fs));
  }

  @Test
  @DisplayName("FS constructor throws when address string is malformed (missing port)")
  void fsConstructor_whenMalformedAddress_expectFSParseException() {
    SimpleFieldSet fs = new AddressTrackerItem(0L, 0L).toFieldSet();
    fs.putOverwrite("Address", "127.0.0.1"); // no port delimiter

    assertThrows(FSParseException.class, () -> new PeerAddressTrackerItem(fs));
  }
}
