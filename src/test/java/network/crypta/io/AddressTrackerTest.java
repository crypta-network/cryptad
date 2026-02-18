package network.crypta.io;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Set;
import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.Peer;
import network.crypta.node.ProgramDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class AddressTrackerTest {

  @Test
  @DisplayName("getPortForwardStatus on fresh tracker returns DONT_KNOW; setBroken flips to NATed")
  void getPortForwardStatus_whenFreshAndWhenBroken_expectDontKnowThenDefinitelyNated() {
    AddressTracker tracker = AddressTracker.create(1L, tempProgramDir(new File(".")), 42);

    assertEquals(Status.DONT_KNOW, tracker.getPortForwardStatus());

    tracker.setBroken();
    assertEquals(Status.DEFINITELY_NATED, tracker.getPortForwardStatus());
  }

  @Test
  @DisplayName(
      "getLongestSendReceiveGap includes only real internet peers and returns the expected gap")
  void getLongestSendReceiveGap_whenMixedPeers_expectIgnoresLocalAndUsesPublic() throws Exception {
    AddressTracker tracker = AddressTracker.create(2L, tempProgramDir(new File(".")), 43);

    // Create two peers: loopback (should be ignored) and a public TEST-NET-2 IPv4 (valid)
    Peer loopback = new Peer(literal("127.0.0.1"), 1111);
    Peer publicPeer = new Peer(literal("198.51.100.23"), 2222);

    // Ensure tracker maps exist by sending once (actual timestamps not used for gap assertions)
    tracker.sentPacketTo(loopback);
    tracker.sentPacketTo(publicPeer);

    // Manipulate the underlying items with deterministic future timestamps to avoid horizon issues
    long base = System.currentTimeMillis() + 5_000_000L; // far in the future

    // For loopback: create an even larger gap which should be ignored by the public-only filter
    AddressTrackerItem loopItem =
        tracker.getPeerAddressTrackerItems()[0].peer.equals(loopback)
            ? tracker.getPeerAddressTrackerItems()[0]
            : tracker.getPeerAddressTrackerItems()[1];
    loopItem.sentPacket(base);
    loopItem.receivedPacket(base + AddressTracker.MAYBE_TUNNEL_LENGTH + 30_000L);

    // For public peer: create a gap shorter than the one above but still over threshold
    AddressTrackerItem pubItem =
        tracker.getPeerAddressTrackerItems()[0].peer.equals(publicPeer)
            ? tracker.getPeerAddressTrackerItems()[0]
            : tracker.getPeerAddressTrackerItems()[1];
    long pubGap = AddressTracker.MAYBE_TUNNEL_LENGTH + 10_000L;
    pubItem.sentPacket(base + 100_000L);
    pubItem.receivedPacket(base + 100_000L + pubGap);

    long longest = tracker.getLongestSendReceiveGap();
    assertEquals(pubGap, longest, "Should consider only gaps from real internet peers");
  }

  @Test
  @DisplayName("getPortForwardStatus returns MAYBE/DEFINITELY when gaps exceed thresholds")
  void getPortForwardStatus_whenGapsCrossThresholds_expectMaybeAndDefinitely() throws Exception {
    // MAYBE
    AddressTracker maybe = AddressTracker.create(3L, tempProgramDir(new File(".")), 44);
    Peer p1 = new Peer(literal("203.0.113.10"), 3333);
    maybe.sentPacketTo(p1); // ensure entry exists
    AddressTrackerItem it1 = maybe.getPeerAddressTrackerItems()[0];
    long t0 = System.currentTimeMillis() + 10_000_000L;
    long maybeGap = AddressTracker.MAYBE_TUNNEL_LENGTH + 5_000L;
    it1.sentPacket(t0);
    it1.receivedPacket(t0 + maybeGap);
    assertEquals(Status.MAYBE_PORT_FORWARDED, maybe.getPortForwardStatus());

    // DEFINITELY
    AddressTracker definitely = AddressTracker.create(4L, tempProgramDir(new File(".")), 45);
    Peer p2 = new Peer(literal("198.51.100.45"), 4444);
    definitely.sentPacketTo(p2);
    AddressTrackerItem it2 = definitely.getPeerAddressTrackerItems()[0];
    long t1 = System.currentTimeMillis() + 20_000_000L;
    long defGap = AddressTracker.DEFINITELY_TUNNEL_LENGTH + 10_000L;
    it2.sentPacket(t1);
    it2.receivedPacket(t1 + defGap);
    assertEquals(Status.DEFINITELY_PORT_FORWARDED, definitely.getPortForwardStatus());
  }

  @Test
  @DisplayName("startSend/startReceive propagate to newly created items")
  void startSendReceive_whenCalledBeforeFirstItem_expectPropagationToItemBounds() throws Exception {
    AddressTracker tracker = AddressTracker.create(5L, tempProgramDir(new File(".")), 46);
    long noSent = 123_456L;
    long noRecv = 234_567L;
    tracker.startSend(noSent);
    tracker.startReceive(noRecv);

    Peer peer = new Peer(literal("203.0.113.77"), 7777);
    tracker.sentPacketTo(peer); // creates the item

    AddressTrackerItem item = tracker.getPeerAddressTrackerItems()[0];
    assertEquals(noSent, item.timeDefinitelyNoPacketsSent());
    assertEquals(noRecv, item.timeDefinitelyNoPacketsReceived());
  }

  @Test
  @DisplayName("packetTo with unresolved hostname (dropHostName=null) does not add trackers")
  void packetTo_whenDropHostNameNull_expectNoItemsAdded() throws Exception {
    AddressTracker tracker = AddressTracker.create(6L, tempProgramDir(new File(".")), 47);
    // Construct peer with a hostname and allowUnknown=true so address remains unresolved
    Peer unresolved = new Peer("nonexistent.invalid:9999", true);

    tracker.sentPacketTo(unresolved);

    assertEquals(0, tracker.getPeerAddressTrackerItems().length);
    assertEquals(0, tracker.getInetAddressTrackerItems().length);
  }

  @Test
  @DisplayName("Capacity guard: over MAX_ITEMS clears maps; setHugeTracker avoids premature clear")
  void capacity_whenExceedDefault_and_whenHuge_expectClearThenNotClear() throws Exception {
    // Default capacity: 1000. Exceed it by adding 1002 unique peers → should clear once, end at 1.
    AddressTracker small = AddressTracker.create(7L, tempProgramDir(new File(".")), 48);
    for (int i = 0; i < AddressTracker.DEFAULT_MAX_ITEMS + 2; i++) {
      Peer p = new Peer(literal("198.51.100." + (i % 250 + 1)), 10000 + i);
      small.sentPacketTo(p);
    }
    assertEquals(1, small.getPeerAddressTrackerItems().length, "Expect map cleared on overflow");
    assertEquals(1, small.getInetAddressTrackerItems().length, "Expect IP map cleared on overflow");

    // Huge capacity: 10k. Add 1.5k unique peers → should not clear and keep them all.
    AddressTracker huge = AddressTracker.create(8L, tempProgramDir(new File(".")), 49);
    huge.setHugeTracker();
    Set<String> ips = new HashSet<>();
    int count = 1500;
    for (int i = 0; i < count; i++) {
      // Cycle through a pool of /24 addresses to keep InetAddress creation deterministic
      String ip = "203.0.113." + (i % 250 + 1);
      ips.add(ip);
      Peer p = new Peer(literal(ip), 20000 + i);
      huge.sentPacketTo(p);
    }
    assertEquals(count, huge.getPeerAddressTrackerItems().length);
    // ip trackers collapse peers that share the same IP; ensure we have the expected distinct IPs
    assertEquals(ips.size(), huge.getInetAddressTrackerItems().length);
  }

  @Test
  @DisplayName("storeData and create round-trip persists peers and IPs; boot ID mismatch resets")
  void storeAndCreate_roundTrip_andBootIdMismatch_expectPersistedThenNewEmpty(@TempDir File tmp)
      throws Exception {
    ProgramDirectory dir = new ProgramDirectory();
    dir.move(tmp.getAbsolutePath());
    int port = 5555;

    AddressTracker original = AddressTracker.create(10L, dir, port);

    // Add two peers with deterministic gaps so items are populated
    Peer p1 = new Peer(literal("192.0.2.10"), 3333);
    Peer p2 = new Peer(literal("2001:db8::1"), 4444);
    original.sentPacketTo(p1);
    original.receivedPacketFrom(p1);
    original.sentPacketTo(p2);

    // Touch underlying items with fixed future times to record gaps
    long base = System.currentTimeMillis() + 30_000_000L;
    for (AddressTrackerItem it : original.getPeerAddressTrackerItems()) {
      it.sentPacket(base);
      it.receivedPacket(base + AddressTracker.MAYBE_TUNNEL_LENGTH + 2_000L);
    }

    // Persist to disk
    original.storeData(10L, dir, port);
    File dat = dir.file("packets-" + port + ".dat");
    assertTrue(dat.exists(), "Expected persisted data file");

    // Reload with matching boot ID → entries should be reconstructed
    AddressTracker reloaded = AddressTracker.create(10L, dir, port);
    assertEquals(2, reloaded.getPeerAddressTrackerItems().length);
    assertEquals(2, reloaded.getInetAddressTrackerItems().length);

    // Verify peers survived the round-trip (compare numeric forms for determinism)
    Set<String> peers = new HashSet<>();
    for (PeerAddressTrackerItem item : reloaded.getPeerAddressTrackerItems()) {
      peers.add(item.peer.toStringPrefNumeric());
    }
    assertTrue(peers.contains(p1.toStringPrefNumeric()));
    assertTrue(peers.contains(p2.toStringPrefNumeric()));

    // Boot ID mismatch → loader should return a fresh, empty tracker
    AddressTracker mismatch = AddressTracker.create(999L, dir, port);
    assertEquals(0, mismatch.getPeerAddressTrackerItems().length);
    assertEquals(0, mismatch.getInetAddressTrackerItems().length);
  }

  // Helper: ProgramDirectory pointing at a directory without touching filesystem in most tests
  private static ProgramDirectory tempProgramDir(File dir) {
    ProgramDirectory pd = new ProgramDirectory();
    try {
      pd.move(dir.getAbsolutePath());
    } catch (Exception e) {
      throw new IllegalStateException("Failed to initialize ProgramDirectory for tests", e);
    }
    return pd;
  }

  private static InetAddress literal(String host) throws UnknownHostException {
    return InetAddress.getAllByName(host)[0];
  }
}
