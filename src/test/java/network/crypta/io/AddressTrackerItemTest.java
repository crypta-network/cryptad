package network.crypta.io;

import network.crypta.node.FSParseException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class AddressTrackerItemTest {

  // Convenience: threshold used by AddressTrackerItem when deciding whether to record a gap
  private static final long GAP_THRESHOLD = AddressTracker.MAYBE_TUNNEL_LENGTH;

  @Test
  @DisplayName("sentPacket when first call sets first and last and increments count")
  void sentPacket_whenFirstCall_expectFirstLastAndCount() {
    long baseNoRecv = 1_000L;
    long baseNoSent = 2_000L;
    AddressTrackerItem item = new AddressTrackerItem(baseNoRecv, baseNoSent);

    long t1 = 10_000L;
    item.sentPacket(t1);

    assertEquals(t1, item.firstSentPacket());
    assertEquals(t1, item.lastSentPacket());
    assertEquals(1L, item.packetsSent());
    // Receiving not yet touched
    assertEquals(-1L, item.firstReceivedPacket());
    assertEquals(-1L, item.lastReceivedPacket());
    assertEquals(0L, item.packetsReceived());
  }

  @Test
  @DisplayName("sentPacket when called twice only updates last and count")
  void sentPacket_whenSecondCall_expectLastAndCountUpdated() {
    AddressTrackerItem item = new AddressTrackerItem(1_000L, 2_000L);
    long t1 = 50_000L;
    long t2 = 60_000L;

    item.sentPacket(t1);
    item.sentPacket(t2);

    assertEquals(t1, item.firstSentPacket());
    assertEquals(t2, item.lastSentPacket());
    assertEquals(2L, item.packetsSent());
  }

  @Test
  @DisplayName("receivedPacket beyond threshold after a send records a gap at index 0")
  void receivedPacket_whenGapOverThreshold_expectGapRecordedAtZero() {
    long base = 1_000_000L; // non-zero to avoid early-return
    AddressTrackerItem item = new AddressTrackerItem(base, base);

    long send = base + 10_000L;
    long recv = send + GAP_THRESHOLD + 1_000L; // strictly beyond threshold
    item.sentPacket(send);
    item.receivedPacket(recv);

    // Validate counters and timestamps
    assertEquals(1L, item.packetsReceived());
    assertEquals(recv, item.firstReceivedPacket());
    assertEquals(recv, item.lastReceivedPacket());

    // Validate gap [0]
    AddressTrackerItem.Gap[] gaps = item.getGaps();
    assertEquals(AddressTrackerItem.TRACK_GAPS, gaps.length);
    assertEquals(recv - send, gaps[0].gapLength());
    assertEquals(recv, gaps[0].receivedPacketAt());
  }

  @Test
  @DisplayName("receivedPacket records multiple gaps: overwrite when no new send; rotate when sent")
  void receivedPacket_whenSecondGap_expectOverwriteOrRotate() {
    long base = 100_000L;
    AddressTrackerItem item = new AddressTrackerItem(base, base);

    long send1 = base + 1_000L;
    long recv1 = send1 + GAP_THRESHOLD + 5_000L;
    item.sentPacket(send1);
    item.receivedPacket(recv1);

    // Inspect gaps once to ensure a first gap is present, but do not store unused locals
    AddressTrackerItem.Gap[] afterFirst = item.getGaps();
    assertEquals(recv1 - send1, afterFirst[0].gapLength());
    assertEquals(recv1, afterFirst[0].receivedPacketAt());

    // Create another gap WITHOUT sending in between -> should overwrite index 0 (no rotate)
    long recv2 = recv1 + GAP_THRESHOLD + 2_000L;
    item.receivedPacket(recv2);

    AddressTrackerItem.Gap[] afterSecondNoSend = item.getGaps();
    // Since no new send, the startTime uses the last received (recv1)
    assertEquals(recv2 - recv1, afterSecondNoSend[0].gapLength());
    assertEquals(recv2, afterSecondNoSend[0].receivedPacketAt());
    // Index 1 should still be default (zero), proving no rotation happened yet
    assertEquals(0L, afterSecondNoSend[1].gapLength());
    assertEquals(0L, afterSecondNoSend[1].receivedPacketAt());

    // Now send again and create a third gap -> should rotate the arrays
    long send2 = recv2 + 500L; // ensure send2 > recv1 so startTime becomes send2
    long recv3 = send2 + GAP_THRESHOLD + 3_000L;
    item.sentPacket(send2);
    item.receivedPacket(recv3);

    AddressTrackerItem.Gap[] afterThirdWithSend = item.getGaps();
    // New gap occupies index 0
    assertEquals(recv3 - send2, afterThirdWithSend[0].gapLength());
    assertEquals(recv3, afterThirdWithSend[0].receivedPacketAt());
    // Previous (overwritten) gap is shifted to index 1 due to rotation
    assertEquals(recv2 - recv1, afterThirdWithSend[1].gapLength());
    assertEquals(recv2, afterThirdWithSend[1].receivedPacketAt());
  }

  @Test
  @DisplayName("longestGap considers only recent gaps within horizon")
  void longestGap_whenWithinHorizon_expectMaxOfRecent() {
    long base = 1_000_000L;
    AddressTrackerItem item = new AddressTrackerItem(base, base);

    long nowRef = 10_000_000L;
    long horizon = 1_000_000L; // 1e6 ms window

    // First gap
    long recv1 = nowRef - (horizon / 2); // within horizon
    long send1 = recv1 - (GAP_THRESHOLD + 10_000L);
    item.sentPacket(send1);
    item.receivedPacket(recv1);

    // Second gap, make sure send2 > recv1 so startTime = send2; longer than first
    long send2 = recv1 + 20_000L;
    long recv2 = send2 + GAP_THRESHOLD + 30_000L;
    item.sentPacket(send2);
    item.receivedPacket(recv2);

    long longest = item.longestGap(horizon, nowRef);
    assertEquals((GAP_THRESHOLD + 30_000L), longest);
  }

  @Test
  @DisplayName("hasLongTunnel true only when most recent gap was recorded within horizon")
  void hasLongTunnel_whenRecentAndWhenStale_expectTrueAndFalseOnSeparateItems() {
    long base = 1L;
    long current = System.currentTimeMillis();
    long horizon = 60_000L; // 60s

    // Recent case (true)
    AddressTrackerItem recent = new AddressTrackerItem(base, base);
    long recvRecent = current - horizon + 1_000L;
    long sendRecent = recvRecent - (GAP_THRESHOLD + 5_000L);
    recent.sentPacket(sendRecent);
    recent.receivedPacket(recvRecent);
    assertTrue(recent.hasLongTunnel(horizon));

    // Stale case (false) - only gap older than horizon
    AddressTrackerItem stale = new AddressTrackerItem(base, base);
    long recvOld = current - horizon - 120_000L;
    long sendOld = recvOld - (GAP_THRESHOLD + 10_000L);
    stale.sentPacket(sendOld);
    stale.receivedPacket(recvOld);
    assertFalse(stale.hasLongTunnel(horizon));
  }

  @Test
  @DisplayName("weSentFirst covers no-recv, no-send, and ordering cases")
  void weSentFirst_variousCases_expectCorrect() {
    long base = 1_000L;
    AddressTrackerItem item = new AddressTrackerItem(base, base);

    // No received yet -> true
    long ts = 5_000L;
    item.sentPacket(ts);
    assertTrue(item.weSentFirst());

    // Only received on another fresh item -> false
    AddressTrackerItem onlyRecv = new AddressTrackerItem(base, base);
    onlyRecv.receivedPacket(ts + 1_000L);
    assertFalse(onlyRecv.weSentFirst());

    // Both present: sent before recv -> true; sent after recv -> false
    AddressTrackerItem both = new AddressTrackerItem(base, base);
    long tSent = 20_000L;
    long tRecv = 25_000L;
    both.sentPacket(tSent);
    both.receivedPacket(tRecv);
    assertTrue(both.weSentFirst());

    AddressTrackerItem both2 = new AddressTrackerItem(base, base);
    both2.receivedPacket(tRecv);
    both2.sentPacket(tSent + 10_000L);
    assertFalse(both2.weSentFirst());
  }

  @Test
  @DisplayName("startup-to-first packet timings and counters behave correctly")
  void startupTiming_andCounters_expectCorrect() {
    long noRecv = 2_000L;
    long noSent = 1_500L;
    AddressTrackerItem item = new AddressTrackerItem(noRecv, noSent);

    // Before any packets
    assertEquals(-1L, item.timeFromStartupToFirstSentPacket());
    assertEquals(-1L, item.timeFromStartupToFirstReceivedPacket());

    // After sending and receiving once
    long tSent = 10_000L;
    long tRecv = 12_000L;
    item.sentPacket(tSent);
    item.receivedPacket(tRecv);

    assertEquals(tSent - noSent, item.timeFromStartupToFirstSentPacket());
    assertEquals(tRecv - noRecv, item.timeFromStartupToFirstReceivedPacket());
    assertEquals(1L, item.packetsSent());
    assertEquals(1L, item.packetsReceived());
  }

  @Test
  @DisplayName("toFieldSet round-trips through FS constructor including gaps")
  void toFieldSet_roundTrip_expectEqualState() throws FSParseException {
    long base = 50_000L;
    AddressTrackerItem original = new AddressTrackerItem(base, base);

    // Populate with several events to exercise fields and gaps
    long s1 = base + 10_000L;
    long r1 = s1 + GAP_THRESHOLD + 2_000L;
    original.sentPacket(s1);
    original.receivedPacket(r1);

    long s2 = r1 + 500L;
    long r2 = s2 + GAP_THRESHOLD + 5_000L;
    original.sentPacket(s2);
    original.receivedPacket(r2);

    SimpleFieldSet fs = original.toFieldSet();
    assertNotNull(fs);

    AddressTrackerItem restored = new AddressTrackerItem(fs);

    // Compare the primitive fields via getters
    assertEquals(original.firstSentPacket(), restored.firstSentPacket());
    assertEquals(original.lastSentPacket(), restored.lastSentPacket());
    assertEquals(original.firstReceivedPacket(), restored.firstReceivedPacket());
    assertEquals(original.lastReceivedPacket(), restored.lastReceivedPacket());
    assertEquals(original.packetsSent(), restored.packetsSent());
    assertEquals(original.packetsReceived(), restored.packetsReceived());
    assertEquals(original.timeDefinitelyNoPacketsSent(), restored.timeDefinitelyNoPacketsSent());
    assertEquals(
        original.timeDefinitelyNoPacketsReceived(), restored.timeDefinitelyNoPacketsReceived());

    // Compare gaps element-wise
    AddressTrackerItem.Gap[] g1 = original.getGaps();
    AddressTrackerItem.Gap[] g2 = restored.getGaps();
    assertEquals(g1.length, g2.length);
    for (int i = 0; i < g1.length; i++) {
      assertEquals(g1[i].gapLength(), g2[i].gapLength());
      assertEquals(g1[i].receivedPacketAt(), g2[i].receivedPacketAt());
    }
  }

  @Test
  @DisplayName("FS constructor throws when subset missing required keys")
  void fsConstructor_whenMissingKeys_expectException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    // Leave out fields like TimeFirstReceivedPacket to trigger parse errors on getLong
    assertThrows(FSParseException.class, () -> new AddressTrackerItem(fs));
  }
}
