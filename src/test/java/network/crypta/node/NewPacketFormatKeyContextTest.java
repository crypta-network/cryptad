package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.TreeMap;
import network.crypta.io.xfer.PacketThrottle;
import network.crypta.node.NewPacketFormat.SentPacket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class NewPacketFormatKeyContextTest {

  @Mock private BasePeerNode pn;

  @Mock private PacketThrottle throttle;

  private static SessionKey dummyKey(NewPacketFormatKeyContext ctx) {
    return new SessionKey(null, null, ctx, /*trackerId*/ 0L);
  }

  private static TreeMap<Integer, Long> acksOf(NewPacketFormatKeyContext ctx) throws Exception {
    Field f = NewPacketFormatKeyContext.class.getDeclaredField("acks");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    TreeMap<Integer, Long> m = (TreeMap<Integer, Long>) f.get(ctx);
    return m;
  }

  private static HashMap<Integer, NewPacketFormat.SentPacket> sentPacketsOf(
      NewPacketFormatKeyContext ctx) throws Exception {
    Field f = NewPacketFormatKeyContext.class.getDeclaredField("sentPackets");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    HashMap<Integer, NewPacketFormat.SentPacket> m =
        (HashMap<Integer, NewPacketFormat.SentPacket>) f.get(ctx);
    return m;
  }

  // Per-test stubbing is used to avoid Mockito's unnecessary stubbing failures.

  // ---------- Constructor and basic state ----------

  @Test
  void constructor_whenTheirStartZero_setsHighestReceivedToMaxInt() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(123, 0);
    assertEquals(123, ctx.nextSeqNum);
    assertEquals(0, ctx.watchListOffset);
    assertEquals(Integer.MAX_VALUE, ctx.highestReceivedSeqNum);
    assertTrue(ctx.canAllocateSeqNum());
  }

  @Test
  void constructor_masksNegativeInputs_into31bitRange() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(-1, -2);
    assertEquals(Integer.MAX_VALUE, ctx.nextSeqNum);
    // theirFirstSeqNum = 0x7ffffffe, so highestReceivedSeqNum = that - 1
    assertEquals(Integer.MAX_VALUE - 2, ctx.highestReceivedSeqNum);
  }

  // ---------- Sequence number allocation ----------

  @Test
  void allocateSequenceNumber_firstCall_setsFirstSeqAndIncrements() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(10, 0);
    int seq = ctx.allocateSequenceNumber(pn);
    assertEquals(10, seq);
    assertEquals(11, ctx.nextSeqNum);
    // No rekeying expected on first allocation
    verify(pn, never()).startRekeying();
  }

  @Test
  void canAllocateSeqNum_whenNextEqualsFirstSeq_returnsFalse() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(5, 0);
    // First allocation sets firstSeqNumUsed to 5
    assertEquals(5, ctx.allocateSequenceNumber(pn));
    // Force wrap back to first to simulate the reuse condition
    ctx.nextSeqNum = ctx.firstSeqNumUsed;
    assertFalse(ctx.canAllocateSeqNum());
  }

  @Test
  void allocateSequenceNumber_whenAtFirstSeq_triggersRekeyAndReturnsMinusOne() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(5, 0);
    // Establish the first used one
    assertEquals(5, ctx.allocateSequenceNumber(pn));
    // Now next equals first => cannot allocate, rekey
    ctx.nextSeqNum = ctx.firstSeqNumUsed;
    int ret = ctx.allocateSequenceNumber(pn);
    assertEquals(-1, ret);
    verify(pn, times(1)).startRekeying();
    // the nextSeqNum should remain unchanged on failure
    assertEquals(ctx.firstSeqNumUsed, ctx.nextSeqNum);
  }

  @Test
  void allocateSequenceNumber_whenNearWrapWithinThreshold_triggersRekeyAndWrapsToZero() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(1, 0);
    // Simulate many prior allocations so the firstSeqNumUsed != -1
    assertEquals(1, ctx.allocateSequenceNumber(pn));
    ctx.firstSeqNumUsed = 10; // pretend we began at 10 on this key
    ctx.nextSeqNum = Integer.MAX_VALUE; // 0x7fffffff

    int ret = ctx.allocateSequenceNumber(pn);
    assertEquals(Integer.MAX_VALUE, ret);
    // After an increment, it would overflow negative; implementation resets to 0
    assertEquals(0, ctx.nextSeqNum);
    verify(pn, times(1)).startRekeying();
  }

  // ---------- Ack queueing and emission ----------

  @Test
  void addAcks_whenEmpty_returnsNull() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    NPFPacket p = new NPFPacket();
    NewPacketFormatKeyContext.AddedAcks res = ctx.addAcks(p, 1400, /*now*/ 0L);
    assertNull(res);
    assertEquals(0, p.getAcks().size());
  }

  @Test
  void addAcks_whenWithinPacketSize_movesAcksAndFlagsUrgentBasedOnAge() throws Exception {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    TreeMap<Integer, Long> acks = acksOf(ctx);
    acks.put(101, 1000L); // old
    acks.put(202, 5000L); // newer

    NPFPacket p = new NPFPacket();
    long now = 1000L + NewPacketFormatKeyContext.MAX_ACK_DELAY + 1; // 1201 => 101 is urgent
    NewPacketFormatKeyContext.AddedAcks added = ctx.addAcks(p, 1400, now);

    assertNotNull(added);
    assertTrue(added.anyUrgentAcks);
    assertEquals(2, p.getAcks().size());
    // All moved out of the internal map
    assertTrue(acks.isEmpty());

    // Abort should restore them
    added.abort();
    assertEquals(2, acks.size());
    assertTrue(acks.containsKey(101));
    assertTrue(acks.containsKey(202));
  }

  @Test
  void addAcks_respectsMaxPacketSize_andStopsWhenFull() throws Exception {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    TreeMap<Integer, Long> acks = acksOf(ctx);
    acks.put(10, 1000L);
    acks.put(11, 1000L);

    NPFPacket p = new NPFPacket();
    // Allow exactly one ack to fit (initial length=5; one ack block adds 5 bytes)
    int maxPacketSize = 10;
    NewPacketFormatKeyContext.AddedAcks added = ctx.addAcks(p, maxPacketSize, /*now*/ 2000L);

    assertNotNull(added);
    assertEquals(1, p.getAcks().size());
    // One ack remains queued because there was no space for it
    assertEquals(1, acks.size());
  }

  @Test
  void timeCheckForAcks_returnsEarliestTimeout() throws Exception {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    TreeMap<Integer, Long> acks = acksOf(ctx);
    acks.put(1, 1000L);
    acks.put(2, 1100L);
    long expected = 1000L + NewPacketFormatKeyContext.MAX_ACK_DELAY; // 1200
    assertEquals(expected, ctx.timeCheckForAcks());
  }

  // ---------- Sent tracking and ack processing ----------

  private static class FixedRttSentPacket extends NewPacketFormat.SentPacket {
    private final long fixedRtt;

    FixedRttSentPacket(NewPacketFormat npf, SessionKey key, long fixedRtt) {
      super(npf, key);
      this.fixedRtt = fixedRtt;
    }

    @Override
    public long acked(SessionKey key) {
      return fixedRtt;
    }
  }

  @Test
  void sentAndAck_whenValidAck_updatesThrottleAndPeer_andUsesMaxSeenInFlight() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    // Minimal NPF instance; it won't be used because FixedRttSentPacket overrides acked()
    NewPacketFormat npf = new NewPacketFormat(/*pn*/ null, 0, 0);
    SessionKey key = dummyKey(ctx);

    // Add two in-flight packets to establish maxSeenInFlight=2
    NewPacketFormat.SentPacket sp1 = new FixedRttSentPacket(npf, key, /*rtt*/ 123);
    NewPacketFormat.SentPacket sp2 = new FixedRttSentPacket(npf, key, /*rtt*/ 123);
    ctx.sent(sp1, /*seq*/ 1, /*len*/ 100);
    ctx.sent(sp2, /*seq*/ 2, /*len*/ 100);
    assertEquals(2, ctx.countSentPackets());

    PeerTransport transport = mock(PeerTransport.class);
    when(pn.transport()).thenReturn(transport);
    when(transport.getThrottle()).thenReturn(throttle);

    // Ack the first packet; should remove one and notify throttle with (2*2)+10=14
    ctx.ack(1, pn, key);

    verify(pn, times(1)).reportPing(123L);
    verify(pn, times(1)).receivedAck(anyLong());
    verify(throttle, times(1)).setRoundTripTime(123L);
    verify(throttle, times(1)).notifyOfPacketAcknowledged(14);
    assertEquals(1, ctx.countSentPackets());
  }

  @Test
  void ack_whenNoSentAndNoLostRecord_performsNoPeerOrThrottleInteractions() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    SessionKey key = dummyKey(ctx);

    ctx.ack(999, pn, key);

    verify(pn, never()).reportPing(anyLong());
    verify(pn, never()).receivedAck(anyLong());
    verify(throttle, never()).setRoundTripTime(anyLong());
    verify(throttle, never()).notifyOfPacketAcknowledged(anyDouble());
  }

  @Test
  void checkForLostPackets_marksLost_notifiesThrottle_andStoresLostTime_enablingLateAck() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    NewPacketFormat npf = new NewPacketFormat(null, 0, 0);
    SessionKey key = dummyKey(ctx);

    // Build a SentPacket with at least one message, so lostSentTimes is recorded on loss
    SentPacket sp = getSentPacket(npf, key);

    // Add to in-flight and force an old sent time so it qualifies as lost
    ctx.sent(sp, /*seq*/ 42, /*len*/ 100);
    // Compute threshold used by checkForLostPackets(avgRTT=0)
    double avgRtt = 0.0; // will be clamped to MIN_RTT_FOR_RETRANSMIT (250)
    long maxDelay = (long) (250 + NewPacketFormatKeyContext.MAX_ACK_DELAY * 1.1); // 470
    long now = 10_000L;

    // Override sent time to be older than the threshold
    sp.sentTime = now - maxDelay - 1; // package-private field; same package access

    PeerTransport transport = mock(PeerTransport.class);
    when(pn.transport()).thenReturn(transport);
    when(transport.getThrottle()).thenReturn(throttle);

    ctx.checkForLostPackets(avgRtt, now, pn);

    // Lost => one packet removed and throttle notified
    verify(throttle, times(1)).notifyOfPacketsLost(1);
    verify(pn, times(1)).backoffOnResend();
    assertEquals(0, ctx.countSentPackets());

    // A late ack for the lost packet should use the stored sent time:
    ctx.ack(42, pn, key);
    verify(pn, times(1)).reportPing(anyLong());
    verify(throttle, times(1)).setRoundTripTime(anyLong());
    // But not these, since it was not a valid (active) ack
    verify(pn, never()).receivedAck(anyLong());
    verify(throttle, never()).notifyOfPacketAcknowledged(anyDouble());
  }

  private static @NotNull NewPacketFormat.SentPacket getSentPacket(
      NewPacketFormat npf, SessionKey key) {
    SentPacket sp = new SentPacket(npf, key);
    MessageItem mi = new MessageItem(new byte[] {1, 2, 3, 4}, null, false, null, (short) 0);
    MessageWrapper mw = new MessageWrapper(mi, /*messageID*/ 7);
    MessageFragment frag =
        new MessageFragment(
            new MessageFragmentHeader(true, false, true, 7),
            new MessageFragmentSizes(4, 4, 0),
            new MessageFragmentPayload(new byte[] {1, 2, 3, 4}, mw));
    sp.addFragment(frag);
    return sp;
  }

  @Test
  void timeCheckForLostPackets_whenNoInFlight_returnsLongMax() {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    assertEquals(Long.MAX_VALUE, ctx.timeCheckForLostPackets(/*avgRTT*/ 10));
  }

  @Test
  void disconnected_marksAllLost_andClearsInFlight() throws Exception {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    NewPacketFormat npf = new NewPacketFormat(null, 0, 0);
    SessionKey key = dummyKey(ctx);

    class FlagSentPacket extends NewPacketFormat.SentPacket {
      boolean lostCalled;

      FlagSentPacket(NewPacketFormat npf, SessionKey key) {
        super(npf, key);
      }

      @Override
      public void lost() {
        lostCalled = true;
        super.lost();
      }
    }

    FlagSentPacket sp1 = new FlagSentPacket(npf, key);
    FlagSentPacket sp2 = new FlagSentPacket(npf, key);
    ctx.sent(sp1, 1, 100);
    ctx.sent(sp2, 2, 100);
    assertEquals(2, ctx.countSentPackets());

    ctx.disconnected();

    assertTrue(sp1.lostCalled);
    assertTrue(sp2.lostCalled);
    assertEquals(0, ctx.countSentPackets());
    // The internal map should also be empty
    assertTrue(sentPacketsOf(ctx).isEmpty());
  }

  @Test
  void sent_withExistingSequence_invokesUnderlyingSent() throws Exception {
    NewPacketFormatKeyContext ctx = new NewPacketFormatKeyContext(0, 0);
    NewPacketFormat npf = new NewPacketFormat(null, 0, 0);
    SessionKey key = dummyKey(ctx);

    class ObservedSentPacket extends NewPacketFormat.SentPacket {
      int seenLength;

      ObservedSentPacket(NewPacketFormat npf, SessionKey key) {
        super(npf, key);
      }

      @Override
      public void sent(int length) {
        seenLength = length;
        super.sent(length);
      }
    }

    ObservedSentPacket sp = new ObservedSentPacket(npf, key);
    // Put directly into the internal map so we can exercise sent(sequenceNumber, length)
    sentPacketsOf(ctx).put(77, sp);

    ctx.sent(77, 321);
    assertEquals(321, sp.seenLength);
  }
}
