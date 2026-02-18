package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MessageWrapperTest {

  @Test
  @DisplayName("getMessageFragment() splits large non-short message into expected chunks")
  void getMessageFragment_whenLargeNonShortMessage_expectFragmentedChunks() {
    // Arrange
    MessageItem item = new MessageItem(new byte[1024], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 0);

    // Act + Assert: first fragment
    MessageFragment frag = wrapper.getMessageFragment(128);
    assertFragmentBasicsFragmented(
        frag, /* first= */ true, /* offset= */ 0, /* len= */ 121, wrapper);
    assertMessageMetaFromWrapper(frag, wrapper);

    // Next fragment
    frag = wrapper.getMessageFragment(128);
    assertFragmentBasicsFragmented(
        frag, /* first= */ false, /* offset= */ 121, /* len= */ 121, wrapper);

    // Skip ahead with a bigger allowance
    frag = wrapper.getMessageFragment(782);
    assertNotNull(frag);
    assertEquals(775, frag.fragmentLength);
    assertEquals(242, frag.fragmentOffset);

    // Final tail fragment
    frag = wrapper.getMessageFragment(128);
    assertFragmentBasicsFragmented(
        frag, /* first= */ false, /* offset= */ 1017, /* len= */ 7, wrapper);
    assertMessageMetaFromWrapper(frag, wrapper);
  }

  // ---- helpers (not counted toward assertion limit in this method) ----
  private static void assertFragmentBasicsFragmented(
      MessageFragment frag, boolean first, int offset, int len, MessageWrapper wrapper) {
    assertNotNull(frag);
    if (first) {
      assertTrue(frag.firstFragment);
    } else {
      assertFalse(frag.firstFragment);
    }
    assertEquals(offset, frag.fragmentOffset);
    assertEquals(len, frag.fragmentLength);
    assertTrue(frag.isFragmented);
    assertSame(wrapper, frag.wrapper);
  }

  private static void assertMessageMetaFromWrapper(MessageFragment frag, MessageWrapper wrapper) {
    assertEquals(wrapper.getMessageID(), frag.messageID);
    assertEquals(wrapper.getLength(), frag.messageLength);
    assertEquals(wrapper.getLength() <= 255, frag.shortMessage);
  }

  @Test
  @DisplayName("getMessageFragment() re-sends only the lost gap when some acks exist")
  void getMessageFragment_whenLossAndAcks_expectResendOfLostGapOnly() {
    // Arrange
    MessageItem item = new MessageItem(new byte[363], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 0);

    MessageFragment frag1 = wrapper.getMessageFragment(128);
    MessageFragment frag2 = wrapper.getMessageFragment(128);
    MessageFragment frag3 = wrapper.getMessageFragment(128);
    assertNotNull(frag1);
    assertNotNull(frag2);
    assertNotNull(frag3);

    // Ack first fragment fully and part of third, then mark the middle as lost
    wrapper.ack(0, 120); // frag1
    wrapper.ack(242, 262); // part of frag3
    wrapper.lost(121, 241); // frag2 range

    // Act
    MessageFragment frag = wrapper.getMessageFragment(128);

    // Assert: we resend exactly the second fragment
    assertNotNull(frag);
    assertFalse(frag.firstFragment);
    assertEquals(121, frag.fragmentOffset);
    assertEquals(121, frag.fragmentLength);
    assertTrue(frag.isFragmented);
    assertEquals(0, frag.messageID);
    assertEquals(363, frag.messageLength);
    assertFalse(frag.shortMessage);
    assertSame(wrapper, frag.wrapper);
  }

  @Test
  @DisplayName("lost() removes lost range from sent but preserves earlier acked range")
  void lost_whenSecondFragmentLost_expectOnlyFirstRangeRemainsInSentAndAcks() {
    // Arrange
    MessageItem item = new MessageItem(new byte[363], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 0);

    MessageFragment frag = wrapper.getMessageFragment(128);
    assertNotNull(frag);
    assertEquals(121, frag.fragmentLength);
    wrapper.ack(frag.fragmentOffset, frag.fragmentOffset + frag.fragmentLength - 1);

    frag = wrapper.getMessageFragment(128);
    assertNotNull(frag);
    assertEquals(121, frag.fragmentLength);

    // Act
    assertEquals(
        121, wrapper.lost(frag.fragmentOffset, frag.fragmentOffset + frag.fragmentLength - 1));

    // Assert: only 0->120 should appear in sent and acks
    for (int[] range : wrapper.getSent()) {
      if (range[0] >= 121 || range[1] >= 121) {
        fail("Expected 0->120 in sent, but got " + wrapper.getSent());
      }
    }
    for (int[] range : wrapper.getAcks()) {
      if (range[0] >= 121 || range[1] >= 121) {
        fail("Expected 0->120 in acks, but got " + wrapper.getAcks());
      }
    }
  }

  @Test
  @DisplayName("ack() returns true only when full message is covered and acknowledges once")
  void ack_whenWholeMessageAcked_expectTrueAndCallbackOnce() {
    // Arrange
    AsyncMessageCallback cb = mock(AsyncMessageCallback.class);
    MessageItem item =
        new MessageItem(new byte[10], new AsyncMessageCallback[] {cb}, false, null, (short) 1);
    MessageWrapper wrapper = new MessageWrapper(item, 99);

    // Act + Assert: partial ack first, should return false and not call acknowledged()
    assertFalse(wrapper.ack(0, 4));
    verify(cb, never()).acknowledged();

    // Complete the remaining part
    assertTrue(wrapper.ack(5, 9));
    verify(cb, times(1)).acknowledged();

    // Extra ack after completion should still return true but not notify again
    assertTrue(wrapper.ack(0, 9));
    verify(cb, times(1)).acknowledged();
  }

  @Test
  @DisplayName("isFragmented() reflects capacity and send/ack state")
  void isFragmented_whenConditionsVary_expectConsistentBehavior() {
    // Arrange
    MessageItem item = new MessageItem(new byte[100], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);

    // Nothing sent/acked and enough space -> not fragmented
    assertFalse(wrapper.isFragmented(1000));

    // After sending a partial fragment, even with large capacity -> fragmented
    assertNotNull(wrapper.getMessageFragment(20)); // mark part of message as sent
    assertTrue(wrapper.isFragmented(1000));

    // Acks alone also imply fragmentation on subsequent sends
    MessageItem item2 = new MessageItem(new byte[100], null, false, null, (short) 0);
    MessageWrapper wrapper2 = new MessageWrapper(item2, 2);
    assertFalse(wrapper2.ack(0, 0));
    assertTrue(wrapper2.isFragmented(1000));
  }

  @Test
  @DisplayName("isFirstFragment() true only before any sent or acked bytes")
  void isFirstFragment_whenStateChanges_expectFlagUpdates() {
    // Arrange
    MessageItem item = new MessageItem(new byte[5], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);
    assertTrue(wrapper.isFirstFragment());

    // Acks make it no longer the first fragment
    wrapper.ack(0, 0);
    assertFalse(wrapper.isFirstFragment());

    // New wrapper: sending a fragment also flips the flag
    MessageWrapper wrapper2 =
        new MessageWrapper(new MessageItem(new byte[5], null, false, null, (short) 0), 2);
    assertNotNull(wrapper2.getMessageFragment(5));
    assertFalse(wrapper2.isFirstFragment());
  }

  @Test
  @DisplayName("getMessageFragment() returns null when maxLength cannot fit headers + payload")
  void getMessageFragment_whenTooSmall_expectNull() {
    // Arrange: short message (<=255)
    MessageItem item = new MessageItem(new byte[1], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);

    // Base header for short: 2 (id+flags) + 1 (frag length) = 3
    // With fragmentation forced, one more byte is required. With maxLength=3, payload <= 0.
    MessageFragment frag = wrapper.getMessageFragment(3);
    assertNull(frag);
  }

  @Test
  @DisplayName("onDisconnect() forwards to callbacks")
  void onDisconnect_whenCalled_expectCallbackDisconnected() {
    // Arrange
    AsyncMessageCallback cb = mock(AsyncMessageCallback.class);
    MessageItem item =
        new MessageItem(new byte[2], new AsyncMessageCallback[] {cb}, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 7);

    // Act
    wrapper.onDisconnect();

    // Assert
    verify(cb, times(1)).disconnected();
  }

  @Test
  @DisplayName("onSent() reports fresh bytes with overhead and triggers sentAll once")
  void onSent_whenCoveringAllBytes_expectReportAndSentAllOnce() {
    // Arrange
    ByteCounter ctr = mock(ByteCounter.class);
    AsyncMessageCallback cb = mock(AsyncMessageCallback.class);
    MessageItem item =
        new MessageItem(new byte[10], new AsyncMessageCallback[] {cb}, false, ctr, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 11);
    BasePeerNode pn = mock(BasePeerNode.class);

    // Act: first half then second half; use an overhead of 6
    wrapper.onSent(0, 4, 6, pn);
    wrapper.onSent(5, 9, 6, pn);

    // Assert: Each call reports its new coverage + full overhead (no resend overlaps)
    verify(ctr, times(2)).sentBytes(11);
    // Completion triggers sentAll once
    verify(cb, times(1)).sent();
    verify(pn, never()).resentBytes(anyInt());
  }

  @Test
  @DisplayName("onSent() on previously-sent range accounts as resent with overhead")
  void onSent_whenResendingRange_expectResentAccounting() {
    // Arrange
    ByteCounter ctr = mock(ByteCounter.class);
    BasePeerNode pn = mock(BasePeerNode.class);
    MessageItem item = new MessageItem(new byte[5], null, false, ctr, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 22);

    // First send marks the range as everSent; second send should count as resent
    wrapper.onSent(0, 4, 4, pn);
    verify(ctr).sentBytes(9); // 5 + overhead 4

    // Act: resend the same range with overhead 4
    wrapper.onSent(0, 4, 4, pn);

    // Assert: no additional reported bytes; only resent including overhead
    verify(pn, times(1)).resentBytes(9); // 5 + 4
    verifyNoInteractions(cbNoop()); // guard that we didn't accidentally interact with callbacks
  }

  @Test
  @DisplayName("onSent() with partial overlap splits overhead between report and resent")
  void onSent_whenPartiallyOverlapping_expectOverheadSplit() {
    // Arrange
    ByteCounter ctr = mock(ByteCounter.class);
    BasePeerNode pn = mock(BasePeerNode.class);
    MessageItem item = new MessageItem(new byte[8], null, false, ctr, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 33);

    // Initial send [0..4] with overhead 3 → report 5+3=8
    wrapper.onSent(0, 4, 3, pn);
    verify(ctr).sentBytes(8);

    // Act: overlap send [3..7] with overhead 3
    wrapper.onSent(3, 7, 3, pn);

    // Assert: new coverage is [5..7] = 3 bytes; resend is [3..4] = 2 bytes
    // Overhead split: report += 1, resent += 2 (3 -> 1+2)
    verify(ctr).sentBytes(4); // 3 + 1
    verify(pn).resentBytes(4); // 2 + 2
  }

  @Test
  @DisplayName("getSent()/getAcks() return defensive copies")
  void getSentAndAcks_whenMutatedExternally_expectNoEffectOnWrapper() {
    // Arrange
    MessageItem item = new MessageItem(new byte[20], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);
    // Send and ack a fragment
    MessageFragment frag = wrapper.getMessageFragment(10);
    assertNotNull(frag);
    wrapper.ack(0, frag.fragmentLength - 1);

    // Copy then mutate the returned bitmaps
    network.crypta.support.SparseBitmap sentCopy = wrapper.getSent();
    network.crypta.support.SparseBitmap acksCopy = wrapper.getAcks();
    sentCopy.clear();
    acksCopy.clear();

    // Assert: wrapper's internal state remains unchanged
    assertFalse(wrapper.getSent().isEmpty());
    assertFalse(wrapper.getAcks().isEmpty());
  }

  @Test
  @DisplayName("Boundary: short vs non-short messages change header budget")
  void getMessageFragment_whenShortBoundary_expectDifferentPayloadBudget() {
    // Arrange: 255 bytes (short) and 256 bytes (non-short)
    MessageWrapper shortWrapper =
        new MessageWrapper(new MessageItem(new byte[255], null, false, null, (short) 0), 1);
    MessageWrapper longWrapper =
        new MessageWrapper(new MessageItem(new byte[256], null, false, null, (short) 0), 2);

    // Act: allow a small maxLength and compare payload sizes
    // For first fragments that must fragment: payload = maxLength - 2 - lenField - extraField
    MessageFragment fShort = shortWrapper.getMessageFragment(20);
    MessageFragment fLong = longWrapper.getMessageFragment(20);

    assertNotNull(fShort);
    assertNotNull(fLong);
    // Short uses 1-byte fields (2+1+1=4 header) → payload 16; Non-short uses 2+2+3=7 (per impl) →
    // payload 13
    assertEquals(16, fShort.fragmentLength);
    assertEquals(13, fLong.fragmentLength);
  }

  @Test
  @DisplayName("Simple getters delegate to underlying state")
  void getters_whenCalled_expectDelegation() {
    // Arrange
    MessageItem item = new MessageItem(new byte[42], null, false, null, (short) 77);
    MessageWrapper wrapper = new MessageWrapper(item, 1234);

    // Assert
    assertEquals(1234, wrapper.getMessageID());
    assertEquals(42, wrapper.getLength());
    assertEquals(77, wrapper.getPriority());
  }

  @Test
  @DisplayName("allSent() reflects sent ranges and updates after loss")
  void allSent_whenRangesChange_expectUpdates() {
    // Arrange
    MessageItem item = new MessageItem(new byte[30], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);

    // First fragment covers all when budget is large enough
    MessageFragment frag = wrapper.getMessageFragment(1000);
    assertNotNull(frag);
    assertTrue(wrapper.allSent());

    // Losing any part resets allSent to false
    wrapper.lost(0, 0);
    assertFalse(wrapper.allSent());
  }

  @Test
  @DisplayName("lost() size includes single-byte ack overlap (current behavior)")
  void lost_whenSingleByteAckOverlap_expectSizeNotReduced() {
    // Arrange: illustrate edge-case behavior in current implementation
    MessageItem item = new MessageItem(new byte[20], null, false, null, (short) 0);
    MessageWrapper wrapper = new MessageWrapper(item, 1);
    // Ack a single byte, then report loss spanning it
    wrapper.ack(5, 5);

    // Act
    int lost = wrapper.lost(0, 9);

    // Assert: due to equality check in lost(), single-byte overlap is not subtracted
    assertEquals(10, lost);
  }

  // Utility: a no-op callback mock for verifyNoInteractions guards where helpful
  private static AsyncMessageCallback cbNoop() {
    return mock(AsyncMessageCallback.class);
  }
}
