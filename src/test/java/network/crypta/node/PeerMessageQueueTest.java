package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.DMT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerMessageQueueTest {
  @Test
  void getNextUrgentTime_whenEmpty_returnsMaxValue() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    long now = System.currentTimeMillis();

    // Act
    long urgentTime = pmq.getNextUrgentTime(Long.MAX_VALUE, now);

    // Assert
    assertEquals(Long.MAX_VALUE, urgentTime);
  }

  @Test
  void getNextUrgentTime_whenSingleQueued_returnsSubmittedPlusTimeoutWithinRange() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    long start = System.currentTimeMillis();
    MessageItem item = new MessageItem(new byte[1024], null, false, null, (short) 0);
    long end = System.currentTimeMillis();
    pmq.queueAndEstimateSize(item, 1024);

    // Act
    long urgentTime = pmq.getNextUrgentTime(Long.MAX_VALUE, System.currentTimeMillis());

    // Assert
    if (!((urgentTime >= (start + 100)) && (urgentTime <= (end + 100)))) {
      fail(
          "Timeout not in expected range. Expected: "
              + (start + 100)
              + "->"
              + (end + 100)
              + ", actual: "
              + urgentTime);
    }
  }

  /* Test that getNextUrgentTime() returns the correct value, even when the items on the queue
   * aren't ordered by their timeout value, e.g. when an item was readded because we couldn't send
   * it. */
  @Test
  void getNextUrgentTime_whenQueuedOrderWrong_returnsMostUrgentTimeoutWithinRange() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    MessageItem itemUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0);
    MessageItem itemNonUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0);
    pmq.queueAndEstimateSize(itemNonUrgent, 1024);
    pmq.queueAndEstimateSize(itemUrgent, 1024);

    // Act
    long urgentTime = pmq.getNextUrgentTime(Long.MAX_VALUE, System.currentTimeMillis());

    // Assert
    long expected =
        Math.min(itemUrgent.submitted, itemNonUrgent.submitted) + PacketSender.MAX_COALESCING_DELAY;
    assertEquals(expected, urgentTime);
  }

  @Test
  void grabQueuedMessageItem_whenMostUrgentQueuedLast_returnsMostUrgentFirst() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1234));
    MessageItem itemUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0);
    MessageItem itemNonUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0);
    pmq.queueAndEstimateSize(itemNonUrgent, 1024);
    pmq.queueAndEstimateSize(itemUrgent, 1024);

    // Act
    MessageItem chosen = pmq.grabQueuedMessageItem(0);

    // Assert
    MessageItem expectedFirst =
        (itemUrgent.submitted < itemNonUrgent.submitted) ? itemUrgent : itemNonUrgent;
    assertSame(expectedFirst, chosen);
  }

  // New tests follow (JUnit 6 + Mockito; deterministic, no sleeps)

  @Test
  void queueAndEstimateSize_withSingleItem_returnsLengthPlusOverhead() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(7));
    byte[] payload = new byte[10];
    MessageItem item = new MessageItem(payload, null, false, null, DMT.PRIORITY_UNSPECIFIED);

    // Act
    int estimate = pmq.queueAndEstimateSize(item, 1024);

    // Assert
    assertEquals(12, estimate); // 10 bytes + 2 bytes overhead
  }

  @Test
  void grabQueuedMessageItems_whenMultipleQueued_returnsAllAndClears() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(42));
    MessageItem a = new MessageItem(new byte[5], null, false, null, DMT.PRIORITY_HIGH);
    MessageItem b = new MessageItem(new byte[7], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    MessageItem c = new MessageItem(new byte[9], null, false, null, DMT.PRIORITY_BULK_DATA);
    pmq.queueAndEstimateSize(a, 1024);
    pmq.queueAndEstimateSize(b, 1024);
    pmq.queueAndEstimateSize(c, 1024);

    // Act
    MessageItem[] firstBatch = pmq.grabQueuedMessageItems();
    MessageItem[] secondBatch = pmq.grabQueuedMessageItems();

    // Assert
    assertEquals(3, firstBatch.length);
    Set<MessageItem> seen = new HashSet<>(Arrays.asList(firstBatch));
    assertTrue(seen.contains(a));
    assertTrue(seen.contains(b));
    assertTrue(seen.contains(c));
    assertNotNull(secondBatch);
    assertEquals(0, secondBatch.length);
  }

  @Test
  void mustSendSize_whenExceedsMax_returnsTrue() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(1));
    MessageItem item = new MessageItem(new byte[5], null, false, null, DMT.PRIORITY_LOW);
    pmq.queueAndEstimateSize(item, 1024);

    // Act
    boolean result = pmq.mustSendSize(2, 6); // 2 + 5 > 6

    // Assert
    assertTrue(result);
  }

  @Test
  void grabQueuedMessageItem_whenRealtimeAndBulkPresent_prefersRealtime() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(99));
    MessageItem realtime =
        new MessageItem(new byte[3], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    MessageItem bulk = new MessageItem(new byte[3], null, false, null, DMT.PRIORITY_BULK_DATA);
    pmq.queueAndEstimateSize(realtime, 1024);
    pmq.queueAndEstimateSize(bulk, 1024);

    // Act
    MessageItem chosen = pmq.grabQueuedMessageItem(0);

    // Assert
    assertNotNull(chosen);
    assertEquals(DMT.PRIORITY_REALTIME_DATA, chosen.getPriority());
  }

  @Test
  void pushfrontPrioritizedMessageItem_onRoundRobin_givesImmediatePrecedence() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(100));
    MessageItem a = new MessageItem(new byte[2], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    MessageItem b = new MessageItem(new byte[2], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    pmq.pushfrontPrioritizedMessageItem(a); // goes to urgent list for the (synthetic) UID
    pmq.queueAndEstimateSize(b, 1024); // non-urgent in same priority

    // Act
    MessageItem first = pmq.grabQueuedMessageItem(0);

    // Assert
    assertSame(a, first);
  }

  @Test
  void getMessageQueueLengthBytes_withOnlyNonUrgent_returnsTotalBytes() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(5));
    MessageItem first = new MessageItem(new byte[4], null, false, null, DMT.PRIORITY_UNSPECIFIED);
    MessageItem second = new MessageItem(new byte[6], null, false, null, DMT.PRIORITY_LOW);
    pmq.queueAndEstimateSize(first, 1024);
    pmq.queueAndEstimateSize(second, 1024);

    // Act
    long queueBytes = pmq.getMessageQueueLengthBytes();

    // Assert
    assertEquals(14L, queueBytes);
  }

  @Test
  void getMessageQueueLengthBytes_withOnlyNonEmptyItemsWithId_returnsTotalBytes() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(6));
    MessageItem first = new MessageItem(new byte[3], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    MessageItem second =
        new MessageItem(new byte[5], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    pmq.pushfrontPrioritizedMessageItem(first);
    pmq.pushfrontPrioritizedMessageItem(second);

    // Act
    long queueBytes = pmq.getMessageQueueLengthBytes();

    // Assert
    assertEquals(12L, queueBytes);
  }

  @Test
  void getMessageQueueLengthBytes_withBothQueueStructures_returnsCombinedTotalBytes() {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(7));
    MessageItem nonUrgent =
        new MessageItem(new byte[4], null, false, null, DMT.PRIORITY_UNSPECIFIED);
    MessageItem urgent =
        new MessageItem(new byte[8], null, false, null, DMT.PRIORITY_REALTIME_DATA);
    pmq.queueAndEstimateSize(nonUrgent, 1024);
    pmq.pushfrontPrioritizedMessageItem(urgent);

    // Act
    long queueBytes = pmq.getMessageQueueLengthBytes();

    // Assert
    assertEquals(16L, queueBytes);
  }

  @Test
  void removeMessage_whenQueued_invokesOnFailed(@Mock AsyncMessageCallback cb) {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(11));
    MessageItem item =
        new MessageItem(
            new byte[8], new AsyncMessageCallback[] {cb}, false, null, DMT.PRIORITY_UNSPECIFIED);
    pmq.queueAndEstimateSize(item, 1024);

    // Act
    boolean removed = pmq.removeMessage(item);

    // Assert
    assertTrue(removed);
    verify(cb, times(1)).fatalError();
  }

  @Test
  void removeMessage_whenNotQueued_returnsFalse(@Mock AsyncMessageCallback cb) {
    // Arrange
    PeerMessageQueue pmq = new PeerMessageQueue(new DummyRandomSource(12));
    MessageItem item =
        new MessageItem(
            new byte[6], new AsyncMessageCallback[] {cb}, false, null, DMT.PRIORITY_LOW);

    // Act
    boolean removed = pmq.removeMessage(item);

    // Assert
    assertFalse(removed);
  }
}
