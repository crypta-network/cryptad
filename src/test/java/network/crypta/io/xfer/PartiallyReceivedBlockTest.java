package network.crypta.io.xfer;

import java.util.ArrayList;
import java.util.Deque;
import network.crypta.support.Buffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method_whenCondition_expectOutcome naming
class PartiallyReceivedBlockTest {

  @Test
  void ctor_withMismatchedData_throwsRuntimeException() {
    int packets = 2;
    int packetSize = 3;
    byte[] data = new byte[5]; // expected 6
    RuntimeException ex =
        assertThrows(
            RuntimeException.class, () -> new PartiallyReceivedBlock(packets, packetSize, data));
    assertTrue(ex.getMessage().contains("Length of data"));
  }

  @Test
  void ctor_withPrepopulatedData_marksAllReceivedAndAllowsGetBlock() throws Exception {
    int packets = 3;
    int packetSize = 4;
    byte[] data = new byte[packets * packetSize];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i + 1);

    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(packets, packetSize, data);

    assertTrue(prb.allReceived());
    assertTrue(prb.allReceivedAndNotAborted());
    assertEquals(packets, prb.getNumPackets());
    assertEquals(packetSize, prb.getPacketSize());
    for (int i = 0; i < packets; i++) {
      assertTrue(prb.isReceived(i));
    }

    // getBlock returns the backing array when all received
    assertSame(data, prb.getBlock());

    // addListener should be given all packet indices in order
    Deque<Integer> already =
        prb.addListener(
            new PartiallyReceivedBlock.PacketReceivedListener() {
              @Override
              public void packetReceived(int packetNo) {
                // Intentionally empty: in this test we only verify that addListener returns
                // already-received indices; callbacks must not fire here.
              }

              @Override
              public void receiveAborted(int reason, String description) {
                // Intentionally empty: aborts are out of scope for this test scenario.
              }
            });
    ArrayList<Integer> list = new ArrayList<>(already);
    assertEquals(packets, list.size());
    for (int i = 0; i < packets; i++) {
      assertEquals(i, list.get(i));
    }
  }

  @Test
  void addListener_onFreshPrb_returnsEmptyDeque() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(3, 2);
    PartiallyReceivedBlock.PacketReceivedListener l =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    Deque<Integer> already = prb.addListener(l);
    assertTrue(already.isEmpty());
  }

  @Test
  void addPacket_whenValid_copiesDataAndNotifiesListeners() throws Exception {
    int packets = 3;
    int packetSize = 2;
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(packets, packetSize);
    PartiallyReceivedBlock.PacketReceivedListener l1 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    PartiallyReceivedBlock.PacketReceivedListener l2 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    prb.addListener(l1);
    prb.addListener(l2);

    // Add packet at position 1
    byte[] chunkBytes = new byte[] {10, 11};
    Buffer buf = new Buffer(chunkBytes);
    prb.addPacket(1, buf);

    // Verify state
    assertTrue(prb.isReceived(1));
    assertFalse(prb.allReceived());

    Buffer fromPrb = prb.getPacket(1);
    assertEquals(packetSize, fromPrb.getLength());
    assertEquals(10, fromPrb.byteAt(0));
    assertEquals(11, fromPrb.byteAt(1));

    // Both listeners notified exactly once with correct index
    verify(l1, times(1)).packetReceived(1);
    verify(l2, times(1)).packetReceived(1);
  }

  @Test
  void addPacket_whenDuplicate_doesNotNotifyAgain() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 1);
    PartiallyReceivedBlock.PacketReceivedListener l =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    prb.addListener(l);

    Buffer buf = new Buffer(new byte[] {42});
    prb.addPacket(0, buf);
    prb.addPacket(0, buf); // second add should be ignored

    verify(l, times(1)).packetReceived(0);
    verifyNoMoreInteractions(l);
  }

  @Test
  void addPacket_whenSizeMismatch_throwsRuntimeException() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 2);
    Buffer wrong = new Buffer(new byte[] {1, 2, 3});
    RuntimeException ex = assertThrows(RuntimeException.class, () -> prb.addPacket(0, wrong));
    assertTrue(ex.getMessage().contains("New packet size"));
  }

  @Test
  void allReceived_whenAborted_throwsAbortedExceptionWithDetails() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 1);
    prb.abort(7, "oops", false);
    AbortedException ex = assertThrows(AbortedException.class, prb::allReceived);
    assertTrue(ex.getMessage().contains("7"));
    assertTrue(ex.getMessage().contains("oops"));
  }

  @Test
  void getBlock_whenNotAllReceived_throwsRuntimeException() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 1);
    assertThrows(RuntimeException.class, prb::getBlock);
  }

  @Test
  void getPacket_whenNotReceived_throwsIllegalStateException() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 1);
    assertThrows(IllegalStateException.class, () -> prb.getPacket(0));
  }

  @Test
  void getPacket_whenAborted_throwsAbortedException() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(1, 1);
    prb.abort(1, "stop", true);
    assertThrows(AbortedException.class, () -> prb.getPacket(0));
  }

  @Test
  void abort_whenNotAllReceived_setsFlagsAndNotifiesAndBlocksNewListeners() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(3, 1);
    PartiallyReceivedBlock.PacketReceivedListener l1 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    PartiallyReceivedBlock.PacketReceivedListener l2 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    prb.addListener(l1);
    prb.addListener(l2);

    byte[] ret = prb.abort(5, "stop", true);
    assertNull(ret);
    assertTrue(prb.isAborted());
    assertEquals(5, prb.getAbortReason());
    assertEquals("stop", prb.getAbortDescription());
    assertTrue(prb.abortedLocally());

    verify(l1, times(1)).receiveAborted(5, "stop");
    verify(l2, times(1)).receiveAborted(5, "stop");

    // Listeners were cleared; adding a new one now must fail
    PartiallyReceivedBlock.PacketReceivedListener l3 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    assertThrows(AbortedException.class, () -> prb.addListener(l3));
  }

  @Test
  void abort_whenAlreadyAborted_returnsNullAndNoFurtherNotifications() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(1, 1);
    PartiallyReceivedBlock.PacketReceivedListener l =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    prb.addListener(l);

    prb.abort(2, "first", false);
    verify(l, times(1)).receiveAborted(2, "first");
    verifyNoMoreInteractions(l);

    // Second abort should return null and not notify anyone (listener list was cleared)
    byte[] ret2 = prb.abort(3, "second", true);
    assertNull(ret2);
    verifyNoMoreInteractions(l);
  }

  @Test
  void abort_whenAllReceived_returnsDataAndDoesNotSetAborted() throws Exception {
    int packets = 2;
    int packetSize = 3;
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(packets, packetSize);

    for (int i = 0; i < packets; i++) {
      byte[] chunk = new byte[packetSize];
      for (int j = 0; j < packetSize; j++) chunk[j] = (byte) (i * 10 + j);
      prb.addPacket(i, new Buffer(chunk));
    }

    assertTrue(prb.allReceived());
    byte[] full = prb.getBlock();

    byte[] ret = prb.abort(9, "ignored", false);
    assertNotNull(ret);
    assertArrayEquals(full, ret);
    assertFalse(prb.isAborted());
  }

  @Test
  void getters_throwAbortedException_afterAbort() {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(1, 1);
    prb.abort(4, "abort", false);
    assertThrows(AbortedException.class, () -> prb.isReceived(0));
    assertThrows(AbortedException.class, prb::getNumPackets);
    assertThrows(AbortedException.class, prb::getPacketSize);
  }

  @Test
  void addListener_returnsAlreadyReceivedIndices_afterSomePacketsAdded() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(4, 2);

    // Receive two packets: 0 and 2
    prb.addPacket(0, new Buffer(new byte[] {1, 2}));
    prb.addPacket(2, new Buffer(new byte[] {5, 6}));

    PartiallyReceivedBlock.PacketReceivedListener l =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    Deque<Integer> already = prb.addListener(l);

    ArrayList<Integer> list = new ArrayList<>(already);
    assertEquals(2, list.size());
    assertEquals(0, list.get(0));
    assertEquals(2, list.get(1));
  }

  @Test
  void removeListener_stopsFurtherNotifications() throws Exception {
    PartiallyReceivedBlock prb = new PartiallyReceivedBlock(2, 1);
    PartiallyReceivedBlock.PacketReceivedListener l1 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    PartiallyReceivedBlock.PacketReceivedListener l2 =
        mock(PartiallyReceivedBlock.PacketReceivedListener.class);
    prb.addListener(l1);
    prb.addListener(l2);

    // First packet notifies both
    prb.addPacket(0, new Buffer(new byte[] {7}));
    verify(l1, times(1)).packetReceived(0);
    verify(l2, times(1)).packetReceived(0);

    // Remove l1, add another packet; only l2 should be notified
    prb.removeListener(l1);
    prb.addPacket(1, new Buffer(new byte[] {8}));
    verify(l2, times(1)).packetReceived(1);
    verifyNoMoreInteractions(l1);
  }
}
