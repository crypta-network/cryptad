package network.crypta.io.xfer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.RetrievalException;
import network.crypta.node.PeerTransport;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BulkReceiverTest {

  @Mock PeerContext peer;
  @Mock PeerTransport transport;

  @Mock MessageCore usm;

  @Mock ByteCounter ctr;

  private static PartiallyReceivedBulk newPrb(
      MessageCore usm, long size, int blockSize, boolean initialState) {
    // Backing RAF must be at least "size" bytes.
    return new PartiallyReceivedBulk(
        usm, size, blockSize, new ByteArrayRandomAccessBuffer((int) size), initialState);
  }

  @BeforeEach
  void setupPeerBootId() {
    when(peer.getBootID()).thenReturn(42L); // Default unless a test overrides with a sequence
    when(peer.transport()).thenReturn(transport);
  }

  @Test
  @DisplayName("receive_whenHasWholeFileInitially_sendsAllReceivedAckAndReturnsTrue")
  @SuppressWarnings("java:S100") // Intentional test naming style
  void receive_whenHasWholeFileInitially_sendsAllReceivedAckAndReturnsTrue() throws Exception {
    PartiallyReceivedBulk prb = newPrb(usm, 0, 4, true); // whole-file already present
    long uid = 12345L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);

    // Act
    boolean result = recv.receive();

    // Assert
    assertTrue(result, "Expected receive() to return true when we already have the file");
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    Message sent = msgCap.getValue();
    assertEquals(DMT.FNPBulkReceivedAll, sent.getSpec());
    assertEquals(uid, sent.getLong(DMT.UID));
    // When whole-file is present, we must not block on the message core.
    verify(usm, never()).waitFor(any(MessageFilter.class), any());
  }

  @Test
  @DisplayName("receive_whenPacketsArrive_writesBlocksAndAcksAll")
  @SuppressWarnings("java:S100")
  void receive_whenPacketsArrive_writesBlocksAndAcksAll() throws Exception {
    // Arrange: two blocks (4 bytes + 3 bytes)
    int blockSize = 4;
    long size = 7; // -> blocks = 2
    PartiallyReceivedBulk prb = newPrb(usm, size, blockSize, false);
    long uid = 999L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);

    byte[] p0 = new byte[] {1, 2, 3, 4};
    byte[] p1 = new byte[] {5, 6, 7};
    Message m0 = DMT.createFNPBulkPacketSend(uid, 0, new ShortBuffer(p0));
    Message m1 = DMT.createFNPBulkPacketSend(uid, 1, new ShortBuffer(p1));

    // First wait returns packet 0, second returns packet 1.
    when(usm.waitFor(any(MessageFilter.class), eq(ctr))).thenReturn(m0, m1);

    // Act
    boolean result = recv.receive();

    // Assert
    assertTrue(result, "Expected receive() to complete after both packets");

    // Stored bytes match inputs
    assertArrayEquals(p0, prb.getBlockData(0));
    assertArrayEquals(p1, prb.getBlockData(1));

    // Acknowledgment that all packets were received
    ArgumentCaptor<Message> sent = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(sent.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceivedAll, sent.getValue().getSpec());
    assertEquals(uid, sent.getValue().getLong(DMT.UID));
  }

  @Test
  @DisplayName(
      "receive_whenDisconnectedDuringWait_abortsWithSenderDisconnectedAndSendsReceiveAborted")
  @SuppressWarnings("java:S100")
  void receive_whenDisconnectedDuringWait_abortsWithSenderDisconnectedAndSendsReceiveAborted()
      throws Exception {
    // Arrange
    PartiallyReceivedBulk prb = newPrb(usm, 8, 4, false);
    long uid = 777L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);
    when(usm.waitFor(any(MessageFilter.class), eq(ctr))).thenThrow(new DisconnectedException());

    // Act
    boolean result = recv.receive();

    // Assert
    assertFalse(result, "Expected receive() to fail on disconnection");
    assertTrue(prb.isAborted(), "PRB should be aborted");
    assertEquals(RetrievalException.SENDER_DISCONNECTED, prb.getAbortReason());
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceiveAborted, msgCap.getValue().getSpec());
    assertEquals(uid, msgCap.getValue().getLong(DMT.UID));
  }

  @Test
  @DisplayName("receive_whenPeerBootIdChanges_abortsWithSenderDiedAndDoesNotWrite")
  @SuppressWarnings("java:S100")
  void receive_whenPeerBootIdChanges_abortsWithSenderDiedAndDoesNotWrite() throws Exception {
    // Arrange
    int blockSize = 4;
    long size = 4;
    PartiallyReceivedBulk prb = org.mockito.Mockito.spy(newPrb(usm, size, blockSize, false));
    long uid = 314L;
    // Record initial boot id at construction, then simulate a restart.
    when(peer.getBootID()).thenReturn(1L, 2L);
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);

    Message m0 = DMT.createFNPBulkPacketSend(uid, 0, new ShortBuffer(new byte[] {9, 9, 9, 9}));
    when(usm.waitFor(any(MessageFilter.class), eq(ctr))).thenReturn(m0);

    // Act
    boolean result = recv.receive();

    // Assert
    assertFalse(result, "Expected receive() to abort when peer boot ID changed");
    assertTrue(prb.isAborted());
    assertEquals(RetrievalException.SENDER_DIED, prb.getAbortReason());
    // Ensure we never attempted to store the received packet because we detected restart first
    verify(prb, never())
        .received(any(Integer.class), any(byte[].class), any(Integer.class), any(Integer.class));
    // Receiver notifies peer about abort
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceiveAborted, msgCap.getValue().getSpec());
  }

  @Test
  @DisplayName("receive_whenTimeout_abortsWithTimedOut")
  @SuppressWarnings("java:S100")
  void receive_whenTimeout_abortsWithTimedOut() throws Exception {
    // Arrange
    PartiallyReceivedBulk prb = newPrb(usm, 8, 4, false);
    long uid = 2024L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);
    when(usm.waitFor(any(MessageFilter.class), eq(ctr))).thenReturn(null);

    // Act
    boolean result = recv.receive();

    // Assert
    assertFalse(result);
    assertTrue(prb.isAborted());
    assertEquals(RetrievalException.TIMED_OUT, prb.getAbortReason());
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceiveAborted, msgCap.getValue().getSpec());
  }

  @Test
  @DisplayName("receive_whenSenderCancelled_abortsWithSenderDied")
  @SuppressWarnings("java:S100")
  void receive_whenSenderCancelled_abortsWithSenderDied() throws Exception {
    // Arrange
    PartiallyReceivedBulk prb = newPrb(usm, 8, 4, false);
    long uid = 55L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);
    Message aborted = DMT.createFNPBulkSendAborted(uid);
    when(usm.waitFor(any(MessageFilter.class), eq(ctr))).thenReturn(aborted);

    // Act
    boolean result = recv.receive();

    // Assert
    assertFalse(result);
    assertTrue(prb.isAborted());
    assertEquals(RetrievalException.SENDER_DIED, prb.getAbortReason());
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceiveAborted, msgCap.getValue().getSpec());
  }

  @Test
  @DisplayName("onAborted_whenCalledTwice_sendsAbortedMessageOnlyOnce")
  @SuppressWarnings("java:S100")
  void onAborted_whenCalledTwice_sendsAbortedMessageOnlyOnce() throws Exception {
    // Arrange
    PartiallyReceivedBulk prb = newPrb(usm, 8, 4, false);
    long uid = 888L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);

    // Act: call twice; the second call should be ignored by the guard.
    recv.onAborted();
    recv.onAborted();

    // Assert
    ArgumentCaptor<Message> msgCap = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(msgCap.capture(), eq(null), eq(ctr));
    assertEquals(DMT.FNPBulkReceiveAborted, msgCap.getValue().getSpec());
    assertEquals(uid, msgCap.getValue().getLong(DMT.UID));
  }

  @Test
  @DisplayName("onAborted_whenPeerNotConnected_swallowsException")
  @SuppressWarnings("java:S100")
  void onAborted_whenPeerNotConnected_swallowsException() throws Exception {
    // Arrange
    PartiallyReceivedBulk prb = newPrb(usm, 8, 4, false);
    long uid = 321L;
    BulkReceiver recv = new BulkReceiver(prb, peer, uid, ctr);
    when(transport.sendAsync(any(Message.class), eq(null), eq(ctr)))
        .thenThrow(new NotConnectedException());

    // Act & Assert: no exception should escape
    recv.onAborted();
    verify(transport, times(1)).sendAsync(any(Message.class), eq(null), eq(ctr));
  }
}
