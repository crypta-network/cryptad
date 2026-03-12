package network.crypta.node;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class OpennetManagerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNode peer;
  @Mock private PeerTransport transport;
  @Mock private MessageCore usm;
  @Mock private ByteCounter byteCounter;

  @BeforeEach
  void setUp() {
    org.mockito.Mockito.lenient().when(peer.transport()).thenReturn(transport);
  }

  @ParameterizedTest
  @CsvSource({
    // target,totalLong,totalShort
    "1,0,1",
    "2,0,2",
    "3,0,3",
    "4,1,3",
    "5,1,4",
    "10,3,7",
    "100,30,70"
  })
  @DisplayName("LinkLengthClass.getTargetPeers splits target by LONG_PROPORTION")
  void linkLengthClass_getTargetPeers_variousTargets_expectSplit(
      int target, int expLong, int expShort) {
    int longPeers = OpennetManager.LinkLengthClass.LONG.getTargetPeers(target);
    int shortPeers = OpennetManager.LinkLengthClass.SHORT.getTargetPeers(target);
    assertEquals(expLong, longPeers, "long peers");
    assertEquals(expShort, shortPeers, "short peers");
    assertEquals(target, longPeers + shortPeers, "sum equals target");
  }

  @Test
  @DisplayName("waitForOpennetNoderef returns null on CompletedAck")
  void waitForOpennetNoderef_whenAck_expectNull() throws Exception {
    // Arrange
    long uid = 42L;
    Message ack = DMT.createFNPOpennetCompletedAck(uid);
    org.mockito.Mockito.when(node.network().usm()).thenReturn(usm);
    try {
      doAnswer(
              inv -> {
                // Simulate immediate match of CompletedAck
                var cb = (network.crypta.io.comm.AsyncMessageFilterCallback) inv.getArgument(1);
                cb.onMatched(ack);
                return null;
              })
          .when(usm)
          .addAsyncFilter(any(MessageFilter.class), any(), any());
    } catch (DisconnectedException e) {
      throw new AssertionError(e);
    }

    // Act
    byte[] result = OpennetNoderefWaiter.waitForOpennetNoderef(true, peer, uid, null, node);

    // Assert
    assertNull(result, "Ack path signals completion without noderef");
  }

  @Test
  @DisplayName("waitForOpennetNoderef throws on explicit timeout callback")
  void waitForOpennetNoderef_whenTimeout_expectException() {
    // Arrange
    long uid = 777L;
    org.mockito.Mockito.when(node.network().usm()).thenReturn(usm);
    try {
      doAnswer(
              inv -> {
                var cb = (network.crypta.io.comm.AsyncMessageFilterCallback) inv.getArgument(1);
                cb.onTimeout();
                return null;
              })
          .when(usm)
          .addAsyncFilter(any(MessageFilter.class), any(), any());
    } catch (DisconnectedException e) {
      throw new AssertionError(e);
    }

    // Act + Assert
    assertThrows(
        OpennetNoderefWaiter.WaitedTooLongForOpennetNoderefException.class,
        () -> OpennetNoderefWaiter.waitForOpennetNoderef(false, peer, uid, byteCounter, node));
  }

  static class TestCallback implements OpennetNoderefWaiter.NoderefCallback {

    boolean timedOut;
    byte[] noderef;

    @Override
    public void gotNoderef(byte[] noderef) {
      this.noderef = noderef;
    }

    @Override
    public void timedOut() {
      this.timedOut = true;
    }

    @Override
    public void acked(boolean timedOutMessage) {
      // No-op for this test callback.
    }
  }

  @Test
  @DisplayName(
      "waitForOpennetNoderef (callback variant) completes with null on DisconnectedException")
  void waitForOpennetNoderef_callback_whenDisconnected_expectNull() throws Exception {
    // Arrange
    long uid = 99L;
    org.mockito.Mockito.when(node.network().usm()).thenReturn(usm);
    doThrow(new DisconnectedException())
        .when(usm)
        .addAsyncFilter(any(MessageFilter.class), any(), any());
    TestCallback cb = new TestCallback();

    // Act
    OpennetNoderefWaiter.waitForOpennetNoderef(true, peer, uid, null, cb, node);

    // Assert
    assertNull(cb.noderef, "Disconnected path delivers null noderef via callback");
    // Ensure no timeout was signaled here
    assertFalse(cb.timedOut, "should not signal timeout on immediate disconnect");
  }

  @Test
  @DisplayName("rejectRef sends message and swallows NotConnectedException")
  void rejectRef_behaviour_expectSendAndNoThrow() throws Exception {
    long uid = 123L;
    int reason = DMT.NODEREF_REJECTED_TRANSFER_FAILED;

    // Case 1: send succeeds
    OpennetManager.rejectRef(uid, peer, reason, byteCounter);
    ArgumentCaptor<Message> captor = ArgumentCaptor.forClass(Message.class);
    verify(transport, times(1)).sendAsync(captor.capture(), any(), any());
    Message sent = captor.getValue();
    assertEquals(DMT.FNPOpennetNoderefRejected, sent.getSpec(), "message type");
    assertEquals(uid, sent.getLong(DMT.UID));
    assertEquals(reason, sent.getInt(DMT.REJECT_CODE));

    // Case 2: send throws NotConnectedException — must not propagate
    org.mockito.Mockito.reset(peer, transport);
    org.mockito.Mockito.when(peer.transport()).thenReturn(transport);
    org.mockito.Mockito.when(transport.sendAsync(any(Message.class), any(), any()))
        .thenThrow(new NotConnectedException());
    OpennetManager.rejectRef(uid, peer, reason, byteCounter);
    verify(transport, times(1)).sendAsync(any(Message.class), any(), any());
  }

  @Test
  @DisplayName("validateNoderef returns null on invalid compressed data")
  void validateNoderef_whenInvalidData_expectNull() {
    byte[] bogus = new byte[] {0x00, 0x01, 0x02, 0x03, 0x7F, 0x00, 0x10, 0x55, (byte) 0xAA, 0x5A};
    // Act
    var ref = OpennetNoderefValidator.validateNoderef(bogus, peer, false);
    // Assert
    assertNull(ref, "invalid bytes should fail parsing and return null");
  }
}
