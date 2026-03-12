package network.crypta.node;

import network.crypta.io.comm.AsyncMessageCallback;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MessageItemTest {

  @Mock private Message message;
  @Mock private ByteCounter byteCounter;
  @Mock private AsyncMessageCallback cb1;
  @Mock private AsyncMessageCallback cb2;

  @Test
  @DisplayName("constructor_withMessage_andPositiveOverride_usesOverridePriority_andEncodes")
  void constructor_withMessage_andPositiveOverride_usesOverridePriority_andEncodes() {
    // Arrange
    byte[] encoded = new byte[] {1, 2, 3};
    when(message.encodeToPacket()).thenReturn(encoded);
    when(message.toString()).thenReturn("MockMessage");

    // Act
    MessageItem item =
        new MessageItem(message, new AsyncMessageCallback[] {cb1}, byteCounter, (short) 1);

    // Assert
    assertArrayEquals(encoded, item.getData());
    assertEquals(3, item.getLength());
    assertEquals(1, item.getPriority());
    String s = item.toString();
    assertTrue(s.contains("formatted=false"));
    assertTrue(s.contains("msg=MockMessage"));
  }

  @Test
  @DisplayName("constructor_withMessage_andNonPositiveOverride_usesMessagePriority")
  void constructor_withMessage_andNonPositiveOverride_usesMessagePriority() {
    // Arrange
    when(message.encodeToPacket()).thenReturn(new byte[] {9});
    when(message.getPriority()).thenReturn((short) 2);

    // Act
    MessageItem item = new MessageItem(message, null, null, (short) -1);

    // Assert
    assertEquals(2, item.getPriority());
    assertEquals(1, item.getLength());
  }

  @Test
  @DisplayName("constructor_withLargeEncodedMessage_logsWarnAndConstructs")
  void constructor_withLargeEncodedMessage_logsWarnAndConstructs() {
    // Arrange: return payload larger than MAX_MESSAGE_SIZE
    byte[] large = new byte[NewPacketFormat.MAX_MESSAGE_SIZE + 1];
    when(message.encodeToPacket()).thenReturn(large);
    when(message.getPriority()).thenReturn((short) 2);

    // Act + Assert: just ensure no exception; logging branch executes
    MessageItem item = new MessageItem(message, null, null, (short) -1);
    assertNotNull(item);
    assertEquals(large.length, item.getLength());
  }

  @Test
  @DisplayName("constructor_withFormattedNullData_throwsNullPointerException")
  void constructor_withFormattedNullData_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () ->
            new MessageItem(null, new AsyncMessageCallback[] {cb1}, true, byteCounter, (short) 0));
  }

  @Test
  @DisplayName("constructor_withUnformattedNullData_allowsNull_getLengthThrows")
  void constructor_withUnformattedNullData_allowsNull_getLengthThrows() {
    // Arrange
    MessageItem item = new MessageItem(null, null, false, null, (short) 0);

    // Act + Assert
    assertNull(item.getData());
    assertTrue(item.toString().contains("formatted=false"));
    assertTrue(item.toString().contains("msg=null"));
    assertThrows(NullPointerException.class, item::getLength);
  }

  @Test
  @DisplayName("onSent_withCounter_reportsBytes_andSwallowsExceptions")
  void onSent_withCounter_reportsBytes_andSwallowsExceptions() {
    // Arrange
    MessageItem ok = new MessageItem(new byte[] {1}, null, false, byteCounter, (short) 0);
    MessageItem throwing = new MessageItem(new byte[] {1}, null, false, byteCounter, (short) 0);

    // Act
    ok.onSent(123);

    // Assert
    verify(byteCounter).sentBytes(123);

    // Arrange a throwing counter on second call
    doThrow(new RuntimeException("boom")).when(byteCounter).sentBytes(456);

    // Act + Assert: no exception should escape
    assertDoesNotThrow(() -> throwing.onSent(456));
    verify(byteCounter).sentBytes(456);
  }

  @Test
  @DisplayName("onSent_withNullCounter_isNoOp")
  void onSent_withNullCounter_isNoOp() {
    MessageItem item = new MessageItem(new byte[] {1, 2}, null, false, null, (short) 0);
    assertDoesNotThrow(() -> item.onSent(99));
  }

  @Test
  @DisplayName("onDisconnect_callsAllCallbacks_evenWhenSomeThrow")
  void onDisconnect_callsAllCallbacks_evenWhenSomeThrow() {
    // Arrange
    doThrow(new RuntimeException("fail")).when(cb1).disconnected();
    MessageItem item =
        new MessageItem(
            new byte[] {1}, new AsyncMessageCallback[] {cb1, cb2}, false, null, (short) 0);

    // Act
    assertDoesNotThrow(item::onDisconnect);

    // Assert: both callbacks invoked despite one throwing
    verify(cb1, times(1)).disconnected();
    verify(cb2, times(1)).disconnected();
    verifyNoMoreInteractions(cb1, cb2);
  }

  @Test
  @DisplayName("onFailed_callsFatalError_onAllCallbacks_evenWhenSomeThrow")
  void onFailed_callsFatalError_onAllCallbacks_evenWhenSomeThrow() {
    // Arrange
    doThrow(new RuntimeException("fail")).when(cb2).fatalError();
    MessageItem item =
        new MessageItem(
            new byte[] {1}, new AsyncMessageCallback[] {cb1, cb2}, false, null, (short) 0);

    // Act
    assertDoesNotThrow(item::onFailed);

    // Assert
    verify(cb1, times(1)).fatalError();
    verify(cb2, times(1)).fatalError();
    verifyNoMoreInteractions(cb1, cb2);
  }

  @Test
  @DisplayName("onSentAll_callsSent_onAllCallbacks_evenWhenSomeThrow")
  void onSentAll_callsSent_onAllCallbacks_evenWhenSomeThrow() {
    // Arrange
    doThrow(new RuntimeException("fail")).when(cb1).sent();
    MessageItem item =
        new MessageItem(
            new byte[] {1}, new AsyncMessageCallback[] {cb1, cb2}, false, null, (short) 0);

    // Act
    assertDoesNotThrow(item::onSentAll);

    // Assert
    verify(cb1, times(1)).sent();
    verify(cb2, times(1)).sent();
    verifyNoMoreInteractions(cb1, cb2);
  }

  @Test
  @DisplayName("getID_withLongUID_returnsValue_andCachesResult")
  void getID_withLongUID_returnsValue_andCachesResult() {
    // Arrange: first call returns 42L, subsequent calls would return 99L if invoked
    when(message.encodeToPacket()).thenReturn(new byte[] {1});
    when(message.getPriority()).thenReturn((short) 2);
    when(message.getObject(DMT.UID)).thenReturn(42L, 99L);
    MessageItem item = new MessageItem(message, null, null, (short) -1);

    // Act
    long id1 = item.getID();
    long id2 = item.getID();

    // Assert
    assertEquals(42L, id1);
    assertEquals(42L, id2, "ID must be cached and stable");
    // Verify underlying lookup called only once due to caching
    verify(message, times(1)).getObject(DMT.UID);
  }

  @Test
  @DisplayName("getID_withNullMessage_returnsMinusOne_andCaches")
  void getID_withNullMessage_returnsMinusOne_andCaches() {
    // Arrange
    MessageItem item = new MessageItem(new byte[] {1}, null, false, null, (short) 0);

    // Act
    long id1 = item.getID();
    long id2 = item.getID();

    // Assert
    assertEquals(-1L, id1);
    assertEquals(-1L, id2);
  }

  @Test
  @DisplayName("getID_withNonLongUID_returnsMinusOne")
  void getID_withNonLongUID_returnsMinusOne() {
    // Arrange
    when(message.encodeToPacket()).thenReturn(new byte[] {1});
    when(message.getPriority()).thenReturn((short) 2);
    when(message.getObject(DMT.UID)).thenReturn("not-a-long");
    MessageItem item = new MessageItem(message, null, null, (short) -1);

    // Act + Assert
    assertEquals(-1L, item.getID());
  }

  @Test
  @DisplayName("deadline_set_and_clear_and_get_behaveAsExpected")
  void deadline_set_and_clear_and_get_behaveAsExpected() {
    // Arrange
    MessageItem item = new MessageItem(new byte[] {1, 2, 3}, null, true, null, (short) 0);

    // Act + Assert
    assertEquals(0L, item.getDeadline(), "Default deadline must be zero");
    item.setDeadline(123456789L);
    assertEquals(123456789L, item.getDeadline());
    item.clearDeadline();
    assertEquals(0L, item.getDeadline());
  }
}
