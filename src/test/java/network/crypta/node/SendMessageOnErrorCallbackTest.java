package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SendMessageOnErrorCallbackTest {

  @Mock private PeerNode dest;
  @Mock private Message msg;
  @Mock private ByteCounter ctr;

  @Test
  void disconnected_whenDestinationConnected_sendsMessageOnce() throws Exception {
    // Arrange
    SendMessageOnErrorCallback cb = new SendMessageOnErrorCallback(msg, dest, ctr);

    // Act
    cb.disconnected();

    // Assert
    verify(dest).sendAsync(eq(msg), isNull(), eq(ctr));
  }

  @Test
  void disconnected_whenDestinationNotConnected_swallowsException() throws Exception {
    // Arrange
    when(dest.sendAsync(any(Message.class), any(), any(ByteCounter.class)))
        .thenThrow(new NotConnectedException());
    SendMessageOnErrorCallback cb = new SendMessageOnErrorCallback(msg, dest, ctr);

    // Act + Assert
    assertDoesNotThrow(cb::disconnected);
    verify(dest).sendAsync(eq(msg), isNull(), eq(ctr));
  }

  @Test
  void fatalError_alwaysDelegatesToDisconnected() throws Exception {
    // Arrange
    SendMessageOnErrorCallback cb = new SendMessageOnErrorCallback(msg, dest, ctr);

    // Act
    cb.fatalError();

    // Assert
    verify(dest).sendAsync(eq(msg), isNull(), eq(ctr));
  }

  @Test
  void toString_containsMessageAndDestination() {
    // Arrange
    when(msg.toString()).thenReturn("MSG");
    when(dest.toString()).thenReturn("DEST");
    SendMessageOnErrorCallback cb = new SendMessageOnErrorCallback(msg, dest, ctr);

    // Act
    String s = cb.toString();

    // Assert
    assertTrue(s.endsWith(": MSG DEST"), "toString should append message and destination");
  }

  @Test
  void sent_and_acknowledged_doNothing() {
    // Arrange
    SendMessageOnErrorCallback cb = new SendMessageOnErrorCallback(msg, dest, ctr);

    // Act
    cb.sent();
    cb.acknowledged();

    // Assert
    verifyNoInteractions(dest);
  }
}
