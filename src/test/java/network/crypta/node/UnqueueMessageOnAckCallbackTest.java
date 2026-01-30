package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class UnqueueMessageOnAckCallbackTest {

  @Mock private DarknetPeerNode dest;

  @Test
  void acknowledged_whenCalled_unqueuesExpectedFile() {
    // Arrange
    int fileNumber = 42;
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(dest, fileNumber);

    // Act
    cb.acknowledged();

    // Assert
    verify(dest).unqueueN2NM(fileNumber);
    verifyNoMoreInteractions(dest);
  }

  @Test
  void sent_whenCalled_doesNothing() {
    // Arrange
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(dest, 7);

    // Act
    cb.sent();

    // Assert
    verifyNoInteractions(dest);
  }

  @Test
  void disconnected_whenCalled_doesNothing() {
    // Arrange
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(dest, 9);

    // Act
    cb.disconnected();

    // Assert
    verifyNoInteractions(dest);
  }

  @Test
  void fatalError_whenCalled_doesNothing() {
    // Arrange
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(dest, 11);

    // Act
    cb.fatalError();

    // Assert
    verifyNoInteractions(dest);
  }

  @Test
  void toString_whenConstructed_containsDestAndFileNumber() {
    // Arrange
    int fileNumber = 7;
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(dest, fileNumber);

    // Act
    String destString = "dest-7";
    doReturn(destString).when(dest).toString();
    String s = cb.toString();

    // Assert
    assertTrue(s.contains(destString));
    assertTrue(s.endsWith(" " + fileNumber));
  }

  @Test
  void acknowledged_whenDestNull_throwsNullPointerException() {
    // Arrange
    UnqueueMessageOnAckCallback cb = new UnqueueMessageOnAckCallback(null, 3);

    // Act & Assert
    assertThrows(NullPointerException.class, cb::acknowledged);
  }
}
