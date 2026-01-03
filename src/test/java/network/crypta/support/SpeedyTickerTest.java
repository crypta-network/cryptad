package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SpeedyTickerTest {

  @Mock private Runnable runnable;

  @Test
  void queueTimedJob_whenCalled_doesNotInvokeRunnable() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act
    ticker.queueTimedJob(runnable, 0L);

    // Assert
    verifyNoInteractions(runnable);
  }

  @Test
  void queueTimedJob_whenCalledWithParameters_doesNotInvokeRunnable() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act
    ticker.queueTimedJob(runnable, "job", 1L, true, true);

    // Assert
    verifyNoInteractions(runnable);
  }

  @Test
  void queueTimedJob_whenJobIsNull_doesNotThrow() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act + Assert
    assertDoesNotThrow(() -> ticker.queueTimedJob(null, 0L));
  }

  @Test
  void getExecutor_whenCalled_throwsUnsupportedOperationException() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, ticker::getExecutor);
  }

  @Test
  void removeQueuedJob_whenCalled_throwsUnsupportedOperationException() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, () -> ticker.removeQueuedJob(runnable));
  }

  @Test
  void queueTimedJobAbsolute_whenCalled_throwsUnsupportedOperationException() {
    // Arrange
    SpeedyTicker ticker = new SpeedyTicker();

    // Act + Assert
    assertThrows(
        UnsupportedOperationException.class,
        () -> ticker.queueTimedJobAbsolute(runnable, "job", 1L, true, false));
  }
}
