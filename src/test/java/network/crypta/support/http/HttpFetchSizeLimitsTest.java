package network.crypta.support.http;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class HttpFetchSizeLimitsTest {

  private long originalMaxLengthNoProgress;
  private long originalMaxLengthWithProgress;

  @BeforeEach
  void captureOriginalLimits() {
    originalMaxLengthNoProgress = HttpFetchSizeLimits.getMaxLengthNoProgress();
    originalMaxLengthWithProgress = HttpFetchSizeLimits.getMaxLengthWithProgress();
  }

  @AfterEach
  void restoreOriginalLimits() {
    HttpFetchSizeLimits.setMaxLengthNoProgress(originalMaxLengthNoProgress);
    HttpFetchSizeLimits.setMaxLengthWithProgress(originalMaxLengthWithProgress);
  }

  @Test
  void setters_whenValuesUpdated_expectGettersReflectCurrentLimits() {
    // Arrange
    long noProgress = 1234L;
    long withProgress = 5678L;

    // Act
    HttpFetchSizeLimits.setMaxLengthNoProgress(noProgress);
    HttpFetchSizeLimits.setMaxLengthWithProgress(withProgress);

    // Assert
    assertEquals(noProgress, HttpFetchSizeLimits.getMaxLengthNoProgress());
    assertEquals(withProgress, HttpFetchSizeLimits.getMaxLengthWithProgress());
  }
}
