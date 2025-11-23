package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import network.crypta.client.FetchException;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FProxyFetchResultTest {

  @Test
  void hasData_whenConstructedWithData_trueAndFieldsMatch() {
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    Bucket bucket = mock(Bucket.class);
    long expectedSize = 42L;

    // Arrange
    // size is derived from the bucket, not passed in
    Mockito.when(bucket.size()).thenReturn(expectedSize);

    FProxyFetchResult result =
        new FProxyFetchResult(progress, bucket, "text/plain", 100L, true, 200L, false);

    // Act & Assert
    assertTrue(result.hasData());
    assertSame(bucket, result.getData());
    assertEquals(expectedSize, result.size);
    assertEquals("text/plain", result.mimeType);
    assertTrue(result.isFinished());
    assertFalse(result.hasWaited());
    assertTrue(result.finalizedBlocks);
    assertEquals(0, result.totalBlocks);
    assertNull(result.failed);
  }

  @Test
  void isFinished_whenFailedConstructor_trueAndFieldsCopied() {
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    FetchException exception = mock(FetchException.class);

    FProxyFetchResult result =
        new FProxyFetchResult(
            progress,
            "application/octet-stream",
            128L,
            50L,
            false,
            10,
            6,
            4,
            1,
            0,
            true,
            exception,
            500L,
            true);

    assertFalse(result.hasData());
    assertTrue(result.isFinished());
    assertSame(exception, result.failed);
    assertEquals(128L, result.size);
    assertEquals(10, result.totalBlocks);
    assertEquals(6, result.requiredBlocks);
    assertEquals(4, result.fetchedBlocks);
    assertEquals(1, result.failedBlocks);
    assertEquals(0, result.fatallyFailedBlocks);
    assertTrue(result.finalizedBlocks);
    assertTrue(result.hasWaited());
  }

  @Test
  void isFinished_whenStillRunning_falseAndProgressReported() {
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);

    FProxyFetchResult result =
        new FProxyFetchResult(
            progress, "text/html", -1L, 75L, true, 20, 15, 5, 0, 0, false, null, 1000L, false);

    assertFalse(result.hasData());
    assertFalse(result.isFinished());
    assertEquals(20, result.totalBlocks);
    assertFalse(result.finalizedBlocks);
    assertFalse(result.hasWaited());
    assertEquals(0, result.getFetchCount());
  }

  @Test
  void close_whenCalled_delegatesToProgress() {
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);
    Bucket bucket = mock(Bucket.class);
    Mockito.when(bucket.size()).thenReturn(1L);

    FProxyFetchResult result =
        new FProxyFetchResult(progress, bucket, "text/plain", 0L, false, -1L, true);

    result.close();

    verify(progress).close(result);
  }

  @Test
  void setFetchCount_whenUpdated_getFetchCountReturnsValue() {
    FProxyFetchInProgress progress = mock(FProxyFetchInProgress.class);

    FProxyFetchResult result =
        new FProxyFetchResult(
            progress, "text/plain", 0L, 0L, false, 0, 0, 0, 0, 0, true, null, -1L, false);

    result.setFetchCount(7);

    assertEquals(7, result.getFetchCount());
  }
}
