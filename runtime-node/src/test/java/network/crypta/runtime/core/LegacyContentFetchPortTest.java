package network.crypta.runtime.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyContentFetchPortTest {
  @Test
  void redirectTarget_whenPermanentRedirectCarriesUri_expectUriReturned() {
    FreenetURI redirectUri = FreenetURI.EMPTY_CHK_URI;
    FetchException exception =
        new FetchException(FetchException.FetchExceptionMode.PERMANENT_REDIRECT, redirectUri);

    assertSame(redirectUri, LegacyContentFetchPort.redirectTarget(exception));
  }

  @Test
  void redirectTarget_whenPermanentRedirectHasNoUri_expectNoRetryTarget() {
    FetchException exception =
        new FetchException(FetchException.FetchExceptionMode.PERMANENT_REDIRECT, (FreenetURI) null);

    assertNull(LegacyContentFetchPort.redirectTarget(exception));
  }

  @Test
  void redirectTarget_whenModeIsNotPermanentRedirect_expectNoRetryTarget() {
    FetchException exception =
        new FetchException(
            FetchException.FetchExceptionMode.DATA_NOT_FOUND, FreenetURI.EMPTY_CHK_URI);

    assertNull(LegacyContentFetchPort.redirectTarget(exception));
  }

  @Test
  void materializeResult_whenWithinBound_expectBytesReturnedAndBucketFreed()
      throws ContentFetchException {
    TrackingBucket bucket = new TrackingBucket(new byte[] {1, 2});
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest("CHK@test", 2, Duration.ofSeconds(1), "catalog test");

    byte[] bytes = LegacyContentFetchPort.materializeResult(request, result);

    assertArrayEquals(new byte[] {1, 2}, bytes);
    assertTrue(bucket.freed());
  }

  @Test
  void materializeResult_whenReportedSizeExceedsBound_expectBucketFreed() {
    TrackingBucket bucket = new TrackingBucket(new byte[] {1, 2});
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest(
            "CHK@test", 1, Duration.ofSeconds(1), "oversized catalog test");

    ContentFetchException exception =
        assertThrows(
            ContentFetchException.class,
            () -> LegacyContentFetchPort.materializeResult(request, result));

    assertEquals(ContentFetchException.CATALOG_FETCH_FAILED, exception.errorCode());
    assertTrue(bucket.freed());
  }

  @Test
  void materializeResult_whenBucketReadFails_expectBucketFreed() {
    ThrowingReadBucket bucket = new ThrowingReadBucket(new byte[] {1});
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest("CHK@test", 1, Duration.ofSeconds(1), "catalog test");

    ContentFetchException exception =
        assertThrows(
            ContentFetchException.class,
            () -> LegacyContentFetchPort.materializeResult(request, result));

    assertEquals(ContentFetchException.CATALOG_FETCH_FAILED, exception.errorCode());
    assertTrue(bucket.freed());
  }

  @Test
  void streamResult_whenWithinBound_expectBytesWrittenAndBucketFreed()
      throws ContentFetchException, IOException {
    TrackingBucket bucket = new TrackingBucket(new byte[] {1, 2});
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest("CHK@test", 2, Duration.ofSeconds(1), "catalog test");
    ByteArrayOutputStream destination = new ByteArrayOutputStream();

    long bytesWritten = LegacyContentFetchPort.streamResult(request, result, destination);

    assertEquals(2L, bytesWritten);
    assertArrayEquals(new byte[] {1, 2}, destination.toByteArray());
    assertTrue(bucket.freed());
  }

  @Test
  void streamResult_whenStreamExceedsBound_expectBucketFreed() {
    TrackingBucket bucket = new MisreportingBucket(new byte[] {1, 2}, 1L);
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest("CHK@test", 1, Duration.ofSeconds(1), "catalog test");
    ByteArrayOutputStream destination = new ByteArrayOutputStream();

    ContentFetchException exception =
        assertThrows(
            ContentFetchException.class,
            () -> LegacyContentFetchPort.streamResult(request, result, destination));

    assertEquals(ContentFetchException.CATALOG_FETCH_FAILED, exception.errorCode());
    assertArrayEquals(new byte[0], destination.toByteArray());
    assertTrue(bucket.freed());
  }

  @Test
  void streamResult_whenBucketReadFails_expectBucketFreed() {
    ThrowingReadBucket bucket = new ThrowingReadBucket(new byte[] {1});
    FetchResult result = FetchResult.create(new ClientMetadata("application/octet-stream"), bucket);
    BoundedContentFetchRequest request =
        new BoundedContentFetchRequest("CHK@test", 1, Duration.ofSeconds(1), "catalog test");
    ByteArrayOutputStream destination = new ByteArrayOutputStream();

    IOException exception =
        assertThrows(
            IOException.class,
            () -> LegacyContentFetchPort.streamResult(request, result, destination));

    assertEquals("read failed", exception.getMessage());
    assertTrue(bucket.freed());
  }

  private static class TrackingBucket extends ArrayBucket {
    private boolean freed;

    private TrackingBucket(byte[] initData) {
      super(initData);
    }

    @Override
    public void free() {
      freed = true;
      super.free();
    }

    boolean freed() {
      return freed;
    }
  }

  private static final class ThrowingReadBucket extends TrackingBucket {
    private ThrowingReadBucket(byte[] initData) {
      super(initData);
    }

    @Override
    public InputStream getInputStreamUnbuffered() throws IOException {
      throw new IOException("read failed");
    }
  }

  private static final class MisreportingBucket extends TrackingBucket {
    private final long reportedSize;

    private MisreportingBucket(byte[] initData, long reportedSize) {
      super(initData);
      this.reportedSize = reportedSize;
    }

    @Override
    public long size() {
      return reportedSize;
    }
  }
}
