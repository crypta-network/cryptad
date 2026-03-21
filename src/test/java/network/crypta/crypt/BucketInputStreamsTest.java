package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S5778", "EmptyTryBlock"})
@ExtendWith(MockitoExtension.class)
class BucketInputStreamsTest {

  @Test
  void openAndFreeOnClose_whenBucketProvidesStream_readDelegatesAndReturnsData() throws Exception {
    byte[] src = new byte[] {0, 1, 2, 3, 4, 5};
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(src));

    try (InputStream is = BucketInputStreams.openAndFreeOnClose(bucket)) {
      byte[] buf = new byte[4];
      int read = is.read(buf, 1, 2);

      assertEquals(2, read);
      assertArrayEquals(new byte[] {0, 0, 1, 0}, buf);
    }
  }

  @Test
  void openAndFreeOnClose_whenUsingArrayOverload_doesNotFallBackToSingleByteRead()
      throws Exception {
    class NoSingleByteReadInputStream extends InputStream {
      private final byte[] data;
      private int pos = 0;

      NoSingleByteReadInputStream(byte[] data) {
        this.data = data;
      }

      @Override
      public int read() {
        throw new IllegalStateException("single-byte read() must not be used");
      }

      @Override
      public int read(byte @NotNull [] b, int off, int len) {
        if (pos >= data.length) return -1;
        int n = Math.min(len, data.length - pos);
        System.arraycopy(data, pos, b, off, n);
        pos += n;
        return n;
      }
    }

    byte[] src = new byte[] {10, 11, 12, 13, 14};
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new NoSingleByteReadInputStream(src));

    try (InputStream is = BucketInputStreams.openAndFreeOnClose(bucket)) {
      byte[] buf1 = new byte[3];
      int r1 = is.read(buf1);
      assertEquals(3, r1);
      assertArrayEquals(new byte[] {10, 11, 12}, buf1);

      byte[] buf2 = new byte[4];
      int r2 = is.read(buf2, 1, 3);
      assertEquals(2, r2);
      assertArrayEquals(new byte[] {0, 13, 14, 0}, buf2);
    }
  }

  @Test
  void openAndFreeOnClose_whenCalled_closesStreamThenFreesBucketInOrder() throws Exception {
    InputStream underlying = mock(InputStream.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(underlying);

    try (var _ = BucketInputStreams.openAndFreeOnClose(bucket)) {
      // no-op
    }

    InOrder order = inOrder(underlying, bucket);
    order.verify(underlying, times(1)).close();
    order.verify(bucket, times(1)).free();
  }

  @Test
  void openAndFreeOnClose_whenUnderlyingCloseThrows_propagatesAndDoesNotFree() throws Exception {
    InputStream underlying = mock(InputStream.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(underlying);
    doThrow(new IOException("boom")).when(underlying).close();

    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (var _ = BucketInputStreams.openAndFreeOnClose(bucket)) {
                // no-op
              }
            });
    assertEquals("boom", ex.getMessage());
    verify(bucket, times(0)).free();
  }

  @Test
  void openAndFreeOnClose_whenBucketOpenThrows_propagatesAndDoesNotFree() throws Exception {
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenThrow(new IOException("boom"));

    IOException ex =
        assertThrows(IOException.class, () -> BucketInputStreams.openAndFreeOnClose(bucket));

    assertEquals("boom", ex.getMessage());
    verify(bucket, times(0)).free();
  }

  @Test
  void openAndFreeOnClose_withNullBucket_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = BucketInputStreams.openAndFreeOnClose(null)) {
            // no-op
          }
        });
  }
}
