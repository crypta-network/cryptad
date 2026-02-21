package network.crypta.client.async;

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

@SuppressWarnings({"java:S100", "java:S5778"})
@ExtendWith(MockitoExtension.class)
class ReadBucketAndFreeInputStreamTest {

  private static int invalidNegativeOffset() {
    return -Math.abs(System.identityHashCode(new Object()) | 1);
  }

  private static int invalidLength(byte[] buffer) {
    return buffer.length + Math.max(1, Math.abs(System.identityHashCode(buffer) % 3));
  }

  @Test
  void create_whenBucketProvidesStream_readDelegatesAndReturnsData() throws Exception {
    // Arrange
    byte[] src = new byte[] {0, 1, 2, 3, 4, 5};
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(src));

    // Act + Assert (try-with-resources)
    try (InputStream is = ReadBucketAndFreeInputStream.create(bucket)) {
      byte[] buf = new byte[4];
      int read = is.read(buf, 1, 2); // read 2 bytes into indices 1..2

      assertEquals(2, read);
      assertArrayEquals(new byte[] {0, 0, 1, 0}, buf);
    }
  }

  @Test
  void read_whenUsingArrayOverload_doesNotFallBackToSingleByteRead() throws Exception {
    // Arrange: InputStream that throws if single-byte read(int) is used
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

    try (InputStream is = ReadBucketAndFreeInputStream.create(bucket)) {
      // Act + Assert: read(byte[])
      byte[] buf1 = new byte[3];
      int r1 = is.read(buf1);
      assertEquals(3, r1);
      assertArrayEquals(new byte[] {10, 11, 12}, buf1);

      // Act + Assert: read(byte[], off, len)
      byte[] buf2 = new byte[4];
      int r2 = is.read(buf2, 1, 3);
      assertEquals(2, r2); // the remaining bytes are 13,14 → only 2 available
      assertArrayEquals(new byte[] {0, 13, 14, 0}, buf2);
    }
  }

  @Test
  void read_withInvalidArgs_throwsIndexOutOfBoundsException() throws Exception {
    // Arrange
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    try (InputStream is = ReadBucketAndFreeInputStream.create(bucket)) {
      // Act + Assert
      byte[] buf = new byte[2];
      int negativeOff = invalidNegativeOffset();
      int tooLargeLen = invalidLength(buf);
      assertThrows(
          IndexOutOfBoundsException.class,
          () -> {
            network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
                is.read(buf, negativeOff, 1));
          });
      assertThrows(
          IndexOutOfBoundsException.class,
          () -> {
            network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
                is.read(buf, 0, tooLargeLen));
          });
    }
  }

  @Test
  void read_withNullBuffer_throwsNullPointerException() throws Exception {
    // Arrange
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[] {1, 2, 3}));
    try (InputStream is = ReadBucketAndFreeInputStream.create(bucket)) {
      // Act + Assert
      //noinspection DataFlowIssue
      assertThrows(
          NullPointerException.class,
          () -> {
            network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(is.read(null));
          });
    }
  }

  @Test
  void close_whenCalled_closesStreamThenFreesBucketInOrder() throws Exception {
    // Arrange
    InputStream underlying = mock(InputStream.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(underlying);
    // Act via try-with-resources implicit close
    //noinspection EmptyTryBlock
    try (var _ = ReadBucketAndFreeInputStream.create(bucket)) {
      // no-op
    }

    // Assert
    InOrder order = inOrder(underlying, bucket);
    order.verify(underlying, times(1)).close();
    order.verify(bucket, times(1)).free();
  }

  @Test
  void close_whenUnderlyingCloseThrows_propagatesAndDoesNotFree() throws Exception {
    // Arrange
    InputStream underlying = mock(InputStream.class);
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(underlying);
    doThrow(new IOException("boom")).when(underlying).close();
    // Act + Assert: closing via try-with-resources propagates
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              //noinspection EmptyTryBlock
              try (var _ = ReadBucketAndFreeInputStream.create(bucket)) {
                // no-op
              }
            });
    assertEquals("boom", ex.getMessage());
    verify(bucket, times(0)).free();
  }

  @Test
  void read_whenUnderlyingThrows_propagatesIOException() throws Exception {
    // Arrange
    InputStream underlying =
        new InputStream() {
          @Override
          public int read(byte @NotNull [] b, int off, int len) throws IOException {
            throw new IOException("read-fail");
          }

          @Override
          public int read() {
            return -1;
          }
        };
    Bucket bucket = mock(Bucket.class);
    when(bucket.getInputStream()).thenReturn(underlying);
    try (InputStream is = ReadBucketAndFreeInputStream.create(bucket)) {
      // Act + Assert
      byte[] buf = new byte[2];
      IOException ex =
          assertThrows(
              IOException.class,
              () -> {
                network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(is.read(buf));
              });
      assertEquals("read-fail", ex.getMessage());
    }
  }

  @Test
  void create_withNullBucket_throwsNullPointerException() {
    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> {
          //noinspection EmptyTryBlock
          try (var _ = ReadBucketAndFreeInputStream.create(null)) {
            // no-op
          }
        });
  }
}
