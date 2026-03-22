package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ResumeContext;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SingleFileStreamGeneratorTest {

  @Test
  void writeTo_whenBucketHasData_copiesBytesAndClosesResources() throws Exception {
    // Arrange
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    TrackingInputStream tis = new TrackingInputStream(new ByteArrayInputStream(data));
    FakeBucket bucket = new FakeBucket(tis, data.length);
    ClientContext ctx = mock(ClientContext.class);
    SingleFileStreamGenerator gen = new SingleFileStreamGenerator(bucket, false);
    try (TrackingOutputStream tos = new TrackingOutputStream()) {
      // Act
      gen.writeTo(tos, ctx);

      // Assert
      assertArrayEquals(data, tos.toByteArray(), "Output must match input");
      assertTrue(tos.isClosed(), "OutputStream should be closed by generator");
      assertTrue(bucket.isFreed(), "Bucket should be closed/freed by generator");
      assertTrue(tis.isClosed(), "InputStream should be closed by generator");
      assertEquals(data.length, gen.size(), "size() must mirror bucket.size()");
    }
  }

  @Test
  void writeTo_whenGetInputStreamThrowsIOException_propagatesIOExceptionAndCloses() {
    // Arrange
    final AtomicBoolean freeCalled = new AtomicBoolean(false);
    Bucket bucket =
        new Bucket() {
          @Override
          public InputStream getInputStream() throws IOException {
            throw new IOException("boom");
          }

          @Override
          public long size() {
            return 1L;
          }

          @Override
          public void free() {
            freeCalled.set(true);
          }

          // Unused methods
          @Override
          public OutputStream getOutputStream() {
            throw new UnsupportedOperationException();
          }

          @Override
          public OutputStream getOutputStreamUnbuffered() {
            throw new UnsupportedOperationException();
          }

          @Override
          public InputStream getInputStreamUnbuffered() {
            throw new UnsupportedOperationException();
          }

          @Override
          public String getName() {
            return "bucket";
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }

          @Override
          public void setReadOnly() {
            /* intentionally empty: not used in this test */
          }

          @Override
          public Bucket createShadow() {
            return null;
          }

          @Override
          public void onResume(ResumeContext context) {
            /* intentionally empty: not used in this test */
          }

          @Override
          public void storeTo(DataOutputStream dos) {
            /* intentionally empty: not used in this test */
          }

          @Override
          public void close() {
            free();
          }
        };

    ClientContext ctx = mock(ClientContext.class);
    SingleFileStreamGenerator gen = new SingleFileStreamGenerator(bucket, false);
    try (TrackingOutputStream tos = new TrackingOutputStream()) {
      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> gen.writeTo(tos, ctx));
      assertEquals("boom", ex.getMessage());
      assertTrue(tos.isClosed(), "OutputStream should be closed when exception occurs");
      assertTrue(freeCalled.get(), "Bucket should be closed on failure");
    }
  }

  @Test
  void writeTo_whenBucketReturnsNullInputStream_wrapsIntoIOException() {
    // Arrange: Bucket returns null input stream (empty bucket)
    FakeBucket bucket = new FakeBucket(null, 0);
    ClientContext ctx = mock(ClientContext.class);
    SingleFileStreamGenerator gen = new SingleFileStreamGenerator(bucket, false);
    try (TrackingOutputStream tos = new TrackingOutputStream()) {
      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> gen.writeTo(tos, ctx));
      assertNotNull(ex.getCause(), "Wrapped exception should carry cause");
      assertEquals(
          "Error during stream generation", ex.getMessage(), "Must use defined wrapper message");
      assertTrue(tos.isClosed(), "OutputStream should be closed by try-with-resources");
      assertTrue(bucket.isFreed(), "Bucket should be closed even on failure");
    }
  }

  @Test
  void writeTo_whenOutputThrowsIOException_propagatesIOException() {
    // Arrange
    byte[] data = new byte[] {1, 2, 3};
    TrackingInputStream tis = new TrackingInputStream(new ByteArrayInputStream(data));
    FakeBucket bucket = new FakeBucket(tis, data.length);
    ClientContext ctx = mock(ClientContext.class);
    SingleFileStreamGenerator gen = new SingleFileStreamGenerator(bucket, false);
    try (OutputStream failing =
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            throw new IOException("fail");
          }
        }) {
      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> gen.writeTo(failing, ctx));
      assertEquals("fail", ex.getMessage());
      assertTrue(bucket.isFreed(), "Bucket should be closed on write failure");
      assertTrue(tis.isClosed(), "InputStream should be closed on write failure");
    } catch (IOException _) {
      // close() on this stream is a no-op and does not throw
    }
  }

  @Test
  void size_returnsBucketSize() {
    // Arrange
    FakeBucket bucket = new FakeBucket(new ByteArrayInputStream(new byte[] {1}), 1L);
    SingleFileStreamGenerator gen = new SingleFileStreamGenerator(bucket, true);

    // Act + Assert
    assertEquals(1L, gen.size());
  }

  // --- Helpers -------------------------------------------------------------------------------

  private static final class FakeBucket implements Bucket {
    private final InputStream in;
    private final long size;
    private final AtomicBoolean freeCalled = new AtomicBoolean(false);

    FakeBucket(InputStream in, long size) {
      this.in = in;
      this.size = size;
    }

    @Override
    public InputStream getInputStream() {
      return in;
    }

    @Override
    public long size() {
      return size;
    }

    @Override
    public void free() {
      freeCalled.set(true);
    }

    boolean isFreed() {
      return freeCalled.get();
    }

    // Unused operations for tests
    @Override
    public OutputStream getOutputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String getName() {
      return "fake";
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    @Override
    public void setReadOnly() {
      /* intentionally empty: not used in this test */
    }

    @Override
    public Bucket createShadow() {
      return null;
    }

    @Override
    public void onResume(ResumeContext context) {
      /* intentionally empty: not used in this test */
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      /* intentionally empty: not used in this test */
    }

    @Override
    public void close() {
      free();
    }
  }

  private static final class TrackingInputStream extends InputStream {
    private final InputStream delegate;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    TrackingInputStream(InputStream delegate) {
      this.delegate = delegate;
    }

    @Override
    public int read() throws IOException {
      return delegate.read();
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) throws IOException {
      return delegate.read(b, off, len);
    }

    @Override
    public void close() throws IOException {
      closed.set(true);
      delegate.close();
    }

    boolean isClosed() {
      return closed.get();
    }
  }

  private static final class TrackingOutputStream extends OutputStream {
    private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    @Override
    public void write(int b) {
      baos.write(b);
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) {
      baos.write(b, off, len);
    }

    @Override
    public void close() {
      closed.set(true);
    }

    byte[] toByteArray() {
      return baos.toByteArray();
    }

    boolean isClosed() {
      return closed.get();
    }
  }
}
