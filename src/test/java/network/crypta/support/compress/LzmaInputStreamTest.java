package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.sevenzip.compression.lzma.Encoder;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LzmaInputStreamTest {

  @Test
  void read_whenValidFrame_expectOriginalBytes() throws Exception {
    // Arrange
    byte[] payload = "cryptad-lzma-stream-read-happy-path".getBytes(StandardCharsets.US_ASCII);
    byte[] frame = createLzmaFrame(payload);

    // Act
    byte[] decoded;
    try (LzmaInputStream stream = new LzmaInputStream(new ByteArrayInputStream(frame));
        ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      int next;
      while ((next = stream.read()) != -1) {
        out.write(next);
      }
      decoded = out.toByteArray();
    }

    // Assert
    assertArrayEquals(payload, decoded);
  }

  @Test
  void readByteArray_whenValidFrame_expectOriginalBytes() throws Exception {
    // Arrange
    byte[] payload =
        "cryptad-lzma-stream-read-byte-array-happy-path".getBytes(StandardCharsets.US_ASCII);
    byte[] frame = createLzmaFrame(payload);

    // Act
    byte[] decoded;
    try (LzmaInputStream stream = new LzmaInputStream(new ByteArrayInputStream(frame));
        ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      byte[] chunk = new byte[9];
      int read;
      while ((read = stream.read(chunk, 2, 5)) != -1) {
        out.write(chunk, 2, read);
      }
      decoded = out.toByteArray();
    }

    // Assert
    assertArrayEquals(payload, decoded);
  }

  @Test
  void constructor_whenPropertiesTruncated_expectIOException() {
    // Arrange
    byte[] truncatedProps = new byte[] {0x5D, 0x00, 0x00, 0x10};

    // Act + Assert
    IOException exception =
        assertThrows(
            IOException.class, () -> new LzmaInputStream(new ByteArrayInputStream(truncatedProps)));
    assertEquals("Unexpected EOF", exception.getMessage());
  }

  @Test
  void constructor_whenSizeHeaderTruncated_expectIOException() throws Exception {
    // Arrange
    byte[] header = createHeader(17L);
    byte[] truncatedSizeHeader = Arrays.copyOf(header, Encoder.PROP_SIZE + 3);

    // Act + Assert
    IOException exception =
        assertThrows(
            IOException.class,
            () -> new LzmaInputStream(new ByteArrayInputStream(truncatedSizeHeader)));
    assertEquals("Unexpected EOF reading LZMA size header", exception.getMessage());
  }

  @Test
  void constructor_whenPropertiesInvalid_expectIOException() {
    // Arrange
    byte[] invalidHeader = new byte[Encoder.PROP_SIZE + Long.BYTES];
    invalidHeader[0] = (byte) 0xFF;

    // Act + Assert
    IOException exception =
        assertThrows(
            IOException.class, () -> new LzmaInputStream(new ByteArrayInputStream(invalidHeader)));
    assertEquals("Invalid LZMA properties", exception.getMessage());
  }

  @Test
  void read_whenDecoderFailsAfterStartup_expectIOException() throws Exception {
    // Arrange
    HeaderThenFailingInputStream source = new HeaderThenFailingInputStream(createHeader(1L));
    IOException exception;

    // Act
    try (LzmaInputStream stream = new LzmaInputStream(source)) {
      source.allowFailure();
      exception =
          assertThrows(
              IOException.class,
              () -> {
                while (stream.read() >= 0) {
                  // Keep consuming until decoder failure is observed.
                }
              });
    }

    // Assert
    assertEquals("synthetic payload failure", exception.getMessage());
  }

  @Test
  void readByteArray_whenDecoderFailsAfterStartup_expectIOException() throws Exception {
    // Arrange
    HeaderThenFailingInputStream source = new HeaderThenFailingInputStream(createHeader(1L));
    IOException exception;

    // Act
    try (LzmaInputStream stream = new LzmaInputStream(source)) {
      source.allowFailure();
      exception =
          assertThrows(
              IOException.class,
              () -> {
                byte[] buffer = new byte[8];
                while (stream.read(buffer, 0, buffer.length) >= 0) {
                  // Keep consuming until decoder failure is observed.
                }
              });
    }

    // Assert
    assertEquals("synthetic payload failure", exception.getMessage());
  }

  @Test
  void close_whenCalled_expectSourceStreamClosed() throws Exception {
    // Arrange
    CloseTrackingInputStream source = new CloseTrackingInputStream(createLzmaFrame(new byte[0]));
    LzmaInputStream stream = new LzmaInputStream(source);

    // Act
    stream.close();

    // Assert
    assertTrue(source.isClosed());
  }

  private static byte[] createLzmaFrame(byte[] payload) throws IOException {
    ByteArrayOutputStream frame = new ByteArrayOutputStream();
    Encoder encoder = new Encoder();
    encoder.writeCoderProperties(frame);
    writeLittleEndianLong(frame, payload.length);
    encoder.code(new ByteArrayInputStream(payload), frame, null);
    return frame.toByteArray();
  }

  private static byte[] createHeader(long outSize) throws IOException {
    ByteArrayOutputStream frame = new ByteArrayOutputStream();
    Encoder encoder = new Encoder();
    encoder.writeCoderProperties(frame);
    writeLittleEndianLong(frame, outSize);
    return frame.toByteArray();
  }

  private static void writeLittleEndianLong(ByteArrayOutputStream out, long value) {
    for (int i = 0; i < Long.BYTES; i++) {
      out.write((int) ((value >>> (i * 8)) & 0xFF));
    }
  }

  private static final class CloseTrackingInputStream extends ByteArrayInputStream {
    private boolean closed;

    private CloseTrackingInputStream(byte[] data) {
      super(data);
    }

    @Override
    public void close() throws IOException {
      closed = true;
      super.close();
    }

    private boolean isClosed() {
      return closed;
    }
  }

  private static final class HeaderThenFailingInputStream extends InputStream {
    private final byte[] header;
    private final CountDownLatch allowFailure = new CountDownLatch(1);
    private int index;

    private HeaderThenFailingInputStream(byte[] header) {
      this.header = header;
    }

    private void allowFailure() {
      allowFailure.countDown();
    }

    @Override
    public int read() throws IOException {
      byte[] oneByte = new byte[1];
      int read = read(oneByte, 0, 1);
      if (read < 0) {
        return -1;
      }
      return oneByte[0] & 0xFF;
    }

    @Override
    public int read(byte @NonNull [] buffer, int off, int len) throws IOException {
      if (len == 0) {
        return 0;
      }
      if (index < header.length) {
        int copyLength = Math.min(len, header.length - index);
        System.arraycopy(header, index, buffer, off, copyLength);
        index += copyLength;
        return copyLength;
      }
      awaitFailureSignal();
      throw new IOException("synthetic payload failure");
    }

    private void awaitFailureSignal() throws IOException {
      try {
        allowFailure.await();
      } catch (InterruptedException interruptedException) {
        Thread.currentThread().interrupt();
        throw new IOException(
            "Interrupted while waiting to fail payload reads", interruptedException);
      }
    }

    @Override
    public void close() {
      allowFailure.countDown();
    }
  }
}
