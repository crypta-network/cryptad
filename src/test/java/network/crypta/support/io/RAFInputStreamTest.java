package network.crypta.support.io;

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import network.crypta.support.api.RandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RAFInputStream}.
 *
 * <p>Tests follow AAA style, use deterministic data, and cover null, empty, boundary, and error
 * paths. External I/O is mocked using Mockito.
 */
class RAFInputStreamTest {

  private static void ignoreInt(int ignored) {
    // Intentional no-op for tests validating exceptional paths.
  }

  private static byte[] patternBytes(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      // Deterministic pattern, stable across runs
      data[i] = (byte) (i * 37 + 11);
    }
    return data;
  }

  @Test
  @DisplayName("readBuffer_whenOffsetNonZero_expectCorrectDataAndThenEof")
  void readBufferWhenOffsetNonZeroExpectCorrectDataAndThenEof() throws Exception {
    // Arrange
    byte[] content = patternBytes(10);
    RandomAccessBuffer raf = stubRaf(content);
    // Window: start at index 4, length 3 -> bytes [4,5,6]
    try (RAFInputStream is = new RAFInputStream(raf, 4, 3)) {
      byte[] buf = new byte[8];

      // Act
      int n1 = is.read(buf, 0, buf.length);

      // Assert
      assertEquals(3, n1);
      assertArrayEquals(
          new byte[] {content[4], content[5], content[6]}, new byte[] {buf[0], buf[1], buf[2]});
      assertThrows(EOFException.class, () -> ignoreInt(is.read(buf)));
    }
  }

  @Test
  @DisplayName("read_whenOffsetNonZero_expectCorrectUnsignedBytesThenEof")
  void readWhenOffsetNonZeroExpectCorrectUnsignedBytesThenEof() throws Exception {
    // Arrange
    byte[] content = patternBytes(6);
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, 1, 2)) { // expect bytes at indices 1 and 2
      // Act & Assert
      assertEquals(Byte.toUnsignedInt(content[1]), is.read());
      assertEquals(Byte.toUnsignedInt(content[2]), is.read());
      assertThrows(EOFException.class, is::read);
    }
  }

  private static RandomAccessBuffer stubRaf(byte[] content) throws IOException {
    RandomAccessBuffer raf = mock(RandomAccessBuffer.class);
    when(raf.size()).thenReturn((long) content.length);
    // Delegate pread() to read from the in-memory array with strict bounds checking
    doAnswer(
            inv -> {
              long fileOffset = inv.getArgument(0);
              byte[] buf = inv.getArgument(1);
              int bufOffset = inv.getArgument(2);
              int len = inv.getArgument(3);
              if (fileOffset < 0) throw new IllegalArgumentException("fileOffset < 0");
              if (len < 0) throw new IllegalArgumentException("len < 0");
              if (buf == null) throw new NullPointerException("buf is null");
              if (bufOffset < 0 || bufOffset + len > buf.length)
                throw new IndexOutOfBoundsException("invalid buf range");
              if (fileOffset + len > content.length)
                throw new IOException("read exceeds available content");
              System.arraycopy(content, (int) fileOffset, buf, bufOffset, len);
              return null;
            })
        .when(raf)
        .pread(anyLong(), any(byte[].class), anyInt(), anyInt());
    // Unused methods can be no-ops in this test
    doNothing().when(raf).pwrite(anyLong(), any(byte[].class), anyInt(), anyInt());
    doNothing().when(raf).free();
    doNothing().when(raf).close();
    return raf;
  }

  @Test
  @DisplayName("read_whenReadingSingleBytes_expectUnsignedValueAndEofOnExhaustion")
  void readWhenReadingSingleBytesExpectUnsignedValueAndEofOnExhaustion() throws Exception {
    // Arrange
    byte[] content = new byte[] {(byte) 0xFF, 0x00, 0x7F};
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, 0, content.length)) {
      // Act & Assert
      assertEquals(255, is.read());
      assertEquals(0, is.read());
      assertEquals(127, is.read());
      assertThrows(EOFException.class, is::read);
    }
  }

  @Test
  @DisplayName("read_whenAtEof_expectEOFException")
  void readWhenAtEofExpectEOFException() throws Exception {
    // Arrange: zero-length view
    RandomAccessBuffer raf = stubRaf(new byte[0]);
    try (RAFInputStream is = new RAFInputStream(raf, 0, 0)) {
      // Act & Assert
      assertThrows(EOFException.class, is::read);
    }
  }

  @Test
  @DisplayName("readBuffer_whenRequestedExceedsRemaining_expectClampedAndThenEof")
  void readBufferWhenRequestedExceedsRemainingExpectClampedAndThenEof() throws Exception {
    // Arrange
    byte[] content = patternBytes(5);
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, 0, content.length)) {
      byte[] buf = new byte[8];

      // Act & Assert
      int n1 = is.read(buf, 0, 3);
      assertEquals(3, n1);
      assertArrayEquals(
          new byte[] {content[0], content[1], content[2]}, new byte[] {buf[0], buf[1], buf[2]});

      int n2 = is.read(buf, 0, 3);
      assertEquals(2, n2); // clamped to remaining
      assertArrayEquals(new byte[] {content[3], content[4]}, new byte[] {buf[0], buf[1]});

      assertThrows(EOFException.class, () -> ignoreInt(is.read(buf)));
    }
  }

  @Test
  @DisplayName("readBuffer_whenZeroLengthAndNotEof_expectZeroAndNoAdvance")
  void readBufferWhenZeroLengthAndNotEofExpectZeroAndNoAdvance() throws Exception {
    // Arrange
    byte[] content = patternBytes(5);
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, 0, content.length)) {
      byte[] buf = new byte[5];

      // Act: first zero-length read
      int zero = is.read(buf, 0, 0);

      // Assert
      assertEquals(0, zero);

      // Next, read all bytes; fileOffset should still be 0 before this call
      int n = is.read(buf, 0, buf.length);
      assertEquals(content.length, n);
      assertArrayEquals(content, buf);

      // Verify pread() was invoked twice and the file offset did not advance on the zero-length
      // call.
      ArgumentCaptor<Long> offsets = ArgumentCaptor.forClass(Long.class);
      verify(raf, times(2)).pread(offsets.capture(), any(byte[].class), anyInt(), anyInt());
      List<Long> captured = offsets.getAllValues();
      assertEquals(2, captured.size());
      assertEquals(0L, captured.get(0)); // zero-length read
      assertEquals(0L, captured.get(1)); // subsequent full read starts at 0
    }
  }

  @Test
  @DisplayName("readBuffer_whenZeroLengthAtEof_expectEOFException")
  void readBufferWhenZeroLengthAtEofExpectEOFException() throws Exception {
    // Arrange: create a view positioned at EOF immediately
    byte[] content = patternBytes(3);
    RandomAccessBuffer raf = stubRaf(content);
    // Zero-length window at EOF
    try (RAFInputStream is = new RAFInputStream(raf, 3, 0)) {
      // Act & Assert
      assertThrows(EOFException.class, () -> ignoreInt(is.read(new byte[1], 0, 0)));
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("readBuffer_whenNullBuffer_expectNullPointerException")
  void readBufferWhenNullBufferExpectNullPointerException() throws Exception {
    // Arrange
    RandomAccessBuffer raf = stubRaf(patternBytes(4));
    try (RAFInputStream is = new RAFInputStream(raf, 0, 4)) {
      // Act & Assert
      assertThrows(NullPointerException.class, () -> ignoreInt(is.read(null)));
    }
  }

  @Test
  @DisplayName("readBuffer_whenInvalidBufferRange_expectIndexOutOfBounds")
  void readBufferWhenInvalidBufferRangeExpectIndexOutOfBounds() throws Exception {
    // Arrange
    byte[] content = patternBytes(10);
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, 0, content.length)) {
      byte[] buf = new byte[8];

      // Act & Assert
      assertThrows(IndexOutOfBoundsException.class, () -> ignoreInt(is.read(buf, -1, 1)));
      assertThrows(IndexOutOfBoundsException.class, () -> ignoreInt(is.read(buf, 0, 9)));
    }
  }

  @Test
  @DisplayName("readBuffer_whenUnderlyingThrowsIOException_expectPropagated")
  void readBufferWhenUnderlyingThrowsIOExceptionExpectPropagated() throws Exception {
    // Arrange
    RandomAccessBuffer raf = mock(RandomAccessBuffer.class);
    doThrow(new IOException("boom"))
        .when(raf)
        .pread(anyLong(), any(byte[].class), anyInt(), anyInt());
    try (RAFInputStream is = new RAFInputStream(raf, 0, 5)) {
      // Act & Assert
      assertThrows(IOException.class, () -> ignoreInt(is.read(new byte[2])));
    }
  }

  @Test
  @DisplayName("readBuffer_whenNegativeFileOffset_expectIllegalArgumentException")
  void readBufferWhenNegativeFileOffsetExpectIllegalArgumentException() throws Exception {
    // Arrange
    byte[] content = patternBytes(2);
    RandomAccessBuffer raf = stubRaf(content);
    try (RAFInputStream is = new RAFInputStream(raf, -1, 2)) {
      // Act & Assert
      assertThrows(IllegalArgumentException.class, () -> ignoreInt(is.read(new byte[1])));
    }
  }

  @Nested
  class ParameterizedReadAll {
    @ParameterizedTest
    @ValueSource(ints = {1, 2, 7, 64, 513})
    @DisplayName("readBuffer_whenConsumingInChunks_expectExactBytesAndEof")
    void readBufferWhenConsumingInChunksExpectExactBytesAndEof(int chunk) throws Exception {
      // Arrange: choose length not divisible by chunk to exercise final clamp
      int length = 5000 + (chunk % 3);
      byte[] content = patternBytes(length);
      RandomAccessBuffer raf = stubRaf(content);
      try (RAFInputStream is = new RAFInputStream(raf, 0, content.length)) {
        byte[] buf = new byte[Math.max(chunk, 1)];
        List<Byte> collected = new ArrayList<>(length);

        // Act
        while (true) {
          try {
            int n = is.read(buf, 0, chunk);
            for (int i = 0; i < n; i++) {
              collected.add(buf[i]);
            }
          } catch (EOFException _) {
            break; // expected at the end
          }
        }

        // Assert
        byte[] out = new byte[collected.size()];
        for (int i = 0; i < out.length; i++) out[i] = collected.get(i);
        assertArrayEquals(content, out);
        assertThrows(EOFException.class, () -> ignoreInt(is.read(buf)));
      }
    }
  }
}
