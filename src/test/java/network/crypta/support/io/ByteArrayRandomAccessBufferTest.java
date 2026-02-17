package network.crypta.support.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

/**
 * Unit tests for {@link ByteArrayRandomAccessBuffer}.
 *
 * <p>This suite verifies core invariants and edge cases of the in-memory {@code RandomAccessBuffer}
 * implementation, including size reporting, bounds checks for {@code pread}/{@code pwrite}, effects
 * of read-only and closed states, lock lifecycle semantics, and no-op behavior for zero-length
 * operations. Tests use deterministic byte patterns from fixed seeds to avoid flakiness. All tests
 * run single-threaded; concurrency validation is out of scope.
 */
class ByteArrayRandomAccessBufferTest {
  private static final String READ_ONLY_MESSAGE = "Read-only";
  private static final String UNREACHABLE_MESSAGE = "unreachable";

  private static ByteArrayRandomAccessBuffer constructBufferWithSize(int size) {
    return new ByteArrayRandomAccessBuffer(size);
  }

  /**
   * Produce a deterministic byte array for test assertions.
   *
   * @param size number of bytes to generate
   * @param seed seed used to initialize the deterministic pattern
   * @return a new array of length {@code size} filled with deterministic data
   */
  private static byte[] bytes(int size, int seed) {
    byte[] data = new byte[size];
    int value = seed;
    for (int i = 0; i < size; i++) {
      value = 1664525 * value + 1013904223;
      data[i] = (byte) (value >>> 16);
    }
    return data;
  }

  // ---------- Constructors & basic properties ----------

  /**
   * Verifies that the size-based constructor creates a buffer whose {@link
   * ByteArrayRandomAccessBuffer#size()} matches the requested length.
   */
  @Test
  void size_whenConstructedWithInt_expectSizeMatches() {
    // Arrange
    int size = 16;
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(size)) {
      // Act
      long actual = raf.size();

      // Assert
      assertEquals(size, actual);
    }
  }

  /**
   * Verifies that constructing with a negative size fails. The constructor throws before an
   * instance is created, so there is no resource to close (hence the suppression on the constructor
   * expression used within {@code assertThrows}).
   *
   * @throws NegativeArraySizeException expected from the JVM when allocating a negative-length
   *     array
   */
  @Test
  @SuppressWarnings("resource")
  void constructor_withNegativeSize_expectNegativeArraySizeException() {
    // Arrange + Act + Assert
    assertThrows(
        NegativeArraySizeException.class, () -> assertNotNull(constructBufferWithSize(-1)));
  }

  /**
   * Ensures the range-copy constructor copies the requested window and honors the {@code readOnly}
   * flag.
   *
   * <p>Postconditions: subsequent mutations to the source array do not affect the buffer; reads
   * return the copied range; writes fail with {@link IOException} when the buffer is read-only.
   *
   * @throws IOException if write is attempted while {@code readOnly} is set
   */
  @Test
  void constructor_withInitialContentsCopiesRange_expectIndependentCopyAndReadOnlyReflected()
      throws IOException {
    // Arrange
    byte[] src = bytes(10, 42);
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(src, 2, 5, true)) {

      // Mutate the source after construction to ensure a deep copy was made.
      src[2] ^= 0x7F;

      // Act
      byte[] out = new byte[5];
      raf.pread(0, out, 0, 5);

      // Verify the source has changed so we do not accidentally compare against it.
      assertFalse(Arrays.equals(bytes(10, 42), src));
      assertTrue(raf.isReadOnly());

      // Verify the buffer equals bytes[2..6) from the original seed snapshot.
      byte[] expected = new byte[5];
      System.arraycopy(bytes(10, 42), 2, expected, 0, 5);
      assertArrayEquals(expected, out);

      // Read-only prevents writes and should raise an IOException.
      byte[] write = new byte[1];
      IOException ex = assertThrows(IOException.class, () -> raf.pwrite(0, write, 0, 1));
      assertTrue(ex.getMessage().contains(READ_ONLY_MESSAGE));
    }
  }

  /**
   * Verifies {@link ByteArrayRandomAccessBuffer#setReadOnly()} flips the state and blocks writes.
   */
  @Test
  void setReadOnly_whenCalled_expectWritesToFail() {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(4)) {
      assertFalse(raf.isReadOnly());
      raf.setReadOnly();
      assertTrue(raf.isReadOnly());

      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> raf.pwrite(0, new byte[1], 0, 1));
      assertTrue(ex.getMessage().contains(READ_ONLY_MESSAGE));
    }
  }

  // ---------- Read (pread) behavior ----------

  /**
   * Provides in-bounds cases for {@code pread}: zero-length reads, full-length reads, and mid-range
   * reads.
   */
  private static Stream<Arguments> inBoundsReadCases() {
    return Stream.of(
        // fileOffset, bufOffset, length, fileSize
        Arguments.of(0L, 0, 0, 8),
        Arguments.of(0L, 0, 8, 8),
        Arguments.of(3L, 2, 3, 8),
        Arguments.of(8L, 0, 0, 8));
  }

  /**
   * Reads within valid ranges and verifies copied bytes match the source. Also asserts that a
   * zero-length read performs no modification to the destination buffer.
   *
   * @param fileOffset offset into the buffer
   * @param bufOffset offset into the destination array
   * @param length number of bytes to read
   * @param fileSize size of the underlying buffer
   * @throws IOException if a read unexpectedly fails
   */
  @ParameterizedTest
  @MethodSource("inBoundsReadCases")
  void pread_whenWithinBounds_expectDataRead(
      long fileOffset, int bufOffset, int length, int fileSize) throws IOException {
    // Arrange
    byte[] content = bytes(fileSize, 7);
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(content)) {
      byte[] out = new byte[bufOffset + length + 4];
      // Fill with a sentinel to detect unintended writes outside the target region.
      Arrays.fill(out, (byte) 0x5A);

      // Act
      raf.pread(fileOffset, out, bufOffset, length);

      // Assert
      if (length > 0) {
        byte[] expected = new byte[length];
        System.arraycopy(content, (int) fileOffset, expected, 0, length);
        byte[] actual = new byte[length];
        System.arraycopy(out, bufOffset, actual, 0, length);
        assertArrayEquals(expected, actual);
      } else {
        // Zero-length read: buffer contents remain equal to the sentinel.
        for (byte b : out) assertEquals((byte) 0x5A, b);
      }
    }
  }

  /** Provides invalid or out-of-bounds cases for {@code pread}. */
  private static Stream<Arguments> outOfBoundsReadCases() {
    return Stream.of(
        Arguments.of(-1L, 0, 1, 4, IllegalArgumentException.class),
        Arguments.of(0L, 0, 5, 4, IOException.class),
        Arguments.of(3L, 0, 2, 4, IOException.class),
        Arguments.of(4L, 0, 1, 4, IOException.class));
  }

  /**
   * Attempts reads that should fail due to negative offsets or overruns and verifies the exception
   * type and message.
   */
  @ParameterizedTest
  @MethodSource("outOfBoundsReadCases")
  void pread_whenOutOfBoundsOrNegative_expectException(
      long fileOffset, int bufOffset, int length, int fileSize, Class<? extends Exception> type) {
    // Arrange
    byte[] content = bytes(fileSize, 11);
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(content)) {
      byte[] out = new byte[Math.max(1, bufOffset + length)];

      // Act + Assert
      Exception ex = assertThrows(type, () -> raf.pread(fileOffset, out, bufOffset, length));
      if (ex instanceof IOException) {
        assertTrue(
            ex.getMessage().contains("Cannot read"),
            "IOException message should indicate read bound issue");
      }
    }
  }

  /** Ensures passing a {@code null} destination triggers {@link NullPointerException}. */
  @Test
  void pread_withNullBuffer_expectNullPointerException() {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(2)) {
      // Act + Assert
      assertThrows(NullPointerException.class, () -> raf.pread(0, null, 0, 1));
    }
  }

  /** Ensures reads on a closed buffer fail with an {@link IOException}. */
  @Test
  void pread_whenClosed_expectIOExceptionClosed() {
    // Arrange
    ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(2);
    raf.close();
    byte[] out = new byte[1];

    // Act
    IOException ex = assertThrows(IOException.class, () -> raf.pread(0, out, 0, 1));

    // Assert
    assertTrue(ex.getMessage().contains("Closed"));
  }

  // ---------- Write (pwrite) behavior ----------

  /** Provides in-bounds cases for {@code pwrite}, including zero-length writes. */
  private static Stream<Arguments> inBoundsWriteCases() {
    return Stream.of(
        // fileOffset, bufOffset, length, fileSize
        Arguments.of(0L, 0, 0, 8),
        Arguments.of(0L, 0, 8, 8),
        Arguments.of(2L, 1, 3, 8),
        Arguments.of(8L, 0, 0, 8));
  }

  /**
   * Writes within valid ranges and verifies the final buffer equals the expected content. Also
   * asserts that zero-length writes act as no-ops.
   *
   * @throws IOException if write unexpectedly fails
   */
  @ParameterizedTest
  @MethodSource("inBoundsWriteCases")
  void pwrite_whenWithinBounds_expectDataWritten(
      long fileOffset, int bufOffset, int length, int fileSize) throws IOException {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(fileSize)) {
      byte[] src = bytes(bufOffset + length + 4, 21);

      // Act
      raf.pwrite(fileOffset, src, bufOffset, length);

      // Assert
      byte[] verify = new byte[fileSize];
      raf.pread(0, verify, 0, fileSize);

      if (length > 0) {
        byte[] expected = new byte[fileSize];
        System.arraycopy(src, bufOffset, expected, (int) fileOffset, length);
        assertArrayEquals(expected, verify);
      } else {
        // Zero-length write: still all zeros
        for (byte b : verify) assertEquals(0, b);
      }
    }
  }

  /** Provides invalid or out-of-bounds cases for {@code pwrite}. */
  private static Stream<Arguments> outOfBoundsWriteCases() {
    return Stream.of(
        Arguments.of(-1L, 0, 1, 4, IllegalArgumentException.class),
        Arguments.of(0L, 0, 5, 4, IOException.class),
        Arguments.of(3L, 0, 2, 4, IOException.class),
        Arguments.of(4L, 0, 1, 4, IOException.class));
  }

  /**
   * Attempts writes that should fail due to negative offsets or overruns and verifies exception
   * type and message.
   */
  @ParameterizedTest
  @MethodSource("outOfBoundsWriteCases")
  void pwrite_whenOutOfBoundsOrNegative_expectException(
      long fileOffset, int bufOffset, int length, int fileSize, Class<? extends Exception> type) {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(fileSize)) {
      byte[] src = new byte[Math.max(1, bufOffset + length)];

      // Act + Assert
      Exception ex = assertThrows(type, () -> raf.pwrite(fileOffset, src, bufOffset, length));
      if (ex instanceof IOException) {
        assertTrue(
            ex.getMessage().contains("Cannot write"),
            "IOException message should indicate write bound issue");
      }
    }
  }

  /** Ensures passing a {@code null} source triggers {@link NullPointerException}. */
  @Test
  void pwrite_withNullBuffer_expectNullPointerException() {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(2)) {
      // Act + Assert
      assertThrows(NullPointerException.class, () -> raf.pwrite(0, null, 0, 1));
    }
  }

  /** Ensures writes on a closed buffer fail with an {@link IOException}. */
  @Test
  void pwrite_whenClosed_expectIOExceptionClosed() {
    // Arrange
    ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(2);
    raf.close();
    byte[] in = new byte[1];

    // Act
    IOException ex = assertThrows(IOException.class, () -> raf.pwrite(0, in, 0, 1));

    // Assert
    assertTrue(ex.getMessage().contains("Closed"));
  }

  // ---------- Locking & lifecycle ----------

  /**
   * Verifies that {@link RAFLock#unlock()} enforces single-use semantics by throwing {@link
   * IllegalStateException} on a second call.
   */
  @Test
  void lockOpen_whenUnlockCalledTwice_expectIllegalStateException() {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(1)) {
      RAFLock lock = raf.lockOpen();

      // Act
      lock.unlock();

      // Assert
      IllegalStateException ex = assertThrows(IllegalStateException.class, lock::unlock);
      assertTrue(ex.getMessage().contains("Already unlocked"));
    }
  }

  /** Ensures {@link ByteArrayRandomAccessBuffer#onResume(ClientContext)} is a no-op. */
  @Test
  void onResume_withMockContext_expectNoException() {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(1)) {
      ClientContext ctx = Mockito.mock(ClientContext.class);

      // Act + Assert
      assertDoesNotThrow(() -> raf.onResume(ctx));
    }
  }

  /**
   * Ensures {@link ByteArrayRandomAccessBuffer#storeTo(DataOutputStream)} is unsupported and throws
   * {@link UnsupportedOperationException}.
   *
   * @throws IOException propagated from the try-with-resources block closing the stream
   */
  @Test
  void storeTo_whenCalled_expectUnsupportedOperationException() throws IOException {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(1)) {
      try (DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream())) {
        // Act + Assert
        assertThrows(UnsupportedOperationException.class, () -> raf.storeTo(dos));
      }
    }
  }

  // ---------- Misc edge cases ----------

  /**
   * Verifies that {@code pread} honors {@code bufOffset} and modifies only the target region in the
   * destination buffer.
   *
   * @throws IOException if the read unexpectedly fails
   */
  @Test
  @DisplayName("pread: bufOffset respected without touching other indices")
  void pread_whenUsingBufOffset_expectOnlyTargetRegionModified() throws IOException {
    // Arrange
    byte[] content = bytes(6, 99);
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(content)) {
      byte[] out = new byte[10];
      Arrays.fill(out, (byte) 0x5A);

      // Act
      raf.pread(1, out, 4, 3);

      // Assert
      // Unmodified prefix remains the sentinel value.
      for (int i = 0; i < 4; i++) assertEquals((byte) 0x5A, out[i]);
      // Only the target region is copied into out[4..6].
      assertArrayEquals(
          new byte[] {content[1], content[2], content[3]}, new byte[] {out[4], out[5], out[6]});
      // Unmodified suffix remains the sentinel value.
      for (int i = 7; i < out.length; i++) assertEquals((byte) 0x5A, out[i]);
    }
  }

  /**
   * Verifies that {@code pwrite} honors {@code bufOffset} and file offset placement.
   *
   * <p>Writes bytes {@code 1,2,3} starting at file offset {@code 2} and validates the final buffer
   * image.
   *
   * @throws IOException if the write unexpectedly fails
   */
  @Test
  @DisplayName("pwrite: bufOffset respected and data lands at correct file offset")
  void pwrite_whenUsingBufOffset_expectDataWrittenAtOffset() throws IOException {
    // Arrange
    try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(7)) {
      byte[] src = new byte[] {9, 9, 1, 2, 3, 9};

      // Act
      // Write 1,2,3 at file offset 2.
      raf.pwrite(2, src, 2, 3);

      // Assert
      byte[] full = new byte[7];
      raf.pread(0, full, 0, 7);
      assertArrayEquals(new byte[] {0, 0, 1, 2, 3, 0, 0}, full);
    }
  }

  // ---------- Factory (ByteArrayRandomAccessBufferFactory) ----------

  /**
   * Verifies that {@link ByteArrayRandomAccessBufferFactory#makeRAF(long)} returns a
   * zero-initialized buffer of the requested size.
   */
  @Test
  void makeRAF_withValidSize_expectZeroInitializedBuffer() throws IOException {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();

    // Act
    try (ByteArrayRandomAccessBuffer raf = (ByteArrayRandomAccessBuffer) factory.makeRAF(6)) {
      // Assert
      assertEquals(6L, raf.size());
      byte[] buf = new byte[6];
      raf.pread(0, buf, 0, 6);
      assertArrayEquals(new byte[6], buf);
    }
  }

  /**
   * Ensures that {@link ByteArrayRandomAccessBufferFactory#makeRAF(long)} rejects negative sizes.
   */
  @Test
  void makeRAF_withNegativeSize_expectIllegalArgumentException() {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.makeRAF(-1)) {
            fail(UNREACHABLE_MESSAGE);
          }
        });
  }

  /**
   * Ensures that sizes larger than {@link Integer#MAX_VALUE} are rejected with an {@link
   * IOException}.
   */
  @Test
  void makeRAF_withSizeAboveIntegerMax_expectIOExceptionTooBig() {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();

    // Act
    IOException ex =
        assertThrows(
            IOException.class,
            () -> {
              try (var _ = factory.makeRAF((long) Integer.MAX_VALUE + 1)) {
                fail(UNREACHABLE_MESSAGE);
              }
            });

    // Assert
    assertTrue(ex.getMessage().contains("Too big"));
  }

  /**
   * Verifies that the range-copy overload copies the specified window and honors the read-only
   * flag.
   */
  @Test
  void makeRAF_withInitialContentsOffsetAndSize_expectCopiesRangeAndHonorsReadOnly()
      throws IOException {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();
    byte[] src = bytes(10, 123);

    // Act
    try (ByteArrayRandomAccessBuffer raf =
        (ByteArrayRandomAccessBuffer) factory.makeRAF(src, 3, 4, true)) {

      // Mutate source to verify deep copy
      src[3] ^= 0x55;

      // Assert
      assertTrue(raf.isReadOnly());
      byte[] out = new byte[4];
      raf.pread(0, out, 0, 4);
      byte[] expected = Arrays.copyOfRange(bytes(10, 123), 3, 7);
      assertArrayEquals(expected, out);

      // Read-only must reject writes
      IOException ioe = assertThrows(IOException.class, () -> raf.pwrite(0, new byte[1], 0, 1));
      assertTrue(ioe.getMessage().contains(READ_ONLY_MESSAGE));
    }
  }

  /** Ensures negative size on the range-copy overload is rejected. */
  @Test
  void makeRAF_withInitialContentsNegativeSize_expectIllegalArgumentException() {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();
    byte[] src = new byte[4];

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.makeRAF(src, 0, -1, false)) {
            fail(UNREACHABLE_MESSAGE);
          }
        });
  }

  /** Ensures negative offset is rejected by the underlying copy. */
  @Test
  void makeRAF_withInitialContentsNegativeOffset_expectArrayIndexOutOfBoundsException() {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();
    byte[] src = new byte[4];

    // Act + Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> {
          try (var _ = factory.makeRAF(src, -1, 2, false)) {
            fail(UNREACHABLE_MESSAGE);
          }
        });
  }

  /** Ensures offset strictly beyond the source length is rejected. */
  @Test
  void makeRAF_withInitialContentsOffsetBeyondLength_expectArrayIndexOutOfBoundsException() {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();
    byte[] src = new byte[4];

    // Act + Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> {
          try (var _ = factory.makeRAF(src, 5, 1, false)) {
            fail(UNREACHABLE_MESSAGE);
          }
        });
  }

  /**
   * Verifies that requesting a range that extends past the source length pads with zeros (behavior
   * of {@link Arrays#copyOfRange(byte[], int, int)}).
   */
  @Test
  void makeRAF_withInitialContentsSizeBeyondArray_expectZeroPaddedCopy() throws IOException {
    // Arrange
    ByteArrayRandomAccessBufferFactory factory = new ByteArrayRandomAccessBufferFactory();
    byte[] src = new byte[] {1, 2, 3, 4};

    try (ByteArrayRandomAccessBuffer raf =
        (ByteArrayRandomAccessBuffer) factory.makeRAF(src, 2, 4, false)) {
      assertEquals(4L, raf.size());
      byte[] out = new byte[4];
      raf.pread(0, out, 0, 4);
      assertArrayEquals(new byte[] {3, 4, 0, 0}, out);
    }
  }
}
