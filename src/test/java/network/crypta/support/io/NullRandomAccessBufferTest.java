package network.crypta.support.io;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link NullRandomAccessBuffer}.
 *
 * <p>AAA style with deterministic behavior. Verifies public API, invariants, and edge cases,
 * including boundary and error paths. Mockito is used for external types.
 */
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome naming
class NullRandomAccessBufferTest {

  // -------------------- size() --------------------

  @ParameterizedTest
  @ValueSource(longs = {0L, 1L, 7L, -1L, Long.MAX_VALUE})
  void size_whenConstructedWithLength_expectSameValue(long length) {
    // Arrange & Act
    try (NullRandomAccessBuffer buf = new NullRandomAccessBuffer(length)) {
      long actual = buf.size();
      // Assert
      assertEquals(length, actual);
    }
  }

  // -------------------- pread() --------------------

  @Test
  void pread_whenFillWholeBuffer_expectAllZeros() throws IOException {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(16)) {
      byte[] out = new byte[] {1, 2, 3, 4, 5, 6};

      // Act
      rab.pread(0L, out, 0, out.length);

      // Assert
      assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 0}, out);
    }
  }

  @ParameterizedTest
  @CsvSource({
    // bufLen, bufOffset, length, fileOffset
    "8, 0, 0, 0",
    "8, 0, 8, 0",
    "8, 1, 3, 12345",
    "8, 3, 4, -1"
  })
  void pread_whenPartialRange_expectZerosOnlyInRange(
      int bufLen, int bufOffset, int length, long fileOffset) throws IOException {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(42)) {
      byte fill = (byte) 0x7F;
      byte[] out = new byte[bufLen];
      Arrays.fill(out, fill);

      // Act
      rab.pread(fileOffset, out, bufOffset, length);

      // Assert
      for (int i = 0; i < out.length; i++) {
        boolean inRange = i >= bufOffset && i < bufOffset + length;
        assertEquals(inRange ? 0 : fill, out[i], "mismatch at index " + i);
      }
    }
  }

  @Test
  void pread_whenNegativeLength_expectNoChangeAndNoException() throws IOException {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(10)) {
      byte[] out = new byte[] {(byte) 0x55, (byte) 0x55, (byte) 0x55};
      byte[] before = out.clone();

      // Act
      rab.pread(0L, out, 1, -3);

      // Assert
      assertArrayEquals(before, out);
    }
  }

  @ParameterizedTest
  @CsvSource({
    // Invalid ranges -> ArrayIndexOutOfBoundsException expected
    "8, -1, 1", // negative offset
    "8, 0, 9", // length too large
    "8, 7, 2" // overflows end
  })
  void pread_whenInvalidRange_expectArrayIndexOutOfBounds(int bufLen, int bufOffset, int length) {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      byte[] out = new byte[bufLen];

      // Act & Assert
      assertThrows(
          ArrayIndexOutOfBoundsException.class, () -> rab.pread(0L, out, bufOffset, length));
    }
  }

  @Test
  void pread_whenNullBuffer_expectNullPointerException() {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      // Act & Assert
      assertThrows(NullPointerException.class, () -> rab.pread(0L, null, 0, 1));
    }
  }

  // -------------------- pwrite() --------------------

  @Test
  void pwrite_whenCalled_expectNoopNoException() {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(5)) {
      byte[] in = new byte[] {9, 8, 7};

      // Act & Assert
      assertDoesNotThrow(
          () -> {
            rab.pwrite(10L, in, 0, in.length);
            rab.pwrite(0L, in, 1, 0); // no-op write
          });
    }
  }

  @Test
  void pwrite_whenNullBuffer_expectNoException() {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      // Act & Assert (noop, should not throw even with null buffer)
      assertDoesNotThrow(() -> rab.pwrite(0L, null, 0, 1));
    }
  }

  // -------------------- lockOpen() / RAFLock --------------------

  @Test
  void lockOpen_whenUnlockOnce_expectNoException() throws IOException {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      // Act
      LockableRandomAccessBuffer.RAFLock lock = rab.lockOpen();
      assertNotNull(lock);
      // Assert: unlocking once does not throw
      assertDoesNotThrow(lock::unlock);
    }
  }

  @Test
  void lockOpen_whenUnlockTwice_expectIllegalStateException() throws IOException {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      LockableRandomAccessBuffer.RAFLock lock = rab.lockOpen();
      // Act
      lock.unlock();
      // Assert
      assertThrows(IllegalStateException.class, lock::unlock);
    }
  }

  // -------------------- Unsupported operations --------------------

  @Test
  void onResume_whenCalled_expectUnsupportedOperationExceptionAndNoInteractions() {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      ClientContext ctx = mock(ClientContext.class);
      // Act & Assert
      assertThrows(UnsupportedOperationException.class, () -> rab.onResume(ctx));
      verifyNoInteractions(ctx);
    }
  }

  @Test
  @DisplayName("storeTo throws UnsupportedOperationException and touches no stream methods")
  void storeTo_whenCalled_expectUnsupportedOperationExceptionAndNoInteractions() {
    // Arrange
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(0)) {
      DataOutputStream dos = mock(DataOutputStream.class);
      // Act & Assert
      assertThrows(UnsupportedOperationException.class, () -> rab.storeTo(dos));
      verifyNoInteractions(dos);
    }
  }

  // -------------------- equals() / hashCode() --------------------

  @Test
  void equals_whenSameClassDifferentLengths_expectTrue() {
    // Arrange & Act
    try (NullRandomAccessBuffer a = new NullRandomAccessBuffer(0);
        NullRandomAccessBuffer b = new NullRandomAccessBuffer(123)) {
      boolean ab = a.equals(b);
      boolean ba = b.equals(a);

      // Assert
      assertTrue(ab);
      assertTrue(ba);
      assertEquals(a.hashCode(), b.hashCode());
      assertEquals(0, a.hashCode());
    }
  }

  @Test
  void equals_whenDifferentClass_expectFalse() {
    // Arrange & Act
    try (NullRandomAccessBuffer a = new NullRandomAccessBuffer(0)) {
      Object other = new Object();
      // Assert
      assertNotEquals(a, other);
    }
  }

  @Test
  void equals_whenNull_expectFalse() {
    // Arrange & Act
    try (NullRandomAccessBuffer a = new NullRandomAccessBuffer(0)) {
      // Assert
      assertNotEquals(null, a);
    }
  }

  // -------------------- close() / free() --------------------

  @Test
  void closeAndFree_whenCalled_expectNoExceptions() {
    // Arrange & Act
    try (NullRandomAccessBuffer rab = new NullRandomAccessBuffer(17)) {
      // Assert
      assertDoesNotThrow(
          () -> {
            rab.close();
            rab.free();
          });
    }
  }
}
