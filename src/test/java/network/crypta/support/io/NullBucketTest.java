package network.crypta.support.io;

import java.io.*;

import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link NullBucket}.
 *
 * <p>AAA style with deterministic behavior. Verifies public API, invariants, and edge cases
 * including negative and large lengths, singleton streams, and unsupported operations.
 */
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome test naming style
class NullBucketTest {

  @Test
  void constructor_whenNoArg_expectSizeZero() {
    // Arrange & Act
    try (NullBucket bucket = new NullBucket()) {
      // Assert
      assertEquals(0L, bucket.size());
    }
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, 1L, 123L, -1L, Long.MAX_VALUE})
  void size_whenConstructedWithLength_expectSameValue(long length) {
    // Arrange
    try (NullBucket bucket = new NullBucket(length)) {
      // Act
      long actual = bucket.size();
      // Assert
      assertEquals(length, actual);
    }
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, 7L, -5L, Long.MAX_VALUE})
  void toRandomAccessBuffer_whenCalled_expectBufferWithSameSize(long length) throws IOException {
    // Arrange
    try (NullBucket bucket = new NullBucket(length)) {
      // Act
      LockableRandomAccessBuffer rab = bucket.toRandomAccessBuffer();
      // Assert
      assertNotNull(rab);
      assertInstanceOf(NullRandomAccessBuffer.class, rab);
      assertEquals(length, rab.size());

      // Additionally verify pread writes zeros (boundary behavior is defined by
      // NullRandomAccessBuffer).
      byte[] buf = new byte[] {1, 2, 3, 4};
      rab.pread(0, buf, 0, buf.length);
      assertArrayEquals(new byte[] {0, 0, 0, 0}, buf);
    }
  }

  @Test
  void getInputStream_whenCalled_expectSingletonNullInputStreamAndEOF() throws IOException {
    // Arrange
    try (NullBucket bucket = new NullBucket(0)) {
      // Act
      InputStream is1 = bucket.getInputStream();
      InputStream is2 = bucket.getInputStreamUnbuffered();
      // Assert
      assertSame(NullBucket.nullIn, is1);
      assertSame(is1, is2);
      assertInstanceOf(NullInputStream.class, is1);
      assertEquals(-1, is1.read());
    }
  }

  @Test
  void getOutputStream_whenCalled_expectSingletonNullOutputStreamAndNoopWrites()
      throws IOException {
    // Arrange
    try (NullBucket bucket = new NullBucket(42)) {
      byte[] data = new byte[] {9, 8, 7};
      // Act
      OutputStream os1 = bucket.getOutputStream();
      OutputStream os2 = bucket.getOutputStreamUnbuffered();
      // Assert
      assertSame(NullBucket.nullOut, os1);
      assertSame(os1, os2);
      assertInstanceOf(NullOutputStream.class, os1);

      // Writes are no-ops and must not throw
      os1.write(0);
      os1.write(data, 0, data.length);
      os1.flush();
      os1.close();
    }
  }

  @Test
  void getName_whenCalled_expectSpecificConstant() {
    // Arrange
    try (NullBucket bucket = new NullBucket()) {
      // Act
      String name = bucket.getName();
      // Assert
      assertEquals("President George W. NullBucket", name);
    }
  }

  @Test
  void readOnly_whenSet_expectStillFalse() {
    // Arrange
    try (NullBucket bucket = new NullBucket(5)) {
      // Act & Assert
      assertFalse(bucket.isReadOnly());
      bucket.setReadOnly();
      assertFalse(bucket.isReadOnly());
    }
  }

  @Test
  void free_whenCalled_expectNoEffectOnSize() {
    // Arrange
    long length = 11L;
    try (NullBucket bucket = new NullBucket(length)) {
      // Act
      bucket.free();
      // Assert
      assertEquals(length, bucket.size());
    }
  }

  @Test
  void createShadow_whenCalled_expectNewNullBucketWithZeroLength() {
    // Arrange
    try (NullBucket original = new NullBucket(123)) {
      // Act
      try (NullBucket shadow = (NullBucket) original.createShadow()) {
        // Assert
        assertNotSame(original, shadow);
        assertEquals(0L, shadow.size());
      }
    }
  }

  @Test
  void onResume_whenCalledWithClientContext_expectNoExceptionAndNoInteractions() {
    // Arrange
    try (NullBucket bucket = new NullBucket(3)) {
      ClientContext ctx = mock(ClientContext.class);
      // Act
      bucket.onResume(ctx);
      // Assert
      verifyNoInteractions(ctx);
    }
  }

  @Test
  @DisplayName("storeTo throws UnsupportedOperationException")
  void storeTo_whenCalled_expectUnsupportedOperationException() {
    // Arrange
    try (NullBucket bucket = new NullBucket(1)) {
      DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream());
      // Act & Assert
      assertThrows(UnsupportedOperationException.class, () -> bucket.storeTo(dos));
    }
  }
}
