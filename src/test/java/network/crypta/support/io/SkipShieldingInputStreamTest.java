package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link SkipShieldingInputStream}.
 *
 * <p>AAA style with Mockito-based I/O stubs to avoid real device streams.
 */
class SkipShieldingInputStreamTest {

  @SuppressWarnings("java:S1172")
  private static void ignoreLong(long ignored) {
    // Intentionally empty helper to consume values in assertions.
  }

  @Test
  @DisplayName("skip_whenNegative_expectZeroAndNoRead")
  void skipWhenNegativeExpectZeroAndNoRead() throws Exception {
    // Arrange
    InputStream in = mock(InputStream.class);
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(in)) {
      // Act
      long negative = -5L;
      // Assert
      assertEquals(0L, s.skip(negative));
      verifyNoInteractions(in);
    }
  }

  @Test
  @DisplayName("skip_whenZero_expectZeroAndReadInvokedWithZeroLength")
  void skipWhenZeroExpectZeroAndReadInvokedWithZeroLength() throws Exception {
    // Arrange
    InputStream in = mock(InputStream.class);
    when(in.read(any(byte[].class), eq(0), eq(0))).thenReturn(0);
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(in)) {
      // Act + Assert
      assertEquals(0L, s.skip(0));
    }
  }

  @ParameterizedTest(name = "n={0}")
  @ValueSource(longs = {1L, 7L, 8192L, 8193L, 100_000L, Long.MAX_VALUE})
  @DisplayName("skip_whenPositiveN_expectReadsMinOfNAndBufferSize")
  void skipWhenPositiveNExpectReadsMinOfNAndBufferSize(long n) throws Exception {
    // Arrange
    InputStream in = mock(InputStream.class);
    // Echo back the requested length to simulate full read of the requested chunk
    when(in.read(any(byte[].class), eq(0), anyInt()))
        .thenAnswer(invocation -> invocation.getArgument(2, Integer.class));
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(in)) {
      int expected = (int) Math.min(n, 8192L);

      // Act
      long skipped = s.skip(n);

      // Assert
      assertEquals(expected, skipped);
    }
  }

  @Test
  @DisplayName("skip_whenRequestedExceedsAvailable_expectAvailableReturned")
  void skipWhenRequestedExceedsAvailableExpectAvailableReturned() throws Exception {
    // Arrange
    byte[] data = new byte[100];
    try (ByteArrayInputStream base = new ByteArrayInputStream(data);
        SkipShieldingInputStream s = new SkipShieldingInputStream(base)) {
      // Act
      long skipped = s.skip(200);

      // Assert
      assertEquals(100L, skipped);
    }
  }

  @Test
  @DisplayName("skip_whenAtEOF_expectZero")
  void skipWhenAtEOFExpectZero() throws Exception {
    // Arrange
    try (ByteArrayInputStream base = new ByteArrayInputStream(new byte[0]);
        SkipShieldingInputStream s = new SkipShieldingInputStream(base)) {
      // Act
      long skipped = s.skip(10);

      // Assert
      assertEquals(0L, skipped);
    }
  }

  @Test
  @DisplayName("skip_whenUnderlyingReadThrowsIOException_expectPropagate")
  void skipWhenUnderlyingReadThrowsIOExceptionExpectPropagate() throws Exception {
    // Arrange
    InputStream in = mock(InputStream.class);
    when(in.read(any(byte[].class), anyInt(), anyInt())).thenThrow(new IOException("boom"));
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(in)) {
      // Act + Assert
      IOException ex = assertThrows(IOException.class, () -> ignoreLong(s.skip(5)));
      assertEquals("boom", ex.getMessage());
    }
  }

  @Test
  @DisplayName("skip_whenUnderlyingSkipWouldThrow_expectNotCalled")
  void skipWhenUnderlyingSkipWouldThrowExpectNotCalled() throws Exception {
    // Arrange
    InputStream in = mock(InputStream.class);
    when(in.skip(anyLong())).thenThrow(new UnsupportedOperationException("no-skip"));
    when(in.read(any(byte[].class), anyInt(), anyInt())).thenReturn(5);
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(in)) {
      // Act
      long skipped = s.skip(5);

      // Assert
      assertEquals(5L, skipped);
    }
  }

  @Test
  @DisplayName("skip_whenUnderlyingIsNull_expectNullPointerException")
  void skipWhenUnderlyingIsNullExpectNullPointerException() {
    // Act + Assert: single-invocation via method reference; helper uses TWR
    assertThrows(NullPointerException.class, SkipShieldingInputStreamTest::skipOnNullStream);
  }

  private static void skipOnNullStream() throws Exception {
    try (SkipShieldingInputStream s = new SkipShieldingInputStream(null)) {
      // Use the return value without boxing to avoid static analysis warnings.
      assertNotNull(String.valueOf(s.skip(1)));
    }
  }
}
