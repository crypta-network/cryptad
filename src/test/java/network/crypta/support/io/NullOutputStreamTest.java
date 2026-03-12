package network.crypta.support.io;

import java.io.IOException;
import java.io.OutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link NullOutputStream}.
 *
 * <p>AAA style, deterministic, covers null/empty/boundary and error paths.
 */
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome test naming
class NullOutputStreamTest {

  @Test
  void constructor_whenInvoked_expectNonNullInstance() {
    // Arrange & Act
    OutputStream os = new NullOutputStream();
    // Assert
    assertNotNull(os);
  }

  @ParameterizedTest
  @ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 1, 255, 256, Integer.MAX_VALUE})
  void writeInt_whenAnyValue_doesNotThrow(int value) throws IOException {
    // Arrange
    try (OutputStream os = new NullOutputStream()) {
      assertNotNull(os);
      // Act & Assert
      assertDoesNotThrow(() -> os.write(value));
    }
  }

  @SuppressWarnings("DataFlowIssue")
  @ParameterizedTest(name = "buf=null off={0} len={1}")
  @MethodSource("nullBufferCases")
  void writeBuffer_whenNullBuffer_doesNotThrow(int off, int len) throws IOException {
    // Arrange
    try (OutputStream os = new NullOutputStream()) {
      // Act & Assert
      assertDoesNotThrow(() -> os.write(null, off, len));
    }
  }

  static Stream<Arguments> nullBufferCases() {
    return Stream.of(
        Arguments.of(0, 0),
        Arguments.of(0, 1),
        Arguments.of(-1, 0),
        Arguments.of(1, -1),
        Arguments.of(Integer.MIN_VALUE, Integer.MAX_VALUE));
  }

  @ParameterizedTest(name = "off={0} len={1}")
  @MethodSource("invalidOffsetLengthCases")
  void writeBuffer_whenOffsetsOrLengthInvalid_doesNotThrow(int off, int len) throws IOException {
    // Arrange
    byte[] data = new byte[] {10, 20, 30, 40};
    try (OutputStream os = new NullOutputStream()) {
      // Act & Assert
      assertDoesNotThrow(() -> os.write(data, off, len));
    }
  }

  static Stream<Arguments> invalidOffsetLengthCases() {
    // Note: These would normally be out-of-bounds, but NullOutputStream ignores parameters.
    return Stream.of(
        Arguments.of(-1, 1), // negative offset
        Arguments.of(0, -1), // negative length
        Arguments.of(5, 1), // offset beyond array length
        Arguments.of(2, 5), // length extends past end
        Arguments.of(Integer.MAX_VALUE, Integer.MIN_VALUE)); // extreme values
  }

  @Test
  void writeBuffer_whenEmptyArrayAndZeroLen_doesNotThrow() throws IOException {
    // Arrange
    byte[] empty = new byte[0];
    try (OutputStream os = new NullOutputStream()) {
      // Act & Assert
      assertDoesNotThrow(() -> os.write(empty, 0, 0));
    }
  }

  @Test
  @DisplayName("write(byte[]) null delegates to JDK and throws NPE")
  void writeArray_whenNull_expectNullPointerException() {
    // Arrange + Act + Assert: single-invocation lambda via method reference; helper uses TWR
    assertThrows(NullPointerException.class, NullOutputStreamTest::writeNullArrayWithTwr);
  }

  @SuppressWarnings("DataFlowIssue")
  private static void writeNullArrayWithTwr() throws IOException {
    try (OutputStream os = new NullOutputStream()) {
      // OutputStream.write(byte[]) calls b.length; null triggers NPE
      os.write((byte[]) null);
    }
  }

  @Test
  void flush_whenCalled_expectNoException() throws IOException {
    // Arrange
    try (OutputStream os = new NullOutputStream()) {
      // Act & Assert
      assertDoesNotThrow(os::flush);
    }
  }

  @Test
  void close_whenCalled_expectNoException() throws IOException {
    // Arrange & Act & Assert
    try (OutputStream os = new NullOutputStream()) {
      assertDoesNotThrow(os::close);
    }
  }
}
