package network.crypta.support.compress;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link SingleOffsetReplacingOutputStream}.
 *
 * <p>AAA style, deterministic, covers boundaries and error paths.
 */
class SingleOffsetReplacingOutputStreamTest {

  private static byte[] rangeBytes(int startInclusive, int length) {
    byte[] arr = new byte[length];
    for (int i = 0; i < length; i++) arr[i] = (byte) (startInclusive + i);
    return arr;
  }

  @ParameterizedTest
  @DisplayName("write(int): replaces exactly one position within bounds")
  @ValueSource(ints = {0, 1, 2, 4})
  void writeInt_whenOffsetWithinWritten_expectSingleReplacement(int replacementOffset)
      throws IOException {
    // Arrange
    byte[] input = new byte[] {10, 20, 30, 40, 50};
    int replacementValue = 0x7A; // 122
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue);

    // Act
    for (byte b : input) {
      out.write(b & 0xFF);
    }
    out.flush();

    // Assert
    byte[] expected = input.clone();
    expected[replacementOffset] = (byte) replacementValue;
    assertThat(target.toByteArray(), equalTo(expected));
  }

  @Test
  @DisplayName("write(int): negative replacement offset -> no replacement")
  void writeInt_whenOffsetNegative_expectNoReplacement() throws IOException {
    // Arrange
    byte[] input = new byte[] {1, 2, 3};
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out = new SingleOffsetReplacingOutputStream(target, -1, 0x42);

    // Act
    for (byte b : input) out.write(b & 0xFF);
    out.flush();

    // Assert
    assertThat(target.toByteArray(), equalTo(input));
  }

  @Test
  @DisplayName("write(int): replacement offset beyond total bytes -> no replacement")
  void writeInt_whenOffsetBeyondWritten_expectNoReplacement() throws IOException {
    // Arrange
    byte[] input = new byte[] {5, 6, 7};
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out = new SingleOffsetReplacingOutputStream(target, 10, 0x33);

    // Act
    for (byte b : input) out.write(b & 0xFF);
    out.flush();

    // Assert
    assertThat(target.toByteArray(), equalTo(input));
  }

  @ParameterizedTest
  @DisplayName("write(byte[],off,len): replace at start/middle/end of buffer")
  @ValueSource(ints = {0, 3, 6})
  void writeBuffer_whenReplacementInsideBuffer_expectReplaced(int replacementOffset)
      throws IOException {
    // Arrange
    byte[] src = rangeBytes(1, 7); // [1..7]
    int replacementValue = 0x7F; // 127
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue);

    // Act
    out.write(src, 0, src.length);
    out.flush();

    // Assert
    byte[] expected = src.clone();
    expected[replacementOffset] = (byte) replacementValue;
    assertThat(target.toByteArray(), equalTo(expected));
  }

  @Test
  @DisplayName("write(byte[],off,len): replacement not in buffer -> forwarded unchanged")
  void writeBuffer_whenReplacementOutsideBuffer_expectForwarded() throws IOException {
    // Arrange
    byte[] src = rangeBytes(10, 5);
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, 10 /* beyond */, 0x55);

    // Act
    out.write(src, 0, src.length);
    out.flush();

    // Assert
    assertThat(target.toByteArray(), equalTo(src));
  }

  @Test
  @DisplayName("write(byte[],off,len): negative replacement offset -> forwarded unchanged")
  void writeBuffer_whenReplacementOffsetNegative_expectForwarded() throws IOException {
    // Arrange
    byte[] src = rangeBytes(3, 4);
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out = new SingleOffsetReplacingOutputStream(target, -5, 0x11);

    // Act
    out.write(src, 0, src.length);
    out.flush();

    // Assert
    assertThat(target.toByteArray(), equalTo(src));
  }

  @Test
  @DisplayName("write(byte[],off,len): replacement occurs across buffer boundary (next call)")
  void writeBuffer_whenReplacementCrossesIntoNextBuffer_expectReplacedOnNextWrite()
      throws IOException {
    // Arrange
    byte[] first = new byte[] {1, 2, 3};
    byte[] second = new byte[] {4, 5, 6};
    int replacementOffset = 3; // first byte of second buffer
    int replacementValue = 0x42;
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue);

    // Act
    out.write(first, 0, first.length); // offsets 0..2
    out.write(second, 0, second.length); // offsets 3..5 (replace index 3)
    out.flush();

    // Assert
    byte[] expected = new byte[] {1, 2, 3, (byte) replacementValue, 5, 6};
    assertThat(target.toByteArray(), equalTo(expected));
  }

  @Test
  @DisplayName("write(byte[],off,len): non-zero input offset handled correctly")
  void writeBuffer_whenNonZeroArrayOffset_expectCorrectReplacement() throws IOException {
    // Arrange
    byte[] src = new byte[] {9, 9, 2, 3, 4, 5, 6, 9, 9}; // we will write 2..5: [2,3,4,5]
    int replacementOffset = 1; // replace second byte of the stream
    int replacementValue = 100;
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue);

    // Act
    out.write(src, 2, 4); // stream becomes [2,3,4,5]
    out.flush();

    // Assert
    byte[] expected = new byte[] {2, (byte) replacementValue, 4, 5};
    assertThat(target.toByteArray(), equalTo(expected));
  }

  @Test
  @DisplayName(
      "write(byte[],off,len): calls underlying in three chunks when replacement inside buffer")
  void writeBuffer_whenReplacementInside_expectThreeUnderlyingWritesInOrder() throws IOException {
    // Arrange
    byte[] src = new byte[] {9, 8, 7, 6, 5};
    int replacementOffset = 2; // third byte
    int replacementValue = 77;
    ByteArrayOutputStream real = new ByteArrayOutputStream();
    ByteArrayOutputStream target = spy(real);
    try (SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue)) {
      // Act
      out.write(src, 0, src.length);

      // Assert content
      byte[] expected = new byte[] {9, 8, (byte) replacementValue, 6, 5};
      byte[] actual = target.toByteArray();
      assertThat(actual, equalTo(expected));

      // Assert call order: prefix, replacement int, suffix
      InOrder order = inOrder(target);
      order.verify((OutputStream) target).write(same(src), eq(0), eq(2));
      order.verify((OutputStream) target).write(replacementValue);
      order.verify((OutputStream) target).write(same(src), eq(3), eq(2));
    }
  }

  @Test
  @DisplayName("write(byte[],off,len): zero-length write forwards once and does nothing else")
  void writeBuffer_whenZeroLength_expectSingleForwardingCall() throws IOException {
    // Arrange
    byte[] src = new byte[] {1, 2, 3};
    ByteArrayOutputStream real = new ByteArrayOutputStream();
    OutputStream target = spy(real);
    try (SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, 0, 0x23)) {
      // Act
      out.write(src, 0, 0);

      // Assert
      InOrder order = inOrder(target);
      order.verify(target).write(same(src), eq(0), eq(0));
      verifyNoMoreInteractions(target);
      assertThat(real.toByteArray(), equalTo(new byte[0]));
    }
  }

  @Test
  @DisplayName("write(byte[],off,len): null buffer -> NullPointerException")
  void writeBuffer_whenNullBuffer_expectNPE() {
    // Arrange
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out = new SingleOffsetReplacingOutputStream(target, 0, 0x12);

    // Act + Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> out.write(null, 0, 1));
  }

  @ParameterizedTest
  @DisplayName("write(byte[],off,len): invalid offset/length -> IndexOutOfBoundsException")
  @ValueSource(ints = {-1, -5})
  void writeBuffer_whenInvalidOffsetOrLength_expectIOOBE(int invalid) {
    // Arrange
    byte[] src = new byte[] {1, 2, 3};
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out = new SingleOffsetReplacingOutputStream(target, 1, 0x77);

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> out.write(src, invalid, 1));
    assertThrows(IndexOutOfBoundsException.class, () -> out.write(src, 0, invalid));
    assertThrows(IndexOutOfBoundsException.class, () -> out.write(src, 2, 5));
  }

  @Test
  @DisplayName(
      "write(byte[],off,len): replacement happens only once; subsequent writes are unchanged")
  void writeBuffer_whenReplacementAlreadyPassed_expectNoFurtherReplacement() throws IOException {
    // Arrange
    byte[] first = rangeBytes(1, 5); // 1..5
    byte[] second = rangeBytes(100, 3); // 100..102
    int replacementOffset = 2; // within first buffer
    int replacementValue = 0x5A;
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    SingleOffsetReplacingOutputStream out =
        new SingleOffsetReplacingOutputStream(target, replacementOffset, replacementValue);

    // Act
    out.write(first, 0, first.length); // replaces index 2
    out.write(second, 0, second.length); // should be forwarded unchanged
    out.flush();

    // Assert
    byte[] expectedFirst = first.clone();
    expectedFirst[replacementOffset] = (byte) replacementValue;
    byte[] expected = new byte[expectedFirst.length + second.length];
    System.arraycopy(expectedFirst, 0, expected, 0, expectedFirst.length);
    System.arraycopy(second, 0, expected, expectedFirst.length, second.length);
    assertThat(target.toByteArray(), equalTo(expected));
  }
}
