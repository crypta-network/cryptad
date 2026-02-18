package network.crypta.support.io;

import java.io.Writer;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

@DisplayName("NullWriter")
@SuppressWarnings("java:S100") // test naming style: method_whenCondition_expectOutcome
class NullWriterTest {

  @Test
  void write_whenCharArrayValid_expectNoException() throws Exception {
    // Arrange
    char[] data = {'a', 'b', 'c'};

    // Act + Assert
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(() -> w.write(data, 0, data.length));
    }
  }

  static Stream<Arguments> invalidOffsetsAndLengths() {
    char[] four = new char[] {'x', 'y', 'z', 'w'};
    return Stream.of(
        // negative offset
        Arguments.of(four, -1, 1),
        // negative length
        Arguments.of(four, 0, -1),
        // offset beyond length
        Arguments.of(four, 5, 0),
        // length beyond remaining
        Arguments.of(four, 2, 3),
        // overflow check (off+len > array length)
        Arguments.of(four, 3, 2));
  }

  @ParameterizedTest(name = "write(char[], off={1}, len={2}) invalid bounds → no exception")
  @MethodSource("invalidOffsetsAndLengths")
  void write_whenInvalidArgs_expectNoException(char[] buf, int off, int len) throws Exception {
    // Act + Assert: NullWriter silently ignores inputs
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(() -> w.write(buf, off, len));
    }
  }

  @SuppressWarnings("DataFlowIssue")
  @Test
  void write_whenNullArray_expectNoException() throws Exception {
    // Act + Assert
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(() -> w.write((char[]) null, 0, 1));
    }
  }

  @Test
  void writeInt_whenAnyValue_expectNoExceptionAndDelegation() throws Exception {
    // Arrange
    NullWriter real = new NullWriter();
    try (NullWriter w = spy(real)) {
      // Act
      w.write('A');

      // Assert: Writer.write(int) delegates to write(char[], 0, 1)
      ArgumentCaptor<char[]> cap = ArgumentCaptor.forClass(char[].class);
      verify(w).write(cap.capture(), eq(0), eq(1));
      assertEquals('A', cap.getValue()[0]);
    }
  }

  @Test
  void writeString_whenNormalString_expectNoException() throws Exception {
    // Act + Assert
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(() -> w.write("hello"));
    }
  }

  @SuppressWarnings("DataFlowIssue")
  @Test
  void writeString_whenNull_expectNullPointerException() {
    // Act + Assert: default Writer.write(String) NPEs on null
    try (Writer w = new NullWriter()) {
      assertThrows(NullPointerException.class, () -> w.write((String) null));
    } catch (Exception e) {
      fail(e);
    }
  }

  @Test
  void append_whenNullCharSequence_expectReturnsThisAndNoException() throws Exception {
    // Act + Assert
    try (Writer w = new NullWriter()) {
      Writer ret = w.append(null);
      assertSame(w, ret);
    }
  }

  static Stream<Arguments> stringInvalidRanges() {
    return Stream.of(
        Arguments.of("abc", -1, 1), // negative offset
        Arguments.of("abc", 0, -1), // negative length
        Arguments.of("abc", 4, 0), // offset beyond length
        Arguments.of("abc", 2, 2)); // off+len beyond length
  }

  @ParameterizedTest(name = "write(String, off={1}, len={2}) invalid → IndexOutOfBounds")
  @MethodSource("stringInvalidRanges")
  void writeStringRange_whenInvalidArgs_expectIndexOutOfBounds(String s, int off, int len)
      throws Exception {
    // Act + Assert: default Writer implementation throws on invalid ranges
    try (Writer w = new NullWriter()) {
      assertThrows(IndexOutOfBoundsException.class, () -> w.write(s, off, len));
    }
  }

  @Test
  void flush_whenCalled_expectNoException() throws Exception {
    // Act + Assert
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(w::flush);
    }
  }

  @Test
  void close_whenCalledTwice_expectNoException() throws Exception {
    // Arrange + Act + Assert
    try (Writer w = new NullWriter()) {
      assertDoesNotThrow(w::close);
      assertDoesNotThrow(w::close); // idempotent even before try-with-resources closes
    }
  }
}
