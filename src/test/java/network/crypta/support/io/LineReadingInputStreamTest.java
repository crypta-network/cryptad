package network.crypta.support.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class LineReadingInputStreamTest {
  private static final String BLOCK = "\ntesting1\ntesting2\r\ntesting3\n\n";
  private static final String[] LINES = new String[] {"", "testing1", "testing2", "testing3", ""};

  private static final String STRESSED_LINE = "\nĔ\n";
  private static final String NULL_LINE = "a\u0000\u0000\u0000\u0000\n";
  private static final String LENGTH_CHECKING_LINE = "a\u0000a\n";
  private static final int LENGTH_CHECKING_LINE_LF = 3;

  private static final int MAX_LENGTH = 128;
  private static final int BUFFER_SIZE = 128;

  private static void ignoreInt(int ignored) {}

  @Test
  void testReadLineWithoutMarking() throws Exception {
    // try utf8
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(STRESSED_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals("", instance.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, true));
      assertEquals("Ĕ", instance.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, true));
      assertNull(instance.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, true));
    }

    // try ISO-8859-1
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(BLOCK.getBytes(StandardCharsets.ISO_8859_1)))) {
      for (String expectedLine : LINES) {
        assertEquals(expectedLine, instance.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, false));
      }
      assertNull(instance.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, false));
    }

    // is it returning null?
    try (LineReadingInputStream instance = new LineReadingInputStream(new MockInputStream())) {
      assertNull(instance.readLineWithoutMarking(0, BUFFER_SIZE, false));
      assertNull(instance.readLineWithoutMarking(0, 0, false));
    }

    // is it throwing?
    try (LineReadingInputStream throwingInstance1 =
        new LineReadingInputStream(
            new ByteArrayInputStream(LENGTH_CHECKING_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertThrows(
          TooLongException.class,
          () ->
              throwingInstance1.readLineWithoutMarking(
                  LENGTH_CHECKING_LINE_LF - 1, BUFFER_SIZE, true));
    }

    // Same test shouldn't throw
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(LENGTH_CHECKING_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals(
          LENGTH_CHECKING_LINE.substring(0, LENGTH_CHECKING_LINE_LF),
          instance.readLineWithoutMarking(LENGTH_CHECKING_LINE_LF, BUFFER_SIZE, true));
    }

    // is it handling nulls properly? @see #2501
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(NULL_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals(
          NULL_LINE.substring(0, 5), instance.readLineWithoutMarking(BUFFER_SIZE, 1, true));
    }
  }

  @Test
  void testReadLine() throws Exception {
    // try utf8
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(STRESSED_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals("", instance.readLine(MAX_LENGTH, BUFFER_SIZE, true));
      assertEquals("Ĕ", instance.readLine(MAX_LENGTH, BUFFER_SIZE, true));
      assertNull(instance.readLine(MAX_LENGTH, BUFFER_SIZE, true));
    }

    // try ISO-8859-1
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(BLOCK.getBytes(StandardCharsets.ISO_8859_1)))) {
      for (String expectedLine : LINES) {
        assertEquals(expectedLine, instance.readLine(MAX_LENGTH, BUFFER_SIZE, false));
      }
      assertNull(instance.readLine(MAX_LENGTH, BUFFER_SIZE, false));
    }

    // is it returning null? and blocking when it should be?
    try (LineReadingInputStream instance = new LineReadingInputStream(new MockInputStream())) {
      assertNull(instance.readLine(0, BUFFER_SIZE, false));
      assertNull(instance.readLine(0, 0, false));
    }

    // is it throwing?
    try (LineReadingInputStream throwingInstance2 =
        new LineReadingInputStream(
            new ByteArrayInputStream(LENGTH_CHECKING_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertThrows(
          TooLongException.class,
          () -> throwingInstance2.readLine(LENGTH_CHECKING_LINE_LF - 1, BUFFER_SIZE, true));
    }

    // Same test shouldn't throw
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(LENGTH_CHECKING_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals(
          LENGTH_CHECKING_LINE.substring(0, LENGTH_CHECKING_LINE_LF),
          instance.readLine(LENGTH_CHECKING_LINE_LF, BUFFER_SIZE, true));
    }

    // is it handling nulls properly? @see #2501
    try (LineReadingInputStream instance =
        new LineReadingInputStream(
            new ByteArrayInputStream(NULL_LINE.getBytes(StandardCharsets.UTF_8)))) {
      assertEquals(NULL_LINE.substring(0, 5), instance.readLine(BUFFER_SIZE, 1, true));
    }
  }

  @Test
  void testBothImplementation() throws Exception {
    try (ByteArrayInputStream bis1 =
            new ByteArrayInputStream(BLOCK.getBytes(StandardCharsets.ISO_8859_1));
        ByteArrayInputStream bis2 =
            new ByteArrayInputStream(BLOCK.getBytes(StandardCharsets.ISO_8859_1));
        LineReadingInputStream lris1 = new LineReadingInputStream(bis1);
        LineReadingInputStream lris2 = new LineReadingInputStream(bis2)) {

      while (bis1.available() > 0 || bis2.available() > 0) {
        String stringWithoutMark = lris2.readLineWithoutMarking(MAX_LENGTH * 10, BUFFER_SIZE, true);
        String stringWithMark = lris1.readLine(MAX_LENGTH * 10, BUFFER_SIZE, true);
        assertEquals(stringWithMark, stringWithoutMark);
      }
      assertNull(lris1.readLine(MAX_LENGTH, BUFFER_SIZE, true));
      assertNull(lris2.readLineWithoutMarking(MAX_LENGTH, BUFFER_SIZE, true));
    }
  }

  // ---- Merged advanced tests ----

  @Test
  @DisplayName("readLine_whenMaxLengthLessThanOne_returnNull")
  void readLineWhenMaxLengthLessThanOneReturnNull() throws Exception {
    byte[] data = "hello\n".getBytes(StandardCharsets.UTF_8);
    try (LineReadingInputStream in = new LineReadingInputStream(new ByteArrayInputStream(data))) {
      String line = in.readLine(0, BUFFER_SIZE, true);
      assertNull(line);
    }
  }

  @Test
  @DisplayName("readLine_whenReadReturnsZero_throwEOFException")
  void readLineWhenReadReturnsZeroThrowEOFException() throws Exception {
    InputStream mocked = mock(InputStream.class);
    when(mocked.markSupported()).thenReturn(true);
    when(mocked.read(any(byte[].class), anyInt(), anyInt())).thenReturn(0);

    try (LineReadingInputStream in = new LineReadingInputStream(mocked)) {
      assertThrows(EOFException.class, () -> in.readLine(MAX_LENGTH, BUFFER_SIZE, true));
      ignoreInt(verify(mocked, atLeastOnce()).read(any(byte[].class), anyInt(), anyInt()));
      ignoreInt(verify(mocked, never()).read());
    }
  }

  @Test
  @DisplayName("readLine_whenLineEqualsMaxLength_returnsLine")
  void readLineWhenLineEqualsMaxLengthReturnsLine() throws Exception {
    int maxLen = 100;
    String line = "x".repeat(maxLen);
    byte[] data = (line + "\n").getBytes(StandardCharsets.UTF_8);
    try (LineReadingInputStream in = new LineReadingInputStream(new ByteArrayInputStream(data))) {
      String result = in.readLine(maxLen, maxLen + 8, true);
      assertEquals(line, result);
    }
  }

  @Test
  @DisplayName("readLineWithoutMarking_whenLongerThanMaxLength_throwTooLongException")
  void readLineWithoutMarkingWhenLongerThanMaxLengthThrowTooLongException() throws Exception {
    int maxLen = 10;
    String line = "a".repeat(maxLen + 1);
    try (LineReadingInputStream in =
        new LineReadingInputStream(
            new NonMarkingInputStream(line.getBytes(StandardCharsets.UTF_8)))) {
      assertThrows(TooLongException.class, () -> in.readLineWithoutMarking(maxLen, 4, true));
    }
  }

  @ParameterizedTest(name = "{index}: term=''{1}''")
  @MethodSource("terminatorCases")
  @DisplayName("readLine_whenDifferentTerminators_expectCorrectContent")
  void readLineWhenDifferentTerminatorsExpectCorrectContent(String content, String term)
      throws Exception {
    byte[] data = (content + term).getBytes(StandardCharsets.ISO_8859_1);
    try (LineReadingInputStream in = new LineReadingInputStream(new ByteArrayInputStream(data))) {
      String result = in.readLine(MAX_LENGTH, BUFFER_SIZE, false);
      String eof = in.readLine(MAX_LENGTH, BUFFER_SIZE, false);
      assertEquals(content, result);
      assertNull(eof);
    }
  }

  static Stream<Arguments> terminatorCases() {
    return Stream.of(
        Arguments.of("", "\n"),
        Arguments.of("abc", "\n"),
        Arguments.of("abc", "\r\n"),
        Arguments.of("only", ""));
  }

  @Test
  @DisplayName("readLineWithoutMarking_whenBufferGrows_correctlyReturnsLongLine")
  void readLineWithoutMarkingWhenBufferGrowsCorrectlyReturnsLongLine() throws Exception {
    String line = "y".repeat(300);
    byte[] data = (line + "\n").getBytes(StandardCharsets.UTF_8);
    try (LineReadingInputStream in = new LineReadingInputStream(new NonMarkingInputStream(data))) {
      String result = in.readLineWithoutMarking(512, 4, true);
      assertEquals(line, result);
    }
  }

  /** ByteArrayInputStream that disables mark/reset support to force non-marking path. */
  private static class NonMarkingInputStream extends ByteArrayInputStream {
    NonMarkingInputStream(byte[] buf) {
      super(buf);
    }

    @Override
    public boolean markSupported() {
      return false;
    }
  }
}
