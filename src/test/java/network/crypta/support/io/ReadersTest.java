package network.crypta.support.io;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link Readers} adapters.
 *
 * <p>Follows AAA style and covers nulls, empty inputs, boundaries, and error paths. Mockito is used
 * to mock {@link BufferedReader} for the adapter created by {@link
 * Readers#fromBufferedReader(BufferedReader)}.
 */
@SuppressWarnings("java:S100") // Allow method_whenCondition_expectOutcome naming in tests
class ReadersTest {

  @Nested
  @DisplayName("fromBufferedReader")
  class FromBufferedReader {

    @Test
    void readLine_whenDelegateReturnsSequence_expectSameSequenceAndNullAtEnd() throws Exception {
      // Arrange
      BufferedReader br = mock(BufferedReader.class);
      when(br.readLine()).thenReturn("one", "two", null);
      LineReader lr = Readers.fromBufferedReader(br);

      // Act & Assert
      assertEquals("one", lr.readLine(1, 1, true));
      assertEquals("two", lr.readLine(Integer.MAX_VALUE, 1024, false));
      assertNull(lr.readLine(10, 10, true));

      // Verify delegation count
      verify(br, times(3)).readLine();
      verifyNoMoreInteractions(br);
    }

    @Test
    void readLine_whenDelegateThrowsIOException_expectPropagatedIOException() throws Exception {
      // Arrange
      BufferedReader br = mock(BufferedReader.class);
      when(br.readLine()).thenThrow(new IOException("boom"));
      LineReader lr = Readers.fromBufferedReader(br);

      // Act & Assert
      IOException ex = assertThrows(IOException.class, () -> lr.readLine(80, 16, true));
      assertTrue(ex.getMessage().contains("boom"));
      verify(br).readLine();
      verifyNoMoreInteractions(br);
    }

    @Test
    void readLine_whenBufferedReaderIsNull_expectNullPointerExceptionOnUse() {
      // Arrange
      LineReader lr = Readers.fromBufferedReader(null);

      // Act & Assert
      assertThrows(NullPointerException.class, () -> lr.readLine(10, 10, true));
    }
  }

  @Nested
  @DisplayName("fromStringArray")
  class FromStringArray {

    static Stream<Arguments> arrayScenarios() {
      return Stream.of(
          Arguments.of(new String[] {}, new String[] {}),
          Arguments.of(new String[] {"only"}, new String[] {"only"}),
          Arguments.of(new String[] {"a", "b"}, new String[] {"a", "b"}),
          Arguments.of(new String[] {"with CR", "line2"}, new String[] {"with CR", "line2"}));
    }

    @ParameterizedTest
    @MethodSource("arrayScenarios")
    void readLine_whenArrayProvided_expectEachElementThenNull(String[] input, String[] expected)
        throws Exception {
      // Arrange
      LineReader lr = Readers.fromStringArray(input);

      // Act & Assert
      for (String s : expected) {
        assertEquals(s, lr.readLine(1, 1, true));
      }
      assertNull(lr.readLine(1, 1, false));
      // Calling again after EOF should keep returning null
      assertNull(lr.readLine(100, 100, true));
    }

    @Test
    void readLine_whenArrayIsEmpty_expectNullImmediately() throws Exception {
      // Arrange
      LineReader lr = Readers.fromStringArray(new String[] {});

      // Act & Assert
      assertNull(lr.readLine(64, 8, true));
    }

    @Test
    void readLine_whenMaxLengthZero_expectStillReturnsArrayElement() throws Exception {
      // Arrange
      LineReader lr = Readers.fromStringArray(new String[] {"x"});

      // Act & Assert
      // Adapters are allowed to ignore maxLength/encoding hints
      assertEquals("x", lr.readLine(0, 0, false));
      assertNull(lr.readLine(0, 0, false));
    }

    @Test
    void readLine_whenArrayIsNull_expectNullPointerExceptionOnUse() {
      // Arrange
      LineReader lr = Readers.fromStringArray(null);

      // Act & Assert
      assertThrows(NullPointerException.class, () -> lr.readLine(10, 10, true));
    }
  }
}
