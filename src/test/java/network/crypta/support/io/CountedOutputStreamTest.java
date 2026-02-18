package network.crypta.support.io;

import java.io.IOException;
import java.io.OutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CountedOutputStreamTest {

  @Test
  void written_whenNoWrites_expectZero() {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act & Assert
      assertEquals(0L, counted.written());
    } catch (IOException e) {
      fail(e);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 127, 255})
  void writeInt_whenAnyByte_expectCountIncrementByOne(int value) throws IOException {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      counted.write(value);
      // Assert
      assertEquals(1L, counted.written());
      verify(mockOut, times(1)).write(value);
    }
  }

  @Test
  void writeInt_whenUnderlyingThrows_expectCountUnchanged() throws IOException {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    doThrow(new IOException("boom")).when(mockOut).write(anyInt());
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      IOException ex = assertThrows(IOException.class, () -> counted.write(42));
      assertEquals("boom", ex.getMessage());
      // Assert
      assertEquals(0L, counted.written());
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 3, 16})
  void writeByteArray_whenWholeArray_expectCountEqualsLength(int len) throws IOException {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    byte[] data = new byte[len];
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      counted.write(data);
      // Assert
      assertEquals(len, counted.written());
      verify(mockOut, times(1)).write(data, 0, len);
    }
  }

  @ParameterizedTest
  @CsvSource({"0,0", "0,3", "1,2", "2,3"})
  @DisplayName("write(byte[],off,len) counts exactly len and delegates")
  void writeByteArray_whenOffsetAndLength_expectCountEqualsLength(int off, int len)
      throws IOException {
    // Arrange
    int total = Math.max(off + len, 0);
    byte[] data = new byte[total];
    OutputStream mockOut = mock(OutputStream.class);
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      counted.write(data, off, len);
      // Assert
      assertEquals(len, counted.written());
      verify(mockOut, times(1)).write(data, off, len);
    }
  }

  @Test
  void writeByteArray_whenZeroLength_expectNoChange() throws IOException {
    // Arrange
    byte[] data = new byte[5];
    OutputStream mockOut = mock(OutputStream.class);
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      counted.write(data, 2, 0);
      // Assert
      assertEquals(0L, counted.written());
      verify(mockOut, times(1)).write(data, 2, 0);
    }
  }

  @Test
  void writeByteArray_whenNull_expectNullPointerException() {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act & Assert
      //noinspection DataFlowIssue
      assertThrows(NullPointerException.class, () -> counted.write(null));
      assertEquals(0L, counted.written());
    } catch (IOException e) {
      fail(e);
    }
  }

  @ParameterizedTest
  @CsvSource({
    "-1,1", // negative offset
    "0,-1", // negative length
    "2,4" // offset+length > array length
  })
  void writeByteArray_whenInvalidRange_expectIndexOutOfBoundsException(int off, int len) {
    // Arrange: use a real OutputStream with default range checks
    OutputStream realOut =
        new OutputStream() {
          @Override
          public void write(int b) {
            // no-op
          }
        };
    try (CountedOutputStream cos = new CountedOutputStream(realOut)) {
      byte[] data = new byte[4];
      // Act & Assert
      assertThrows(IndexOutOfBoundsException.class, () -> cos.write(data, off, len));
      assertEquals(0L, cos.written());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void constructor_whenNullStream_expectNpeOnWriteAndCountUnchanged() {
    // Arrange
    try (CountedOutputStream cos =
        new CountedOutputStream(null) {
          @Override
          public void close() {
            // Do nothing: underlying is null
          }
        }) {
      // Act & Assert
      assertThrows(NullPointerException.class, () -> cos.write(1));
      assertEquals(0L, cos.written());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void multipleWrites_whenMixedCalls_expectAccumulatedCount() throws IOException {
    // Arrange
    OutputStream mockOut = mock(OutputStream.class);
    byte[] a = new byte[4];
    byte[] b = new byte[3];

    try (CountedOutputStream counted = new CountedOutputStream(mockOut)) {
      // Act
      counted.write(0x7F); // +1
      counted.write(a); // +4
      counted.write(b, 1, 2); // +2

      // Assert
      assertEquals(1 + 4 + 2, counted.written());
      verify(mockOut, times(1)).write(0x7F);
      verify(mockOut, times(1)).write(a, 0, 4);
      verify(mockOut, times(1)).write(b, 1, 2);
    }
  }
}
