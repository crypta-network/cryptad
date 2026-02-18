package network.crypta.support.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@DisplayName("NullInputStream")
@SuppressWarnings("java:S100") // test naming style: method_whenCondition_expectOutcome
class NullInputStreamTest {

  @Test
  void read_whenCalled_expectEOF() throws Exception {
    try (InputStream in = new NullInputStream()) {
      int result = in.read();
      assertThat(result, equalTo(-1));
    }
  }

  @Test
  void read_againAfterEOF_expectEOF() throws Exception {
    try (InputStream in = new NullInputStream()) {
      assertEquals(-1, in.read());
      int result = in.read();
      assertEquals(-1, result);
    }
  }

  @Test
  void readByteArray_whenLenZero_expectZeroAndUnchanged() throws Exception {
    byte[] buf = new byte[0];
    try (InputStream in = new NullInputStream()) {
      int read = in.read(buf);
      assertEquals(0, read);
      assertEquals(0, buf.length);
    }
  }

  @Test
  void readByteArray_whenPositiveLen_expectEOFAndBufferUnchanged() throws Exception {
    byte[] buf = new byte[] {1, 2, 3, 4};
    byte[] original = buf.clone();
    try (InputStream in = new NullInputStream()) {
      int read = in.read(buf);
      assertEquals(-1, read);
      assertArrayEquals(original, buf);
    }
  }

  @Test
  void readWithOffset_whenLenZero_expectZeroAndBufferUnchanged() throws Exception {
    byte[] buf = new byte[] {10, 20, 30};
    byte[] original = buf.clone();
    try (InputStream in = new NullInputStream()) {
      int read = in.read(buf, 1, 0);
      assertEquals(0, read);
      assertArrayEquals(original, buf);
    }
  }

  @Test
  void readWithOffset_whenPositiveLen_expectEOFAndBufferUnchanged() throws Exception {
    byte[] buf = new byte[] {10, 20, 30, 40};
    byte[] original = buf.clone();
    try (InputStream in = new NullInputStream()) {
      int read = in.read(buf, 1, 2);
      assertEquals(-1, read);
      assertArrayEquals(original, buf);
    }
  }

  static Stream<Arguments> invalidOffsetsAndLengths() {
    byte[] four = new byte[4];
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

  @ParameterizedTest(name = "read(byte[], off={1}, len={2}) with invalid bounds")
  @MethodSource("invalidOffsetsAndLengths")
  void readWithOffset_whenInvalidArgs_expectIndexOutOfBounds(byte[] buf, int off, int len)
      throws Exception {
    try (InputStream in = new NullInputStream()) {
      assertThrows(IndexOutOfBoundsException.class, () -> in.read(buf, off, len));
    }
  }

  @SuppressWarnings("DataFlowIssue")
  @Test
  void readWithNullArray_whenCalled_expectNullPointerException() {
    try (InputStream in = new NullInputStream()) {
      assertThrows(NullPointerException.class, () -> in.read(null, 0, 1));
    } catch (IOException e) {
      fail(e);
    }
  }

  static Stream<Long> skipValues() {
    return Stream.of(-10L, -1L, 0L, 1L, 1024L);
  }

  @ParameterizedTest(name = "skip({0}) -> 0")
  @MethodSource("skipValues")
  void skip_whenAnyValue_expectZero(long n) throws Exception {
    try (InputStream in = new NullInputStream()) {
      long skipped = in.skip(n);
      assertEquals(0L, skipped);
    }
  }

  @Test
  void available_whenCalled_expectZero() throws Exception {
    try (InputStream in = new NullInputStream()) {
      int available = in.available();
      assertEquals(0, available);
    }
  }

  @Test
  void markSupported_whenCalled_expectFalse() {
    try (InputStream in = new NullInputStream()) {
      assertFalse(in.markSupported());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void reset_whenMarkUnsupported_expectIOException() {
    try (InputStream in = new NullInputStream()) {
      assertThrows(IOException.class, in::reset);
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void transferTo_whenCalled_expectZeroAndNoWrites() throws Exception {
    OutputStream out = mock(OutputStream.class);
    try (InputStream in = new NullInputStream()) {
      long transferred = in.transferTo(out);
      assertEquals(0L, transferred);
      verify(out, never()).write(any(byte[].class), anyInt(), anyInt());
      verify(out, never()).write(anyInt());
    }
  }

  @Test
  void readAllBytes_whenCalled_expectEmptyArray() throws Exception {
    try (InputStream in = new NullInputStream()) {
      byte[] all = in.readAllBytes();
      assertNotNull(all);
      assertEquals(0, all.length);
    }
  }

  @Test
  void readNBytes_whenCalled_expectEmptyArray() throws Exception {
    try (InputStream in = new NullInputStream()) {
      byte[] some = in.readNBytes(128);
      assertNotNull(some);
      assertEquals(0, some.length);
    }
  }

  @Test
  void close_whenCalled_expectNoException() {
    try (InputStream in = new NullInputStream()) {
      assertDoesNotThrow(in::close); // explicit close; try-with-resources closes again
    } catch (IOException e) {
      fail(e);
    }
  }
}
