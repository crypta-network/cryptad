package com.onionnetworks.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class JoiningInputStreamTest {

  @Test
  void constructor_whenFirstIsNull_throwsNullPointerException() {
    InputStream second = new ByteArrayInputStream(new byte[0]);

    assertThrows(NullPointerException.class, () -> new JoiningInputStream(null, second));
  }

  @Test
  void constructor_whenSecondIsNull_throwsNullPointerException() {
    InputStream first = new ByteArrayInputStream(new byte[0]);

    assertThrows(NullPointerException.class, () -> new JoiningInputStream(first, null));
  }

  @Test
  void read_whenBothStreamsHaveData_returnsBytesInOrder() throws IOException {
    InputStream first = new ByteArrayInputStream("abc".getBytes(StandardCharsets.US_ASCII));
    InputStream second = new ByteArrayInputStream("def".getBytes(StandardCharsets.US_ASCII));
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);

    ByteArrayOutputStream result = new ByteArrayOutputStream();
    int value;
    while ((value = joiningInputStream.read()) != -1) {
      result.write(value);
    }

    assertEquals("abcdef", result.toString(StandardCharsets.US_ASCII));
  }

  @Test
  void readByteArray_whenFirstStreamIsEmpty_switchesToSecondWithinSameCall() throws IOException {
    InputStream first = new ByteArrayInputStream(new byte[0]);
    InputStream second = new ByteArrayInputStream("XY".getBytes(StandardCharsets.US_ASCII));
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);
    byte[] buffer = new byte[2];

    int read = joiningInputStream.read(buffer, 0, buffer.length);

    assertEquals(2, read);
    assertArrayEquals("XY".getBytes(StandardCharsets.US_ASCII), buffer);
  }

  @Test
  void readByteArray_whenFirstStreamExhausted_switchesOnNextCall() throws IOException {
    InputStream first = new ByteArrayInputStream("A".getBytes(StandardCharsets.US_ASCII));
    InputStream second = new ByteArrayInputStream("BC".getBytes(StandardCharsets.US_ASCII));
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);
    byte[] buffer = new byte[3];

    int firstRead = joiningInputStream.read(buffer, 0, 1);
    int secondRead = joiningInputStream.read(buffer, 1, 2);

    assertEquals(1, firstRead);
    assertEquals(2, secondRead);
    assertArrayEquals("ABC".getBytes(StandardCharsets.US_ASCII), buffer);
  }

  @Test
  void read_whenBothStreamsEmpty_returnsMinusOne() throws IOException {
    InputStream first = new ByteArrayInputStream(new byte[0]);
    InputStream second = new ByteArrayInputStream(new byte[0]);
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);

    assertEquals(-1, joiningInputStream.read());
  }

  @Test
  void readByteArray_whenFirstReturnsEndOfStream_invokesSecondRead() throws IOException {
    byte[] buffer = new byte[4];
    InputStream first = mock(InputStream.class);
    InputStream second = mock(InputStream.class);
    when(first.read(buffer, 0, buffer.length)).thenReturn(-1);
    when(second.read(buffer, 0, buffer.length)).thenReturn(2);
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);

    int read = joiningInputStream.read(buffer, 0, buffer.length);

    assertEquals(2, read);
    verify(first).read(buffer, 0, buffer.length);
    verify(second).read(buffer, 0, buffer.length);
  }

  @Test
  void close_closesBothStreams() throws IOException {
    InputStream first = mock(InputStream.class);
    InputStream second = mock(InputStream.class);
    JoiningInputStream joiningInputStream = new JoiningInputStream(first, second);

    joiningInputStream.close();

    verify(first).close();
    verify(second).close();
  }
}
