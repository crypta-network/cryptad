package network.crypta.crypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import network.crypta.support.Fields;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ChecksumOutputStreamTest {

  @Test
  void getValue_whenWritingAcrossPrefix_expectCountsOnlyAfterPrefix() throws IOException {
    byte[] data = "0123456789".getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    Checksum crc = new CRC32();
    ChecksumOutputStream cos =
        new ChecksumOutputStream(underlying, crc, false, /* skipPrefix= */ 5);

    // Act
    cos.write(data); // contains prefix (first 5 bytes) and payload (rest)

    // Assert
    CRC32 expected = new CRC32();
    expected.update(data, 5, data.length - 5);
    assertEquals(expected.getValue(), cos.getValue());
    assertArrayEquals(data, underlying.toByteArray());
  }

  @Test
  void write_whenMixedIntAndArrayCrossingPrefix_expectCorrectCrcAccumulation() throws IOException {
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    CRC32 crc = new CRC32();
    ChecksumOutputStream cos =
        new ChecksumOutputStream(underlying, crc, false, /* skipPrefix= */ 3);

    // Arrange
    byte[] arr = "cde".getBytes(StandardCharsets.US_ASCII); // will cross the prefix boundary

    // Act
    cos.write('a'); // prefix 1/3
    cos.write('b'); // prefix 2/3
    cos.write(arr); // 'c' finishes prefix; 'd','e' are counted
    cos.write('F'); // counted
    cos.write('G'); // counted

    // Assert
    CRC32 expected = new CRC32();
    expected.update('d');
    expected.update('e');
    expected.update('F');
    expected.update('G');

    assertEquals(expected.getValue(), cos.getValue());
    assertArrayEquals(
        "ab".concat("cdeFG").getBytes(StandardCharsets.US_ASCII), underlying.toByteArray());
  }

  @Test
  void write_withOffsetAndLength_crossingPrefix_expectOnlyPostfixCounted() throws IOException {
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    CRC32 crc = new CRC32();
    ChecksumOutputStream cos =
        new ChecksumOutputStream(underlying, crc, false, /* skipPrefix= */ 4);

    byte[] payload = "xxABCDyy".getBytes(StandardCharsets.US_ASCII);
    // Write only "ABCD" using offset/length (crosses the prefix: first 4 bytes skipped, then
    // counted fully on subsequent writes)
    cos.write(payload, 2, 4); // "ABCD" -- completes the prefix exactly
    cos.write('Z'); // counted

    CRC32 expected = new CRC32();
    expected.update('Z');

    assertEquals(expected.getValue(), cos.getValue());
    assertArrayEquals(new byte[] {'A', 'B', 'C', 'D', 'Z'}, underlying.toByteArray());
  }

  @Test
  void close_whenWriteChecksumTrue_appendsLittleEndianCrcOnceAndBeforeClose() throws IOException {
    byte[] data = "abc".getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream underlyingSpy = spy(new ByteArrayOutputStream());
    CRC32 crc = new CRC32();

    ChecksumOutputStream cos =
        new ChecksumOutputStream(underlyingSpy, crc, true, /* skipPrefix= */ 0);

    // Act
    cos.write(data);

    // Compute expected checksum after data
    CRC32 expected = new CRC32();
    expected.update(data, 0, data.length);
    byte[] expectedTrailer = Fields.intToBytes((int) expected.getValue());

    cos.close();

    // Assert output content (data + trailer)
    byte[] expectedBytes = new byte[data.length + expectedTrailer.length];
    System.arraycopy(data, 0, expectedBytes, 0, data.length);
    System.arraycopy(expectedTrailer, 0, expectedBytes, data.length, expectedTrailer.length);
    assertArrayEquals(expectedBytes, underlyingSpy.toByteArray());

    // Assert call ordering: data write -> trailer write -> close
    InOrder order = inOrder(underlyingSpy);
    order.verify(underlyingSpy).write(data, 0, data.length);
    order.verify(underlyingSpy).write(expectedTrailer);
    order.verify(underlyingSpy).close();

    // Calling close again must not append another trailer and should not close again
    cos.close();
    verify(underlyingSpy, times(1)).close();
    assertArrayEquals(expectedBytes, underlyingSpy.toByteArray());
  }

  @Test
  void close_whenWriteChecksumFalse_expectNoAppendAndCloseInvoked() throws IOException {
    byte[] data = "hello".getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream underlyingSpy = spy(new ByteArrayOutputStream());
    ChecksumOutputStream cos =
        new ChecksumOutputStream(underlyingSpy, new CRC32(), false, /* skipPrefix= */ 0);

    cos.write(data);
    cos.close();
    cos.close(); // subsequent closes should not close the underlying stream again

    assertArrayEquals(data, underlyingSpy.toByteArray());
    verify(underlyingSpy, times(1)).close();
  }

  @Test
  void write_whenUnderlyingThrowsWithinPrefix_expectExceptionAndNoCrcChange() throws IOException {
    OutputStream bad = org.mockito.Mockito.mock(OutputStream.class);
    doThrow(new IOException("boom")).when(bad).write(any(byte[].class), anyInt(), anyInt());

    CRC32 crc = new CRC32();
    try (ChecksumOutputStream cos =
        new ChecksumOutputStream(bad, crc, false, /* skipPrefix= */ 10)) {
      byte[] data = new byte[] {1, 2, 3}; // entirely within the prefix
      assertThrows(IOException.class, () -> cos.write(data));
      assertEquals(0L, cos.getValue());
    }
  }

  @Test
  void write_whenUnderlyingThrowsAfterPrefix_expectExceptionAndCrcUpdated() throws IOException {
    OutputStream bad = org.mockito.Mockito.mock(OutputStream.class);
    doThrow(new IOException("boom")).when(bad).write(any(byte[].class), anyInt(), anyInt());

    CRC32 crc = new CRC32();
    try (ChecksumOutputStream cos =
        new ChecksumOutputStream(bad, crc, false, /* skipPrefix= */ 0)) {
      byte[] data = new byte[] {10, 20, 30, 40};

      IOException ex = assertThrows(IOException.class, () -> cos.write(data));
      assertEquals("boom", ex.getMessage());

      CRC32 expected = new CRC32();
      expected.update(data, 0, data.length);
      assertEquals(expected.getValue(), cos.getValue());
    }
  }

  @Test
  void close_whenAllDataWithinPrefix_appendsZeroChecksum() throws IOException {
    byte[] data = "123".getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    ChecksumOutputStream cos = new ChecksumOutputStream(underlying, new CRC32(), true, 100);

    cos.write(data); // CRC should remain zero
    cos.close();

    byte[] trailer = Fields.intToBytes(0);
    byte[] expected = Arrays.copyOf(data, data.length + trailer.length);
    System.arraycopy(trailer, 0, expected, data.length, trailer.length);

    assertArrayEquals(expected, underlying.toByteArray());
  }
}
