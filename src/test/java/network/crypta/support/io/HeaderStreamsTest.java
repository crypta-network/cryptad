package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link HeaderStreams} using JUnit 6 and Mockito.
 *
 * <p>Tests follow AAA style and cover normal and error paths for both augInput and dimOutput.
 */
class HeaderStreamsTest {

  // ----------------------- augInput (InputStream) -----------------------

  @Test
  @DisplayName("augInput_read_whenHeaderThenPayload_expectHeaderThenPayloadThenEOF")
  void augInput_read_whenHeaderThenPayload_expectHeaderThenEOF() throws Exception {
    // Arrange
    byte[] header = new byte[] {1, 2, 3};
    byte[] payload = new byte[] {10, 20};
    InputStream underlying = new ByteArrayInputStream(payload);
    InputStream in = HeaderStreams.augInput(header, underlying);

    // Act + Assert
    assertEquals(1, in.read());
    assertEquals(2, in.read());
    assertEquals(3, in.read());
    assertEquals(10, in.read());
    assertEquals(20, in.read());
    assertEquals(-1, in.read());
  }

  @Test
  @DisplayName("augInput_available_whenPartiallyThroughHeader_expectHeaderRemainingPlusUnderlying")
  void augInput_available_whenPartiallyThroughHeader_expectHeaderRemainingPlusUnderlying()
      throws Exception {
    // Arrange
    byte[] header = new byte[] {9, 9, 9, 9};
    InputStream underlying = mock(InputStream.class);
    when(underlying.available()).thenReturn(5);
    InputStream in = HeaderStreams.augInput(header, underlying);

    // Act + Assert
    // Initially: 4 header bytes + 5 available from underlying
    assertEquals(9, in.available());

    // Consume two header bytes
    assertEquals(9, in.read());
    assertEquals(9, in.read());

    // Now: 2 header bytes left + 5 underlying
    assertEquals(7, in.available());
  }

  @Test
  @DisplayName("augInput_readBuffer_whenBufferSmallerThanHeader_expectOnlyHeaderCopied")
  void augInput_readBuffer_whenBufferSmallerThanHeader_expectOnlyHeaderCopied() throws Exception {
    // Arrange
    byte[] header = new byte[] {0x01, 0x7F, (byte) 0x80, (byte) 0xFF};
    byte[] payload = new byte[] {5};
    InputStream underlying = new ByteArrayInputStream(payload);
    InputStream in = HeaderStreams.augInput(header, underlying);
    byte[] buf = new byte[4];

    // Act
    int n1 = in.read(buf, 0, 2);
    int n2 = in.read(buf, 2, 2);
    // Assert header fully copied first
    assertEquals(2, n1);
    assertEquals(2, n2);
    assertArrayEquals(header, buf);

    // Act: now consume payload and EOF
    int n3 = in.read(buf, 0, 1);
    int n4 = in.read(buf, 0, 1);

    // Assert payload and EOF
    assertEquals(1, n3);
    assertEquals(5, buf[0]);
    assertEquals(-1, n4);
  }

  @Test
  @DisplayName("augInput_skip_whenHeaderAndUnderlying_expectCorrectCountAndPosition")
  void augInput_skip_whenHeaderAndUnderlying_expectCorrectCountAndPosition() throws Exception {
    // Arrange
    byte[] header = new byte[] {1, 2, 3};
    byte[] payload = new byte[] {10, 20, 30, 40};
    InputStream underlying = new ByteArrayInputStream(payload);
    InputStream in = HeaderStreams.augInput(header, underlying);

    // Act
    long skipped = in.skip(5); // 3 from header + 2 from payload

    // Assert
    assertEquals(5, skipped);
    assertEquals(30, in.read());
    assertEquals(40, in.read());
    assertEquals(-1, in.read());
  }

  @Test
  @DisplayName("augInput_markReset_whenCalled_expectUnsupported")
  void augInput_markReset_whenCalled_expectUnsupported() {
    // Arrange
    byte[] header = new byte[] {1};
    InputStream underlying = new ByteArrayInputStream(new byte[] {42});
    InputStream in = HeaderStreams.augInput(header, underlying);

    // Act + Assert
    assertFalse(in.markSupported());
    assertThrows(IOException.class, in::reset);
  }

  @Test
  @DisplayName("augInput_read_whenHeaderContainsNegativeBytes_expectUnsignedReturnValues")
  void augInput_read_whenHeaderContainsNegativeBytes_expectUnsignedReturnValues() throws Exception {
    // Arrange
    byte[] header = new byte[] {(byte) 0xFF, (byte) 0x80};
    InputStream underlying = new ByteArrayInputStream(new byte[0]);
    InputStream in = HeaderStreams.augInput(header, underlying);

    // Act + Assert
    assertEquals(255, in.read());
    assertEquals(128, in.read());
    assertEquals(-1, in.read());
  }

  @Test
  @DisplayName("augInput_nullHeader_whenRead_expectNullPointerException")
  void augInput_nullHeader_whenRead_expectNullPointerException() {
    // Arrange
    InputStream underlying = new ByteArrayInputStream(new byte[] {1});
    InputStream in = HeaderStreams.augInput(null, underlying);

    // Act + Assert
    assertThrows(NullPointerException.class, in::read);
  }

  // ----------------------- dimOutput (OutputStream) -----------------------

  @Test
  @DisplayName("dimOutput_writeInt_whenHeaderMatches_expectForwardOnlyAfterHeader")
  void dimOutput_writeInt_whenHeaderMatches_expectForwardOnlyAfterHeader() throws Exception {
    // Arrange
    byte[] header = new byte[] {1, 2, 3};
    OutputStream underlying = mock(OutputStream.class);
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act
    out.write(1);
    out.write(2);
    out.write(3);
    out.write(99);

    // Assert
    verify(underlying, times(1)).write(99);
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("dimOutput_writeArray_whenHeaderAndPayloadSameCall_expectPayloadForwarded")
  void dimOutput_writeArray_whenHeaderAndPayloadSameCall_expectPayloadForwarded() throws Exception {
    // Arrange
    byte[] header = new byte[] {10, 11};
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    OutputStream out = HeaderStreams.dimOutput(header, underlying);
    byte[] buf = new byte[] {10, 11, 12, 13};

    // Act
    out.write(buf, 0, buf.length);

    // Assert
    assertArrayEquals(new byte[] {12, 13}, underlying.toByteArray());
  }

  @Test
  @DisplayName("dimOutput_writeArray_whenMismatchWithinHeader_expectIOExceptionAndNoWrites")
  void dimOutput_writeArray_whenMismatchWithinHeader_expectIOExceptionAndNoWrites() {
    // Arrange
    byte[] header = new byte[] {1, 2, 3};
    OutputStream underlying = mock(OutputStream.class);
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> out.write(new byte[] {1, 9}, 0, 2));
    assertTrue(
        ex.getMessage().contains("byte 1: expected '2'; got '9'."),
        () -> "Unexpected message: " + ex.getMessage());
    verifyNoInteractions(underlying);
  }

  @Test
  @DisplayName("dimOutput_writeArray_whenPartialHeaderThenFinish_expectPayloadAfterHeader")
  void dimOutput_writeArray_whenPartialHeaderThenFinish_expectPayloadAfterHeader()
      throws Exception {
    // Arrange
    byte[] header = new byte[] {1, 2, 3};
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act
    out.write(new byte[] {1}, 0, 1); // nothing forwarded yet
    out.write(new byte[] {2, 3, 88, 89}, 0, 4); // 88, 89 should be forwarded

    // Assert
    assertArrayEquals(new byte[] {88, 89}, underlying.toByteArray());
  }

  @Test
  @DisplayName("dimOutput_writeInt_whenAfterHeader_expectWriteDelegated")
  void dimOutput_writeInt_whenAfterHeader_expectWriteDelegated() throws Exception {
    // Arrange
    byte[] header = new byte[] {7};
    OutputStream underlying = mock(OutputStream.class);
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act
    out.write(7); // consumes header
    out.write(55); // forwarded

    // Assert
    verify(underlying, times(1)).write(55);
    verifyNoMoreInteractions(underlying);
  }

  @Test
  @DisplayName("dimOutput_writeArray_whenZeroLengthHeader_expectAllForwarded")
  void dimOutput_writeArray_whenZeroLengthHeader_expectAllForwarded() throws Exception {
    // Arrange
    byte[] header = new byte[0];
    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    OutputStream out = HeaderStreams.dimOutput(header, underlying);
    byte[] buf = new byte[] {8, 9};

    // Act
    out.write(buf, 0, buf.length);

    // Assert
    assertArrayEquals(buf, underlying.toByteArray());
  }

  @Test
  @DisplayName("dimOutput_writeInt_whenHeaderMismatch_expectIOExceptionAndNoWrites")
  void dimOutput_writeInt_whenHeaderMismatch_expectIOExceptionAndNoWrites() {
    // Arrange
    byte[] header = new byte[] {1, 2};
    OutputStream underlying = mock(OutputStream.class);
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> out.write(9));
    assertTrue(ex.getMessage().contains("byte 0: expected '1'; got '9'."));
    verifyNoInteractions(underlying);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3})
  @DisplayName("dimOutput_writeArray_param_headerLengths_expectPayloadForwarded")
  void dimOutput_writeArray_param_headerLengths_expectPayloadForwarded(int headerLen)
      throws Exception {
    // Arrange
    byte[] header = new byte[headerLen];
    for (int i = 0; i < headerLen; i++) header[i] = (byte) (i + 1);
    byte[] payload = new byte[] {88, 89};
    byte[] combined = Arrays.copyOf(header, headerLen + payload.length);
    System.arraycopy(payload, 0, combined, headerLen, payload.length);

    ByteArrayOutputStream underlying = new ByteArrayOutputStream();
    OutputStream out = HeaderStreams.dimOutput(header, underlying);

    // Act
    out.write(combined, 0, combined.length);

    // Assert
    assertArrayEquals(payload, underlying.toByteArray());
  }

  @Test
  @DisplayName("dimOutput_nullHeader_whenWrite_expectNullPointerException")
  void dimOutput_nullHeader_whenWrite_expectNullPointerException() {
    // Arrange
    OutputStream underlying = mock(OutputStream.class);
    OutputStream out = HeaderStreams.dimOutput(null, underlying);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> out.write(1));
    verifyNoInteractions(underlying);
  }
}
