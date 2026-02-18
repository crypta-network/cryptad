package network.crypta.support;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ByteBufferInputStreamTest {

  @Test
  void readUnsigned_whenDataPresent_expectValuesAndEof() throws IOException {
    byte[] b = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0x00};
    try (ByteBufferInputStream in = new ByteBufferInputStream(b)) {
      assertEquals(0xFF, in.readUnsignedByte());
      assertEquals(0xFF00, in.readUnsignedShort());
      assertThrows(EOFException.class, in::readUnsignedByte);
    }
  }

  @Test
  void constructors_arrayOffsetLength_readsOnlySlice() throws IOException {
    byte[] src = new byte[] {0x10, 0x20, 0x30, 0x40, 0x50};
    try (ByteBufferInputStream in = new ByteBufferInputStream(src, 1, 3)) {
      assertEquals(0x20, in.readUnsignedByte());
      assertEquals(0x30, in.readUnsignedByte());
      assertEquals(0x40, in.readUnsignedByte());
      assertThrows(EOFException.class, in::readUnsignedByte);
    }
  }

  @Test
  void read_whenEof_returnsMinusOne() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {})) {
      assertEquals(-1, in.read());
    }
  }

  @Test
  void read_whenHasData_returnsUnsignedAndAdvances() throws IOException {
    try (ByteBufferInputStream in =
        new ByteBufferInputStream(new byte[] {(byte) 0xFE, (byte) 0x7F})) {
      assertEquals(0xFE, in.read());
      assertEquals(0x7F, in.read());
      assertEquals(-1, in.read());
    }
  }

  @Test
  void read_arrayOffLen_whenEof_returnsZeroNotMinusOne() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {})) {
      byte[] dst = new byte[4];
      int read = in.read(dst, 0, 4);
      assertEquals(0, read);
    }
  }

  @Test
  void read_arrayOffLen_lenZero_returnsZeroAndNoAdvance() throws IOException {
    byte[] data = new byte[] {1, 2, 3};
    try (ByteBufferInputStream in = new ByteBufferInputStream(data)) {
      byte[] dst = new byte[] {9, 9, 9};
      int before = in.remaining();
      int read = in.read(dst, 1, 0);
      assertEquals(0, read);
      assertEquals(before, in.remaining());
      assertArrayEquals(new byte[] {9, 9, 9}, dst);
    }
  }

  @Test
  void read_arrayOffLen_invalidArguments_throwIndexOutOfBounds() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {1, 2, 3})) {
      byte[] dst = new byte[2];
      int invalidOffset = Integer.parseInt("-1");
      assertThrows(IndexOutOfBoundsException.class, () -> in.read(dst, invalidOffset, 1));
      assertThrows(IndexOutOfBoundsException.class, () -> in.read(dst, 0, -1));
      assertThrows(IndexOutOfBoundsException.class, () -> in.read(dst, 1, 2));
    }
  }

  @Test
  void primitives_whenSufficientBytes_readCorrectValues() throws IOException {
    // short 0x1234, int 0xDEADBEEF, long 0x0123456789ABCDEF, float/double 1.0
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeShort(0x1234);
      dos.writeInt(0xDEADBEEF);
      dos.writeLong(0x0123456789ABCDEFL);
      dos.writeFloat(1.0f);
      dos.writeDouble(1.0);
    }

    try (ByteBufferInputStream in = new ByteBufferInputStream(baos.toByteArray())) {
      assertEquals((short) 0x1234, in.readShort());
      assertEquals(0xDEADBEEF, in.readInt());
      assertEquals(0x0123456789ABCDEFL, in.readLong());
      assertThat(in.readFloat(), is(1.0f));
      assertThat(in.readDouble(), is(1.0));
    }
  }

  @Test
  void readBoolean_whenZeroAndNonZero_expectFalseTrue() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {0x00, 0x01})) {
      assertFalse(in.readBoolean());
      assertTrue(in.readBoolean());
    }
  }

  @Test
  void readFully_variants_readExactBytesOrThrow() throws IOException {
    byte[] data = new byte[] {10, 20, 30, 40};
    try (ByteBufferInputStream in = new ByteBufferInputStream(data)) {
      byte[] dst = new byte[4];
      in.readFully(dst);
      assertArrayEquals(data, dst);
    }

    try (ByteBufferInputStream in2 = new ByteBufferInputStream(new byte[] {1, 2, 3, 4})) {
      byte[] dst2 = new byte[] {9, 9, 9, 9, 9};
      in2.readFully(dst2, 1, 3);
      assertArrayEquals(new byte[] {9, 1, 2, 3, 9}, dst2);
    }

    try (ByteBufferInputStream in3 = new ByteBufferInputStream(new byte[] {1, 2})) {
      byte[] tooBig = new byte[3];
      assertThrows(EOFException.class, () -> in3.readFully(tooBig));
    }
  }

  @Test
  void skipBytes_whenWithinAndExceedingRemaining_advancesAndReturnsSkipped() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {1, 2, 3, 4})) {
      assertEquals(2, in.skipBytes(2));
      assertEquals(2, in.remaining());
      assertEquals(2, in.skipBytes(10)); // clamp to remaining
      assertEquals(0, in.remaining());
    }
  }

  @Test
  void remaining_reflectsConsumption() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {1, 2, 3})) {
      assertEquals(3, in.remaining());
      assertEquals(1, in.read());
      assertEquals(2, in.remaining());
      assertEquals(1, in.skipBytes(1));
      assertEquals(1, in.remaining());
    }
  }

  @Test
  void readUTF_roundTrip_matchesDataOutputEncoding() throws IOException {
    String s = "Hello \u0000 € \uD83D\uDE00"; // includes NUL, Euro, and emoji
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeUTF(s);
    }
    try (ByteBufferInputStream in = new ByteBufferInputStream(baos.toByteArray())) {
      String read = in.readUTF();
      assertEquals(s, read);
    }
  }

  @Test
  @SuppressWarnings("deprecation")
  @DisplayName("readLine handles LF, CR, and CRLF and returns null at EOF")
  void readLine_variousTerminators_expectLinesAndNull() throws IOException {
    String payload = "alpha\rbravo\ncharlie\r\ndelta";
    try (ByteBufferInputStream in =
            new ByteBufferInputStream(payload.getBytes(StandardCharsets.ISO_8859_1));
        DataInputStream dis = new DataInputStream(in)) {
      assertEquals("alpha", dis.readLine());
      assertEquals("bravo", dis.readLine());
      assertEquals("charlie", dis.readLine());
      assertEquals("delta", dis.readLine());
      assertNull(dis.readLine());
    }
  }

  @Test
  void slice_whenValidSize_returnsViewAndAdvancesOriginal() throws IOException {
    byte[] data = new byte[] {1, 2, 3, 4, 5};
    try (ByteBufferInputStream in = new ByteBufferInputStream(data);
        ByteBufferInputStream slice = in.slice(3)) {
      assertNotNull(slice);
      assertEquals(2, in.remaining());

      byte[] read = new byte[3];
      slice.readFully(read);
      assertArrayEquals(new byte[] {1, 2, 3}, read);
      assertEquals(-1, slice.read());
    }
  }

  @Test
  void slice_whenZeroSize_returnsEmptySliceAndNoAdvance() throws IOException {
    byte[] data = new byte[] {9, 8, 7};
    try (ByteBufferInputStream in = new ByteBufferInputStream(data);
        ByteBufferInputStream slice = in.slice(0)) {
      assertEquals(3, in.remaining());
      assertEquals(-1, slice.read());
    }
  }

  @Test
  void slice_whenInsufficientRemaining_throwsEOF() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {1})) {
      assertThrows(EOFException.class, () -> sliceAndClose(in, 2));
    }
  }

  @Test
  void slice_whenNegativeSize_throwsIllegalArgument() throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(new byte[] {1, 2, 3})) {
      assertThrows(IllegalArgumentException.class, () -> sliceAndClose(in, -1));
    }
  }

  private static void sliceAndClose(ByteBufferInputStream in, int size) throws IOException {
    ByteBufferInputStream slice = in.slice(size);
    slice.close();
  }

  // -------------------- Underflow → EOFException tests --------------------

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> underflowReaders() {
    return java.util.stream.Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(
            "readByte", (Reader) ByteBufferInputStream::readByte, new byte[] {}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readChar", (Reader) ByteBufferInputStream::readChar, new byte[] {0x00}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readShort", (Reader) ByteBufferInputStream::readShort, new byte[] {0x00}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readInt", (Reader) ByteBufferInputStream::readInt, new byte[] {0x00, 0x01}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readLong", (Reader) ByteBufferInputStream::readLong, new byte[] {0x00, 0x01, 0x02}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readFloat", (Reader) ByteBufferInputStream::readFloat, new byte[] {0x00, 0x01, 0x02}),
        org.junit.jupiter.params.provider.Arguments.of(
            "readDouble",
            (Reader) ByteBufferInputStream::readDouble,
            new byte[] {0x00, 0x01, 0x02, 0x03}));
  }

  @ParameterizedTest(name = "{0} underflow throws EOFException")
  @MethodSource("underflowReaders")
  void dataInput_underflow_throwsEOFException(String name, Reader reader, byte[] bytes)
      throws IOException {
    try (ByteBufferInputStream in = new ByteBufferInputStream(bytes)) {
      assertThrows(EOFException.class, () -> reader.read(in), name);
    }
  }

  @FunctionalInterface
  interface Reader {
    void read(ByteBufferInputStream in) throws IOException;
  }
}
