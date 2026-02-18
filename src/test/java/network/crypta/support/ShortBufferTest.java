package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // method_whenCondition_expectOutcome naming
class ShortBufferTest {

  private static final String DATA_STRING =
      "asldkjaskjdsakdhasdhaskjdhaskjhbkasbhdjkasbduiwbxgdoudgboewuydxbybuewyxbuewyuwe"
          + "dasdkljasndijwnodhnqweoidhnaouidhbnwoduihwnxodiuhnwuioxdhnwqiouhnxwqoiushdnxwqoiudhxnwqoiudhxni";

  // ---------- Constructors ----------

  @Test
  void constructor_withByteArray_returnsSameArrayAndLength() {
    byte[] data = DATA_STRING.getBytes(StandardCharsets.UTF_8);

    ShortBuffer buffer = new ShortBuffer(data);

    assertSame(data, buffer.getData());
    assertEquals(data.length, buffer.getLength());
    for (int i = 0; i < data.length; i++) {
      assertEquals(data[i], buffer.byteAt(i));
    }
  }

  @Test
  void constructor_withByteArrayStartLength_returnsCopyAndExposesSlice() {
    byte[] data = DATA_STRING.getBytes(StandardCharsets.UTF_8);
    ShortBuffer buffer = new ShortBuffer(data, 4, 5);

    byte[] expected = new byte[5];
    System.arraycopy(data, 4, expected, 0, 5);

    assertNotSame(data, buffer.getData());
    assertArrayEquals(expected, buffer.getData());
    assertEquals(5, buffer.getLength());
    for (int i = 0; i < buffer.getLength(); i++) {
      assertEquals(expected[i], buffer.byteAt(i));
    }
  }

  @Test
  void constructor_withEmpty_noThrowAndHasZeroLength() {
    ShortBuffer buffer = new ShortBuffer();
    assertEquals(0, buffer.getLength());
    assertEquals(0, buffer.getData().length);
  }

  @Test
  void constructor_withTooLargeArray_throwsIllegalArgument() {
    byte[] big = new byte[Short.MAX_VALUE + 1];
    assertThrows(IllegalArgumentException.class, () -> new ShortBuffer(big));
  }

  static Stream<Arguments> invalidStartLenCases() {
    return Stream.of(
        // length < 0
        Arguments.of(0, -1, 0),
        // start < 0
        Arguments.of(-1, 0, 0),
        // start + length > data.length
        Arguments.of(0, 1, 0),
        Arguments.of(1, 0, 0),
        // length > Short.MAX_VALUE
        Arguments.of(0, Short.MAX_VALUE + 1, Short.MAX_VALUE + 1));
  }

  @ParameterizedTest
  @MethodSource("invalidStartLenCases")
  void constructor_withInvalidStartOrLength_throwsIllegalArgument(
      int start, int length, int dataLen) {
    byte[] data = new byte[dataLen];
    assertThrows(IllegalArgumentException.class, () -> new ShortBuffer(data, start, length));
  }

  @Test
  void constructor_withMaxAllowedLength_succeeds() {
    byte[] data = new byte[Short.MAX_VALUE];
    ShortBuffer buffer = new ShortBuffer(data, 0, data.length);
    assertEquals(Short.MAX_VALUE, buffer.getLength());
  }

  @Test
  void constructor_withDataInput_readsLengthAndBytes() throws IOException {
    byte[] data = DATA_STRING.getBytes(StandardCharsets.UTF_8);
    int len = data.length;
    byte[] in = new byte[len + 2];
    in[0] = (byte) ((len >>> 8) & 0xFF);
    in[1] = (byte) (len & 0xFF);
    System.arraycopy(data, 0, in, 2, len);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(in))) {
      ShortBuffer buffer = new ShortBuffer(dis);
      assertEquals(len, buffer.getLength());
      for (int i = 0; i < len; i++) {
        assertEquals(data[i], buffer.byteAt(i));
      }
    }
  }

  @Test
  void constructor_withDataInputNegativeLength_throwsIllegalArgument() {
    // length = -1 -> 0xFFFF
    byte[] in = new byte[] {(byte) 0xFF, (byte) 0xFF};
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(in))) {
      assertThrows(IllegalArgumentException.class, () -> new ShortBuffer(dis));
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  @Test
  void constructor_withDataInputInsufficientBytes_throwsIOException() {
    // declare length 5 but only provide 2 payload bytes
    byte[] in = new byte[] {0, 5, 1, 2};
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(in))) {
      assertThrows(EOFException.class, () -> new ShortBuffer(dis));
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  // ---------- Accessors ----------

  @Test
  void getData_whenFullRange_returnsInternalArray() {
    byte[] data = {1, 2, 3};
    ShortBuffer b = new ShortBuffer(data);
    assertSame(data, b.getData());
  }

  @Test
  void getData_whenSlice_returnsCopy() {
    byte[] data = {10, 20, 30, 40};
    ShortBuffer b = new ShortBuffer(data, 1, 2);
    byte[] out = b.getData();
    assertNotSame(data, out);
    assertArrayEquals(new byte[] {20, 30}, out);
  }

  @Test
  void byteAt_whenNegativeOrAtLength_throws() {
    byte[] data = {9, 8, 7};
    ShortBuffer b = new ShortBuffer(data);
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> b.byteAt(-1));
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> b.byteAt(data.length));
  }

  // ---------- write/copy semantics ----------

  @Test
  void writeToDataOutputStream_roundTripsViaDataInputConstructor() throws IOException {
    byte[] data = {1, 2, 3, 4, 5};
    ShortBuffer original = new ShortBuffer(data);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      original.writeToDataOutputStream(dos);
    }

    byte[] payload = bos.toByteArray();
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload))) {
      ShortBuffer restored = new ShortBuffer(dis);
      assertEquals(original, restored);
      assertEquals(original.hashCode(), restored.hashCode());
    }
  }

  @Test
  void copyTo_whenOffsetCopiesIntoDestination() {
    byte[] data = {10, 20, 30};
    ShortBuffer b = new ShortBuffer(data);

    byte[] dest = new byte[6];
    Arrays.fill(dest, (byte) 0x7F);

    b.copyTo(dest, 2);

    assertArrayEquals(new byte[] {(byte) 0x7F, (byte) 0x7F, 10, 20, 30, (byte) 0x7F}, dest);
  }

  @Test
  void copyTo_whenDestinationTooSmall_throws() {
    byte[] data = {1, 2, 3, 4};
    ShortBuffer b = new ShortBuffer(data);
    byte[] dest = new byte[5];
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> b.copyTo(dest, 2));
  }

  // ---------- equals / hashCode / toString ----------

  @Test
  void equalsAndHashCode_whenDifferentArraysSameContent_areEqual() {
    byte[] a1 = "ShortBuffer1".getBytes(StandardCharsets.UTF_8);
    byte[] a2 = "ShortBuffer1".getBytes(StandardCharsets.UTF_8);
    ShortBuffer b1 = new ShortBuffer(a1);
    ShortBuffer b2 = new ShortBuffer(a2);

    assertEquals(b1, b2);
    assertEquals(b1.hashCode(), b2.hashCode());
  }

  @Test
  void equals_whenSameArrayDifferentStart_notEqual() {
    byte[] arr = {1, 2, 3, 4};
    ShortBuffer b1 = new ShortBuffer(arr, 0, 2);
    ShortBuffer b2 = new ShortBuffer(arr, 1, 2);
    assertNotEquals(b1, b2);
  }

  @Test
  @DisplayName("toString small: shows bytes and trailing space")
  void toString_whenShort_returnsVerboseWithTrailingSpace() {
    ShortBuffer b = new ShortBuffer("feep".getBytes(StandardCharsets.UTF_8));
    assertEquals("{4:102 101 101 112 ", b.toString());
  }

  @Test
  void toString_whenLengthGreaterThan50_isSummaryOnly() {
    byte[] longArr = new byte[51];
    ShortBuffer b = new ShortBuffer(longArr);
    assertEquals("Buffer {51}", b.toString());
  }
}
