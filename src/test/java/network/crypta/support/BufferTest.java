package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test case for {@link Buffer} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 */
class BufferTest {

  private static final String DATA_STRING_1 =
      "asldkjaskjdsakdhasdhaskjdhaskjhbkasbhdjkasbduiwbxgdoudgboewuydxbybuewyxbuewyuwe"
          + "dasdkljasndijwnodhnqweoidhnaouidhbnwoduihwnxodiuhnwuioxdhnwqiouhnxwqoiushdnxwqoiudhxnwqoiudhxni";

  private static void ignoreByte(byte ignored) {}

  @Test
  @DisplayName("getData_whenFullArray_expectSameInstanceAndCorrectContent")
  void getData_whenFullArray_expectSameInstanceAndCorrectContent() {
    // Arrange
    byte[] data = DATA_STRING_1.getBytes(StandardCharsets.UTF_8);

    // Act
    Buffer buffer = new Buffer(data);

    // Assert: returns the same backing array instance and content matches
    assertSame(data, buffer.getData());
    doTestBufferContent(data, buffer);
  }

  @Test
  @DisplayName("getData_whenSubrange_expectCopyWithEqualContentAndNewInstanceEachCall")
  void getData_whenSubrange_expectCopyWithEqualContentAndNewInstanceEachCall() {
    // Arrange
    byte[] data = DATA_STRING_1.getBytes(StandardCharsets.UTF_8);
    byte[] dataSub = Arrays.copyOfRange(data, 4, 9);

    // Act
    Buffer buffer = new Buffer(data, 4, 5);

    // Assert: returns copies, not the same instance
    byte[] first = buffer.getData();
    byte[] second = buffer.getData();
    assertNotEquals(dataSub, buffer.getData()); // reference inequality
    assertNotSame(first, second);
    assertArrayEquals(dataSub, first);
    assertArrayEquals(dataSub, second);

    // Mutating one snapshot does not affect subsequent calls
    first[0] = (byte) 123;
    assertArrayEquals(dataSub, buffer.getData());

    doTestBufferContent(dataSub, buffer);
  }

  @Test
  @DisplayName("ctorByteArrayStartLen_whenInvalidArguments_expectIllegalArgumentException")
  void ctorByteArrayStartLen_whenInvalidArguments_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new Buffer(new byte[0], 0, -1));
    assertThrows(IllegalArgumentException.class, () -> new Buffer(new byte[0], 0, 1));
    assertThrows(IllegalArgumentException.class, () -> new Buffer(new byte[0], 1, 0));

    // Valid edge cases should not throw
    assertDoesNotThrow(() -> new Buffer(new byte[1], 1, 0));
    assertDoesNotThrow(() -> new Buffer(new byte[1], 0, 1));
  }

  @Test
  @DisplayName("ctorDataInput_whenValidLengthAndBytes_expectBufferWithCorrectContent")
  void ctorDataInput_whenValidLengthAndBytes_expectBufferWithCorrectContent() {
    // Arrange
    byte[] data = DATA_STRING_1.getBytes(StandardCharsets.UTF_8);
    byte[] framed = new byte[data.length + 4];
    int length = data.length;
    framed[0] = (byte) ((length >>> 24) & 0xFF);
    framed[1] = (byte) ((length >>> 16) & 0xFF);
    framed[2] = (byte) ((length >>> 8) & 0xFF);
    framed[3] = (byte) (length & 0xFF);
    System.arraycopy(data, 0, framed, 4, data.length);

    // Act
    Buffer buffer =
        assertDoesNotThrow(() -> new Buffer(new DataInputStream(new ByteArrayInputStream(framed))));
    assertNotNull(buffer);

    // Assert
    doTestBufferContent(data, buffer);
  }

  @Test
  @DisplayName("ctorDataInput_whenNegativeLength_expectIllegalArgumentException")
  void ctorDataInput_whenNegativeLength_expectIllegalArgumentException() {
    byte[] hdr = ByteBuffer.allocate(4).putInt(-1).array();
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(hdr));
    assertThrows(IllegalArgumentException.class, () -> new Buffer(dis));
  }

  @Test
  @DisplayName("ctorDataInput_whenLengthExceedsMax_expectIllegalArgumentException")
  void ctorDataInput_whenLengthExceedsMax_expectIllegalArgumentException() {
    int tooLarge = Serializer.MAX_ARRAY_LENGTH + 1; // 4093
    byte[] hdr = ByteBuffer.allocate(4).putInt(tooLarge).array();
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(hdr));
    assertThrows(IllegalArgumentException.class, () -> new Buffer(dis));
  }

  @Test
  @DisplayName("ctorDataInput_whenPrematureEOF_expectEOFException")
  void ctorDataInput_whenPrematureEOF_expectEOFException() {
    // Declare a length of 3 but provide only 2 payload bytes
    int declaredLength = 3;
    byte[] hdr = ByteBuffer.allocate(4).putInt(declaredLength).array();
    byte[] payload = new byte[] {1, 2}; // 2 bytes only
    byte[] framed = new byte[hdr.length + payload.length];
    System.arraycopy(hdr, 0, framed, 0, hdr.length);
    System.arraycopy(payload, 0, framed, hdr.length, payload.length);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(framed));
    assertThrows(EOFException.class, () -> new Buffer(dis));
  }

  private void doTestBufferContent(byte[] data, Buffer buffer) {
    assertEquals(data.length, buffer.getLength());
    for (int i = 0; i < buffer.getLength(); i++) {
      assertEquals(data[i], buffer.byteAt(i));
    }
  }

  @Test
  @DisplayName("byteAt_whenIndexOutOfBounds_expectArrayIndexOutOfBoundsException")
  void byteAt_whenIndexOutOfBounds_expectArrayIndexOutOfBoundsException() {
    Buffer b = new Buffer(new byte[] {10, 20, 30});
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> ignoreByte(b.byteAt(3))); // == length
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> ignoreByte(b.byteAt(-1)));
  }

  @Test
  void toString_whenLengthGreaterThan50_expectSummaryForm() {
    Buffer buffer = new Buffer(DATA_STRING_1.getBytes(StandardCharsets.UTF_8));
    String longString = buffer.toString();
    assertEquals("Buffer {" + buffer.getLength() + "}", longString);
  }

  @Test
  @DisplayName("toString_whenShort_expectByteValuesWithLengthPrefix")
  void toString_whenShort_expectByteValuesWithLengthPrefix() {
    byte[] bytes = new byte[] {1, 2, 3};
    Buffer buffer = new Buffer(bytes);
    assertEquals("{3:1 2 3 ", buffer.toString());
  }

  @Test
  @SuppressWarnings("EqualsWithItself")
  void equals_whenSameContentAndLayout_expectEquality() {
    Buffer b1 = new Buffer("Buffer1".getBytes(StandardCharsets.UTF_8));
    Buffer b2 = new Buffer("Buffer2".getBytes(StandardCharsets.UTF_8));
    Buffer b3 = new Buffer("Buffer1".getBytes(StandardCharsets.UTF_8));

    assertNotEquals(b1, b2);
    assertEquals(b1, b3);
    assertNotEquals(b2, b3);
    assertEquals(b1, b1);
    assertEquals(b2, b2);
    assertEquals(b3, b1);
  }

  @Test
  @DisplayName("equals_whenSameWindowBytesButDifferentStart_expectNotEqual")
  void equals_whenSameWindowBytesButDifferentStart_expectNotEqual() {
    byte[] base = new byte[] {0, 1, 2, 3};
    Buffer a = new Buffer(base, 1, 2); // [1,2]
    Buffer b = new Buffer(new byte[] {1, 2}); // start=0, len=2
    assertNotEquals(a, b); // start differs
  }

  @Test
  @DisplayName("equals_whenSameWindowBytesButDifferentBackingArrays_expectNotEqual")
  void equals_whenSameWindowBytesButDifferentBackingArrays_expectNotEqual() {
    byte[] arr1 = new byte[] {9, 1, 2, 9};
    byte[] arr2 = new byte[] {8, 1, 2, 8}; // different outside window
    Buffer a = new Buffer(arr1, 1, 2); // window [1,2]
    Buffer b = new Buffer(arr2, 1, 2); // window [1,2], identical start/len

    // Per implementation, equality requires full array equality, not just the window
    assertNotEquals(a, b);
  }

  @Test
  void hashCode_whenPutInMap_expectKeyCollisionForEqualBuffers() {
    Buffer b1 = new Buffer("Buffer1".getBytes(StandardCharsets.UTF_8));
    Buffer b2 = new Buffer("Buffer2".getBytes(StandardCharsets.UTF_8));
    Buffer b3 = new Buffer("Buffer1".getBytes(StandardCharsets.UTF_8));

    Map<Buffer, Buffer> hashMap = new HashMap<>();
    hashMap.put(b1, b1);
    hashMap.put(b2, b2);
    hashMap.put(b3, b3); // should clobber b1 due to equality with b1

    Object o = hashMap.get(b3);
    assertNotSame(o, b1);
    assertSame(o, b3);

    o = hashMap.get(b1);
    assertNotSame(o, b1);
    assertSame(o, b3);
  }

  @Test
  void copyTo_whenPositionZero_expectExactCopy() {
    byte[] oldBuf = DATA_STRING_1.getBytes(StandardCharsets.UTF_8);
    Buffer b = new Buffer(oldBuf);

    byte[] newBuf = new byte[b.getLength()];
    b.copyTo(newBuf, 0);

    assertArrayEquals(oldBuf, newBuf);
  }

  @Test
  @DisplayName("copyTo_whenWithOffset_expectCopiedAtGivenPosition")
  void copyTo_whenWithOffset_expectCopiedAtGivenPosition() {
    byte[] src = new byte[] {10, 20, 30};
    Buffer b = new Buffer(src);
    byte[] dest = new byte[5];
    b.copyTo(dest, 2);

    assertArrayEquals(new byte[] {0, 0, 10, 20, 30}, dest);
  }

  @Test
  @DisplayName("copyTo_whenDestTooSmall_expectArrayIndexOutOfBoundsException")
  void copyTo_whenDestTooSmall_expectArrayIndexOutOfBoundsException() {
    Buffer b = new Buffer(new byte[] {1, 2, 3});
    byte[] dest = new byte[4];
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> b.copyTo(dest, 2));
  }

  @Test
  @DisplayName("writeToDataOutputStream_whenSubrange_expectLengthAndPayloadWritten")
  void writeToDataOutputStream_whenSubrange_expectLengthAndPayloadWritten() throws IOException {
    byte[] src = new byte[] {9, 10, 11, 12, 13};
    Buffer b = new Buffer(src, 1, 3); // [10,11,12]
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    b.writeToDataOutputStream(dos);
    dos.flush();

    byte[] written = baos.toByteArray();
    // Verify length prefix and payload
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(written))) {
      assertEquals(3, dis.readInt());
      byte[] payload = new byte[3];
      dis.readFully(payload);
      assertArrayEquals(new byte[] {10, 11, 12}, payload);
    }
  }
}
