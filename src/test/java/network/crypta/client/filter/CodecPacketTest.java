package network.crypta.client.filter;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings({"java:S100", "java:S1764", "java:S2159"})
class CodecPacketTest {

  @Test
  void toArray_whenPayloadProvided_returnsSameReference() {
    // Arrange
    byte[] payload = new byte[] {1, 2, 3};
    CodecPacket packet = new CodecPacket(payload);

    // Act
    byte[] result = packet.toArray();

    // Assert
    assertSame(payload, result, "toArray() should return the same array reference");
    assertArrayEquals(new byte[] {1, 2, 3}, result);
  }

  @Test
  void toArray_whenPayloadIsNull_returnsNull() {
    // Arrange
    CodecPacket packet = new CodecPacket(null);

    // Act
    byte[] result = packet.toArray();

    // Assert
    assertNull(result, "toArray() should return null when payload is null");
  }

  @Test
  void equals_whenSameInstance_returnsTrue() {
    // Arrange
    CodecPacket packet = new CodecPacket(new byte[] {10});

    // Act & Assert
    //noinspection EqualsWithItself
    assertEquals(packet, packet);
  }

  @Test
  void equals_whenOtherIsNull_returnsFalse() {
    // Arrange
    CodecPacket packet = new CodecPacket(new byte[] {1});

    // Act & Assert
    assertNotEquals(null, packet);
  }

  @Test
  void equals_whenDifferentType_returnsFalse() {
    // Arrange
    CodecPacket packet = new CodecPacket(new byte[] {1, 2});

    // Act & Assert
    assertNotEquals(new Object(), packet);
  }

  @Test
  void equals_and_hashCode_whenSameContentDifferentArrays_areEqualAndHashMatch() {
    // Arrange
    byte[] a1 = new byte[] {5, 6, 7};
    byte[] a2 = new byte[] {5, 6, 7}; // distinct instance, same content
    CodecPacket p1 = new CodecPacket(a1);
    CodecPacket p2 = new CodecPacket(a2);

    // Sanity check the arrays are different references
    assertNotSame(a1, a2);

    // Act & Assert
    assertEquals(p1, p2, "Packets with same content should be equal");
    assertEquals(p1.hashCode(), p2.hashCode(), "Equal packets must have same hashCode");
  }

  @Test
  void equals_whenBothPayloadsNull_returnsTrue() {
    // Arrange
    CodecPacket p1 = new CodecPacket(null);
    CodecPacket p2 = new CodecPacket(null);

    // Act & Assert
    assertEquals(p1, p2);
    assertEquals(p1.hashCode(), p2.hashCode());
  }

  @Test
  void equals_whenOnePayloadNull_returnsFalse() {
    // Arrange
    CodecPacket p1 = new CodecPacket(null);
    CodecPacket p2 = new CodecPacket(new byte[] {});

    // Act & Assert
    assertNotEquals(p1, p2);
    assertNotEquals(p2, p1);
  }

  @Test
  void equals_whenDifferentContent_returnsFalse() {
    // Arrange
    CodecPacket p1 = new CodecPacket(new byte[] {1, 2, 3});
    CodecPacket p2 = new CodecPacket(new byte[] {1, 2, 4});

    // Act & Assert
    assertNotEquals(p1, p2);
  }

  @Test
  void equals_whenEmptyArrays_areEqual() {
    // Arrange
    CodecPacket p1 = new CodecPacket(new byte[] {});
    CodecPacket p2 = new CodecPacket(new byte[] {});

    // Act & Assert
    assertEquals(p1, p2);
    assertEquals(p1.hashCode(), p2.hashCode());
  }
}
