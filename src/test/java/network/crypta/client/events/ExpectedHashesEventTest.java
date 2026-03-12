package network.crypta.client.events;

import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings("java:S100")
class ExpectedHashesEventTest {

  @Test
  void constructor_whenNullArray_expectNullReferenceStored() {
    // Arrange
    HashResult[] input = null;

    // Act
    //noinspection ConstantValue
    ExpectedHashesEvent event = new ExpectedHashesEvent(input);

    // Assert
    assertNull(event.hashes, "Expected null to be stored when input is null");
  }

  @Test
  void constructor_whenEmptyArray_expectSameReferenceStored() {
    // Arrange
    HashResult[] input = new HashResult[0];

    // Act
    ExpectedHashesEvent event = new ExpectedHashesEvent(input);

    // Assert
    assertSame(input, event.hashes, "Constructor should not defensively copy the array");
    assertEquals(0, event.hashes.length, "Empty input array should remain empty");
  }

  @Test
  void constructor_whenArrayProvided_expectSameReferenceAndElementsPreserved() {
    // Arrange
    byte[] sha1 = new byte[HashType.SHA1.hashLength];
    for (int i = 0; i < sha1.length; i++) sha1[i] = (byte) i;
    byte[] md5 = new byte[HashType.MD5.hashLength];
    for (int i = 0; i < md5.length; i++) md5[i] = (byte) (i + 1);

    HashResult h1 = new HashResult(HashType.SHA1, sha1);
    HashResult h2 = new HashResult(HashType.MD5, md5);
    HashResult[] input = new HashResult[] {h1, h2};

    // Act
    ExpectedHashesEvent event = new ExpectedHashesEvent(input);

    // Assert
    assertSame(input, event.hashes, "Array reference should be stored as-is");
    assertArrayEquals(input, event.hashes, "Element order and values should be preserved");
  }

  @Test
  void api_whenQueried_expectStableCodeAndDescription() {
    // Arrange
    ExpectedHashesEvent event = new ExpectedHashesEvent(new HashResult[0]);

    // Act & Assert
    assertInstanceOf(ClientEvent.class, event, "Event must implement ClientEvent");
    assertEquals(ExpectedHashesEvent.CODE, event.getCode(), "getCode should return CODE constant");
    assertEquals(0x0E, event.getCode(), "CODE must be the expected numeric value");
    assertNotNull(event.getDescription(), "Description must be non-null");
    assertEquals("Expected hashes", event.getDescription(), "Description text must match");
  }
}
