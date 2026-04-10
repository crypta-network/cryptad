package network.crypta.client.async.persistence;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PersistentRequestIdentifierTest {

  @Test
  void writeToAndConstructor_whenNonGlobalQueue_roundTripsFields() throws IOException {
    // Arrange
    PersistentRequestIdentifier original =
        new PersistentRequestIdentifier(
            false, "client-a", "request-1", PersistentRequestIdentifier.RequestType.PUT);

    // Act
    PersistentRequestIdentifier restored = roundTrip(original);

    // Assert
    assertEquals(original, restored);
    assertFalse(restored.isGlobalQueue());
    assertEquals("client-a", restored.clientName());
    assertEquals("request-1", restored.identifier());
    assertEquals(PersistentRequestIdentifier.RequestType.PUT, restored.type());
  }

  @Test
  void writeToAndConstructor_whenGlobalQueue_roundTripsFields() throws IOException {
    // Arrange
    PersistentRequestIdentifier original =
        new PersistentRequestIdentifier(
            true, null, "global-request", PersistentRequestIdentifier.RequestType.GET);

    // Act
    PersistentRequestIdentifier restored = roundTrip(original);

    // Assert
    assertEquals(original, restored);
    assertTrue(restored.isGlobalQueue());
    assertNull(restored.clientName());
    assertEquals("global-request", restored.identifier());
    assertEquals(PersistentRequestIdentifier.RequestType.GET, restored.type());
  }

  @Test
  void sameIdentifier_whenTypeDiffers_expectTrueAndEqualsFalse() {
    // Arrange
    PersistentRequestIdentifier first =
        new PersistentRequestIdentifier(
            false, "client-a", "shared-id", PersistentRequestIdentifier.RequestType.GET);
    PersistentRequestIdentifier second =
        new PersistentRequestIdentifier(
            false, "client-a", "shared-id", PersistentRequestIdentifier.RequestType.PUTDIR);

    // Act
    boolean sameIdentifier = first.sameIdentifier(second);

    // Assert
    assertTrue(sameIdentifier);
    assertNotEquals(first, second);
  }

  @Test
  void sameIdentifier_whenClientDiffers_expectFalse() {
    // Arrange
    PersistentRequestIdentifier first =
        new PersistentRequestIdentifier(
            false, "client-a", "shared-id", PersistentRequestIdentifier.RequestType.GET);
    PersistentRequestIdentifier second =
        new PersistentRequestIdentifier(
            false, "client-b", "shared-id", PersistentRequestIdentifier.RequestType.GET);

    // Act
    boolean sameIdentifier = first.sameIdentifier(second);

    // Assert
    assertFalse(sameIdentifier);
  }

  @Test
  void constructor_whenMagicInvalid_throwsIOException() throws IOException {
    // Arrange
    byte[] payload =
        rawBytes(
            PersistentRequestIdentifier.MAGIC + 1, PersistentRequestIdentifier.VERSION, (short) 0);

    // Act & Assert
    assertThrows(IOException.class, () -> readIdentifier(payload));
  }

  @Test
  void constructor_whenVersionInvalid_throwsIOException() throws IOException {
    // Arrange
    byte[] payload =
        rawBytes(
            PersistentRequestIdentifier.MAGIC,
            (short) (PersistentRequestIdentifier.VERSION + 1),
            (short) 0);

    // Act & Assert
    assertThrows(IOException.class, () -> readIdentifier(payload));
  }

  @Test
  void constructor_whenTypeInvalid_throwsIOException() throws IOException {
    // Arrange
    byte[] payload =
        rawBytes(
            PersistentRequestIdentifier.MAGIC,
            PersistentRequestIdentifier.VERSION,
            Short.MAX_VALUE);

    // Act & Assert
    assertThrows(IOException.class, () -> readIdentifier(payload));
  }

  private static PersistentRequestIdentifier roundTrip(PersistentRequestIdentifier identifier)
      throws IOException {
    byte[] payload = writeBytes(identifier);
    return readIdentifier(payload);
  }

  private static byte[] writeBytes(PersistentRequestIdentifier identifier) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      identifier.writeTo(dos);
    }
    return baos.toByteArray();
  }

  private static PersistentRequestIdentifier readIdentifier(byte[] payload) throws IOException {
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload))) {
      return new PersistentRequestIdentifier(dis);
    }
  }

  private static byte[] rawBytes(int magic, short version, short typeCode) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(magic);
      dos.writeShort(version);
      dos.writeBoolean(false);
      dos.writeUTF("client-a");
      dos.writeUTF("request-1");
      dos.writeShort(typeCode);
    }
    return baos.toByteArray();
  }
}
