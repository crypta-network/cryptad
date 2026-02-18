package network.crypta.clients.fcp;

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
class RequestIdentifierTest {

  private static final short GET_CODE = 0;

  @Test
  void writeTo_andConstructor_whenNonGlobalQueue_roundTripsFields() throws Exception {
    RequestIdentifier original =
        new RequestIdentifier(false, "clientA", "identifier-1", RequestIdentifier.RequestType.PUT);

    RequestIdentifier restored = roundTrip(original);

    assertEquals(original, restored);
    assertFalse(restored.globalQueue);
    assertEquals("clientA", restored.clientName);
    assertEquals("identifier-1", restored.identifier);
    assertEquals(RequestIdentifier.RequestType.PUT, restored.type);
  }

  @Test
  void writeTo_andConstructor_whenGlobalQueue_roundTripsFields() throws Exception {
    RequestIdentifier original =
        new RequestIdentifier(true, null, "global-id", RequestIdentifier.RequestType.GET);

    RequestIdentifier restored = roundTrip(original);

    assertEquals(original, restored);
    assertTrue(restored.globalQueue);
    assertNull(restored.clientName);
    assertEquals("global-id", restored.identifier);
    assertEquals(RequestIdentifier.RequestType.GET, restored.type);
  }

  @Test
  void sameIdentifier_whenTypeDiffers_stillMatches() {
    RequestIdentifier first =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.GET);
    RequestIdentifier second =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.PUT);

    assertTrue(first.sameIdentifier(second));
    assertNotEquals(first, second);
  }

  @Test
  void hashCode_whenTypeDiffers_ignoresTypeInComputation() {
    RequestIdentifier first =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.GET);
    RequestIdentifier second =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.PUT);

    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void equals_whenTypeDiffers_returnsFalse() {
    RequestIdentifier first =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.GET);
    RequestIdentifier second =
        new RequestIdentifier(false, "clientA", "shared-id", RequestIdentifier.RequestType.PUT);

    assertNotEquals(first, second);
  }

  @Test
  void constructor_whenMagicInvalid_throwsIOException() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(RequestIdentifier.MAGIC + 1);
      dos.writeShort(RequestIdentifier.VERSION);
      dos.writeBoolean(false);
      dos.writeUTF("clientA");
      dos.writeUTF("identifier-1");
      dos.writeShort(GET_CODE);
    }

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      assertThrows(IOException.class, () -> new RequestIdentifier(dis));
    }
  }

  @Test
  void constructor_whenVersionInvalid_throwsIOException() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(RequestIdentifier.MAGIC);
      dos.writeShort(RequestIdentifier.VERSION + 1);
      dos.writeBoolean(false);
      dos.writeUTF("clientA");
      dos.writeUTF("identifier-1");
      dos.writeShort(GET_CODE);
    }

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      assertThrows(IOException.class, () -> new RequestIdentifier(dis));
    }
  }

  @Test
  void constructor_whenTypeInvalid_throwsIOException() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(RequestIdentifier.MAGIC);
      dos.writeShort(RequestIdentifier.VERSION);
      dos.writeBoolean(false);
      dos.writeUTF("clientA");
      dos.writeUTF("identifier-1");
      dos.writeShort(Short.MAX_VALUE);
    }

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      assertThrows(IOException.class, () -> new RequestIdentifier(dis));
    }
  }

  private RequestIdentifier roundTrip(RequestIdentifier original) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      original.writeTo(dos);
    }
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      return new RequestIdentifier(dis);
    }
  }
}
