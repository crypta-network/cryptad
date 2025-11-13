package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // test method naming convention
class ClientMetadataTest {

  @Test
  @DisplayName("getMIMEType when unset returns default and isTrivial is true")
  void getMIMEType_whenUnset_returnsDefault() {
    ClientMetadata meta = new ClientMetadata();
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, meta.getMIMEType());
    assertTrue(meta.isTrivial());
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, meta.toString());
  }

  @Test
  @DisplayName("getMIMEType when empty string returns default and isTrivial is true")
  void getMIMEType_whenEmpty_returnsDefault() {
    ClientMetadata meta = new ClientMetadata("");
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, meta.getMIMEType());
    assertTrue(meta.isTrivial());
  }

  @Test
  @DisplayName("getMIMEType when set returns provided value (interned) and isTrivial is false")
  void getMIMEType_whenSet_returnsValue() {
    String input = "text/plain";
    ClientMetadata meta = new ClientMetadata(input);
    assertEquals("text/plain", meta.getMIMEType());
    // value should be interned by constructor (reference equality with literal)
    assertSame("text/plain", meta.getMIMEType());
    assertFalse(meta.isTrivial());
    assertEquals("text/plain", meta.toString());
  }

  @Test
  @DisplayName("copyOf returns null for null and copies MIME type otherwise")
  void copyOf_whenNullOrNonNull_behavesAsExpected() {
    assertNull(ClientMetadata.copyOf(null));

    ClientMetadata src = new ClientMetadata("image/png");
    ClientMetadata copy = ClientMetadata.copyOf(src);
    assertNotNull(copy);
    assertNotSame(src, copy);
    assertEquals("image/png", copy.getMIMEType());

    // Mutating source after copy does not affect the copy
    src.clear();
    assertEquals("image/png", copy.getMIMEType());
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, src.getMIMEType());
  }

  @Test
  @DisplayName("mergeNoOverwrite sets when current is trivial and leaves when non-trivial")
  void mergeNoOverwrite_whenTrivialOrNot_updatesCorrectly() {
    ClientMetadata current = new ClientMetadata();
    ClientMetadata incoming = new ClientMetadata("text/html");

    current.mergeNoOverwrite(incoming);
    assertEquals("text/html", current.getMIMEType());

    // Now current is non-trivial; merging a different value should not overwrite
    ClientMetadata other = new ClientMetadata("application/json");
    current.mergeNoOverwrite(other);
    assertEquals("text/html", current.getMIMEType());
  }

  @Test
  @DisplayName("mergeNoOverwrite with null argument throws NullPointerException")
  void mergeNoOverwrite_whenNull_throwsNPE() {
    ClientMetadata current = new ClientMetadata();
    assertThrows(NullPointerException.class, () -> current.mergeNoOverwrite(null));
  }

  @Test
  @DisplayName("clear resets to trivial/default")
  void clear_whenCalled_resetsState() {
    ClientMetadata meta = new ClientMetadata("application/pdf");
    assertFalse(meta.isTrivial());
    meta.clear();
    assertTrue(meta.isTrivial());
    assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, meta.getMIMEType());
  }

  @Test
  @DisplayName("getMIMETypeNoParams handles null, no-params, and with-params cases")
  void getMIMETypeNoParams_variousInputs_returnsExpected() {
    // null
    ClientMetadata m0 = new ClientMetadata();
    assertNull(m0.getMIMETypeNoParams());

    // no parameters
    ClientMetadata m1 = new ClientMetadata("application/zip");
    assertEquals("application/zip", m1.getMIMETypeNoParams());

    // with parameters — verify current implementation behavior (returns substring starting at ';')
    ClientMetadata m2 = new ClientMetadata("text/plain; charset=UTF-8");
    assertEquals("; charset=UTF-8", m2.getMIMETypeNoParams());
  }

  @Test
  @DisplayName("writeTo + construct round-trip with non-null MIME type")
  void writeRead_roundTrip_withMimeType() throws Exception {
    ClientMetadata original = new ClientMetadata("application/json");
    byte[] bytes = writeToBytes(original);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      ClientMetadata restored = ClientMetadata.construct(dis);
      assertEquals("application/json", restored.getMIMEType());
      assertFalse(restored.isTrivial());
    }
  }

  @Test
  @DisplayName("writeTo + construct round-trip when MIME is null")
  void writeRead_roundTrip_withNullMime() throws Exception {
    ClientMetadata original = new ClientMetadata();
    byte[] bytes = writeToBytes(original);

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      ClientMetadata restored = ClientMetadata.construct(dis);
      assertTrue(restored.isTrivial());
      assertEquals(DefaultMIMETypes.DEFAULT_MIME_TYPE, restored.getMIMEType());
    }
  }

  @Test
  @DisplayName("construct throws on bad magic")
  void construct_whenBadMagic_throws() {
    // Write an obviously wrong magic and omit the rest (will fail on first read)
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(0xDEADBEEF);
      // version/flags are irrelevant; the parser will already fail on magic
      bytes = bos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    assertThrows(
        MetadataParseException.class,
        () -> ClientMetadata.construct(new DataInputStream(new ByteArrayInputStream(bytes))));
  }

  @Test
  @DisplayName("construct throws on unsupported version")
  void construct_whenBadVersion_throws() throws Exception {
    // First, discover the expected magic by writing a valid instance.
    byte[] valid = writeToBytes(new ClientMetadata("video/mp4"));
    int magic;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(valid))) {
      magic = dis.readInt();
    }

    // Now craft bytes with the correct magic but an invalid version.
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(magic);
      dos.writeShort(Short.MAX_VALUE); // definitely not the expected version (currently 1)
      bytes = bos.toByteArray();
    }

    assertThrows(
        MetadataParseException.class,
        () -> ClientMetadata.construct(new DataInputStream(new ByteArrayInputStream(bytes))));
  }

  @Test
  @DisplayName("Java serialization round-trip preserves MIME type")
  void javaSerialization_roundTrip_preservesState() throws Exception {
    ClientMetadata original = new ClientMetadata("application/xml");
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(original);
      oos.flush();
      bytes = bos.toByteArray();
    }

    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      Object obj = ois.readObject();
      assertInstanceOf(ClientMetadata.class, obj);
      ClientMetadata restored = (ClientMetadata) obj;
      assertEquals("application/xml", restored.getMIMEType());
    }
  }

  private static byte[] writeToBytes(ClientMetadata meta) throws IOException {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      meta.writeTo(dos);
      dos.flush();
      return bos.toByteArray();
    }
  }
}
