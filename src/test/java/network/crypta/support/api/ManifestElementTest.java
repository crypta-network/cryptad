package network.crypta.support.api;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.RAFBucket;
import network.crypta.support.io.ResumeFailedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method names follow given_when_then format
class ManifestElementTest {

  private static final String REDIR_NAME = "redir";

  @Mock private RandomAccessBucket rab;
  @Mock private ClientContext clientContext;

  @Test
  @DisplayName("file ctor (simple): fields set; MIME guessed when no override")
  void constructor_fileSimple_whenNoOverride_mimeGuessed() {
    // Arrange
    String name = "note.txt"; // 'txt' -> text/plain in DefaultMIMETypes
    long size = 123L;

    // Act
    ManifestElement me = new ManifestElement(name, rab, null, size);

    // Assert
    assertEquals(name, me.getName());
    assertEquals(name, me.fullName);
    assertSame(rab, me.getData());
    assertEquals(size, me.getSize());
    assertNull(me.getTargetURI());
    assertEquals("text/plain", me.getMimeType());
  }

  @Test
  @DisplayName("file ctor (full name): uses provided fullName and MIME override")
  void constructor_fileWithFullName_whenOverrideProvided_mimeFromOverride() {
    // Arrange
    String name =
        "image.bin"; // extension intentionally mismatched to verify override takes precedence
    String fullName = "assets/picture";
    String override = "image/png";
    long size = 42L;

    // Act
    ManifestElement me = new ManifestElement(name, fullName, rab, override, size);

    // Assert
    assertEquals(name, me.getName());
    assertEquals(fullName, me.fullName);
    assertEquals(override, me.getMimeTypeOverride());
    assertEquals(override, me.getMimeType());
    assertNull(me.getTargetURI());
    assertEquals(size, me.getSize());
  }

  @Test
  @DisplayName("redirect ctor (name only): target set; data null; size -1")
  void constructor_redirectNameOnly_setsTargetAndFlags() {
    // Arrange
    FreenetURI target = FreenetURI.EMPTY_CHK_URI;
    String override = "text/html";

    // Act
    ManifestElement me = new ManifestElement(REDIR_NAME, target, override);

    // Assert
    assertEquals(REDIR_NAME, me.getName());
    assertEquals(REDIR_NAME, me.fullName);
    assertSame(target, me.getTargetURI());
    assertNull(me.getData());
    assertEquals(-1L, me.getSize());
    assertEquals(override, me.getMimeType());
  }

  @Test
  @DisplayName("redirect ctor (with full name): respects provided fullName")
  void constructor_redirectWithFullName_setsFullName() {
    // Arrange
    FreenetURI target = new FreenetURI("KSK", "index.html");

    // Act
    ManifestElement me = new ManifestElement("n", "dir/index.html", "text/html", target);

    // Assert
    assertEquals("n", me.getName());
    assertEquals("dir/index.html", me.fullName);
    assertSame(target, me.getTargetURI());
    assertNull(me.getData());
    assertEquals(-1L, me.getSize());
  }

  @Test
  @DisplayName("equals/hashCode: compare by name only")
  void equalsHashCode_whenSameName_onlyNameMatters() {
    // Arrange
    ManifestElement a = new ManifestElement("same-name", rab, null, 10L);
    ManifestElement b = new ManifestElement("same-name", rab, "application/octet-stream", 999L);
    ManifestElement c = new ManifestElement("different", rab, null, 10L);

    // Act & Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(a, c);
  }

  @Test
  @DisplayName("freeData: calls free() only when data present")
  void freeData_whenDataPresent_invokesFree() {
    // Arrange
    ManifestElement file = new ManifestElement("a.bin", rab, null, 5L);
    ManifestElement redirect = new ManifestElement("r", FreenetURI.EMPTY_CHK_URI, null);

    // Act
    file.freeData();
    redirect.freeData();

    // Assert
    verify(rab).free();
  }

  @Test
  @DisplayName("onResume: delegates to RandomAccessBucket when data present; no-op otherwise")
  void onResume_whenDataPresent_delegatesToBucket() throws ResumeFailedException {
    // Arrange
    ManifestElement file = new ManifestElement("file", rab, null, 17L);
    ManifestElement redirect = new ManifestElement(REDIR_NAME, FreenetURI.EMPTY_CHK_URI, null);

    // Act
    file.onResume(clientContext);
    redirect.onResume(clientContext);

    // Assert
    verify(rab).onResume(clientContext);
  }

  @Test
  @DisplayName("getMimeType: returns null when no override and no extension")
  void getMimeType_whenNoOverrideAndNoExtension_returnsNull() {
    // Arrange
    ManifestElement me = new ManifestElement("README", rab, null, 1L);

    // Act & Assert
    assertNull(me.getMimeType());
  }

  @Test
  @DisplayName("getMimeType: returns null when extension unknown and no override")
  void getMimeType_whenUnknownExtension_returnsNull() {
    // Arrange
    String name = "artifact.abcxyz"; // an extension not present in DefaultMIMETypes
    // Defensive check: ensure our assumption really holds in this codebase
    assertEquals(-1, DefaultMIMETypes.byName("application/x-abcxyz"));

    ManifestElement me = new ManifestElement(name, rab, null, 2L);

    // Act & Assert
    assertNull(me.getMimeType());
  }

  @Test
  @DisplayName("copy ctors: change name, optionally fullName; preserve other fields")
  void copyConstructors_whenChangingNames_preserveOtherFields() {
    // Arrange
    ManifestElement original = new ManifestElement("old.txt", "dir/old.txt", rab, null, 11L);

    // Act
    ManifestElement renamed = new ManifestElement(original, "new.txt");
    ManifestElement renamedAndMoved = new ManifestElement(original, "new2.txt", "dir/new2.txt");

    // Assert
    assertEquals("new.txt", renamed.getName());
    assertEquals("dir/old.txt", renamed.fullName);
    assertSame(rab, renamed.getData());
    assertEquals(11L, renamed.getSize());
    assertNull(renamed.getTargetURI());

    assertEquals("new2.txt", renamedAndMoved.getName());
    assertEquals("dir/new2.txt", renamedAndMoved.fullName);
    assertSame(rab, renamedAndMoved.getData());
    assertEquals(11L, renamedAndMoved.getSize());
    assertNull(renamedAndMoved.getTargetURI());
  }

  @Test
  @DisplayName("Serializable bucket: round-trip preserves data reference and size")
  void serialization_whenBucketSerializable_roundTrips() throws Exception {
    // Arrange: a serializable RandomAccessBucket
    ArrayBucket bucket = new ArrayBucket("arr");
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(new byte[] {1, 2, 3});
    }
    ManifestElement original = new ManifestElement("f.bin", bucket, null, bucket.size());

    // Act: serialize then deserialize
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(original);
      oos.flush();
      bytes = bos.toByteArray();
    }
    ManifestElement restored;
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      restored = (ManifestElement) ois.readObject();
    }

    // Assert: data is present and size preserved
    assertNotNull(restored.getData());
    assertEquals(3L, restored.getSize());
  }

  @Test
  @DisplayName("Non-serializable bucket: writeObject throws NotSerializableException")
  void serialization_whenBucketNotSerializable_writeObjectThrows() throws Exception {
    // Arrange: RAFBucket is not java.io.Serializable
    RAFBucket nonSerializable = new RAFBucket(new ByteArrayRandomAccessBuffer(0));
    ManifestElement me = new ManifestElement("n.bin", nonSerializable, null, 0L);

    // Act & Assert
    try (ObjectOutputStream oos = new ObjectOutputStream(new ByteArrayOutputStream())) {
      assertThrows(NotSerializableException.class, () -> oos.writeObject(me));
    }
  }

  @Test
  @DisplayName(
      "Deserialization: speculative trailing read must not consume the next object in stream")
  void deserialization_whenTwoElementsInStream_doesNotConsumeNextObject() throws Exception {
    // Arrange: two serializable-bucket elements written back-to-back using current writer
    ArrayBucket b1 = new ArrayBucket("b1");
    try (OutputStream os = b1.getOutputStream()) {
      os.write(new byte[] {10, 20});
    }
    ManifestElement e1 = new ManifestElement("first.bin", b1, null, b1.size());

    ArrayBucket b2 = new ArrayBucket("b2");
    try (OutputStream os = b2.getOutputStream()) {
      os.write(new byte[] {30});
    }
    ManifestElement e2 = new ManifestElement("second.bin", b2, null, b2.size());

    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(e1);
      oos.writeObject(e2);
      oos.flush();
      bytes = bos.toByteArray();
    }

    // Act: read the first, then the second object
    ManifestElement r1;
    ManifestElement r2;
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      r1 = (ManifestElement) ois.readObject();
      r2 = (ManifestElement) ois.readObject();
    }

    // Assert: both objects are present and intact; stream was not advanced past r2
    assertEquals("first.bin", r1.getName());
    assertNotNull(r1.getData());
    assertEquals(2L, r1.getSize());

    assertEquals("second.bin", r2.getName());
    assertNotNull(r2.getData());
    assertEquals(1L, r2.getSize());
  }
}
