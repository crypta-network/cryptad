package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S3011"})
class ClientPutDirPersistentTagBuilderTest {

  @Test
  void persistentTagMessage_whenAllFieldsPresent_preservesPersistentPutDirLayout()
      throws Exception {
    ClientPutDir request = new ClientPutDir();
    ClientPutDirExecution putter = mock(ClientPutDirExecution.class);
    RequestClient requestClient = mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(true);
    when(putter.getSplitfileCryptoKey()).thenReturn(new byte[] {0x01, 0x02, 0x0A, (byte) 0xFF});
    when(putter.persistentPutDirEntries())
        .thenReturn(
            List.of(
                new PersistentPutDirEntrySnapshot(
                    "disk.dat",
                    ClientPutBase.UploadFrom.DISK,
                    4,
                    "/tmp/disk.dat",
                    "text/plain",
                    null)));

    setField(request, "publicURI", new FreenetURI("KSK", "public"));
    setField(request, "uri", new FreenetURI("KSK", "private"));
    setField(request, "identifier", "id-123");
    setField(request, "verbosity", 2);
    setField(request, "priorityClass", (short) 5);
    setField(request, "persistence", ClientRequest.Persistence.FOREVER);
    setField(request, "clientToken", "token-abc");
    setField(request, "global", true);
    setField(request, "started", true);
    setField(request, "ctx", newContext(3, true, "lzma", FcpCompatibilityMode.COMPAT_1468));
    setField(request, "defaultName", "index.html");
    setField(request, "wasDiskPut", true);
    setField(request, "lowLevelClient", requestClient);
    setField(request, "putter", putter);

    ClientPutDirPersistentTagBuilder builder = new ClientPutDirPersistentTagBuilder(request);

    FCPMessage message = builder.persistentTagMessage();

    SimpleFieldSet fs = message.getFieldSet();
    assertEquals("id-123", fs.get("Identifier"));
    assertEquals("KSK@public", fs.get("URI"));
    assertEquals("KSK@private", fs.get("PrivateURI"));
    assertEquals("2", fs.get("Verbosity"));
    assertEquals("5", fs.get("PriorityClass"));
    assertEquals("forever", fs.get("Persistence"));
    assertEquals("true", fs.get("Global"));
    assertEquals("disk", fs.get("PutDirType"));
    assertEquals("index.html", fs.get("DefaultName"));
    assertEquals("token-abc", fs.get("ClientToken"));
    assertEquals("true", fs.get("Started"));
    assertEquals("3", fs.get("MaxRetries"));
    assertEquals("true", fs.get("DontCompress"));
    assertEquals("lzma", fs.get("Codecs"));
    assertEquals("true", fs.get("RealTime"));
    assertEquals("01020aff", fs.get("SplitfileCryptoKey"));
    SimpleFieldSet files = message.getFieldSet().subset("Files");
    assertNotNull(files);
    assertEquals("1", files.get("Count"));
    SimpleFieldSet file = files.subset("0");
    assertNotNull(file);
    assertEquals("disk.dat", file.get("Name"));
    assertEquals("disk", file.get("UploadFrom"));
    assertEquals("/tmp/disk.dat", file.get("Filename"));
  }

  @Test
  void persistentTagMessage_whenPutterAndRuntimeFlagAbsent_usesEmptyFilesAndRealtimeFalse()
      throws Exception {
    ClientPutDir request = new ClientPutDir();
    setField(request, "publicURI", new FreenetURI("KSK", "public"));
    setField(request, "uri", new FreenetURI("KSK", "private"));
    setField(request, "identifier", "id-optional");
    setField(request, "verbosity", 0);
    setField(request, "priorityClass", (short) 1);
    setField(request, "persistence", ClientRequest.Persistence.REBOOT);
    setField(request, "global", false);
    setField(request, "started", false);
    setField(request, "ctx", newContext(0, false, null, FcpCompatibilityMode.COMPAT_UNKNOWN));
    setField(request, "defaultName", "default");
    setField(request, "wasDiskPut", false);
    setField(request, "lowLevelClient", null);
    setField(request, "putter", null);

    ClientPutDirPersistentTagBuilder builder = new ClientPutDirPersistentTagBuilder(request);

    FCPMessage message = builder.persistentTagMessage();

    SimpleFieldSet fs = message.getFieldSet();
    assertEquals("false", fs.get("RealTime"));
    assertNull(fs.get("SplitfileCryptoKey"));
    SimpleFieldSet files = message.getFieldSet().subset("Files");
    assertNotNull(files);
    assertEquals("0", files.get("Count"));
  }

  @Test
  void persistentTagMessage_whenPutterMissingButManifestRestored_preservesSerializedFiles()
      throws Exception {
    Path file = Files.createTempFile("persistent-put-dir", ".txt");
    Files.writeString(file, "data");

    ClientPutDir request = new ClientPutDir();
    Map<String, Object> manifestElements = new HashMap<>();
    manifestElements.put(
        "disk.dat",
        new ManifestElement(
            "disk.dat",
            "disk.dat",
            new FileBucket(file.toFile(), true, false, false, false),
            "text/plain",
            4));
    setField(request, "manifestElements", manifestElements);
    setField(request, "publicURI", new FreenetURI("KSK", "public"));
    setField(request, "uri", new FreenetURI("KSK", "private"));
    setField(request, "identifier", "id-restored");
    setField(request, "verbosity", 0);
    setField(request, "priorityClass", (short) 1);
    setField(request, "persistence", ClientRequest.Persistence.REBOOT);
    setField(request, "global", false);
    setField(request, "started", false);
    setField(request, "ctx", newContext(0, false, null, FcpCompatibilityMode.COMPAT_CURRENT));
    setField(request, "defaultName", "default");
    setField(request, "wasDiskPut", true);
    setField(request, "lowLevelClient", null);
    setField(request, "putter", null);

    ClientPutDirPersistentTagBuilder builder = new ClientPutDirPersistentTagBuilder(request);

    FCPMessage message = builder.persistentTagMessage();

    SimpleFieldSet files = message.getFieldSet().subset("Files");
    assertNotNull(files);
    assertEquals("1", files.get("Count"));
    SimpleFieldSet restored = files.subset("0");
    assertNotNull(restored);
    assertEquals("disk.dat", restored.get("Name"));
    assertEquals("disk", restored.get("UploadFrom"));
    assertEquals(file.toString(), restored.get("Filename"));
  }

  private static DefaultFcpInsertContextHandle newContext(
      int maxRetries,
      boolean dontCompress,
      String compressorDescriptor,
      FcpCompatibilityMode compatibilityMode) {
    return new DefaultFcpInsertContextHandle(
        new FcpInsertContextLimits(0, 0, 0),
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(
                false, dontCompress, false, maxRetries, null, false, false, false),
            new FcpInsertTuningOptions(false, false, compressorDescriptor, 0, 0, compatibilityMode),
            null));
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = findField(target.getClass(), fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Field findField(Class<?> type, String fieldName) throws NoSuchFieldException {
    Class<?> current = type;
    while (current != null) {
      try {
        return current.getDeclaredField(fieldName);
      } catch (NoSuchFieldException _) {
        current = current.getSuperclass();
      }
    }
    throw new NoSuchFieldException(fieldName);
  }
}
