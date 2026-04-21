package network.crypta.clients.fcp;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import network.crypta.client.ClientMetadata;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S3011"})
@ExtendWith(MockitoExtension.class)
class ClientPutPersistentTagBuilderTest {

  @TempDir Path tempDir;

  @Test
  void persistentTagMessage_whenAllFieldsPresent_preservesLegacyPersistentPutLayout()
      throws Exception {
    FreenetURI publicUri = new FreenetURI("KSK", "public");
    FreenetURI privateUri = new FreenetURI("KSK", "private");
    FreenetURI targetUri = new FreenetURI("KSK", "target");
    File originalFile = tempDir.resolve("upload.bin").toFile();
    byte[] cryptoKey = new byte[] {0x01, 0x02, 0x0A, (byte) 0xFF};
    RandomAccessBucket data = mock(RandomAccessBucket.class);
    when(data.size()).thenReturn(1024L);
    RequestClient requestClient = requestClient(true);
    ClientPutExecution putter = mock(ClientPutExecution.class);
    when(putter.getSplitfileCryptoKey()).thenReturn(cryptoKey);

    ClientPut request = new ClientPut();
    setField(request, "publicURI", publicUri);
    setField(request, "uri", privateUri);
    setField(request, "identifier", "id-123");
    setField(request, "verbosity", 2);
    setField(request, "priorityClass", (short) 5);
    setField(request, "persistence", Persistence.FOREVER);
    setField(request, "clientToken", "token-abc");
    setField(request, "started", true);
    setField(request, "client", new PersistentRequestRoot().getGlobalForeverClient());
    setField(request, "lowLevelClient", requestClient);
    setField(request, "ctx", newContext(3, true, "lzma", FcpCompatibilityMode.COMPAT_1468));
    setField(request, "clientMetadata", new ClientMetadata("text/plain"));
    setField(request, "uploadFrom", UploadFrom.DISK);
    setField(request, "origFilename", originalFile);
    setField(request, "targetURI", targetUri);
    setField(request, "targetFilename", "target.dat");
    setField(request, "binaryBlob", true);
    setField(request, "data", data);
    setField(request, "putter", putter);

    ClientPutPersistentTagBuilder builder = new ClientPutPersistentTagBuilder(request);

    FCPMessage message = builder.persistentTagMessage();

    SimpleFieldSet fs = message.getFieldSet();
    assertEquals("id-123", fs.get("Identifier"));
    assertEquals(publicUri.toString(false, false), fs.get("URI"));
    assertEquals(privateUri.toString(false, false), fs.get("PrivateURI"));
    assertEquals("2", fs.get("Verbosity"));
    assertEquals("5", fs.get("PriorityClass"));
    assertEquals("disk", fs.get("UploadFrom"));
    assertEquals("forever", fs.get("Persistence"));
    assertEquals(originalFile.getAbsolutePath(), fs.get("Filename"));
    assertEquals(targetUri.toString(), fs.get("TargetURI"));
    assertEquals("text/plain", fs.get("Metadata.ContentType"));
    assertEquals("true", fs.get("Global"));
    assertEquals("1024", fs.get("DataLength"));
    assertEquals("token-abc", fs.get("ClientToken"));
    assertEquals("true", fs.get("Started"));
    assertEquals("3", fs.get("MaxRetries"));
    assertEquals("target.dat", fs.get("TargetFilename"));
    assertEquals("true", fs.get("BinaryBlob"));
    assertEquals("COMPAT_1468", fs.get("CompatibilityMode"));
    assertEquals("true", fs.get("DontCompress"));
    assertEquals("lzma", fs.get("Codecs"));
    assertEquals("true", fs.get("RealTime"));
    assertEquals("01020aff", fs.get("SplitfileCryptoKey"));
  }

  @Test
  void persistentTagMessage_whenOptionalFieldsAbsent_omitsNullableEntriesAndKeepsDefaultMime()
      throws Exception {
    ClientPut request = new ClientPut();
    setField(request, "publicURI", new FreenetURI("KSK", "public"));
    setField(request, "uri", new FreenetURI("KSK", "private"));
    setField(request, "identifier", "id-optional");
    setField(request, "verbosity", 0);
    setField(request, "priorityClass", (short) 0);
    setField(request, "persistence", Persistence.REBOOT);
    setField(request, "clientToken", null);
    setField(request, "started", false);
    setField(
        request,
        "client",
        new PersistentRequestClient("client", null, false, null, Persistence.REBOOT, null));
    setField(request, "lowLevelClient", requestClient(false));
    setField(request, "ctx", newContext(0, false, null, FcpCompatibilityMode.COMPAT_UNKNOWN));
    setField(request, "clientMetadata", new ClientMetadata(null));
    setField(request, "uploadFrom", UploadFrom.REDIRECT);
    setField(request, "origFilename", null);
    setField(request, "targetURI", null);
    setField(request, "targetFilename", null);
    setField(request, "binaryBlob", false);
    setField(request, "finishedSize", -1L);
    setField(request, "putter", null);

    ClientPutPersistentTagBuilder builder = new ClientPutPersistentTagBuilder(request);

    FCPMessage message = builder.persistentTagMessage();

    SimpleFieldSet fs = message.getFieldSet();
    assertEquals("id-optional", fs.get("Identifier"));
    assertEquals("redirect", fs.get("UploadFrom"));
    assertEquals("reboot", fs.get("Persistence"));
    assertEquals("false", fs.get("Global"));
    assertEquals("false", fs.get("Started"));
    assertEquals("0", fs.get("MaxRetries"));
    assertEquals("COMPAT_UNKNOWN", fs.get("CompatibilityMode"));
    assertEquals("false", fs.get("DontCompress"));
    assertEquals("false", fs.get("RealTime"));
    assertNull(fs.get("Filename"));
    assertNull(fs.get("TargetURI"));
    assertEquals("application/octet-stream", fs.get("Metadata.ContentType"));
    assertNull(fs.get("DataLength"));
    assertNull(fs.get("ClientToken"));
    assertNull(fs.get("TargetFilename"));
    assertNull(fs.get("BinaryBlob"));
    assertNull(fs.get("Codecs"));
    assertNull(fs.get("SplitfileCryptoKey"));
    assertFalse(fs.getBoolean("BinaryBlob", false));
    assertInstanceOf(PersistentPut.class, message);
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

  private static RequestClient requestClient(boolean realTime) {
    RequestClient requestClient = mock(RequestClient.class);
    when(requestClient.realTimeFlag()).thenReturn(realTime);
    return requestClient;
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
