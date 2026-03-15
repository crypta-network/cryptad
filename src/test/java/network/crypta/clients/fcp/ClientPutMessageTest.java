package network.crypta.clients.fcp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientPutMessageTest {

  @TempDir Path tempDir;

  @Test
  void constructor_directWithoutDataLength_expectMissingField() {
    SimpleFieldSet fs = baseFieldSet("put-no-length");
    fs.putSingle("UploadFrom", "direct");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientPutMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("put-no-length", exception.ident);
  }

  @Test
  void constructor_diskSourceWithMissingFile_expectFileNotFound() {
    SimpleFieldSet fs = baseFieldSet("put-missing-file");
    fs.putSingle("UploadFrom", "disk");
    fs.putSingle("Filename", tempDir.resolve("missing.bin").toString());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientPutMessage(fs));

    assertEquals(ProtocolErrorMessage.FILE_NOT_FOUND, exception.protocolCode);
    assertEquals("put-missing-file", exception.ident);
  }

  @Test
  void constructor_redirectWithoutTarget_expectMissingField() {
    SimpleFieldSet fs = baseFieldSet("put-redirect");
    fs.putSingle("UploadFrom", "redirect");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientPutMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("put-redirect", exception.ident);
  }

  @Test
  void constructor_targetFilenameContainingSlash_expectInvalidField() {
    SimpleFieldSet fs = baseFieldSet("put-target-filename");
    fs.putSingle("UploadFrom", "direct");
    fs.put("DataLength", 5L);
    fs.putSingle("TargetFilename", "folder/illegal.txt");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientPutMessage(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("put-target-filename", exception.ident);
  }

  @Test
  void getFieldSet_directValuesRoundTrip_expectSerializedFields() throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet("put-fieldset");
    fs.putSingle("UploadFrom", "direct");
    fs.put("DataLength", 10L);
    fs.put("GetCHKOnly", true);
    fs.put("DontCompress", true);
    fs.putSingle("ClientToken", "token-123");
    fs.putSingle("TargetFilename", "output.bin");
    fs.putSingle("Codecs", "GZIP");
    fs.put("Global", true);

    ClientPutMessage message = new ClientPutMessage(fs);

    SimpleFieldSet serialized = message.getFieldSet();

    assertEquals("CHK@", serialized.get("URI"));
    assertEquals("put-fieldset", serialized.get("Identifier"));
    assertEquals("direct", serialized.get("UploadFrom"));
    assertEquals(10L, serialized.getLong("DataLength", -1));
    assertTrue(serialized.getBoolean("GetCHKOnly", false));
    assertEquals(
        RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
        serialized.getShort("PriorityClass", (short) -1));
    assertEquals("connection", serialized.get("Persistence"));
    assertTrue(serialized.getBoolean("DontCompress", false));
    assertEquals("GZIP", serialized.get("Codecs"));
    assertEquals("token-123", serialized.get("ClientToken"));
    assertTrue(serialized.getBoolean("Global", false));
    assertFalse(serialized.getBoolean("BinaryBlob", true));
  }

  @Test
  void run_whenInvoked_startsClientPutOnHandler() throws MessageInvalidException {
    ClientPutMessage message = newDirectMessage("put-run", 8L);
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);

    message.run(handler);

    Mockito.verify(handler).startClientPut(message);
  }

  @Test
  void createBucket_whenPersistentForever_usesPersistentFactory() throws Exception {
    ClientPutMessage message = newForeverMessage("put-forever", 64L);
    BucketFactory transientFactory = Mockito.mock(BucketFactory.class);
    FCPServer server = Mockito.mock(FCPServer.class);
    NodeClientCore core = Mockito.mock(NodeClientCore.class);
    PersistentTempBucketFactory persistentFactory = Mockito.mock(PersistentTempBucketFactory.class);

    Mockito.when(server.getCore()).thenReturn(core);
    Mockito.when(core.killedDatabase()).thenReturn(false);
    Mockito.when(core.getPersistentTempBucketFactory()).thenReturn(persistentFactory);

    try (RandomAccessBucket expectedBucket = Mockito.mock(RandomAccessBucket.class)) {
      Mockito.when(persistentFactory.makeBucket(64L)).thenReturn(expectedBucket);

      try (RandomAccessBucket bucket = message.createBucket(transientFactory, 64L, server)) {
        assertSame(expectedBucket, bucket);
      }
    }
    Mockito.verifyNoInteractions(transientFactory);
  }

  @Test
  void createBucket_whenPersistentForeverAndDatabaseKilled_expectPersistenceDisabled()
      throws MessageInvalidException {
    ClientPutMessage message = newForeverMessage("put-forever-disabled", 16L);
    BucketFactory transientFactory = Mockito.mock(BucketFactory.class);
    FCPServer server = Mockito.mock(FCPServer.class);
    NodeClientCore core = Mockito.mock(NodeClientCore.class);

    Mockito.when(server.getCore()).thenReturn(core);
    Mockito.when(core.killedDatabase()).thenReturn(true);

    assertThrows(
        PersistenceDisabledException.class,
        () -> {
          try (var _ = message.createBucket(transientFactory, 16L, server)) {
            fail("PersistenceDisabledException expected before bucket allocation");
          }
        });
    Mockito.verify(core, Mockito.never()).getPersistentTempBucketFactory();
    Mockito.verifyNoInteractions(transientFactory);
  }

  @Test
  void createBucket_whenConnectionPersistence_usesProvidedFactory() throws Exception {
    ClientPutMessage message = newDirectMessage("put-connection", 32L);
    BucketFactory factory = Mockito.mock(BucketFactory.class);

    try (RandomAccessBucket expectedBucket = Mockito.mock(RandomAccessBucket.class)) {
      try {
        Mockito.when(factory.makeBucket(32L)).thenReturn(expectedBucket);
      } catch (IOException e) {
        fail(e);
      }

      try (RandomAccessBucket bucket =
          message.createBucket(factory, 32L, Mockito.mock(FCPServer.class))) {
        assertSame(expectedBucket, bucket);
      }
    }
  }

  @Test
  void dataLength_directUpload_returnsProvidedLength() throws MessageInvalidException {
    ClientPutMessage message = newDirectMessage("put-length", 99L);

    assertEquals(99L, message.dataLength());
  }

  @Test
  void dataLength_diskUpload_returnsNegativeOne() throws Exception {
    Path file = Files.createTempFile(tempDir, "client-put", ".bin");
    Files.writeString(file, "payload");

    ClientPutMessage message = newDiskMessage(file);

    assertEquals(-1L, message.dataLength());
    message.freeData();
  }

  @Test
  void constructor_diskBareChkWithoutExplicitTarget_doesNotInferTargetFilename() throws Exception {
    Path file = Files.createTempFile(tempDir, "changelog-short", ".md");
    Files.writeString(file, "payload");

    ClientPutMessage message = newDiskMessage(file);

    assertEquals(ClientPutBase.UploadFrom.DISK, message.uploadFromType);
    assertEquals(file.toFile(), message.origFilename);
    assertEquals(-1L, message.dataLength());
    assertNull(message.targetFilename);
    message.freeData();
  }

  @Test
  void constructor_diskSskWithoutExplicitTarget_infersFilenameForDocName() throws Exception {
    Path file = Files.createTempFile(tempDir, "client-put", ".txt");
    Files.writeString(file, "payload");
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "put-ssk-disk");
    fs.putSingle("URI", "SSK@");
    fs.put("Verbosity", 0);
    fs.putSingle("UploadFrom", "disk");
    fs.putSingle("Filename", file.toString());

    ClientPutMessage message = new ClientPutMessage(fs);

    assertEquals(file.getFileName().toString(), message.targetFilename);
    message.freeData();
  }

  @Test
  void freeData_whenBucketPresent_invokesBucketFree() throws MessageInvalidException {
    ClientPutMessage message = newDirectMessage("put-free", 5L);
    Bucket bucket = Mockito.mock(Bucket.class);
    message.bucket = bucket;

    message.freeData();

    Mockito.verify(bucket).free();
  }

  private ClientPutMessage newDirectMessage(String identifier, long length)
      throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet(identifier);
    fs.putSingle("UploadFrom", "direct");
    fs.put("DataLength", length);
    return new ClientPutMessage(fs);
  }

  private ClientPutMessage newDiskMessage(Path file) throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet("put-disk");
    fs.putSingle("UploadFrom", "disk");
    fs.putSingle("Filename", file.toString());
    return new ClientPutMessage(fs);
  }

  private ClientPutMessage newForeverMessage(String identifier, long length)
      throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet(identifier);
    fs.putSingle("UploadFrom", "direct");
    fs.put("DataLength", length);
    fs.putSingle("Persistence", Persistence.FOREVER.name());
    return new ClientPutMessage(fs);
  }

  private SimpleFieldSet baseFieldSet(String identifier) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("URI", "CHK@");
    fs.putSingle("Metadata.ContentType", "text/plain");
    fs.put("Verbosity", 0);
    return fs;
  }
}
