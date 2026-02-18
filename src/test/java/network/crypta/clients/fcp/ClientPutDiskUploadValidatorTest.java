package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.UUID;
import network.crypta.crypt.SHA256;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "resource"})
class ClientPutDiskUploadValidatorTest {
  @TempDir private Path tempDir;

  @Test
  void validatePersistentDiskUpload_whenNotAllowed_throwsNotAllowed() {
    NodeClientCore core = mock(NodeClientCore.class);
    File file = tempDir.resolve("upload.dat").toFile();
    when(core.allowUploadFrom(file)).thenReturn(false);

    assertThrows(
        NotAllowedException.class,
        () -> ClientPutDiskUploadValidator.validatePersistentDiskUpload(core, file));
  }

  @Test
  void validatePersistentDiskUpload_whenMissingFile_throwsFileNotFound() {
    NodeClientCore core = mock(NodeClientCore.class);
    File file = tempDir.resolve("missing.dat").toFile();
    when(core.allowUploadFrom(file)).thenReturn(true);

    assertThrows(
        FileNotFoundException.class,
        () -> ClientPutDiskUploadValidator.validatePersistentDiskUpload(core, file));
  }

  @Test
  void validatePersistentDiskUpload_whenReadableFile_allowsUpload() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    File file = tempDir.resolve("data.bin").toFile();
    assertTrue(file.createNewFile());
    when(core.allowUploadFrom(file)).thenReturn(true);

    ClientPutDiskUploadValidator.validatePersistentDiskUpload(core, file);
  }

  @Test
  void validateDiskUpload_whenNotDisk_returnsEmptyContext() throws Exception {
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    ClientPutMessage message =
        buildMessage(ClientPutBase.UploadFrom.DIRECT, tempDir.resolve("direct.dat").toFile(), null);

    DiskUploadContext context =
        ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "id", false);

    assertSame(DiskUploadContext.empty(), context);
  }

  @Test
  void validateDiskUpload_whenUploadNotAllowed_throwsMessageInvalid() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    File file = createFile("blocked.dat");

    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DISK, file, null);
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.allowUploadFrom(file)).thenReturn(false);

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "id", true));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, error.protocolCode);
  }

  @Test
  void validateDiskUpload_whenFileHashProvided_buildsSaltedContext() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    File file = createFile("file.dat");
    UUID connectionId = UUID.fromString("f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    byte[] expectedHash = new byte[] {1, 2, 3, 4};

    ClientPutMessage message =
        buildMessage(ClientPutBase.UploadFrom.DISK, file, Base64.encodeStandard(expectedHash));
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.allowUploadFrom(file)).thenReturn(true);
    when(handler.getConnectionIdentifierUUID()).thenReturn(connectionId);

    DiskUploadContext context =
        ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "request-1", false);

    assertEquals(connectionId + "-request-1-", context.salt());
    assertArrayEquals(expectedHash, context.saltedHash());
  }

  @Test
  void validateDiskUpload_whenDdaDenied_throwsMessageInvalid() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);
    DdaAccessController ddaController = mock(DdaAccessController.class);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    File file = createFile("file.dat");

    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DISK, file, null);
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.allowUploadFrom(file)).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaController);
    when(ddaController.allowDDAFrom(file, false)).thenReturn(false);

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "id", true));

    assertEquals(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, error.protocolCode);
  }

  @Test
  void validateDiskUpload_whenDdaAllowed_returnsEmptyContext() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);
    DdaAccessController ddaController = mock(DdaAccessController.class);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    File file = createFile("file.dat");

    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DISK, file, null);
    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.allowUploadFrom(file)).thenReturn(true);
    when(handler.ddaAccessController()).thenReturn(ddaController);
    when(ddaController.allowDDAFrom(file, false)).thenReturn(true);

    DiskUploadContext context =
        ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "id", false);

    assertSame(DiskUploadContext.empty(), context);
  }

  @Test
  void validateDiskUpload_whenInvalidFileHash_throwsMessageInvalid() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    FCPServer server = mock(FCPServer.class);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    File file = createFile("file.dat");
    ClientPutMessage message = buildMessage(ClientPutBase.UploadFrom.DISK, file, "@@@");

    when(handler.getServer()).thenReturn(server);
    when(server.getCore()).thenReturn(core);
    when(core.allowUploadFrom(file)).thenReturn(true);
    when(handler.getConnectionIdentifierUUID())
        .thenReturn(UUID.fromString("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"));

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutDiskUploadValidator.validateDiskUpload(handler, message, "id", false));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, error.protocolCode);
  }

  @Test
  void verifySaltedHash_whenNoSalt_returnsWithoutError() throws Exception {
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    DiskUploadContext context = DiskUploadContext.empty();

    ClientPutDiskUploadValidator.verifySaltedHash(context, bucket, "id", false);
  }

  @Test
  void verifySaltedHash_whenHashesMatch_allowsUpload() throws Exception {
    String salt = "salt";
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    byte[] hash = hashPayload(salt, payload);
    DiskUploadContext context = new DiskUploadContext(salt, hash);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

    ClientPutDiskUploadValidator.verifySaltedHash(context, bucket, "id", false);
  }

  @Test
  void verifySaltedHash_whenHashesDiffer_throwsMessageInvalid() throws Exception {
    String salt = "salt";
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    DiskUploadContext context = new DiskUploadContext(salt, new byte[] {9, 9, 9});
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    when(bucket.getInputStream()).thenReturn(new ByteArrayInputStream(payload));

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutDiskUploadValidator.verifySaltedHash(context, bucket, "id", true));

    assertEquals(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, error.protocolCode);
  }

  @Test
  void verifySaltedHash_whenBucketFails_throwsMessageInvalid() throws Exception {
    String salt = "salt";
    DiskUploadContext context = new DiskUploadContext(salt, new byte[] {1, 2});
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    doThrow(new IOException("fail")).when(bucket).getInputStream();

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutDiskUploadValidator.verifySaltedHash(context, bucket, "id", true));

    assertEquals(ProtocolErrorMessage.COULD_NOT_READ_FILE, error.protocolCode);
  }

  @Test
  void diskUploadContext_equalsAndHashCode_matchOnState() {
    byte[] hash = new byte[] {1, 2, 3};
    DiskUploadContext first = new DiskUploadContext("salt", hash);
    DiskUploadContext second = new DiskUploadContext("salt", new byte[] {1, 2, 3});
    DiskUploadContext different = new DiskUploadContext("other", new byte[] {1, 2, 3});

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
    assertNotEquals(first, different);
  }

  @Test
  void diskUploadContext_toString_includesFields() {
    DiskUploadContext context = new DiskUploadContext("salt", new byte[] {1, 2});

    String value = context.toString();

    assertNotNull(value);
    assertTrue(value.contains("salt"));
  }

  private static byte[] hashPayload(String salt, byte[] payload) throws IOException {
    MessageDigest digest = SHA256.getMessageDigest();
    digest.update(salt.getBytes(StandardCharsets.UTF_8));
    try (ByteArrayInputStream stream = new ByteArrayInputStream(payload)) {
      SHA256.hash(stream, digest);
    }
    return digest.digest();
  }

  private ClientPutMessage buildMessage(
      ClientPutBase.UploadFrom uploadFrom, File file, String fileHash)
      throws MessageInvalidException {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "request-1");
    fields.putSingle("URI", "CHK@");
    if (uploadFrom == ClientPutBase.UploadFrom.DIRECT) {
      fields.putSingle("UploadFrom", "direct");
      fields.putSingle("DataLength", "4");
    } else if (uploadFrom == ClientPutBase.UploadFrom.DISK) {
      if (file != null) {
        fields.putSingle("Filename", file.getPath());
      }
      fields.putSingle("UploadFrom", "disk");
    }
    if (fileHash != null) {
      fields.putSingle(ClientPutBase.FILE_HASH, fileHash);
    }
    return new ClientPutMessage(fields);
  }

  private File createFile(String name) throws IOException {
    File file = tempDir.resolve(name).toFile();
    assertTrue(file.createNewFile());
    return file;
  }
}
