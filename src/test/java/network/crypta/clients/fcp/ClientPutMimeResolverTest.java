package network.crypta.clients.fcp;

import java.io.File;
import java.nio.file.Path;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.BinaryBlob;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientPutMimeResolverTest {
  @TempDir private Path tempDir;

  @Test
  void resolve_whenBinaryBlobWithMime_throwsInvalidField() throws Exception {
    ClientPutMessage message = buildMessage("text/plain", true);

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutMimeResolver.resolve(message, null, null, true, "id", true));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, error.protocolCode);
  }

  @Test
  void resolve_whenBinaryBlobWithBinaryMime_allows() throws Exception {
    ClientPutMessage message = buildMessage(BinaryBlob.MIME_TYPE, true);

    String mime = ClientPutMimeResolver.resolve(message, null, null, true, "id", false);

    assertEquals(BinaryBlob.MIME_TYPE, mime);
  }

  @Test
  void resolve_whenOrigFilenamePresent_guessesMime() throws Exception {
    ClientPutMessage message = buildMessage(null, false);
    String filename = "photo" + ".jpg";
    File file = createFile(filename);

    String mime = ClientPutMimeResolver.resolve(message, file, null, false, "id", false);

    assertEquals(DefaultMIMETypes.guessMIMEType(filename, true), mime);
  }

  @Test
  void resolve_whenTargetFilenamePresent_guessesMime() throws Exception {
    ClientPutMessage message = buildMessage(null, false);

    String mime = ClientPutMimeResolver.resolve(message, null, "index.html", false, "id", false);

    assertEquals(DefaultMIMETypes.guessMIMEType("index.html", true), mime);
  }

  @Test
  void resolve_whenEmptyMime_returnsNull() throws Exception {
    ClientPutMessage message = buildMessage("", false);

    String mime = ClientPutMimeResolver.resolve(message, null, null, false, "id", false);

    assertNull(mime);
  }

  @Test
  void resolve_whenBadMime_throwsMessageInvalid() throws Exception {
    ClientPutMessage message = buildMessage("not a mime", false);

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutMimeResolver.resolve(message, null, null, false, "id", false));

    assertEquals(ProtocolErrorMessage.BAD_MIME_TYPE, error.protocolCode);
  }

  @Test
  void resolve_whenDiskBareChkWithoutTargetFilename_stripsExplicitMime() throws Exception {
    File file = createFile("disk-upload.txt");
    ClientPutMessage message = buildDiskMessage(file, "text/plain", null);

    String mime = ClientPutMimeResolver.resolve(message, file, null, false, "id", false);

    assertNull(mime);
  }

  @Test
  void resolve_whenDiskBareChkWithoutTargetFilenameAndBadMime_throwsMessageInvalid()
      throws Exception {
    File file = createFile("disk-upload.dat");
    ClientPutMessage message = buildDiskMessage(file, "not a mime", null);

    MessageInvalidException error =
        assertThrows(
            MessageInvalidException.class,
            () -> ClientPutMimeResolver.resolve(message, file, null, false, "id", false));

    assertEquals(ProtocolErrorMessage.BAD_MIME_TYPE, error.protocolCode);
  }

  @Test
  void resolve_whenDiskBareChkWithoutTargetFilename_suppressesGuessedMime() throws Exception {
    File file = createFile("disk-upload.html");
    ClientPutMessage message = buildDiskMessage(file, null, null);

    String mime = ClientPutMimeResolver.resolve(message, file, null, false, "id", false);

    assertNull(mime);
  }

  @Test
  void resolve_whenDiskBareChkWithTargetFilename_keepsMime() throws Exception {
    File file = createFile("disk-upload.txt");
    ClientPutMessage message = buildDiskMessage(file, "text/plain", "keep-mime.txt");

    String mime =
        ClientPutMimeResolver.resolve(message, file, message.targetFilename, false, "id", false);

    assertEquals("text/plain", mime);
  }

  private File createFile(String name) throws Exception {
    File file = tempDir.resolve(name).toFile();
    assertTrue(file.createNewFile());
    return file;
  }

  private ClientPutMessage buildMessage(String contentType, boolean binaryBlob)
      throws MessageInvalidException {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "request-1");
    fields.putSingle("UploadFrom", "direct");
    fields.putSingle("DataLength", "4");
    if (binaryBlob) {
      fields.putSingle("BinaryBlob", "true");
    } else {
      fields.putSingle("URI", "CHK@");
    }
    if (contentType != null) {
      fields.putSingle("Metadata.ContentType", contentType);
    }
    return new ClientPutMessage(fields);
  }

  private ClientPutMessage buildDiskMessage(File file, String contentType, String targetFilename)
      throws MessageInvalidException {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "disk-request");
    fields.putSingle("URI", "CHK@");
    fields.putSingle("UploadFrom", "disk");
    fields.putSingle("Filename", file.getAbsolutePath());
    if (contentType != null) {
      fields.putSingle("Metadata.ContentType", contentType);
    }
    if (targetFilename != null) {
      fields.putSingle("TargetFilename", targetFilename);
    }
    return new ClientPutMessage(fields);
  }
}
