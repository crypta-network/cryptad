package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void parseReturnTypeFCP_whenStringIsNull_returnsDirect() throws MessageInvalidException {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    ReturnType result = message.parseReturnTypeFCP(null);

    assertEquals(ReturnType.DIRECT, result);
  }

  @Test
  void parseReturnTypeFCP_whenLowerCaseValue_parsesEnum() throws MessageInvalidException {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    ReturnType result = message.parseReturnTypeFCP("disk");

    assertEquals(ReturnType.DISK, result);
  }

  @Test
  void parseReturnTypeFCP_whenInvalid_throwsMessageInvalidException()
      throws MessageInvalidException {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.parseReturnTypeFCP("bogus"));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals(message.identifier, exception.ident);
  }

  @Test
  void constructor_whenGlobalAndConnectionPersistence_throwsNotSupported() {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("Global", true);
    fs.putOverwrite("Persistence", Persistence.CONNECTION.name());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientGetMessage(fs));

    assertEquals(ProtocolErrorMessage.NOT_SUPPORTED, exception.protocolCode);
    assertEquals(fs.get("Identifier"), exception.ident);
  }

  @Test
  void constructor_whenDiskReturnTypeWithoutFilename_throwsMissingField() {
    SimpleFieldSet fs = baseFieldSet();
    fs.putOverwrite("ReturnType", ReturnType.DISK.name());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientGetMessage(fs));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("Missing Filename", exception.getMessage());
  }

  @Test
  void constructor_whenDiskReturnTargetExists_throwsDiskTargetExists(@TempDir Path tempDir)
      throws IOException {
    Path existing = tempDir.resolve("existing.bin");
    Files.createFile(existing);
    SimpleFieldSet fs = baseFieldSet();
    fs.putOverwrite("ReturnType", ReturnType.DISK.name());
    fs.putSingle("Filename", existing.toString());

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientGetMessage(fs));

    assertEquals(ProtocolErrorMessage.DISK_TARGET_EXISTS, exception.protocolCode);
    assertEquals(fs.get("Identifier"), exception.ident);
  }

  @Test
  void constructor_whenMaxSizeIsNegative_throwsInvalidField() {
    SimpleFieldSet fs = baseFieldSet();
    fs.putOverwrite("MaxSize", "-5");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientGetMessage(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertTrue(exception.getMessage().contains("Maximum size"));
  }

  @Test
  void constructor_whenInitialMetadataLengthNegative_throwsInvalidField() {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("InitialMetadata.DataLength", -1);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new ClientGetMessage(fs));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("Invalid data length for initial metadata", exception.getMessage());
  }

  @Test
  void getFieldSet_whenCalled_containsCoreValues() throws MessageInvalidException {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    SimpleFieldSet fields = message.getFieldSet();

    assertTrue(fields.getBoolean("IgnoreDS", false));
    assertEquals(message.uri.toString(false, false), fields.get("URI"));
    assertTrue(fields.getBoolean("FilterData", false));
    assertEquals("UTF-8", fields.get("Charset"));
    assertEquals(message.identifier, fields.get("Identifier"));
    assertEquals(message.verbosity, fields.getInt("Verbosity", -1));
    assertEquals(message.returnType.toString(), fields.get("ReturnType"));
    assertEquals(message.maxSize, fields.getLong("MaxSize", -1));
    assertEquals(message.maxTempSize, fields.getLong("MaxTempSize", -1));
    assertEquals(message.maxRetries, fields.getInt("MaxRetries", -1));
    assertTrue(fields.getBoolean("BinaryBlob", false));
  }

  @Test
  void run_whenInvoked_delegatesToConnectionHandler() throws MessageInvalidException {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    message.run(handler, node);

    verify(handler).startClientGet(message);
  }

  @Test
  void readFrom_whenMetadataPresent_storesBucketWithPayload() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("InitialMetadata.DataLength", 5);
    ClientGetMessage message = new ClientGetMessage(fs);
    byte[] payload = "HELLO".getBytes(StandardCharsets.UTF_8);
    ByteArrayInputStream input = new ByteArrayInputStream(payload);

    message.readFrom(input, new ArrayBucketFactory(), null);

    Bucket metadata = message.getInitialMetadata();
    assertNotNull(metadata);
    assertEquals(payload.length, metadata.size());
    try (InputStream stored = metadata.getInputStream()) {
      assertArrayEquals(payload, stored.readAllBytes());
    }
  }

  @Test
  void readFrom_whenMetadataLengthZero_keepsMetadataNull() throws Exception {
    ClientGetMessage message = new ClientGetMessage(baseFieldSet());

    message.readFrom(new ByteArrayInputStream(new byte[0]), new ArrayBucketFactory(), null);

    assertNull(message.getInitialMetadata());
  }

  @Test
  void dataLength_whenMetadataLengthProvided_returnsSameValue() throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet();
    fs.put("InitialMetadata.DataLength", 42);
    ClientGetMessage message = new ClientGetMessage(fs);

    long length = message.dataLength();

    assertEquals(42, length);
  }

  private SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "request-1");
    fs.putSingle("URI", "KSK@sample.txt");
    fs.put("IgnoreDS", true);
    fs.put("FilterData", true);
    fs.putSingle("Charset", "UTF-8");
    fs.put("Verbosity", 1);
    fs.putSingle("ReturnType", ReturnType.DIRECT.name());
    fs.put("MaxSize", 4096);
    fs.put("MaxTempSize", 8192);
    fs.put("MaxRetries", 2);
    fs.put("BinaryBlob", true);
    fs.putSingle("Persistence", Persistence.REBOOT.name());
    return fs;
  }
}
