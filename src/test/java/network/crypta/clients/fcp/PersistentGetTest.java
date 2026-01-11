package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Path;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentGetTest {

  private static final String IDENTIFIER = "test-id";

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void constructor_whenUriIsNull_throwsNullPointerException(@TempDir Path tempDir) {
    File targetFile = tempDir.resolve("target.bin").toFile();

    ClientRequestParams requestParams =
        new ClientRequestParams(
            null, IDENTIFIER, 1, (short) 2, Persistence.CONNECTION, false, "token", false);
    PersistentGetDescriptor descriptor =
        new PersistentGetDescriptor(ReturnType.DIRECT, targetFile, true, 3, false, 1024L);

    assertThrows(NullPointerException.class, () -> new PersistentGet(requestParams, descriptor));
  }

  @Test
  void getFieldSet_whenReturnTypeDisk_populatesAllExpectedFields(@TempDir Path tempDir) {
    FreenetURI uri = new FreenetURI("KSK", "file");
    File targetFile = tempDir.resolve("disk-output.bin").toFile();
    ClientRequestParams requestParams =
        new ClientRequestParams(
            uri, IDENTIFIER, 5, (short) 3, Persistence.FOREVER, true, "client-token", true);
    PersistentGetDescriptor descriptor =
        new PersistentGetDescriptor(ReturnType.DISK, targetFile, true, 7, true, 4096L);
    PersistentGet persistentGet = new PersistentGet(requestParams, descriptor);

    SimpleFieldSet fieldSet = persistentGet.getFieldSet();

    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertEquals(uri.toString(false, false), fieldSet.get("URI"));
    assertEquals(5, fieldSet.getInt("Verbosity", -1));
    assertEquals("disk", fieldSet.get("ReturnType"));
    assertEquals("forever", fieldSet.get("Persistence"));
    assertEquals(targetFile.getAbsolutePath(), fieldSet.get("Filename"));
    assertEquals(3, fieldSet.getShort("PriorityClass", (short) -1));
    assertEquals("client-token", fieldSet.get("ClientToken"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertTrue(fieldSet.getBoolean("Started", false));
    assertEquals(7, fieldSet.getInt("MaxRetries", -1));
    assertTrue(fieldSet.getBoolean("BinaryBlob", false));
    assertEquals(4096L, fieldSet.getLong("MaxSize", -1));
    assertTrue(fieldSet.getBoolean("RealTime", false));
  }

  @Test
  void getFieldSet_whenReturnTypeNotDisk_omitsFilenameAndClientToken() {
    FreenetURI uri = new FreenetURI("KSK", "nodisk");
    ClientRequestParams requestParams =
        new ClientRequestParams(
            uri, IDENTIFIER, 2, (short) 1, Persistence.REBOOT, false, null, false);
    PersistentGetDescriptor descriptor =
        new PersistentGetDescriptor(ReturnType.DIRECT, null, false, 0, false, 0L);
    PersistentGet persistentGet = new PersistentGet(requestParams, descriptor);

    SimpleFieldSet fieldSet = persistentGet.getFieldSet();

    assertEquals("direct", fieldSet.get("ReturnType"));
    assertEquals("reboot", fieldSet.get("Persistence"));
    assertNull(fieldSet.get("Filename"));
    assertNull(fieldSet.get("ClientToken"));
    assertEquals(0, fieldSet.getInt("MaxRetries", -1));
    assertFalse(fieldSet.getBoolean("BinaryBlob", true));
    assertEquals(0L, fieldSet.getLong("MaxSize", -1));
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithProtocolDetails() {
    FreenetURI uri = new FreenetURI("KSK", "run");
    ClientRequestParams requestParams =
        new ClientRequestParams(
            uri, IDENTIFIER, 1, (short) 1, Persistence.CONNECTION, false, "token", true);
    PersistentGetDescriptor descriptor =
        new PersistentGetDescriptor(ReturnType.NONE, null, false, 1, false, 10L);
    PersistentGet persistentGet = new PersistentGet(requestParams, descriptor);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> persistentGet.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(IDENTIFIER, exception.ident);
    assertTrue(exception.global);
    assertEquals(
        "PersistentGet goes from server to client not the other way around",
        exception.getMessage());
  }
}
