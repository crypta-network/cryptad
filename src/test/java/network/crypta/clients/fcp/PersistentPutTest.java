package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.nio.file.Path;
import network.crypta.client.InsertContext;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentPutTest {

  @TempDir Path tempDir;

  @Test
  void getFieldSet_whenAllFieldsProvided_populatesAllKeys() {
    FreenetURI publicUri = new FreenetURI("KSK", "public");
    FreenetURI privateUri = new FreenetURI("KSK", "private");
    FreenetURI targetUri = new FreenetURI("KSK", "target");
    File originalFile = tempDir.resolve("upload.bin").toFile();
    byte[] cryptoKey = new byte[] {0x01, 0x02, 0x0A, (byte) 0xFF};

    PersistentPut put =
        new PersistentPut(
            "id-123",
            publicUri,
            privateUri,
            2,
            (short) 5,
            UploadFrom.DIRECT,
            targetUri,
            Persistence.FOREVER,
            originalFile,
            "text/plain",
            true,
            1024L,
            "token-abc",
            true,
            3,
            "target.dat",
            true,
            InsertContext.CompatibilityMode.COMPAT_1468,
            true,
            "lzma",
            true,
            cryptoKey);

    SimpleFieldSet fs = put.getFieldSet();

    assertEquals("id-123", fs.get("Identifier"));
    assertEquals(publicUri.toString(false, false), fs.get("URI"));
    assertEquals(privateUri.toString(false, false), fs.get("PrivateURI"));
    assertEquals("2", fs.get("Verbosity"));
    assertEquals("5", fs.get("PriorityClass"));
    assertEquals("direct", fs.get("UploadFrom"));
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
    assertEquals(HexUtil.bytesToHex(cryptoKey), fs.get("SplitfileCryptoKey"));
  }

  @Test
  void getFieldSet_whenOptionalFieldsNull_omitsThoseKeys() {
    FreenetURI publicUri = new FreenetURI("KSK", "public");
    PersistentPut put =
        createMinimalPut(
            "id-optional", publicUri, Persistence.CONNECTION, false, UploadFrom.REDIRECT);

    SimpleFieldSet fs = put.getFieldSet();

    assertEquals("id-optional", fs.get("Identifier"));
    assertEquals(publicUri.toString(false, false), fs.get("URI"));
    assertEquals("redirect", fs.get("UploadFrom"));
    assertEquals("connection", fs.get("Persistence"));
    assertEquals("false", fs.get("Global"));
    assertEquals("false", fs.get("Started"));
    assertEquals("0", fs.get("MaxRetries"));
    assertEquals("COMPAT_UNKNOWN", fs.get("CompatibilityMode"));
    assertEquals("false", fs.get("DontCompress"));
    assertEquals("false", fs.get("RealTime"));

    assertNull(fs.get("PrivateURI"));
    assertNull(fs.get("Filename"));
    assertNull(fs.get("TargetURI"));
    assertNull(fs.get("Metadata.ContentType"));
    assertNull(fs.get("DataLength"));
    assertNull(fs.get("ClientToken"));
    assertNull(fs.get("TargetFilename"));
    assertNull(fs.get("BinaryBlob"));
    assertNull(fs.get("Codecs"));
    assertNull(fs.get("SplitfileCryptoKey"));
  }

  @Test
  void getName_alwaysReturnsConstant() {
    PersistentPut put =
        new PersistentPut(
            "id-name",
            new FreenetURI("KSK", "name"),
            null,
            1,
            (short) 1,
            UploadFrom.DIRECT,
            null,
            Persistence.REBOOT,
            null,
            null,
            false,
            -1,
            null,
            false,
            0,
            null,
            false,
            InsertContext.CompatibilityMode.COMPAT_CURRENT,
            false,
            null,
            false,
            null);

    assertEquals("PersistentPut", put.getName());
  }

  @Test
  void run_whenInvoked_throwsInvalidMessageExceptionWithDetails() {
    boolean global = true;
    FreenetURI publicUri = new FreenetURI("KSK", "run");
    PersistentPut put =
        createMinimalPut("id-run", publicUri, Persistence.REBOOT, global, UploadFrom.DIRECT);

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () ->
                put.run(
                    mock(FCPConnectionHandler.class),
                    mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, ex.protocolCode);
    assertEquals(
        "PersistentPut goes from server to client not the other way around", ex.getMessage());
    assertEquals("id-run", ex.ident);
    assertTrue(ex.global);
  }

  private PersistentPut createMinimalPut(
      String identifier,
      FreenetURI publicUri,
      Persistence persistence,
      boolean global,
      UploadFrom uploadFrom) {
    return new PersistentPut(
        identifier,
        publicUri,
        null,
        0,
        (short) 0,
        uploadFrom,
        null,
        persistence,
        null,
        null,
        global,
        -1,
        null,
        false,
        0,
        null,
        false,
        InsertContext.CompatibilityMode.COMPAT_UNKNOWN,
        false,
        null,
        false,
        null);
  }
}
