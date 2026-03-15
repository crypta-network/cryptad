package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.clients.fcp.RequestIdentifier.RequestType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GetFailedMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void getFieldSet_whenGlobalFalse_setsGlobalFalse() {
    FetchException exception = new FetchException(FetchExceptionMode.INTERNAL_ERROR);

    GetFailedMessage message = new GetFailedMessage(exception, "TestMessage", false);

    assertEquals("false", message.getFieldSet().get("Global"));
  }

  @Test
  void getFieldSet_whenGlobalTrue_setsGlobalTrue() {
    FetchException exception = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);

    GetFailedMessage message = new GetFailedMessage(exception, "TestMessage", true);

    assertEquals("true", message.getFieldSet().get("Global"));
  }

  @Test
  void getFieldSet_whenVerboseFalse_omitsVerboseFields() {
    FetchException exception =
        new FetchException(FetchExceptionMode.BUCKET_ERROR, 42L, true, "text/plain");
    GetFailedMessage message = new GetFailedMessage(exception, "id-1", true);

    SimpleFieldSet fieldSet = message.getFieldSet(false);

    assertNull(fieldSet.get("CodeDescription"));
    assertNull(fieldSet.get("ShortCodeDescription"));
    assertNull(fieldSet.get("Fatal"));
    assertEquals("42", fieldSet.get("ExpectedDataLength"));
    assertEquals("text/plain", fieldSet.get("ExpectedMetadata.ContentType"));
  }

  @Test
  void getFieldSet_whenVerboseTrue_includesVerboseFields() {
    FetchException exception = new FetchException(FetchExceptionMode.TOO_BIG, "details");
    GetFailedMessage message = new GetFailedMessage(exception, "id-2", false);

    SimpleFieldSet fieldSet = message.getFieldSet(true);

    assertEquals(
        FetchException.getMessage(FetchExceptionMode.TOO_BIG), fieldSet.get("CodeDescription"));
    assertEquals(
        FetchException.getShortMessage(FetchExceptionMode.TOO_BIG),
        fieldSet.get("ShortCodeDescription"));
    assertEquals("false", fieldSet.get("Global"));
  }

  @Test
  void getLongFailedMessage_withExtraDescription_appendsDetails() {
    FetchException exception =
        new FetchException(FetchExceptionMode.INTERNAL_ERROR, "extra detail");
    GetFailedMessage message = new GetFailedMessage(exception, "id-3", false);

    assertEquals(
        FetchException.getMessage(FetchExceptionMode.INTERNAL_ERROR) + ": extra detail",
        message.getLongFailedMessage());
  }

  @Test
  void constructor_withNonVerboseFieldSet_derivesFatalFromCode() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id-4");
    fs.putSingle("Code", String.valueOf(FetchExceptionMode.TOO_BIG.code));
    fs.putSingle("Fatal", "false");

    GetFailedMessage message = new GetFailedMessage(fs, false);

    assertTrue(message.isFatal);
    assertEquals(FetchExceptionMode.TOO_BIG, message.failureMode);
  }

  @Test
  void constructor_withVerboseFieldSet_respectsFatalFlag() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id-5");
    fs.putSingle("Code", String.valueOf(FetchExceptionMode.DATA_NOT_FOUND.code));
    fs.putSingle("Fatal", "true");
    fs.putSingle("ExpectedDataLength", "77");
    fs.putSingle("ExpectedMimeType", "application/json");
    fs.putSingle("RedirectURI", "KSK@redirect");
    fs.putSingle("Global", "true");

    GetFailedMessage message = new GetFailedMessage(fs, true);

    assertTrue(message.isFatal);
    assertEquals(77L, message.expectedDataLength);
    assertEquals("application/json", message.expectedMimeType);
    assertNotNull(message.redirectURI);
    assertEquals("KSK@redirect", message.redirectURI.toString(false, false));
    assertTrue(message.global);
  }

  @Test
  void constructor_whenIdentifierMissing_throwsNullPointerException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Code", String.valueOf(FetchExceptionMode.INTERNAL_ERROR.code));

    assertThrows(NullPointerException.class, () -> new GetFailedMessage(fs, false));
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    FetchException exception = new FetchException(FetchExceptionMode.INTERNAL_ERROR);
    GetFailedMessage message = new GetFailedMessage(exception, "run-id", true);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals("run-id", thrown.ident);
    assertTrue(thrown.global);
  }

  @Test
  void streamConstructor_whenDataValid_roundTripsCoreFields() throws Exception {
    FetchException exception =
        new FetchException(
            FetchExceptionMode.ARCHIVE_FAILURE,
            128L,
            true,
            "application/octet-stream",
            new FreenetURI("KSK@alpha"));
    GetFailedMessage original = new GetFailedMessage(exception, "stream-id", false);
    RequestIdentifier reqId = new RequestIdentifier(true, null, "stream-id", RequestType.GET);

    byte[] serialized = writeToBytes(original);

    GetFailedMessage restored =
        new GetFailedMessage(
            new DataInputStream(new ByteArrayInputStream(serialized)), reqId, 64L, "text/html");

    assertEquals(original.failureMode, restored.failureMode);
    assertTrue(restored.finalizedExpected);
    assertEquals("stream-id", restored.requestIdentifier);
    assertTrue(restored.global);
    assertEquals(64L, restored.expectedDataLength);
    assertEquals("text/html", restored.expectedMimeType);
    assertNotNull(restored.redirectURI);
    assertEquals("KSK@alpha", restored.redirectURI.toString(false, false));
  }

  @Test
  void streamConstructor_whenVersionMismatch_throwsStorageFormatException() throws Exception {
    byte[] payload = writeStreamPayload(99, FetchExceptionMode.CANCELLED.code, "meta", true, null);
    RequestIdentifier reqId =
        new RequestIdentifier(false, "client", "bad-version", RequestType.GET);

    assertThrows(
        StorageFormatException.class,
        () ->
            new GetFailedMessage(
                new DataInputStream(new ByteArrayInputStream(payload)), reqId, -1, null));
  }

  @Test
  void streamConstructor_whenCodeUnknown_throwsStorageFormatException() throws Exception {
    byte[] payload = writeStreamPayload(GetFailedMessage.VERSION, -999, null, false, null);
    RequestIdentifier reqId = new RequestIdentifier(false, "client", "bad-code", RequestType.GET);

    StorageFormatException thrown =
        assertThrows(
            StorageFormatException.class,
            () ->
                new GetFailedMessage(
                    new DataInputStream(new ByteArrayInputStream(payload)), reqId, -1, null));

    assertEquals("Bad error code", thrown.getMessage());
  }

  @Test
  void streamConstructor_whenRedirectMalformed_throwsStorageFormatException() throws Exception {
    byte[] payload =
        writeStreamPayload(
            GetFailedMessage.VERSION,
            FetchExceptionMode.INTERNAL_ERROR.code,
            "hint",
            true,
            "invalid-uri-without-at");
    RequestIdentifier reqId = new RequestIdentifier(true, null, "bad-redirect", RequestType.GET);

    StorageFormatException thrown =
        assertThrows(
            StorageFormatException.class,
            () ->
                new GetFailedMessage(
                    new DataInputStream(new ByteArrayInputStream(payload)), reqId, 0L, null));

    assertTrue(thrown.getMessage().startsWith("Bad redirect URI in GetFailedMessage"));
  }

  private static byte[] writeToBytes(GetFailedMessage message) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      message.writeTo(dos);
    }
    return baos.toByteArray();
  }

  private static byte[] writeStreamPayload(
      int version, int code, String extra, boolean finalized, String redirect) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(version);
      dos.writeInt(code);
      if (extra != null) {
        dos.writeBoolean(true);
        dos.writeUTF(extra);
      } else {
        dos.writeBoolean(false);
      }
      dos.writeBoolean(finalized);
      if (redirect != null) {
        dos.writeBoolean(true);
        dos.writeUTF(redirect);
      } else {
        dos.writeBoolean(false);
      }
    }
    return baos.toByteArray();
  }
}
