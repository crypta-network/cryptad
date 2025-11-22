package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.util.Map;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PutFailedMessageTest {

  private static BaseL10n originalL10n;

  private static final Map<Integer, String> LONG_MESSAGES =
      Map.of(
          InsertExceptionMode.COLLISION.code, "Long collision",
          InsertExceptionMode.REJECTED_OVERLOAD.code, "Long rejected overload",
          InsertExceptionMode.CANCELLED.code, "Long cancelled",
          InsertExceptionMode.BUCKET_ERROR.code, "Long bucket error");

  private static final Map<Integer, String> SHORT_MESSAGES =
      Map.of(
          InsertExceptionMode.COLLISION.code, "Collision short",
          InsertExceptionMode.REJECTED_OVERLOAD.code, "Rejected overload short",
          InsertExceptionMode.CANCELLED.code, "Cancelled short",
          InsertExceptionMode.BUCKET_ERROR.code, "Bucket short");

  @BeforeAll
  static void stubLocalization() {
    originalL10n = NodeL10n.getBase();
    BaseL10n stub = mock(BaseL10n.class);
    when(stub.getString(anyString()))
        .thenAnswer(
            invocation -> {
              String key = invocation.getArgument(0);
              String longPrefix = "InsertException.longError.";
              String shortPrefix = "InsertException.shortError.";
              if (key.startsWith(longPrefix)) {
                int code = Integer.parseInt(key.substring(longPrefix.length()));
                return LONG_MESSAGES.getOrDefault(code, "long-" + code);
              }
              if (key.startsWith(shortPrefix)) {
                int code = Integer.parseInt(key.substring(shortPrefix.length()));
                return SHORT_MESSAGES.getOrDefault(code, "short-" + code);
              }
              return key;
            });
    overrideNodeL10n(stub);
  }

  @AfterAll
  static void restoreLocalization() {
    overrideNodeL10n(originalL10n);
  }

  private static void overrideNodeL10n(BaseL10n baseL10n) {
    try {
      Field field = NodeL10n.class.getDeclaredField("b");
      field.setAccessible(true);
      field.set(null, baseL10n);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Unable to override NodeL10n base", e);
    }
  }

  @Test
  void getFieldSet_whenVerbose_includesVerboseFields() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.COLLISION);
    InsertException exception =
        new InsertException(
            InsertExceptionMode.COLLISION, "disk error", tracker, FreenetURI.EMPTY_CHK_URI);

    PutFailedMessage message = new PutFailedMessage(exception, "insert-1", true);

    SimpleFieldSet fieldSet = message.getFieldSet(true);

    assertEquals("insert-1", fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals(InsertExceptionMode.COLLISION.code, fieldSet.getInt("Code", -1));
    assertEquals("Long collision", fieldSet.get("CodeDescription"));
    assertEquals("Collision short", fieldSet.get("ShortCodeDescription"));
    assertEquals("disk error", fieldSet.get("ExtraDescription"));
    assertEquals(FreenetURI.EMPTY_CHK_URI.toString(), fieldSet.get("ExpectedURI"));
    assertTrue(fieldSet.getBoolean("Fatal", false));
    SimpleFieldSet errors = fieldSet.subset("Errors");
    assertNotNull(errors);
    assertEquals(1, errors.getInt("9.Count", -1));
  }

  @Test
  void getFieldSet_whenNotVerbose_omitsVerboseOnlyKeys() {
    InsertException exception = new InsertException(InsertExceptionMode.REJECTED_OVERLOAD);

    PutFailedMessage message = new PutFailedMessage(exception, "insert-2", false);

    SimpleFieldSet fieldSet = message.getFieldSet(false);

    assertEquals("insert-2", fieldSet.get("Identifier"));
    assertEquals(InsertExceptionMode.REJECTED_OVERLOAD.code, fieldSet.getInt("Code", -1));
    assertNull(fieldSet.get("CodeDescription"));
    assertNull(fieldSet.get("ShortCodeDescription"));
    assertNull(fieldSet.get("Fatal"));
    assertNull(fieldSet.get("ExpectedURI"));
    assertNull(fieldSet.subset("Errors"));
  }

  @Test
  void constructor_withVerboseFieldSet_preservesDescriptions() throws MalformedURLException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "from-fs");
    fs.put("Global", true);
    fs.put("Code", InsertExceptionMode.BUCKET_ERROR.code);
    fs.putSingle("CodeDescription", "Provided bucket description");
    fs.put("Fatal", true);
    fs.putSingle("ShortCodeDescription", "Provided short");
    fs.putSingle("ExtraDescription", "disk full");
    fs.putSingle("ExpectedURI", FreenetURI.EMPTY_CHK_URI.toString());
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.BUCKET_ERROR);
    fs.tput("Errors", tracker.toFieldSet(true));

    PutFailedMessage message = new PutFailedMessage(fs, true);

    SimpleFieldSet fieldSet = message.getFieldSet(true);
    assertEquals("Provided bucket description", fieldSet.get("CodeDescription"));
    assertEquals("Provided short", message.getShortFailedMessage());
    assertEquals("Provided short: disk full", message.getLongFailedMessage());
    assertEquals(1, fieldSet.subset("Errors").getInt("2.Count", -1));
  }

  @Test
  void constructor_withNonVerboseFieldSet_reconstructsDescriptions() throws MalformedURLException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "non-verbose");
    fs.put("Global", true);
    fs.put("Code", InsertExceptionMode.REJECTED_OVERLOAD.code);
    fs.putSingle("ExtraDescription", "retry later");

    PutFailedMessage message = new PutFailedMessage(fs, false);

    SimpleFieldSet fieldSet = message.getFieldSet(true);
    assertEquals("Long rejected overload", fieldSet.get("CodeDescription"));
    assertEquals("Rejected overload short", fieldSet.get("ShortCodeDescription"));
    assertEquals("retry later", fieldSet.get("ExtraDescription"));
    assertEquals(
        InsertException.isFatal(InsertExceptionMode.REJECTED_OVERLOAD),
        fieldSet.getBoolean("Fatal", true));
  }

  @Test
  void getLongFailedMessage_whenNoExtra_returnsShortMessage() {
    InsertException exception = new InsertException(InsertExceptionMode.CANCELLED);

    PutFailedMessage message = new PutFailedMessage(exception, "insert-3", true);

    assertEquals("Cancelled short", message.getLongFailedMessage());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    InsertException exception = new InsertException(InsertExceptionMode.INVALID_URI);
    PutFailedMessage message = new PutFailedMessage(exception, "insert-4", true);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(null, null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals("insert-4", thrown.ident);
    assertTrue(thrown.global);
  }

  @Test
  void constructor_whenIdentifierMissing_throwsNullPointerException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Code", InsertExceptionMode.COLLISION.code);

    assertThrows(NullPointerException.class, () -> new PutFailedMessage(fs, true));
  }
}
