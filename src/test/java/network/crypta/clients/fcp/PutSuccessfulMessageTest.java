package network.crypta.clients.fcp;

import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("java:S100")
class PutSuccessfulMessageTest {

  @Test
  void getFieldSet_whenUriProvided_populatesAllFields() {
    FreenetURI uri = new FreenetURI("KSK", "test-doc");
    PutSuccessfulMessage message = new PutSuccessfulMessage("insert-1", true, uri, 42L, 84L);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("insert-1", fieldSet.get("Identifier"));
    assertTrue(fieldSet.getBoolean("Global", false));
    assertEquals(uri.toString(false, false), fieldSet.get("URI"));
    assertEquals("42", fieldSet.get("StartupTime"));
    assertEquals("84", fieldSet.get("CompletionTime"));
  }

  @Test
  void getFieldSet_whenUriMissing_omitsUriFieldButRetainsTiming() {
    PutSuccessfulMessage message = new PutSuccessfulMessage("insert-2", false, null, 0L, 1L);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("insert-2", fieldSet.get("Identifier"));
    assertFalse(fieldSet.getBoolean("Global", true));
    assertNull(fieldSet.get("URI"));
    assertEquals("0", fieldSet.get("StartupTime"));
    assertEquals("1", fieldSet.get("CompletionTime"));
  }

  @Test
  void getName_whenCalled_returnsLiteralName() {
    PutSuccessfulMessage message = new PutSuccessfulMessage("id", false, null, 0L, 0L);

    assertEquals("PutSuccessful", message.getName());
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithContext() {
    PutSuccessfulMessage message = new PutSuccessfulMessage("id-123", false, null, 0L, 0L);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals(
        "InsertSuccessful goes from server to client not the other way around",
        thrown.getMessage());
    assertEquals("id-123", thrown.ident);
    assertFalse(thrown.global);
  }
}
