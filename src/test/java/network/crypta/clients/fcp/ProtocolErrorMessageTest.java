package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProtocolErrorMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Test
  void getFieldSet_whenAllFieldsProvided_containsExpectedValues() {
    ProtocolErrorMessage message =
        new ProtocolErrorMessage(
            ProtocolErrorMessage.INVALID_MESSAGE, true, "details", "identifier", true);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("identifier", fieldSet.get("Identifier"));
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, Integer.parseInt(fieldSet.get("Code")));
    assertEquals("Don't know what to do with message", fieldSet.get("CodeDescription"));
    assertEquals("details", fieldSet.get("ExtraDescription"));
    assertTrue(fieldSet.getBoolean("Fatal", false));
    assertTrue(fieldSet.getBoolean("Global", false));
  }

  @Test
  void getFieldSet_whenOptionalFieldsNull_omitsThem() {
    ProtocolErrorMessage message = new ProtocolErrorMessage(1234, false, null, null, false);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertFalse(fieldSet.directKeys().contains("Identifier"));
    assertFalse(fieldSet.directKeys().contains("ExtraDescription"));
    assertEquals("(Unknown)", fieldSet.get("CodeDescription"));
    assertFalse(fieldSet.getBoolean("Fatal", true));
    assertFalse(fieldSet.getBoolean("Global", true));
  }

  @Test
  void constructor_withSimpleFieldSet_parsesValues() {
    SimpleFieldSet source = new SimpleFieldSet(true);
    source.putSingle("Identifier", "abc");
    source.put("Code", ProtocolErrorMessage.FILE_NOT_FOUND);
    source.putSingle("ExtraDescription", "missing");
    source.put("Fatal", true);
    source.put("Global", true);

    ProtocolErrorMessage message = new ProtocolErrorMessage(source);

    assertEquals("abc", message.ident);
    assertEquals(ProtocolErrorMessage.FILE_NOT_FOUND, message.getCode());
    assertEquals("missing", message.extra);
    assertTrue(message.fatal);
    assertTrue(message.global);
  }

  @Test
  void run_whenInvoked_doesNotThrow() {
    ProtocolErrorMessage message = new ProtocolErrorMessage(1, false, null, null, false);

    assertDoesNotThrow(() -> message.run(handler));
  }

  @Test
  void getName_whenCalled_returnsProtocolError() {
    ProtocolErrorMessage message = new ProtocolErrorMessage(1, false, null, null, false);

    assertEquals("ProtocolError", message.getName());
  }

  @Test
  void toString_whenCalled_containsFieldValues() {
    ProtocolErrorMessage message = new ProtocolErrorMessage(7, true, "extra", "id", true);

    String result = message.toString();

    assertTrue(result.contains(":7:extra:true:id:true"));
  }
}
