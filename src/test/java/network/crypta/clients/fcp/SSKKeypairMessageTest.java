package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SSKKeypairMessageTest {

  @Mock FCPConnectionHandler handler;
  @Mock Node node;

  private static final String INSERT_URI_STRING =
      "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17/index_d51.xml";

  private static final String REQUEST_URI_STRING =
      "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/WebOfTrust-5";

  @Test
  void getFieldSet_whenIdentifierProvided_containsAllFields() throws Exception {
    FreenetURI insertURI = new FreenetURI(INSERT_URI_STRING);
    FreenetURI requestURI = new FreenetURI(REQUEST_URI_STRING);
    String identifier = "id-123";
    SSKKeypairMessage message = new SSKKeypairMessage(insertURI, requestURI, identifier);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(insertURI.toString(), fieldSet.get("InsertURI"));
    assertEquals(requestURI.toString(), fieldSet.get("RequestURI"));
    assertEquals(identifier, fieldSet.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierMissing_omitsIdentifierField() throws Exception {
    FreenetURI insertURI = new FreenetURI(INSERT_URI_STRING);
    FreenetURI requestURI = new FreenetURI(REQUEST_URI_STRING);
    SSKKeypairMessage message = new SSKKeypairMessage(insertURI, requestURI, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(insertURI.toString(), fieldSet.get("InsertURI"));
    assertEquals(requestURI.toString(), fieldSet.get("RequestURI"));
    assertNull(fieldSet.get("Identifier"));
  }

  @Test
  void getName_returnsFixedMessageName() throws Exception {
    SSKKeypairMessage message =
        new SSKKeypairMessage(
            new FreenetURI(INSERT_URI_STRING), new FreenetURI(REQUEST_URI_STRING), "id");

    assertEquals("SSKKeypair", message.getName());
  }

  @Test
  void run_alwaysThrowsMessageInvalidExceptionWithProtocolDetails() throws Exception {
    String identifier = "identifier";
    SSKKeypairMessage message =
        new SSKKeypairMessage(
            new FreenetURI(INSERT_URI_STRING), new FreenetURI(REQUEST_URI_STRING), identifier);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "SSKKeypair goes from server to client not the other way around", exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
  }
}
