package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ExpectedMIMETest {

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @Test
  void getFieldSet_whenAllFieldsProvided_expectIdentifierGlobalAndMimeStored() {
    ExpectedMIME expectedMIME = new ExpectedMIME("req-123", true, "text/plain");

    SimpleFieldSet fieldSet = expectedMIME.getFieldSet();

    assertEquals("req-123", fieldSet.get("Identifier"));
    assertEquals("true", fieldSet.get("Global"));
    assertEquals("text/plain", fieldSet.get("Metadata.ContentType"));
  }

  @Test
  void getFieldSet_whenExpectedMimeNull_expectContentTypeOmitted() {
    ExpectedMIME expectedMIME = new ExpectedMIME("req-456", false, null);

    SimpleFieldSet fieldSet = expectedMIME.getFieldSet();

    assertEquals("req-456", fieldSet.get("Identifier"));
    assertEquals("false", fieldSet.get("Global"));
    assertNull(fieldSet.get("Metadata.ContentType"));
  }

  @Test
  void getName_whenCalled_expectLiteralName() {
    ExpectedMIME expectedMIME = new ExpectedMIME("identifier", true, "application/json");

    assertEquals("ExpectedMIME", expectedMIME.getName());
  }

  @Test
  void run_whenInvoked_expectNoInteractionsOrExceptions() {
    ExpectedMIME expectedMIME = new ExpectedMIME("identifier", true, "application/json");

    assertDoesNotThrow(() -> expectedMIME.run(handler, node));
    verifyNoInteractions(handler, node);
  }
}
