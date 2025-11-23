package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class URIGeneratedMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void getFieldSet_whenConstructedWithValues_containsUriIdentifierAndGlobalFlag(boolean global)
      throws MalformedURLException {
    // Arrange
    FreenetURI uri = new FreenetURI("KSK@some-doc");
    String identifier = "id-123";
    URIGeneratedMessage message = new URIGeneratedMessage(uri, identifier, global);

    // Act
    SimpleFieldSet fieldSet = message.getFieldSet();

    // Assert
    assertEquals(uri.toString(), fieldSet.get("URI"));
    assertEquals(identifier, fieldSet.get("Identifier"));
    assertEquals(Boolean.toString(global), fieldSet.get("Global"));
    assertEquals(Set.of("URI", "Identifier", "Global"), toKeySet(fieldSet));
  }

  @Test
  void getName_whenCalled_returnsURIGeneratedLiteral() throws MalformedURLException {
    // Arrange
    URIGeneratedMessage message =
        new URIGeneratedMessage(new FreenetURI("KSK@another"), "name-test", false);

    // Act
    String result = message.getName();

    // Assert
    assertEquals("URIGenerated", result);
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidExceptionWithProtocolDetails()
      throws MalformedURLException {
    // Arrange
    String identifier = "client-identifier";
    URIGeneratedMessage message =
        new URIGeneratedMessage(new FreenetURI("KSK@run-check"), identifier, true);

    // Act + Assert
    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "URIGenerated goes from server to client not the other way around", exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
    verifyNoInteractions(handler, node);
  }

  private Set<String> toKeySet(SimpleFieldSet fieldSet) {
    Set<String> keys = new HashSet<>();
    Iterator<String> iterator = fieldSet.toplevelKeyIterator();
    while (iterator.hasNext()) {
      keys.add(iterator.next());
    }
    return keys;
  }
}
