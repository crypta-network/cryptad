package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import java.util.List;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GetNodeTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void constructor_whenFieldsPresent_setsFlagsAndRemovesIdentifier() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("GiveOpennetRef", "true");
    fs.putSingle("WithPrivate", "true");
    fs.putSingle("WithVolatile", "true");
    String identifier = "abc12345";
    fs.putSingle("Identifier", identifier);

    GetNode getNode = new GetNode(fs);

    assertTrue(getNode.giveOpennetRef);
    assertTrue(getNode.withPrivate);
    assertTrue(getNode.withVolatile);
    assertEquals(identifier, getNode.requestIdentifier);
    assertNull(fs.get("Identifier"));
  }

  @Test
  void constructor_whenOptionalFieldsMissing_usesDefaults() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    GetNode getNode = new GetNode(fs);

    assertFalse(getNode.giveOpennetRef);
    assertFalse(getNode.withPrivate);
    assertFalse(getNode.withVolatile);
    assertNull(getNode.requestIdentifier);
  }

  @Test
  void getFieldSet_whenIdentifierPresent_returnsFieldSetWithIdentifierOnly() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "node-123");
    GetNode getNode = new GetNode(fs);

    SimpleFieldSet result = getNode.getFieldSet();

    List<String> keys = new java.util.ArrayList<>();
    Iterator<String> iterator = result.keyIterator();
    iterator.forEachRemaining(keys::add);

    assertEquals(List.of("Identifier"), keys);
    assertEquals("node-123", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenIdentifierMissing_returnsEmptyFieldSet() {
    GetNode getNode = new GetNode(new SimpleFieldSet(true));

    SimpleFieldSet result = getNode.getFieldSet();

    assertFalse(result.keyIterator().hasNext());
  }

  @Test
  void getName_returnsConstantName() {
    GetNode getNode = new GetNode(new SimpleFieldSet(true));

    assertEquals("GetNode", getNode.getName());
  }

  @Test
  void run_whenNoFullAccess_throwsAccessDeniedMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "restricted-client");
    GetNode getNode = new GetNode(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> getNode.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, exception.protocolCode);
    assertEquals("restricted-client", exception.ident);
    assertFalse(exception.global);
    assertEquals("GetNode requires full access", exception.getMessage());
  }

  @Test
  void run_whenFullAccess_sendsNodeDataWithFlags() throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("GiveOpennetRef", "true");
    fs.putSingle("WithPrivate", "false");
    fs.putSingle("WithVolatile", "true");
    fs.putSingle("Identifier", "req-42");
    GetNode getNode = new GetNode(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    ArgumentCaptor<NodeData> messageCaptor = ArgumentCaptor.forClass(NodeData.class);

    getNode.run(handler, node);

    verify(handler).send(messageCaptor.capture());
    NodeData sent = messageCaptor.getValue();
    assertSame(node, sent.node);
    assertTrue(sent.giveOpennetRef);
    assertFalse(sent.withPrivate);
    assertTrue(sent.withVolatile);
    assertEquals("req-42", sent.requestIdentifier);
  }
}
