package network.crypta.clients.fcp;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import network.crypta.node.Node;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GetNodeTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private NodeInfoPort nodeInfoPort;

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
    verifyNoInteractions(server, runtimePorts, nodeInfoPort, node);
  }

  @ParameterizedTest
  @CsvSource({
    "true,true,OPENNET_PRIVATE",
    "true,false,OPENNET_PUBLIC",
    "false,true,DARKNET_PRIVATE",
    "false,false,DARKNET_PUBLIC"
  })
  void run_whenFullAccess_requestsMatchingReferenceViewAndSendsNodeData(
      boolean giveOpennetRef, boolean withPrivate, NodeReferenceView expectedView)
      throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("GiveOpennetRef", Boolean.toString(giveOpennetRef));
    fs.putSingle("WithPrivate", Boolean.toString(withPrivate));
    fs.putSingle("WithVolatile", "true");
    fs.putSingle("Identifier", "req-42");
    GetNode getNode = new GetNode(fs);
    NodeReferenceSnapshot snapshot =
        new NodeReferenceSnapshot(new NodeFieldSet(Map.of("identity", "alpha"), Map.of()));
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.nodeInfo()).thenReturn(nodeInfoPort);
    when(nodeInfoPort.exportReference(expectedView, true)).thenReturn(snapshot);
    ArgumentCaptor<NodeData> messageCaptor = ArgumentCaptor.forClass(NodeData.class);

    getNode.run(handler, node);

    verify(nodeInfoPort).exportReference(expectedView, true);
    verify(handler).send(messageCaptor.capture());
    NodeData sent = messageCaptor.getValue();
    assertEquals(snapshot, sent.snapshot);
    assertEquals("req-42", sent.requestIdentifier);
    verifyNoInteractions(node);
  }
}
