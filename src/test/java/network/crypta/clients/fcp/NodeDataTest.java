package network.crypta.clients.fcp;

import java.util.Map;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeDataTest {

  @Test
  void getFieldSet_whenSnapshotContainsNestedValues_rebuildsFieldSetRecursively() {
    NodeReferenceSnapshot snapshot =
        new NodeReferenceSnapshot(
            new NodeFieldSet(
                Map.of("identity", "alpha"),
                Map.of(
                    "physical", new NodeFieldSet(Map.of("address", "127.0.0.1"), Map.of()),
                    "volatile", new NodeFieldSet(Map.of("uptimeSeconds", "42"), Map.of()))));
    NodeData nodeData = new NodeData(snapshot, "node-identifier-1");

    SimpleFieldSet result = nodeData.getFieldSet();

    assertEquals("alpha", result.get("identity"));
    assertEquals("127.0.0.1", result.get("physical.address"));
    assertEquals("42", result.get("volatile.uptimeSeconds"));
    assertEquals("node-identifier-1", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenSnapshotContainsEmptySubset_expectEmptySubsetOmitted() {
    NodeReferenceSnapshot snapshot =
        new NodeReferenceSnapshot(
            new NodeFieldSet(
                Map.of("identity", "alpha"),
                Map.of(
                    "empty",
                    NodeFieldSet.empty(),
                    "present",
                    new NodeFieldSet(Map.of("name", "beta"), Map.of()))));
    NodeData nodeData = new NodeData(snapshot, null);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertEquals("alpha", result.get("identity"));
    assertEquals("beta", result.get("present.name"));
    assertNull(result.subset("empty"));
  }

  @Test
  void getFieldSet_whenSnapshotEmpty_expectEmptyFieldSetWithoutIdentifier() {
    NodeData nodeData = new NodeData(NodeReferenceSnapshot.empty(), null);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertTrue(result.directKeys().isEmpty());
    assertTrue(result.directSubsets().isEmpty());
  }

  @Test
  void getName_returnsStaticName() {
    NodeData nodeData = new NodeData(NodeReferenceSnapshot.empty(), null);

    assertEquals("NodeData", nodeData.getName());
  }

  @Test
  void run_whenCalled_throwsInvalidMessageExceptionWithIdentifier() {
    String identifier = "client-id-123";
    NodeData nodeData = new NodeData(NodeReferenceSnapshot.empty(), identifier);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> nodeData.run(null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "NodeData goes from server to client not the other way around", exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
  }

  @Test
  void run_whenIdentifierNull_throwsInvalidMessageExceptionWithNullIdentifier() {
    NodeData nodeData = new NodeData(NodeReferenceSnapshot.empty(), null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> nodeData.run(null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
