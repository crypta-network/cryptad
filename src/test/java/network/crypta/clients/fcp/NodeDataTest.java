package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeDataTest {

  private static final String VOLATILE_KEY = "volatile";

  @Mock private Node node;

  @ParameterizedTest
  @CsvSource({"true,true", "true,false", "false,true", "false,false"})
  void getFieldSet_whenFlagsCombination_selectsCorrectBaseFieldSet(
      boolean giveOpennetRef, boolean withPrivate) {
    SimpleFieldSet expected = new SimpleFieldSet(true);

    if (giveOpennetRef && withPrivate) {
      when(node.exportOpennetPrivateFieldSet()).thenReturn(expected);
    } else if (giveOpennetRef) {
      when(node.exportOpennetPublicFieldSet()).thenReturn(expected);
    } else if (withPrivate) {
      when(node.exportDarknetPrivateFieldSet()).thenReturn(expected);
    } else {
      when(node.exportDarknetPublicFieldSet()).thenReturn(expected);
    }

    NodeData nodeData =
        new NodeData(node, giveOpennetRef, withPrivate, /* withVolatile= */ false, null);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertSame(expected, result);
    assertNull(result.subset(VOLATILE_KEY));
    assertNull(result.get("Identifier"));
    verify(node, never()).exportVolatileFieldSet();
  }

  @Test
  void getFieldSet_whenWithVolatileAndNonEmpty_exportAddsVolatileSubset() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    SimpleFieldSet vol = new SimpleFieldSet(true);
    vol.putSingle("stat", "value");
    when(node.exportOpennetPublicFieldSet()).thenReturn(base);
    when(node.exportVolatileFieldSet()).thenReturn(vol);
    NodeData nodeData =
        new NodeData(node, /* giveOpennetRef= */ true, /* withPrivate= */ false, true, null);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertSame(base, result);
    assertSame(vol, result.subset(VOLATILE_KEY));
  }

  @Test
  void getFieldSet_whenWithVolatileAndEmpty_exportDoesNotAddVolatileSubset() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    SimpleFieldSet emptyVol = new SimpleFieldSet(true);
    when(node.exportDarknetPrivateFieldSet()).thenReturn(base);
    when(node.exportVolatileFieldSet()).thenReturn(emptyVol);
    NodeData nodeData =
        new NodeData(node, /* giveOpennetRef= */ false, /* withPrivate= */ true, true, null);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertSame(base, result);
    assertNull(result.subset(VOLATILE_KEY));
  }

  @Test
  void getFieldSet_whenIdentifierProvided_addsIdentifierField() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    when(node.exportOpennetPrivateFieldSet()).thenReturn(base);
    String identifier = "node-identifier-1";
    NodeData nodeData =
        new NodeData(node, /* giveOpennetRef= */ true, /* withPrivate= */ true, false, identifier);

    SimpleFieldSet result = nodeData.getFieldSet();

    assertSame(base, result);
    assertEquals(identifier, result.get("Identifier"));
  }

  @Test
  void getName_returnsStaticName() {
    NodeData nodeData =
        new NodeData(node, /* giveOpennetRef= */ true, /* withPrivate= */ false, false, null);

    assertEquals("NodeData", nodeData.getName());
  }

  @Test
  void run_whenCalled_throwsInvalidMessageExceptionWithIdentifier() {
    String identifier = "client-id-123";
    NodeData nodeData =
        new NodeData(
            node, /* giveOpennetRef= */ false, /* withPrivate= */ false, false, identifier);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> nodeData.run(null, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "NodeData goes from server to client not the other way around", exception.getMessage());
    assertEquals(identifier, exception.ident);
    assertFalse(exception.global);
  }

  @Test
  void run_whenIdentifierNull_throwsInvalidMessageExceptionWithNullIdentifier() {
    NodeData nodeData =
        new NodeData(node, /* giveOpennetRef= */ false, /* withPrivate= */ true, false, null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> nodeData.run(null, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertNull(exception.ident);
    assertFalse(exception.global);
  }
}
