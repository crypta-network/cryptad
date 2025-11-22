package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ListPeersMessageTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private Node node;
  @Mock private PeerNode peerOne;
  @Mock private PeerNode peerTwo;

  @Test
  void constructor_whenFieldsPresent_setsFlagsAndStripsIdentifierFromFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putSingle("WithMetadata", "true");
    fs.putSingle("WithVolatile", "false");
    fs.putSingle("Identifier", "req-123");

    ListPeersMessage message = new ListPeersMessage(fs);

    assertTrue(message.withMetadata);
    assertFalse(message.withVolatile);
    assertEquals("req-123", message.requestIdentifier);
    assertNull(fs.get("Identifier"));
  }

  @Test
  void constructor_whenFieldsMissing_usesDefaults() {
    SimpleFieldSet fs = new SimpleFieldSet(false);

    ListPeersMessage message = new ListPeersMessage(fs);

    assertFalse(message.withMetadata);
    assertFalse(message.withVolatile);
    assertNull(message.requestIdentifier);
  }

  @Test
  void run_whenNoFullAccess_throwsAccessDeniedAndDoesNotSend() {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(false, false, "id-1"));
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    assertEquals("id-1", ex.ident);
    verify(node, never()).getPeerNodes();
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenFullAccess_sendsEachPeerFollowedByEnd() throws MessageInvalidException {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(true, true, "identifier"));
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.getPeerNodes()).thenReturn(new PeerNode[] {peerOne, peerTwo});

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(3)).send(captor.capture());

    List<FCPMessage> sentMessages = captor.getAllValues();
    assertEquals(3, sentMessages.size());

    PeerMessage firstPeer = (PeerMessage) sentMessages.getFirst();
    assertEquals(peerOne, firstPeer.pn);
    assertTrue(firstPeer.withMetadata);
    assertTrue(firstPeer.withVolatile);
    assertEquals("identifier", firstPeer.messageIdentifier);

    PeerMessage secondPeer = (PeerMessage) sentMessages.get(1);
    assertEquals(peerTwo, secondPeer.pn);
    assertTrue(secondPeer.withMetadata);
    assertTrue(secondPeer.withVolatile);
    assertEquals("identifier", secondPeer.messageIdentifier);

    EndListPeersMessage endMessage = (EndListPeersMessage) sentMessages.get(2);
    assertEquals("identifier", endMessage.getFieldSet().get("Identifier"));

    InOrder order = inOrder(handler);
    order.verify(handler).send(sentMessages.get(0));
    order.verify(handler).send(sentMessages.get(1));
    order.verify(handler).send(sentMessages.get(2));
  }

  @Test
  void run_whenNoPeersStillEmitsEndMarker() throws MessageInvalidException {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(false, false, null));
    when(handler.hasFullAccess()).thenReturn(true);
    when(node.getPeerNodes()).thenReturn(new PeerNode[0]);

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(EndListPeersMessage.class, captor.getValue());
  }

  @Test
  void getName_returnsProtocolLiteral() {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(false, false, null));

    assertEquals("ListPeers", message.getName());
  }

  @Test
  void getFieldSet_returnsEmptyFieldSet() {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(false, false, null));

    assertTrue(message.getFieldSet().isEmpty());
  }

  private SimpleFieldSet buildFieldSet(boolean withMetadata, boolean withVolatile, String id) {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.putSingle("WithMetadata", Boolean.toString(withMetadata));
    fs.putSingle("WithVolatile", Boolean.toString(withVolatile));
    if (id != null) {
      fs.putSingle("Identifier", id);
    }
    return fs;
  }
}
