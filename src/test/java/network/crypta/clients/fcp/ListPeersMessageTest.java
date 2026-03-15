package network.crypta.clients.fcp;

import java.util.List;
import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ListPeersMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Mock private FCPServer server;

  @Mock private RuntimePorts runtimePorts;

  @Mock private PeerPort peerPort;

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
    verifyNoInteractions(server, runtimePorts, peerPort, node);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenFullAccess_sendsEachPeerFollowedByEnd() throws MessageInvalidException {
    ListPeersMessage message = new ListPeersMessage(buildFieldSet(true, true, "identifier"));
    PeerSnapshot peerOne = peerSnapshot("peer-one");
    PeerSnapshot peerTwo = peerSnapshot("peer-two");
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.list(true, true)).thenReturn(List.of(peerOne, peerTwo));

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(3)).send(captor.capture());

    List<FCPMessage> sentMessages = captor.getAllValues();
    assertEquals(3, sentMessages.size());

    PeerMessage firstPeer = (PeerMessage) sentMessages.getFirst();
    assertEquals(peerOne, firstPeer.snapshot);
    assertEquals("identifier", firstPeer.messageIdentifier);

    PeerMessage secondPeer = (PeerMessage) sentMessages.get(1);
    assertEquals(peerTwo, secondPeer.snapshot);
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
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.list(false, false)).thenReturn(List.of());

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

  private static PeerSnapshot peerSnapshot(String identity) {
    return new PeerSnapshot(
        new network.crypta.runtime.spi.PeerFieldSet(
            java.util.Map.of("identity", identity), java.util.Map.of()));
  }
}
