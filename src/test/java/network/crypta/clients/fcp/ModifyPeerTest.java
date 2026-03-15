package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetPeerSettingsUpdate;
import network.crypta.runtime.spi.PeerPort;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModifyPeerTest {

  private static final String IDENTIFIER = "req-1";
  private static final String NODE_IDENTIFIER = "peer-123";

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @Mock FCPServer server;

  @Mock RuntimePorts runtimePorts;

  @Mock PeerPort peerPort;

  @Test
  void getName_returnsModifyPeerLiteral() {
    SimpleFieldSet fs = baseFieldSet();

    ModifyPeer modifyPeer = new ModifyPeer(fs);

    assertEquals("ModifyPeer", modifyPeer.getName());
  }

  @Test
  void getFieldSet_returnsEmptyFieldSet() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeer modifyPeer = new ModifyPeer(fs);

    assertTrue(modifyPeer.getFieldSet().isEmpty());
  }

  @Test
  void run_whenAccessDenied_throwsAccessDenied() {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeer.run(handler));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenNodeIdentifierMissing_throwsMissingField() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeer.run(handler));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verifyNoInteractions(server, runtimePorts, peerPort, node);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenPeerNotFound_sendsUnknownNodeIdentifierMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.updateDarknetPeer(any(), any()))
        .thenThrow(new UnknownPeerException(NODE_IDENTIFIER));

    modifyPeer.run(handler);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(UnknownNodeIdentifierMessage.class, captor.getValue());
    UnknownNodeIdentifierMessage sent = (UnknownNodeIdentifierMessage) captor.getValue();
    assertEquals(NODE_IDENTIFIER, sent.nodeIdentifier);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  @Test
  void run_whenPeerIsNotDarknet_throwsDarknetOnly() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.updateDarknetPeer(any(), any()))
        .thenThrow(new DarknetPeerRequiredException(NODE_IDENTIFIER));

    MessageInvalidException ex =
        assertThrows(MessageInvalidException.class, () -> modifyPeer.run(handler));

    assertEquals(ProtocolErrorMessage.DARKNET_ONLY, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    verify(handler, never()).send(any());
  }

  @Test
  void run_whenFlagsProvided_updatesPeerAndSendsPeerMessage() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("IsDisabled", "true");
    fs.putSingle("IsListenOnly", "TrUe");
    fs.putSingle("IsBurstOnly", "false");
    fs.putSingle("IgnoreSourcePort", "true");
    fs.putSingle("AllowLocalAddresses", "FALSE");
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    PeerSnapshot snapshot =
        new PeerSnapshot(
            new network.crypta.runtime.spi.PeerFieldSet(
                java.util.Map.of("identity", NODE_IDENTIFIER), java.util.Map.of()));
    when(peerPort.updateDarknetPeer(any(), any())).thenReturn(snapshot);

    modifyPeer.run(handler);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort)
        .updateDarknetPeer(
            org.mockito.ArgumentMatchers.eq(NODE_IDENTIFIER), updateCaptor.capture());
    DarknetPeerSettingsUpdate update = updateCaptor.getValue();
    assertEquals(Boolean.TRUE, update.disabled());
    assertEquals(Boolean.TRUE, update.listenOnly());
    assertEquals(Boolean.FALSE, update.burstOnly());
    assertEquals(Boolean.TRUE, update.ignoreSourcePort());
    assertEquals(Boolean.FALSE, update.allowLocalAddresses());

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler, times(1)).send(captor.capture());
    assertInstanceOf(PeerMessage.class, captor.getValue());
    PeerMessage sent = (PeerMessage) captor.getValue();
    assertEquals(snapshot, sent.snapshot);
    assertEquals(IDENTIFIER, sent.messageIdentifier);
  }

  @Test
  void run_whenIsDisabledFalse_enablesPeer() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("IsDisabled", "false");
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.updateDarknetPeer(any(), any()))
        .thenReturn(
            new PeerSnapshot(
                new network.crypta.runtime.spi.PeerFieldSet(
                    java.util.Map.of("identity", NODE_IDENTIFIER), java.util.Map.of())));

    modifyPeer.run(handler);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort)
        .updateDarknetPeer(
            org.mockito.ArgumentMatchers.eq(NODE_IDENTIFIER), updateCaptor.capture());
    assertEquals(Boolean.FALSE, updateCaptor.getValue().disabled());
    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    assertInstanceOf(PeerMessage.class, captor.getValue());
  }

  @Test
  void run_whenOptionalFieldsEmpty_doesNotInvokeMutators() throws Exception {
    SimpleFieldSet fs = baseFieldSet();
    fs.putSingle("IsDisabled", "");
    fs.putSingle("IsListenOnly", "");
    fs.putSingle("IsBurstOnly", "");
    fs.putSingle("IgnoreSourcePort", "");
    fs.putSingle("AllowLocalAddresses", "");
    ModifyPeer modifyPeer = new ModifyPeer(fs);
    when(handler.hasFullAccess()).thenReturn(true);
    when(handler.getServer()).thenReturn(server);
    when(server.runtime()).thenReturn(runtimePorts);
    when(runtimePorts.peer()).thenReturn(peerPort);
    when(peerPort.updateDarknetPeer(any(), any()))
        .thenReturn(
            new PeerSnapshot(
                new network.crypta.runtime.spi.PeerFieldSet(
                    java.util.Map.of("identity", NODE_IDENTIFIER), java.util.Map.of())));

    modifyPeer.run(handler);

    ArgumentCaptor<DarknetPeerSettingsUpdate> updateCaptor =
        ArgumentCaptor.forClass(DarknetPeerSettingsUpdate.class);
    verify(peerPort)
        .updateDarknetPeer(
            org.mockito.ArgumentMatchers.eq(NODE_IDENTIFIER), updateCaptor.capture());
    DarknetPeerSettingsUpdate update = updateCaptor.getValue();
    assertNull(update.disabled());
    assertNull(update.listenOnly());
    assertNull(update.burstOnly());
    assertNull(update.ignoreSourcePort());
    assertNull(update.allowLocalAddresses());
    verify(handler, times(1)).send(any(PeerMessage.class));
  }

  private static SimpleFieldSet baseFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", IDENTIFIER);
    fs.putSingle("NodeIdentifier", NODE_IDENTIFIER);
    return fs;
  }
}
