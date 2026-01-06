package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerMessageTest {

  @Mock private PeerNode peerNode;
  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void getName_whenCalled_returnsPeerConstant() {
    PeerMessage message = new PeerMessage(peerNode, false, false, null);

    assertEquals("Peer", message.getName());
  }

  @Test
  void getFieldSet_whenAllDataPresent_addsMetadataVolatileAndIdentifier() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    base.putSingle("peerKey", "peerValue");
    SimpleFieldSet metadata = new SimpleFieldSet(true);
    metadata.putSingle("metaKey", "metaValue");
    SimpleFieldSet volatileFs = new SimpleFieldSet(true);
    volatileFs.putSingle("volKey", "volValue");
    when(peerNode.exportFieldSet()).thenReturn(base);
    when(peerNode.exportMetadataFieldSet(anyLong())).thenReturn(metadata);
    when(peerNode.exportVolatileFieldSet()).thenReturn(volatileFs);
    PeerMessage message = new PeerMessage(peerNode, true, true, "identifier-1");

    SimpleFieldSet result = message.getFieldSet();

    assertSame(base, result, "PeerMessage should reuse the base field set from the peer node");
    assertEquals("peerValue", result.get("peerKey"));
    assertSame(metadata, result.subset("metadata"));
    assertSame(volatileFs, result.subset("volatile"));
    assertEquals("metaValue", result.get("metadata.metaKey"));
    assertEquals("volValue", result.get("volatile.volKey"));
    assertEquals("identifier-1", result.get("Identifier"));
    verify(peerNode).exportFieldSet();
    verify(peerNode).exportMetadataFieldSet(anyLong());
    verify(peerNode).exportVolatileFieldSet();
    verifyNoMoreInteractions(peerNode);
  }

  @Test
  void getFieldSet_whenNoMetadataOrVolatileFlags_skipExports() {
    when(peerNode.exportFieldSet()).thenReturn(new SimpleFieldSet(true));
    PeerMessage message = new PeerMessage(peerNode, false, false, null);

    SimpleFieldSet result = message.getFieldSet();

    assertNull(result.subset("metadata"));
    assertNull(result.subset("volatile"));
    assertNull(result.get("Identifier"));
    verify(peerNode).exportFieldSet();
    verify(peerNode, never()).exportMetadataFieldSet(anyLong());
    verify(peerNode, never()).exportVolatileFieldSet();
    verifyNoMoreInteractions(peerNode);
  }

  @Test
  void getFieldSet_whenMetadataEmpty_skipsMetadataSubsetButCallsExport() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    when(peerNode.exportFieldSet()).thenReturn(base);
    when(peerNode.exportMetadataFieldSet(anyLong())).thenReturn(new SimpleFieldSet(true));
    PeerMessage message = new PeerMessage(peerNode, true, false, null);
    long start = System.currentTimeMillis();

    SimpleFieldSet result = message.getFieldSet();

    long end = System.currentTimeMillis();
    assertSame(base, result);
    assertNull(result.subset("metadata"));
    ArgumentCaptor<Long> timeCaptor = ArgumentCaptor.forClass(Long.class);
    verify(peerNode).exportFieldSet();
    verify(peerNode).exportMetadataFieldSet(timeCaptor.capture());
    assertTrue(
        timeCaptor.getValue() >= start && timeCaptor.getValue() <= end,
        "Timestamp provided to exportMetadataFieldSet should be the current time");
    verify(peerNode, never()).exportVolatileFieldSet();
    verifyNoMoreInteractions(peerNode);
  }

  @Test
  void getFieldSet_whenVolatileEmpty_skipsVolatileSubsetButCallsExport() {
    SimpleFieldSet base = new SimpleFieldSet(true);
    when(peerNode.exportFieldSet()).thenReturn(base);
    when(peerNode.exportVolatileFieldSet()).thenReturn(new SimpleFieldSet(true));
    PeerMessage message = new PeerMessage(peerNode, false, true, null);

    SimpleFieldSet result = message.getFieldSet();

    assertSame(base, result);
    assertNull(result.subset("volatile"));
    verify(peerNode).exportFieldSet();
    verify(peerNode).exportVolatileFieldSet();
    verify(peerNode, never()).exportMetadataFieldSet(anyLong());
    verifyNoMoreInteractions(peerNode);
  }

  @Test
  void run_whenCalled_throwsInvalidMessageException() {
    PeerMessage message = new PeerMessage(peerNode, false, false, null);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals("Peer goes from server to client not the other way around", thrown.getMessage());
    assertNull(thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verifyNoInteractions(handler, node);
  }
}
