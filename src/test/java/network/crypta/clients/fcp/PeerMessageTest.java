package network.crypta.clients.fcp;

import java.util.Map;
import network.crypta.node.Node;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerMessageTest {

  @Mock private FCPConnectionHandler handler;

  @Mock private Node node;

  @Test
  void getName_whenCalled_returnsPeerConstant() {
    PeerMessage message = new PeerMessage(PeerSnapshot.empty(), null);

    assertEquals("Peer", message.getName());
  }

  @Test
  void getFieldSet_whenAllDataPresent_rebuildsSnapshotTreeAndIdentifier() {
    PeerSnapshot snapshot =
        new PeerSnapshot(
            new PeerFieldSet(
                Map.of("peerKey", "peerValue"),
                Map.of(
                    "metadata",
                    new PeerFieldSet(Map.of("metaKey", "metaValue"), Map.of()),
                    "volatile",
                    new PeerFieldSet(Map.of("volKey", "volValue"), Map.of()),
                    "nested",
                    new PeerFieldSet(
                        Map.of(),
                        Map.of(
                            "child",
                            new PeerFieldSet(Map.of("leafKey", "leafValue"), Map.of()))))));
    PeerMessage message = new PeerMessage(snapshot, "identifier-1");

    SimpleFieldSet result = message.getFieldSet();

    assertEquals("peerValue", result.get("peerKey"));
    assertEquals("metaValue", result.get("metadata.metaKey"));
    assertEquals("volValue", result.get("volatile.volKey"));
    assertEquals("leafValue", result.get("nested.child.leafKey"));
    assertEquals("identifier-1", result.get("Identifier"));
  }

  @Test
  void getFieldSet_whenSnapshotHasOnlyRootValues_omitsOptionalSubsets() {
    PeerMessage message =
        new PeerMessage(
            new PeerSnapshot(new PeerFieldSet(Map.of("identity", "alpha"), Map.of())), null);

    SimpleFieldSet result = message.getFieldSet();

    assertNull(result.subset("metadata"));
    assertNull(result.subset("volatile"));
    assertNull(result.get("Identifier"));
    assertEquals("alpha", result.get("identity"));
    assertNull(result.subset("nested"));
  }

  @Test
  void run_whenCalled_throwsInvalidMessageException() {
    PeerMessage message = new PeerMessage(PeerSnapshot.empty(), null);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals("Peer goes from server to client not the other way around", thrown.getMessage());
    assertNull(thrown.ident);
    assertFalse(thrown.global, "Expected non-global error");
    verifyNoInteractions(handler, node);
  }
}
