package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerOpennetGateTest {
  @Mock private Node node;
  @Mock private OpennetManager opennet;
  @Mock private OpennetPeerNode opennetPeer;
  @Mock private PeerNode nonOpennetPeer;

  @Test
  void allowPeer_whenIgnoreOpennetTrue_expectTrue() {
    PeerOpennetGate gate = new PeerOpennetGate(node);

    boolean allowed = gate.allowPeer(opennetPeer, true);

    assertTrue(allowed);
    verifyNoInteractions(node);
  }

  @Test
  void allowPeer_whenPeerNotOpennet_expectTrue() {
    PeerOpennetGate gate = new PeerOpennetGate(node);

    boolean allowed = gate.allowPeer(nonOpennetPeer, false);

    assertTrue(allowed);
    verifyNoInteractions(node);
  }

  @Test
  void allowPeer_whenOpennetEnabled_expectTrueAndForceAdd() {
    PeerOpennetGate gate = new PeerOpennetGate(node);
    when(node.getOpennet()).thenReturn(opennet);

    boolean allowed = gate.allowPeer(opennetPeer, false);

    assertTrue(allowed);
    verify(node).getOpennet();
    verify(opennet).forceAddPeer(opennetPeer, true);
  }

  @Test
  void allowPeer_whenOpennetDisabled_expectFalse() {
    PeerOpennetGate gate = new PeerOpennetGate(node);
    when(node.getOpennet()).thenReturn(null);

    boolean allowed = gate.allowPeer(opennetPeer, false);

    assertFalse(allowed);
    verify(node).getOpennet();
    verifyNoInteractions(opennet);
  }
}
