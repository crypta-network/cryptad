package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.crypt.KeyAgreementSchemeContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeHandshakeTest {

  @Mock private PeerNode peerNode;
  @Mock private KeyAgreementSchemeContext context;

  @Test
  void constructor_whenValidKeys_expectDistinctCiphersCreated() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x11), fixedKey((byte) 0x22), fixedKey((byte) 0x33));

    assertNotNull(handshake.incomingSetupCipher());
    assertNotNull(handshake.outgoingSetupCipher());
    assertNotNull(handshake.anonymousInitiatorSetupCipher());
    assertNotSame(handshake.incomingSetupCipher(), handshake.outgoingSetupCipher());
    assertNotSame(handshake.incomingSetupCipher(), handshake.anonymousInitiatorSetupCipher());
    assertNotSame(handshake.outgoingSetupCipher(), handshake.anonymousInitiatorSetupCipher());
  }

  @Test
  void getKeyAgreementSchemeContext_whenNotSet_expectNull() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x01), fixedKey((byte) 0x02), fixedKey((byte) 0x03));

    assertNull(handshake.getKeyAgreementSchemeContext());
  }

  @Test
  void setKeyAgreementSchemeContext_whenValidContext_expectStored() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x04), fixedKey((byte) 0x05), fixedKey((byte) 0x06));

    handshake.setKeyAgreementSchemeContext(context);

    assertSame(context, handshake.getKeyAgreementSchemeContext());
  }

  @Test
  void clearKeyAgreementSchemeContext_whenSet_expectCleared() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x07), fixedKey((byte) 0x08), fixedKey((byte) 0x09));
    handshake.setKeyAgreementSchemeContext(context);

    handshake.clearKeyAgreementSchemeContext();

    assertNull(handshake.getKeyAgreementSchemeContext());
  }

  @Test
  void setKeyAgreementSchemeContext_whenWrongType_expectClassCastException() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x0A), fixedKey((byte) 0x0B), fixedKey((byte) 0x0C));

    assertThrows(ClassCastException.class, () -> handshake.setKeyAgreementSchemeContext("not-a-context"));
  }

  @Test
  void hasLiveHandshake_whenContextMissing_expectFalse() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x0D), fixedKey((byte) 0x0E), fixedKey((byte) 0x0F));

    boolean live = handshake.hasLiveHandshake(12345L);

    assertFalse(live);
  }

  @Test
  void hasLiveHandshake_whenWithinTimeoutBoundary_expectTrue() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x10), fixedKey((byte) 0x11), fixedKey((byte) 0x12));
    when(context.lastUsedTime()).thenReturn(1_000L);
    handshake.setKeyAgreementSchemeContext(context);

    boolean live = handshake.hasLiveHandshake(1_000L + Node.HANDSHAKE_TIMEOUT);

    assertTrue(live);
  }

  @Test
  void hasLiveHandshake_whenPastTimeout_expectFalse() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x13), fixedKey((byte) 0x14), fixedKey((byte) 0x15));
    when(context.lastUsedTime()).thenReturn(2_000L);
    handshake.setKeyAgreementSchemeContext(context);

    boolean live = handshake.hasLiveHandshake(2_000L + Node.HANDSHAKE_TIMEOUT + 1);

    assertFalse(live);
  }

  @Test
  void completedHandshake_whenCalled_expectDelegatesToPeerNode() {
    PeerNodeHandshake handshake =
        new PeerNodeHandshake(peerNode, fixedKey((byte) 0x16), fixedKey((byte) 0x17), fixedKey((byte) 0x18));
    HandshakeCompletionParams params = new HandshakeCompletionParams();
    when(peerNode.completeHandshake(params)).thenReturn(42L);

    long trackerId = handshake.completedHandshake(params);

    assertEquals(42L, trackerId);
    verify(peerNode).completeHandshake(params);
  }

  private static byte[] fixedKey(byte value) {
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) {
      key[i] = value;
    }
    return key;
  }
}
