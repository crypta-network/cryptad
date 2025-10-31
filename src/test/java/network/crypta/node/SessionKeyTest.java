package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import network.crypta.crypt.BlockCipher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SessionKeyTest {

  @Test
  void constructor_whenGivenValidInputs_assignsFieldsCorrectly() {
    // Arrange
    PeerNode parent = mock(PeerNode.class);
    BlockCipher outgoing = mock(BlockCipher.class);
    BlockCipher incoming = mock(BlockCipher.class);
    BlockCipher iv = mock(BlockCipher.class);
    byte[] outgoingKey = new byte[] {1, 2, 3};
    byte[] incomingKey = new byte[] {4, 5, 6};
    byte[] ivNonce = new byte[] {7, 8};
    byte[] hmacKey = new byte[] {9, 10, 11, 12};
    NewPacketFormatKeyContext ctx = mock(NewPacketFormatKeyContext.class);
    long trackerId = 42L;

    // Act
    SessionKey key =
        new SessionKey(
            parent,
            outgoing,
            outgoingKey,
            incoming,
            incomingKey,
            iv,
            ivNonce,
            hmacKey,
            ctx,
            trackerId);

    // Assert
    assertSame(parent, key.pn, "Parent PeerNode should be stored by reference");
    assertSame(outgoing, key.outgoingCipher, "Outgoing cipher should match reference");
    assertSame(incoming, key.incommingCipher, "Incoming cipher should match reference");
    assertSame(iv, key.ivCipher, "IV cipher should match reference");
    assertSame(ctx, key.packetContext, "Packet context should match reference");
    assertArrayEquals(outgoingKey, key.outgoingKey, "Outgoing key bytes should match");
    assertArrayEquals(incomingKey, key.incommingKey, "Incoming key bytes should match");
    assertArrayEquals(ivNonce, key.ivNonce, "IV nonce bytes should match");
    assertArrayEquals(hmacKey, key.hmacKey, "HMAC key bytes should match");
    assertEquals(trackerId, key.trackerID, "Tracker ID should match");
  }

  @Test
  void disconnected_whenCalled_delegatesToContext() {
    // Arrange
    NewPacketFormatKeyContext ctx = mock(NewPacketFormatKeyContext.class);
    SessionKey key =
        new SessionKey(
            /*parent*/ null,
            /*outgoingCipher*/ null,
            /*outgoingKey*/ null,
            /*incommingCipher*/ null,
            /*incommingKey*/ null,
            /*ivCipher*/ null,
            /*ivNonce*/ null,
            /*hmacKey*/ null,
            /*context*/ ctx,
            /*trackerID*/ 7L);

    // Act
    key.disconnected();

    // Assert
    verify(ctx).disconnected();
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void constructor_whenNullValuesProvided_storesNulls() {
    // Arrange
    // All optional dependencies set to null; only trackerId is meaningful
    long trackerId = -123L;

    // Act
    SessionKey key =
        new SessionKey(
            /*parent*/ null,
            /*outgoingCipher*/ null,
            /*outgoingKey*/ null,
            /*incommingCipher*/ null,
            /*incommingKey*/ null,
            /*ivCipher*/ null,
            /*ivNonce*/ null,
            /*hmacKey*/ null,
            /*context*/ null,
            trackerId);

    // Assert
    assertNull(key.pn, "Parent should be null");
    assertNull(key.outgoingCipher, "Outgoing cipher should be null");
    assertNull(key.incommingCipher, "Incoming cipher should be null");
    assertNull(key.ivCipher, "IV cipher should be null");
    assertNull(key.outgoingKey, "Outgoing key should be null");
    assertNull(key.incommingKey, "Incoming key should be null");
    assertNull(key.ivNonce, "IV nonce should be null");
    assertNull(key.hmacKey, "HMAC key should be null");
    assertNull(key.packetContext, "Context should be null");
    assertEquals(trackerId, key.trackerID, "Tracker ID should match");
  }

  @Test
  void constructor_doesNotDefensivelyCopyArrays_mutationReflectsInFields() {
    // Arrange
    byte[] outgoingKey = new byte[] {1, 2, 3};
    byte[] incomingKey = new byte[] {4, 5, 6};
    byte[] ivNonce = new byte[] {7, 8};
    byte[] hmacKey = new byte[] {9, 10, 11, 12};

    SessionKey key =
        new SessionKey(
            null, null, outgoingKey, null, incomingKey, null, ivNonce, hmacKey, null, 0L);

    // Act
    outgoingKey[0] = 99;
    incomingKey[1] = 88;
    ivNonce[0] = 77;
    hmacKey[3] = 66;

    // Assert
    assertEquals(99, key.outgoingKey[0], "Outgoing key reference should not be copied");
    assertEquals(88, key.incommingKey[1], "Incoming key reference should not be copied");
    assertEquals(77, key.ivNonce[0], "IV nonce reference should not be copied");
    assertEquals(66, key.hmacKey[3], "HMAC key reference should not be copied");
  }
}
