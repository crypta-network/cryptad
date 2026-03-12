package network.crypta.client.async;

import java.util.Arrays;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SingleKeyListenerTest {

  @Mock private BaseSingleFileFetcher fetcher;
  @Mock private ClientContext context;
  @Mock private KeyBlock block;

  private static byte[] filledBytes(int len, byte value) {
    byte[] b = new byte[len];
    Arrays.fill(b, value);
    return b;
  }

  private NodeCHK newChk(byte fill) {
    return new NodeCHK(filledBytes(NodeCHK.KEY_LENGTH, fill), Key.ALGO_AES_PCFB_256_SHA256);
  }

  private NodeSSK newSsk() {
    return new NodeSSK(
        filledBytes(NodeSSK.PUBKEY_HASH_SIZE, (byte) 13),
        filledBytes(NodeSSK.E_H_DOCNAME_SIZE, (byte) 14),
        Key.ALGO_AES_PCFB_256_SHA256);
  }

  @BeforeEach
  void resetMocks() {
    // No-op placeholder to keep AAA structure consistent across tests if needed later.
  }

  @Test
  void probablyWantKey_whenKeyMatchesAndNotDone_true() {
    // Arrange
    NodeCHK key = newChk((byte) 1);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 7, true);

    // Act
    boolean result = listener.probablyWantKey(key, new byte[] {0});

    // Assert
    assertTrue(result);
  }

  @Test
  void probablyWantKey_whenDone_false() {
    // Arrange
    NodeCHK key = newChk((byte) 2);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 5, false);
    listener.onRemove();

    // Act
    boolean result = listener.probablyWantKey(key, new byte[] {0});

    // Assert
    assertFalse(result);
  }

  @Test
  void definitelyWantKey_whenKeyMatches_returnsPrio() {
    // Arrange
    NodeCHK key = newChk((byte) 3);
    short prio = 42;
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, prio, true);

    // Act
    short res = listener.definitelyWantKey(key, new byte[] {1}, context);

    // Assert
    assertEquals(prio, res);
  }

  @Test
  void definitelyWantKey_whenKeyDifferent_returnsMinusOne() {
    // Arrange
    NodeCHK key = newChk((byte) 4);
    NodeCHK other = newChk((byte) 5);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 9, false);

    // Act
    short res = listener.definitelyWantKey(other, new byte[] {1}, context);

    // Assert
    assertEquals(-1, res);
  }

  @Test
  void getRequestsForKey_whenMatches_returnsFetcherArray() {
    // Arrange
    NodeCHK key = newChk((byte) 6);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 1, false);

    // Act
    SendableGet[] reqs = listener.getRequestsForKey(key, new byte[] {2}, context);

    // Assert
    assertNotNull(reqs);
    assertEquals(1, reqs.length);
    assertEquals(fetcher, reqs[0]);
  }

  @Test
  void getRequestsForKey_whenNotMatch_returnsNull() {
    // Arrange
    NodeCHK key = newChk((byte) 7);
    NodeCHK other = newChk((byte) 8);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 1, false);

    // Act
    SendableGet[] reqs = listener.getRequestsForKey(other, new byte[] {3}, context);

    // Assert
    assertNull(reqs);
  }

  @Test
  void handleBlock_whenKeyMismatch_returnsFalseAndNoFetcherCalls() {
    // Arrange
    NodeCHK key = newChk((byte) 9);
    NodeCHK other = newChk((byte) 10);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 3, true);

    // Act
    boolean handled = listener.handleBlock(other, new byte[] {4}, block, context);

    // Assert
    assertFalse(handled);
    verify(fetcher, never()).onGotKey(any(), any(), any());
    verify(fetcher, never()).onFailure(any(), any(), any());
    verifyNoMoreInteractions(fetcher);
  }

  @Test
  void handleBlock_whenKeyMatches_callsOnGotKey_andSetsDone_andReturnsTrue() {
    // Arrange
    NodeCHK key = newChk((byte) 11);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 3, false);

    // Act
    boolean handled = listener.handleBlock(key, new byte[] {5}, block, context);

    // Assert
    assertTrue(handled);
    verify(fetcher).onGotKey(key, block, context);
    assertTrue(listener.isEmpty());
    assertEquals(0, listener.countKeys());
  }

  @Test
  void handleBlock_whenFetcherThrows_callsOnFailureWithInternalError_andSetsDone() {
    // Arrange
    NodeCHK key = newChk((byte) 12);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 3, true);
    RuntimeException boom = new RuntimeException("boom");
    doThrow(boom).when(fetcher).onGotKey(key, block, context);

    // Act
    boolean handled = listener.handleBlock(key, new byte[] {6}, block, context);

    // Assert
    assertTrue(handled);
    ArgumentCaptor<LowLevelGetException> cap = ArgumentCaptor.forClass(LowLevelGetException.class);
    ArgumentCaptor<SendableRequestItem> tokenCap =
        ArgumentCaptor.forClass(SendableRequestItem.class);
    ArgumentCaptor<ClientContext> ctxCap = ArgumentCaptor.forClass(ClientContext.class);
    verify(fetcher).onFailure(cap.capture(), tokenCap.capture(), ctxCap.capture());
    LowLevelGetException lle = cap.getValue();
    assertNull(tokenCap.getValue());
    assertEquals(context, ctxCap.getValue());
    assertEquals(LowLevelGetException.INTERNAL_ERROR, lle.code);
    assertEquals(boom, lle.getCause());
    assertTrue(listener.isEmpty());
    assertEquals(0, listener.countKeys());
  }

  @Test
  void isSSK_and_getWantedKey_whenNodeSSK_behaveAsExpected() {
    // Arrange
    NodeSSK ssk = newSsk();
    SingleKeyListener listener = new SingleKeyListener(ssk, fetcher, (short) 2, true);

    // Act
    boolean sskFlag = listener.isSSK();
    byte[] wanted = listener.getWantedKey();

    // Assert
    assertTrue(sskFlag);
    assertArrayEquals(ssk.getPubKeyHash(), wanted);
  }

  @Test
  void getWantedKey_whenNotSSK_returnsRoutingKey() {
    // Arrange
    NodeCHK chk = newChk((byte) 15);
    SingleKeyListener listener = new SingleKeyListener(chk, fetcher, (short) 2, false);

    // Act
    byte[] wanted = listener.getWantedKey();

    // Assert
    assertArrayEquals(chk.getRoutingKey(), wanted);
  }

  @Test
  void countKeys_and_isEmpty_behaviors_before_and_after_onRemove() {
    // Arrange
    NodeCHK key = newChk((byte) 16);
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, (short) 1, false);

    // Act & Assert (before)
    assertEquals(1, listener.countKeys());
    assertFalse(listener.isEmpty());

    // Act
    listener.onRemove();

    // Assert (after)
    assertEquals(0, listener.countKeys());
    assertTrue(listener.isEmpty());
    assertFalse(listener.probablyWantKey(key, new byte[] {0}));
  }

  @Test
  void accessors_returnFetcherPriorityAndPersistent() {
    // Arrange
    NodeCHK key = newChk((byte) 17);
    short prio = 77;
    boolean persistent = true;
    SingleKeyListener listener = new SingleKeyListener(key, fetcher, prio, persistent);

    // Act & Assert
    assertEquals(fetcher, listener.getHasKeyListener());
    assertEquals(prio, listener.getPriorityClass());
    assertTrue(listener.persistent());
  }
}
