package network.crypta.client.async;

import java.net.MalformedURLException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.keys.USK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKKeyWatchSetTest {

  @Test
  void getEditionsToFetch_whenAlreadyRunningAndSuggestedAhead_deduplicatesAndRemovesRunning()
      throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 1), cryptoKey((byte) 3), 5L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 2L, 2, false);
    USKKeyWatchSet.Lookup runningLookup = new USKKeyWatchSet.Lookup();
    runningLookup.val = 3L;
    List<USKKeyWatchSet.Lookup> alreadyRunning = new ArrayList<>(List.of(runningLookup));

    // Act
    USKKeyWatchSet.ToFetch result =
        watchSet.getEditionsToFetch(2L, secureRandom(), alreadyRunning, false, true);

    // Assert
    assertTrue(alreadyRunning.isEmpty());
    assertEquals(List.of(4L, 5L), editions(result.fetch));
    assertEquals(0, result.poll.length);
  }

  @Test
  void updateSubscriberHints_whenPersistentAndSuggestedAhead_tracksSurvivingHints()
      throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 2), cryptoKey((byte) 7), 10L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    watchSet.addHintEdition(8L, 5L);

    // Act
    watchSet.updateSubscriberHints(new Long[] {6L, 6L, 4L, 9L}, 5L);

    // Assert
    assertEquals((1L + 4L) * USKKeyWatchSet.WATCH_KEYS, watchSet.size());
    long sizeBefore = watchSet.size();
    watchSet.addHintEdition(4L, 5L);
    assertEquals(sizeBefore, watchSet.size());
  }

  @Test
  void definitelyWantKey_whenKeyNotNodeSsk_returnsMinusOne() throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 6), cryptoKey((byte) 11), 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    Key key = mock(Key.class);

    // Act
    short priority = watchSet.definitelyWantKey(key, 0L, (short) 2);

    // Assert
    assertEquals(-1, priority);
  }

  @Test
  void probablyWantKey_whenPubKeyHashMismatch_returnsFalse() throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 8), cryptoKey((byte) 12), 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    USK otherUsk = newUsk(createPubKeyHash((byte) 9), cryptoKey((byte) 12), 0L);
    NodeSSK key = nodeKeyForEditionZero(otherUsk);

    // Act
    boolean wanted = watchSet.probablyWantKey(key, 0L);

    // Assert
    assertFalse(wanted);
  }

  @Test
  void getDatastoreCheckers_whenHintsPresent_returnsCheckers() throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 10), cryptoKey((byte) 13), 2L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);

    // Act
    List<USKKeyWatchSet.KeyList.StoreSubChecker> checkers = watchSet.getDatastoreCheckers(0L);

    // Assert
    assertNotNull(checkers);
    assertEquals(2, checkers.size());
    assertEquals(USKKeyWatchSet.WATCH_KEYS, checkers.get(0).keysToCheck.length);
    assertEquals(USKKeyWatchSet.WATCH_KEYS, checkers.get(1).keysToCheck.length);
  }

  @Test
  void decode_whenDocnameMismatch_throwsVerifyException() throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 11), cryptoKey((byte) 14), 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    ClientSSK csk = usk.getSSK(0L);
    byte[] mismatched = copyEhDocname(csk);

    mismatched[0] ^= 0x01;
    NodeSSK nodeKey = new NodeSSK(usk.getPubKeyHash(), mismatched, Key.ALGO_AES_PCFB_256_SHA256);
    SSKBlock block = mock(SSKBlock.class);
    when(block.getKey()).thenReturn(nodeKey);

    // Act + Assert
    assertThrows(SSKVerifyException.class, () -> watchSet.decode(block, 0L));
  }

  @Test
  void matchBlock_whenNonSskBlock_returnsNull() throws Exception {
    // Arrange
    USK usk = newUsk(createPubKeyHash((byte) 13), cryptoKey((byte) 22), 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    NodeSSK key = nodeKeyForEditionZero(usk);
    KeyBlock block = mock(KeyBlock.class);

    // Act
    USKKeyWatchSet.MatchedBlock matched = watchSet.matchBlock(key, block, 0L);

    // Assert
    assertNull(matched);
  }

  private static byte[] createPubKeyHash(byte seed) {
    byte[] data = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    Arrays.fill(data, seed);
    return data;
  }

  private static List<Long> editions(USKKeyWatchSet.Lookup[] lookups) {
    return Arrays.stream(lookups).map(lookup -> lookup.val).sorted().toList();
  }

  private static NodeSSK nodeKeyForEditionZero(USK usk) {
    ClientSSK csk = usk.getSSK(0L);
    return new NodeSSK(usk.getPubKeyHash(), csk.ehDocname, Key.ALGO_AES_PCFB_256_SHA256);
  }

  private static byte[] copyEhDocname(ClientSSK csk) {
    assertNotNull(csk);
    assertNotNull(csk.ehDocname);
    return csk.ehDocname.clone();
  }

  private static USK newUsk(byte[] pubKeyHash, byte[] cryptoKey, long suggestedEdition)
      throws MalformedURLException {
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    return new USK(pubKeyHash, cryptoKey, extras, "site", suggestedEdition);
  }

  private static Random secureRandom() {
    return new SecureRandom();
  }

  private static byte[] cryptoKey(byte seed) {
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    Arrays.fill(cryptoKey, seed);
    return cryptoKey;
  }
}
