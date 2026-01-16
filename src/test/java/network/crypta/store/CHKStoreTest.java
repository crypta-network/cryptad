package network.crypta.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CHKStoreTest {

  @Mock private FreenetStore<CHKBlock> mockStore;

  @Captor private ArgumentCaptor<byte[]> routingKeyCaptor;

  @Captor private ArgumentCaptor<byte[]> fullKeyCaptor;

  private CHKStore sut;

  @BeforeEach
  void setup() {
    sut = new CHKStore();
    sut.setStore(mockStore);
  }

  // ---------- Simple invariants ----------

  @Test
  @DisplayName("collisionPossible returns false for CHKStore")
  void collisionPossible_alwaysFalse() {
    assertFalse(sut.collisionPossible());
  }

  @Test
  void dataLength_matchesCHKBlockConstant() {
    assertEquals(CHKBlock.DATA_LENGTH, sut.dataLength());
  }

  @Test
  void headerLength_matchesCHKBlockConstant() {
    assertEquals(CHKBlock.TOTAL_HEADERS_LENGTH, sut.headerLength());
  }

  @Test
  void fullKeyLength_matchesNodeCHKConstant() {
    assertEquals(NodeCHK.FULL_KEY_LENGTH, sut.fullKeyLength());
  }

  @Test
  void routingKeyLength_matchesNodeCHKConstant() {
    assertEquals(NodeCHK.KEY_LENGTH, sut.routingKeyLength());
  }

  @Test
  void storeFullKeys_returnsTrue() {
    assertTrue(sut.storeFullKeys());
  }

  @Test
  void constructNeedsKey_returnsFalse() {
    assertFalse(sut.constructNeedsKey());
  }

  @Test
  void totalBlockSize_sumsAllParts() {
    int expected =
        CHKBlock.DATA_LENGTH
            + CHKBlock.TOTAL_HEADERS_LENGTH
            + NodeCHK.FULL_KEY_LENGTH
            + NodeCHK.KEY_LENGTH;
    assertEquals(expected, sut.getTotalBlockSize());
  }

  // ---------- construct(...) ----------

  @Test
  void construct_whenNullData_throwsCHKVerifyException() {
    CHKVerifyException ex =
        assertThrows(
            CHKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(
                        null, newHeadersSha256(), null, validFullKey(Key.ALGO_AES_PCFB_256_SHA256)),
                    new StoreCallback.ConstructOptions(false, false, new BlockMetadata()),
                    null));
    assertEquals("Need either data and headers", ex.getMessage());
  }

  @Test
  void construct_whenNullHeaders_throwsCHKVerifyException() {
    CHKVerifyException ex =
        assertThrows(
            CHKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(
                        new byte[CHKBlock.DATA_LENGTH],
                        null,
                        null,
                        validFullKey(Key.ALGO_AES_PCFB_256_SHA256)),
                    new StoreCallback.ConstructOptions(false, false, new BlockMetadata()),
                    null));
    assertEquals("Need either data and headers", ex.getMessage());
  }

  @Test
  void construct_whenValidBytes_buildsCHKBlockWithAlgorithmFromFullKey() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    byte[] headers = newHeadersSha256();
    byte algo = Key.ALGO_AES_CTR_256_SHA256;
    byte[] fullKey = validFullKey(algo);

    CHKBlock block =
        sut.construct(
            new StoreCallback.BlockPayload(data, headers, null, fullKey),
            new StoreCallback.ConstructOptions(false, false, new BlockMetadata()),
            null);

    assertNotNull(block);
    // CHKBlock holds the same backing arrays; verify identity to ensure no copies were made.
    assertSame(data, block.getRawData());
    assertSame(headers, block.getRawHeaders());
    // Algorithm recorded in the NodeCHK is exposed via the low 8 bits of getType().
    assertEquals(algo & 0xFF, block.getKey().getType() & 0xFF);
  }

  // ---------- routingKeyFromFullKey(...) delegation ----------

  @Test
  void routingKeyFromFullKey_when32Bytes_returnsSameReference() {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    byte[] out = sut.routingKeyFromFullKey(rk);
    assertSame(rk, out);
  }

  @Test
  void routingKeyFromFullKey_whenValidFullKey_extractsRoutingKey() {
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] fullKey = validFullKey(algo);
    byte[] out = sut.routingKeyFromFullKey(fullKey);
    assertNotNull(out);
    assertEquals(NodeCHK.KEY_LENGTH, out.length);
    // Expect the exact bytes from fullKey after the 2-byte header
    assertArrayEquals(slice(fullKey, 2, 2 + NodeCHK.KEY_LENGTH), out);
  }

  @Test
  void routingKeyFromFullKey_whenInvalidHeader_returnsFirst32BytesCopy() {
    byte[] bogusFullKey = new byte[NodeCHK.FULL_KEY_LENGTH];
    // Deliberately set an invalid base type/algorithm header
    bogusFullKey[0] = 0x55;
    bogusFullKey[1] = (byte) 0xEE;
    // Embed a recognizable routing-key prefix to assert copy semantics
    for (int i = 0; i < NodeCHK.KEY_LENGTH; i++) bogusFullKey[i] = (byte) i;

    byte[] out = sut.routingKeyFromFullKey(bogusFullKey);
    assertNotNull(out);
    assertEquals(NodeCHK.KEY_LENGTH, out.length);
    assertArrayEquals(slice(bogusFullKey, 0, NodeCHK.KEY_LENGTH), out);
    // Different reference because NodeCHK returns a copy in this recovery path
    Assertions.assertNotSame(bogusFullKey, out);
  }

  @Test
  void routingKeyFromFullKey_whenInvalidLength_returnsNull() {
    byte[] wrong = new byte[17];
    assertNull(sut.routingKeyFromFullKey(wrong));
  }

  // ---------- fetch(...) delegation ----------

  @Test
  void fetch_delegatesToStoreWithDerivedKeys() throws Exception {
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    for (int i = 0; i < rk.length; i++) rk[i] = (byte) (i + 1);
    NodeCHK chk = new NodeCHK(rk, algo);

    CHKBlock expected =
        CHKBlock.construct(new byte[CHKBlock.DATA_LENGTH], newHeadersSha256(), algo);
    when(mockStore.fetch(
            any(byte[].class),
            any(byte[].class),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            anyBoolean(),
            any(BlockMetadata.class)))
        .thenReturn(expected);

    BlockMetadata meta = new BlockMetadata();
    CHKBlock got = sut.fetch(chk, /*dontPromote*/ true, /*ignoreOldBlocks*/ false, meta);
    assertSame(expected, got);

    verify(mockStore)
        .fetch(
            routingKeyCaptor.capture(),
            fullKeyCaptor.capture(),
            /*dontPromote*/ ArgumentMatchers.eq(true),
            /*canReadClientCache*/ ArgumentMatchers.eq(false),
            /*canReadSlashdotCache*/ ArgumentMatchers.eq(false),
            /*ignoreOldBlocks*/ ArgumentMatchers.eq(false),
            ArgumentMatchers.same(meta));

    assertArrayEquals(chk.getRoutingKey(), routingKeyCaptor.getValue());
    assertArrayEquals(chk.getFullKey(), fullKeyCaptor.getValue());
  }

  // ---------- put(...) delegation and exception path ----------

  @Test
  void put_delegatesWithRawBuffersAndFlags() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    byte[] headers = newHeadersSha256();
    CHKBlock block = CHKBlock.construct(data, headers, Key.ALGO_AES_PCFB_256_SHA256);

    sut.put(block, /*isOldBlock*/ true);

    verify(mockStore)
        .put(
            ArgumentMatchers.same(block),
            ArgumentMatchers.same(block.getRawData()),
            ArgumentMatchers.same(block.getRawHeaders()),
            /*overwrite*/ ArgumentMatchers.eq(false),
            /*oldBlock*/ ArgumentMatchers.eq(true));
  }

  @Test
  void put_whenKeyCollisionException_isCaughtAndNotPropagated() throws Exception {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    byte[] headers = newHeadersSha256();
    CHKBlock block = CHKBlock.construct(data, headers, Key.ALGO_AES_CTR_256_SHA256);

    doThrow(new KeyCollisionException())
        .when(mockStore)
        .put(block, block.getRawData(), block.getRawHeaders(), false, false);

    // Should not throw and completes normally
    assertDoesNotThrow(() -> sut.put(block, /*isOldBlock*/ false));
  }

  // ---------- helpers ----------

  private static byte[] newHeadersSha256() {
    byte[] h = new byte[CHKBlock.TOTAL_HEADERS_LENGTH];
    // Big-endian short = 1 (HASH_SHA256)
    h[0] = 0;
    h[1] = (byte) KeyBlock.HASH_SHA256;
    return h;
  }

  private static byte[] validFullKey(byte algo) {
    byte[] fk = new byte[NodeCHK.FULL_KEY_LENGTH];
    fk[0] = NodeCHK.BASE_TYPE; // base type = CHK
    fk[1] = algo; // algorithm
    // the remaining 32 bytes are the routing key; left as zeros for simplicity
    return fk;
  }

  private static byte[] slice(byte[] src, int from, int to) {
    byte[] out = new byte[to - from];
    System.arraycopy(src, from, out, 0, out.length);
    return out;
  }
}
