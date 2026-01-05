package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.store.PubkeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeGetPubkeyTest {

  private static final byte[] HASH = new byte[] {1, 2, 3, 4, 5};

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PubkeyStore store;
  @Mock private PubkeyStore cache;
  @Mock private PubkeyStore clientCache;
  @Mock private PubkeyStore slashdotCache;
  @Mock private PubkeyStore oldClientCache;
  @Mock private PubkeyStore oldStore;
  @Mock private PubkeyStore oldCache;

  private NodeGetPubkey uut;

  private static DSAPublicKey newKey(int y) {
    return new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(y));
  }

  @BeforeEach
  void setUp() {
    uut = new NodeGetPubkey(node);
    uut.setDataStore(store, cache);
  }

  @Test
  void getKey_whenFirstFromStore_thenMemoryCacheOnSecondCall() throws Exception {
    DSAPublicKey k = newKey(10);
    when(node.getWriteLocalToDatastore()).thenReturn(false);
    org.mockito.Mockito.doReturn(k).when(store).fetch(any(), anyBoolean(), anyBoolean(), any());

    DSAPublicKey first =
        uut.getKey(HASH, /* canReadClientCache= */ false, /* forULPR= */ false, null);
    assertSame(k, first, "should return key from store on first resolution");
    verify(store).fetch(HASH, false, true, null);
    verifyNoInteractions(cache);

    // Second call should hit in-memory LRU without touching stores
    clearInvocations(store, cache);
    DSAPublicKey second =
        uut.getKey(HASH, /* canReadClientCache= */ false, /* forULPR= */ false, null);
    assertSame(k, second, "should return same instance from RAM cache");
    verifyNoInteractions(store, cache);
  }

  @Test
  void getKey_whenClientCacheEnabled_prefersClientCache() throws Exception {
    uut.setLocalDataStore(clientCache);
    when(node.getWriteLocalToDatastore()).thenReturn(true); // value ignored when reading client
    DSAPublicKey k = newKey(11);
    org.mockito.Mockito.doReturn(k)
        .when(clientCache)
        .fetch(any(), anyBoolean(), anyBoolean(), any());

    DSAPublicKey got = uut.getKey(HASH, /* canReadClientCache= */ true, /* forULPR= */ false, null);
    assertSame(k, got, "should return key from client cache when allowed");
    verify(clientCache).fetch(HASH, false, false, null);
    verifyNoInteractions(store, cache);
  }

  @Test
  void getKey_whenClientCacheMiss_usesOldClientCacheBeforeStores() throws Exception {
    uut.setLocalDataStore(clientCache);
    when(node.getWriteLocalToDatastore()).thenReturn(true);
    when(node.storage().getOldPKClientCache()).thenReturn(oldClientCache);
    DSAPublicKey k = newKey(12);
    org.mockito.Mockito.doReturn(null)
        .when(clientCache)
        .fetch(any(), anyBoolean(), anyBoolean(), any());
    org.mockito.Mockito.doReturn(k)
        .when(oldClientCache)
        .fetch(any(), anyBoolean(), anyBoolean(), any());

    DSAPublicKey got = uut.getKey(HASH, /* canReadClientCache= */ true, /* forULPR= */ false, null);
    assertSame(k, got, "should fall back to old client cache");
    verify(clientCache).fetch(HASH, false, false, null);
    verify(oldClientCache).fetch(HASH, false, false, null);
    verifyNoInteractions(store, cache);
  }

  @Test
  void getKey_whenOnlySlashdotHas_itIsUsedForULPR() throws Exception {
    // No client cache reading; stores miss
    when(node.getWriteLocalToDatastore()).thenReturn(false);
    org.mockito.Mockito.doReturn(null).when(store).fetch(any(), anyBoolean(), anyBoolean(), any());
    org.mockito.Mockito.doReturn(null).when(cache).fetch(any(), anyBoolean(), anyBoolean(), any());
    when(node.storage().getOldPK()).thenReturn(oldStore);
    when(node.storage().getOldPKCache()).thenReturn(oldCache);
    org.mockito.Mockito.doReturn(null)
        .when(oldStore)
        .fetch(any(), anyBoolean(), anyBoolean(), any());
    org.mockito.Mockito.doReturn(null)
        .when(oldCache)
        .fetch(any(), anyBoolean(), anyBoolean(), any());

    uut.setLocalSlashdotcache(slashdotCache);
    DSAPublicKey k = newKey(13);
    org.mockito.Mockito.doReturn(k)
        .when(slashdotCache)
        .fetch(any(), anyBoolean(), anyBoolean(), any());

    DSAPublicKey got = uut.getKey(HASH, /* canReadClientCache= */ false, /* forULPR= */ true, null);
    assertSame(k, got, "should read from slashdot cache when forULPR");
    verify(slashdotCache).fetch(HASH, false, true, null);
  }

  @Test
  void cacheKey_whenClientAndSlashdotOnly_writesOnlyThose() throws Exception {
    uut.setLocalDataStore(clientCache);
    uut.setLocalSlashdotcache(slashdotCache);

    DSAPublicKey k = newKey(20);
    uut.cacheKey(
        HASH,
        k,
        /* deep= */ false,
        /* canWriteClientCache= */ true,
        /* canWriteDatastore= */ false,
        /* forULPR= */ true,
        /* writeLocalToDatastore= */ false);

    verify(clientCache).put(k, false);
    verify(slashdotCache).put(k, false);
    verifyNoInteractions(store, cache);

    // Verify the key is now available from the in-memory cache (no store access)
    when(node.getWriteLocalToDatastore()).thenReturn(false);
    DSAPublicKey got =
        uut.getKey(HASH, /* canReadClientCache= */ false, /* forULPR= */ false, null);
    assertSame(k, got, "should come from RAM cache without store fetch");
    verifyNoInteractions(store, cache);
  }

  @Test
  void cacheKey_whenDeepAndCanWriteDatastore_writesStoreAndDataCache() throws Exception {
    DSAPublicKey k = newKey(21);
    uut.cacheKey(
        HASH,
        k,
        /* deep= */ true,
        /* canWriteClientCache= */ false,
        /* canWriteDatastore= */ true,
        /* forULPR= */ false,
        /* writeLocalToDatastore= */ false);

    verify(store).put(k, false);
    verify(cache).put(k, false);
    verifyNoInteractions(clientCache, slashdotCache);
  }

  @Test
  void cacheKey_whenWriteLocalToDatastoreTrue_setsOldFlagOnPuts() throws Exception {
    DSAPublicKey k = newKey(22);

    uut.cacheKey(
        HASH,
        k,
        /* deep= */ true,
        /* canWriteClientCache= */ false,
        /* canWriteDatastore= */ false,
        /* forULPR= */ false,
        /* writeLocalToDatastore= */ true);

    // When writeLocalToDatastore == true, we still write, but mark entries as old
    // (!canWriteDatastore)
    verify(store).put(k, true);
    verify(cache).put(k, true);
    verifyNoInteractions(clientCache, slashdotCache);
  }

  @Test
  void cacheKey_whenDifferentKeyForSameHash_throws() {
    DSAPublicKey k1 = newKey(30);
    DSAPublicKey k2 = newKey(31);

    uut.cacheKey(HASH, k1, false, false, false, false, false);
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> uut.cacheKey(HASH, k2, false, false, false, false, false));
    assertNotNull(ex.getMessage());
  }

  @Test
  void getKey_whenUnderlyingThrowsIOException_returnsNull() throws Exception {
    when(node.getWriteLocalToDatastore()).thenReturn(false);
    org.mockito.Mockito.doThrow(new IOException("disk error"))
        .when(store)
        .fetch(any(), anyBoolean(), anyBoolean(), any());
    DSAPublicKey got =
        uut.getKey(HASH, /* canReadClientCache= */ false, /* forULPR= */ false, null);
    assertNull(got, "should swallow IOExceptions and return null");
    // No further fetches attempted after an IOException
    verify(cache, never()).fetch(any(), anyBoolean(), anyBoolean(), any());
  }
}
