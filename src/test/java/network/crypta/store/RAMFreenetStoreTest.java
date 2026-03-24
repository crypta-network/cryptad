package network.crypta.store;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.store.alerts.StoreAlertSink;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RAMFreenetStoreTest {

  // Typed abstract subclass to avoid raw-type Mockito mock warnings for generics
  private abstract static class TypedStoreCallback extends StoreCallback<StorableBlock> {}

  private static byte[] bytes(int... vals) {
    byte[] out = new byte[vals.length];
    for (int i = 0; i < vals.length; i++) out[i] = (byte) vals[i];
    return out;
  }

  private static StorableBlock mockBlock(byte[] routingKey, byte[] fullKey) {
    StorableBlock b = mock(StorableBlock.class);
    when(b.getRoutingKey()).thenReturn(Arrays.copyOf(routingKey, routingKey.length));
    when(b.getFullKey()).thenReturn(Arrays.copyOf(fullKey, fullKey.length));
    return b;
  }

  private static StoreCallback<StorableBlock> baseCallback() {
    TypedStoreCallback cb = mock(TypedStoreCallback.class);
    // Methods not used by RAMFreenetStore, but some tests query stats via callback.getStore().
    lenient().when(cb.dataLength()).thenReturn(0);
    lenient().when(cb.headerLength()).thenReturn(0);
    lenient().when(cb.routingKeyLength()).thenReturn(0);
    lenient().when(cb.constructNeedsKey()).thenReturn(false);
    lenient().when(cb.fullKeyLength()).thenReturn(0);
    lenient().when(cb.routingKeyFromFullKey(any())).thenReturn(new byte[0]);
    return cb;
  }

  @Test
  @DisplayName("constructor sets store on callback")
  void constructor_whenGivenCallback_registersStoreOnCallback() {
    StoreCallback<StorableBlock> cb = baseCallback();

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 10)) {
      verify(cb).setStore(store);
    }
  }

  @Test
  void putAndFetch_whenPresent_returnsConstructedAndCountsHit() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);

    StorableBlock toReturn = mock(StorableBlock.class);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(toReturn);

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 16)) {
      StorableBlock key = mockBlock(bytes(1, 2), bytes(9, 9));
      byte[] data = bytes(10, 11, 12);
      byte[] header = bytes(7);
      store.put(key, data, header, /* overwrite= */ false, /* old= */ false);

      BlockMetadata meta = new BlockMetadata();
      StorableBlock got =
          store.fetch(
              bytes(1, 2), bytes(9, 9), false, true, false, /* ignoreOldBlocks= */ false, meta);

      assertSame(toReturn, got);
      assertFalse(meta.isOldBlock());
      assertEquals(1, store.hits());
      assertEquals(0, store.misses());

      // Verify construct received the raw arrays we stored
      ArgumentCaptor<StoreCallback.BlockPayload> payloadCap =
          ArgumentCaptor.forClass(StoreCallback.BlockPayload.class);
      verify(cb).construct(payloadCap.capture(), any(StoreCallback.ConstructOptions.class), any());
      assertArrayEquals(data, payloadCap.getValue().data());
      assertArrayEquals(header, payloadCap.getValue().headers());
      assertArrayEquals(bytes(1, 2), payloadCap.getValue().routingKey());
      // Full key is only stored when callback.storeFullKeys() is true (false in this test)
      assertNull(payloadCap.getValue().fullKey());
    }
  }

  @Test
  void fetch_whenAbsent_incrementsMissesAndReturnsNull() throws IOException {
    StoreCallback<StorableBlock> cb = baseCallback();
    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      StorableBlock got =
          store.fetch(bytes(4, 5, 6), null, true, false, false, false, /* meta= */ null);

      assertNull(got);
      assertEquals(1, store.misses());
    }
  }

  @Test
  void fetch_whenOldAndIgnoreOldBlocksTrue_returnsNull_withoutMiss() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      StorableBlock key = mockBlock(bytes(3), bytes(8));
      store.put(key, bytes(1), bytes(2), false, /* old= */ true);

      BlockMetadata meta = new BlockMetadata();
      StorableBlock got = store.fetch(bytes(3), bytes(8), false, true, false, true, meta);

      assertNull(got);
      assertFalse(meta.isOldBlock()); // meta untouched when we return null
      assertEquals(0, store.misses()); // no miss counted for ignoreOldBlocks path
    }
  }

  @Test
  void fetch_whenOldAndMetaProvided_setsOldInMetadata() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      StorableBlock key = mockBlock(bytes(7), bytes(7));
      store.put(key, bytes(42), bytes(24), false, /* old= */ true);

      BlockMetadata meta = new BlockMetadata();
      StorableBlock got = store.fetch(bytes(7), bytes(7), false, false, false, false, meta);

      assertNotNull(got);
      assertTrue(meta.isOldBlock());
      assertEquals(1, store.hits());
    }
  }

  @Test
  void fetch_whenConstructThrows_removesEntryAndCountsMiss() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenThrow(new KeyVerifyException("bad"));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      StorableBlock key = mockBlock(bytes(5), bytes(9));
      store.put(key, bytes(99), bytes(0), false, false);

      StorableBlock got = store.fetch(bytes(5), bytes(9), false, false, false, false, null);

      assertNull(got);
      assertEquals(1, store.misses());
      assertFalse(store.probablyInStore(bytes(5)));
      assertEquals(0, store.keyCount());
    }
  }

  @Test
  void put_whenCollisionPossibleTrue_equalBytesClearsOldFlag() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      byte[] rk = bytes(1, 1);
      byte[] fk = bytes(2, 2);
      byte[] data = bytes(10);
      byte[] hdr = bytes(11);
      StorableBlock k1 = mockBlock(rk, fk);
      store.put(k1, data, hdr, false, /* old= */ true);

      // Equal content, mark as not old
      StorableBlock k2 = mockBlock(rk, fk);
      store.put(k2, Arrays.copyOf(data, data.length), Arrays.copyOf(hdr, hdr.length), false, false);

      BlockMetadata meta = new BlockMetadata();
      assertNotNull(store.fetch(rk, fk, false, false, false, false, meta));
      assertFalse(meta.isOldBlock());
    }
  }

  @Test
  void put_whenCollisionPossibleTrue_diffBytesNoOverwrite_throwsCollisionAndKeepsOriginal()
      throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);

    StorableBlock ret = mock(StorableBlock.class);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(ret);

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      byte[] rk = bytes(3, 3);
      byte[] fk = bytes(4, 4);
      StorableBlock b1 = mockBlock(rk, fk);
      store.put(b1, bytes(1, 1), bytes(2, 2), false, false);

      StorableBlock b2 = mockBlock(rk, fk);
      assertThrows(
          KeyCollisionException.class,
          () -> store.put(b2, bytes(9, 9), bytes(8, 8), /* overwrite= */ false, false));

      // Fetch should still return original bytes
      ArgumentCaptor<StoreCallback.BlockPayload> payloadCap =
          ArgumentCaptor.forClass(StoreCallback.BlockPayload.class);
      store.fetch(rk, fk, false, false, false, false, null);
      verify(cb).construct(payloadCap.capture(), any(StoreCallback.ConstructOptions.class), any());
      assertArrayEquals(bytes(1, 1), payloadCap.getValue().data());
      assertArrayEquals(bytes(2, 2), payloadCap.getValue().headers());
    }
  }

  @Test
  void put_whenCollisionPossibleTrue_diffBytesOverwriteTrue_updatesStored() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      byte[] rk = bytes(5, 5);
      byte[] fk = bytes(6, 6);
      StorableBlock b1 = mockBlock(rk, fk);
      store.put(b1, bytes(1), bytes(2), false, false);

      StorableBlock b2 = mockBlock(rk, fk);
      store.put(b2, bytes(9), bytes(8), /* overwrite= */ true, /* old= */ true);

      BlockMetadata meta = new BlockMetadata();
      store.fetch(rk, fk, false, false, false, false, meta);

      // Last write marked as old
      assertTrue(meta.isOldBlock());
    }
  }

  @Test
  void put_whenStoreFullKeysTrue_diffFullKeyCountsAsDifferent() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(true);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      byte[] rk = bytes(1, 2, 3);
      StorableBlock b1 = mockBlock(rk, bytes(1));
      store.put(b1, bytes(7), bytes(8), false, false);

      StorableBlock b2 = mockBlock(rk, bytes(2));
      assertThrows(
          KeyCollisionException.class,
          () -> store.put(b2, bytes(7), bytes(8), /* overwrite= */ false, false));
    }
  }

  @Test
  void put_whenCollisionNotPossible_existingKeyKeepsDataButClearsOldFlag() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(false);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 8)) {
      byte[] rk = bytes(9, 9);
      byte[] fk = bytes(8, 8);
      store.put(mockBlock(rk, fk), bytes(1, 1, 1), bytes(2, 2), false, /* old= */ true);

      // Second, put with different content and not old must not replace the stored bytes
      store.put(mockBlock(rk, fk), bytes(5, 5), bytes(6), false, /* old= */ false);

      BlockMetadata meta = new BlockMetadata();
      store.fetch(rk, fk, false, false, false, false, meta);
      assertFalse(meta.isOldBlock());
    }
  }

  @Test
  void setMaxKeys_whenShrinking_evictsLRU() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 3)) {
      store.put(mockBlock(bytes(1), bytes(1)), bytes(1), bytes(0), false, false); // K1 (LRU)
      store.put(mockBlock(bytes(2), bytes(2)), bytes(2), bytes(0), false, false); // K2
      store.put(mockBlock(bytes(3), bytes(3)), bytes(3), bytes(0), false, false); // K3 (MRU)
      assertEquals(3, store.keyCount());

      store.setMaxKeys(2, /* shrinkNow= */ false);
      assertEquals(2, store.getMaxKeys());

      // After shrinking, K1 should be evicted; K2 and K3 remain
      assertFalse(store.probablyInStore(bytes(1)));
      assertTrue(store.probablyInStore(bytes(2)));
      assertTrue(store.probablyInStore(bytes(3)));
      assertEquals(2, store.keyCount());
    }
  }

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void fetchPromotion_whenDontPromoteFlag_controlsEviction(boolean promote) throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 2)) {
      byte[] a = bytes(1);
      byte[] b = bytes(2);
      byte[] c = bytes(3);
      store.put(mockBlock(a, a), bytes(1), bytes(0), false, false); // A (LRU)
      store.put(mockBlock(b, b), bytes(2), bytes(0), false, false); // B (MRU)

      // Access A
      store.fetch(a, a, /* dontPromote= */ !promote, false, false, false, null);

      // Insert C, forcing eviction down to 2 keys
      store.put(mockBlock(c, c), bytes(3), bytes(0), false, false);

      if (promote) {
        // B should be evicted, A and C remain
        assertFalse(store.probablyInStore(b));
        assertTrue(store.probablyInStore(a));
        assertTrue(store.probablyInStore(c));
      } else {
        // A should be evicted, B and C remain
        assertFalse(store.probablyInStore(a));
        assertTrue(store.probablyInStore(b));
        assertTrue(store.probablyInStore(c));
      }
    }
  }

  @Test
  void getSessionAccessStats_reflectsCounters() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    when(cb.storeFullKeys()).thenReturn(false);
    when(cb.collisionPossible()).thenReturn(true);
    when(cb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 10)) {
      // 2 writes, 1 hit, 1 miss
      store.put(mockBlock(bytes(1), bytes(1)), bytes(1), bytes(0), false, false);
      store.put(mockBlock(bytes(2), bytes(2)), bytes(2), bytes(0), false, false);
      store.fetch(bytes(1), bytes(1), false, false, false, false, null);
      store.fetch(bytes(42), null, true, false, false, false, null);

      StoreAccessStats s = store.getSessionAccessStats();
      assertEquals(1, s.hits());
      assertEquals(1, s.misses());
      assertEquals(2, s.writes());
    }
  }

  @Test
  void misc_accessorsAndNoops_behaveAsDocumented() throws Exception {
    StoreCallback<StorableBlock> cb = baseCallback();
    try (RAMFreenetStore<StorableBlock> store = new RAMFreenetStore<>(cb, 5)) {
      assertEquals(-1, store.getBloomFalsePositive());
      assertSame(store, store.getUnderlyingStore());
      assertFalse(store.start(mock(Ticker.class), true));
      assertNull(store.getTotalAccessStats());

      StoreAlertSink alertSink = mock(StoreAlertSink.class);
      store.setStoreAlertSink(alertSink);
      verifyNoInteractions(alertSink);

      // Clear removes everything
      store.put(mockBlock(bytes(1), bytes(1)), bytes(1), bytes(0), false, false);
      assertTrue(store.probablyInStore(bytes(1)));
      store.clear();
      assertEquals(0, store.keyCount());
      assertFalse(store.probablyInStore(bytes(1)));
    }

    // Explicitly verify close does not throw using try-with-resources
    assertDoesNotThrow(
        () -> {
          try (RAMFreenetStore<StorableBlock> ignored = new RAMFreenetStore<>(cb, 1)) {
            // Simple read calls so the try block is not empty
            assertEquals(1, ignored.getMaxKeys());
            assertSame(ignored, ignored.getUnderlyingStore());
          }
        });
  }

  @Test
  void migrateTo_whenConstructSucceeds_putsIntoTargetWithFlags() throws Exception {
    // Source callback used by RAMFreenetStore
    StoreCallback<StorableBlock> sourceCb = baseCallback();
    when(sourceCb.storeFullKeys()).thenReturn(false);
    when(sourceCb.collisionPossible()).thenReturn(true);
    StorableBlock ret = mock(StorableBlock.class);
    when(sourceCb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenReturn(ret);

    try (RAMFreenetStore<StorableBlock> source = new RAMFreenetStore<>(sourceCb, 10)) {
      // Target callback + underlying store mock
      StoreCallback<StorableBlock> targetCb = baseCallback();
      @SuppressWarnings("unchecked")
      FreenetStore<StorableBlock> targetStore = mock(FreenetStore.class);
      when(targetCb.getStore()).thenReturn(targetStore);

      byte[] rk1 = bytes(1);
      byte[] fk1 = bytes(1);
      byte[] d1 = bytes(10);
      byte[] h1 = bytes(11);
      source.put(mockBlock(rk1, fk1), d1, h1, false, /* old= */ false);

      byte[] rk2 = bytes(2);
      byte[] fk2 = bytes(2);
      byte[] d2 = bytes(20);
      byte[] h2 = bytes(21);
      source.put(mockBlock(rk2, fk2), d2, h2, false, /* old= */ true);

      source.migrateTo(targetCb, /* canReadClientCache= */ true);

      ArgumentCaptor<StorableBlock> blockCap = ArgumentCaptor.forClass(StorableBlock.class);
      ArgumentCaptor<byte[]> dataCap = ArgumentCaptor.forClass(byte[].class);
      ArgumentCaptor<byte[]> headerCap = ArgumentCaptor.forClass(byte[].class);
      ArgumentCaptor<Boolean> oldCap = ArgumentCaptor.forClass(Boolean.class);

      verify(targetStore, times(2))
          .put(
              blockCap.capture(),
              dataCap.capture(),
              headerCap.capture(),
              eq(false),
              oldCap.capture());

      // We can only assert data/header bytes and flags; order is LRU->MRU (rk1 then rk2)
      assertArrayEquals(d1, dataCap.getAllValues().getFirst());
      assertArrayEquals(h1, headerCap.getAllValues().getFirst());
      assertFalse(oldCap.getAllValues().getFirst());

      assertArrayEquals(d2, dataCap.getAllValues().get(1));
      assertArrayEquals(h2, headerCap.getAllValues().get(1));
      assertTrue(oldCap.getAllValues().get(1));
    }
  }

  @Test
  void migrateTo_whenConstructThrows_skipsThatEntry() throws Exception {
    StoreCallback<StorableBlock> sourceCb = baseCallback();
    when(sourceCb.storeFullKeys()).thenReturn(false);
    when(sourceCb.collisionPossible()).thenReturn(true);

    // The first construct throws, the second succeeds
    when(sourceCb.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenThrow(new KeyVerifyException("oops"))
        .thenReturn(mock(StorableBlock.class));

    try (RAMFreenetStore<StorableBlock> source = new RAMFreenetStore<>(sourceCb, 10)) {
      StoreCallback<StorableBlock> targetCb = baseCallback();
      @SuppressWarnings("unchecked")
      FreenetStore<StorableBlock> targetStore = mock(FreenetStore.class);
      when(targetCb.getStore()).thenReturn(targetStore);

      source.put(mockBlock(bytes(1), bytes(1)), bytes(1), bytes(0), false, false);
      source.put(mockBlock(bytes(2), bytes(2)), bytes(2), bytes(0), false, false);

      source.migrateTo(targetCb, /* canReadClientCache= */ false);

      verify(targetStore, times(1)).put(any(), any(), any(), eq(false), anyBoolean());
    }
  }
}
