package network.crypta.store;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NullFreenetStoreTest {

  private static final class TestCallback extends StoreCallback<StorableBlock> {
    private FreenetStore<StorableBlock> lastSetStore;

    @Override
    public void setStore(FreenetStore<StorableBlock> store) {
      super.setStore(store);
      this.lastSetStore = store;
    }

    @Override
    public int dataLength() {
      return 0;
    }

    @Override
    public int headerLength() {
      return 0;
    }

    @Override
    public int routingKeyLength() {
      return 0;
    }

    @Override
    public boolean storeFullKeys() {
      return false;
    }

    @Override
    public boolean constructNeedsKey() {
      return false;
    }

    @Override
    public int fullKeyLength() {
      return 0;
    }

    @Override
    public boolean collisionPossible() {
      return false;
    }

    @Override
    public StorableBlock construct(
        BlockPayload payload, ConstructOptions options, DSAPublicKey knownPubKey) {
      return null;
    }

    @Override
    public byte[] routingKeyFromFullKey(byte[] keyBuf) {
      return new byte[0];
    }
  }

  @Test
  @DisplayName("constructor sets store on callback")
  void constructor_whenGivenCallback_registersStoreOnCallback() {
    TestCallback callback = new TestCallback();

    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(callback)) {
      // Also verify via captured reference on the callback
      assertSame(store, callback.lastSetStore);
    }
  }

  @Test
  void fetch_whenMetaNull_returnsNull() throws IOException {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      byte[] rk = new byte[] {1, 2, 3};
      byte[] fk = new byte[] {4, 5, 6};

      StorableBlock result =
          store.fetch(
              rk, fk, /* dontPromote= */ false, true, true, /* ignoreOldBlocks= */ false, null);

      assertNull(result);
    }
  }

  @Test
  void fetch_whenMetaProvided_doesNotModifyMetadata() throws IOException {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      BlockMetadata meta = new BlockMetadata();
      meta.setOldBlock(); // pre-set to true so we can detect unintended changes

      StorableBlock result = store.fetch(new byte[] {9}, null, true, false, false, true, meta);

      assertNull(result);
      // Implementation must not alter caller-provided metadata when returning null
      // (regression guard for accidental meta.reset()).
      assertTrue(meta.isOldBlock());
    }
  }

  @Test
  void probablyInStore_whenNullKey_returnsFalse() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      boolean present = store.probablyInStore(null);
      assertFalse(present);
    }
  }

  @Test
  void probablyInStore_whenNonNullKey_returnsFalse() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      boolean present = store.probablyInStore(new byte[] {42});
      assertFalse(present);
    }
  }

  @Test
  void counters_whenQueried_returnZeros() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      assertEquals(0L, store.getBloomFalsePositive());
      assertEquals(0L, store.getMaxKeys());
      assertEquals(0L, store.hits());
      assertEquals(0L, store.keyCount());
      assertEquals(0L, store.misses());
      assertEquals(0L, store.writes());
    }
  }

  @Test
  void put_whenCalled_doesNothingAndDoesNotThrow() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      StorableBlock block = org.mockito.Mockito.mock(StorableBlock.class);

      assertDoesNotThrow(
          () ->
              store.put(
                  block, new byte[] {7}, new byte[] {8}, /* overwrite= */ false, /* old= */ true));
    }
  }

  @Test
  void setMaxKeys_whenCalled_doesNothingAndDoesNotThrow() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      assertDoesNotThrow(() -> store.setMaxKeys(123L, true));
    }
  }

  @Test
  void getSessionAccessStats_whenCalled_returnsNonNullAllZeros() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      StoreAccessStats stats = store.getSessionAccessStats();

      assertNotNull(stats);
      assertEquals(0L, stats.hits());
      assertEquals(0L, stats.misses());
      assertEquals(0L, stats.falsePos());
      assertEquals(0L, stats.writes());
    }
  }

  @Test
  void getTotalAccessStats_whenCalled_returnsNull() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      assertNull(store.getTotalAccessStats());
    }
  }

  @Test
  void start_whenCalled_returnsFalse() throws IOException {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      Ticker ticker = org.mockito.Mockito.mock(Ticker.class);

      boolean started = store.start(ticker, true);

      assertFalse(started);
    }
  }

  @Test
  void setUserAlertManager_whenCalled_noInteractions() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      UserAlertManager manager = org.mockito.Mockito.mock(UserAlertManager.class);

      store.setUserAlertManager(manager);

      verifyNoInteractions(manager);
    }
  }

  @Test
  void getUnderlyingStore_whenCalled_returnsThis() {
    try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
      FreenetStore<StorableBlock> underlying = store.getUnderlyingStore();
      assertSame(store, underlying);
    }
  }

  @Test
  void close_whenCalled_doesNothingAndDoesNotThrow() {
    assertDoesNotThrow(
        () -> {
          try (NullFreenetStore<StorableBlock> store = new NullFreenetStore<>(new TestCallback())) {
            // Perform a harmless call so the block is not empty
            assertNotNull(store.getUnderlyingStore());
          }
        });
  }
}
