package network.crypta.store.saltedhash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.nio.file.Path;
import java.util.Random;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.BlockMetadata;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // test method naming convention
@ExtendWith(MockitoExtension.class)
class SaltedHashFreenetStoreTest {

  // Fixed sizes keep the on-disk layout small and predictable for tests.
  private static final int DATA_LEN = 32;
  private static final int HEADER_LEN = 16;
  private static final int KEY_LEN = 32; // routing + full key lengths used by the test callback

  @TempDir Path tempDir;

  private Random rnd;
  private Ticker ticker;

  @BeforeEach
  void setup() {
    // Deterministic across runs.
    rnd = new Random(42L);
    // Use a ticker mock so the cleaner thread isn't started in tests.
    ticker = mock(Ticker.class);
    // Ensure the cleaner, if started elsewhere, doesn’t sleep long.
    SaltedHashFreenetStore.setNoCleanerSleep(true);
  }

  @AfterEach
  void tearDown() {
    // Nothing to do: individual tests close/destruct stores they create.
  }

  @Test
  void start_whenNewStoreAndLongStartFalse_returnsEarlyAndDefersResizing() throws Exception {
    File base = tempDir.resolve("storeA").toFile();
    TestCallback cb = new TestCallback();

    try (SaltedHashFreenetStore<TestBlock> store =
        SaltedHashFreenetStore.construct(
            base,
            "dat",
            cb,
            rnd,
            /*maxKeys*/ 8,
            /*useSlotFilter*/ true,
            SemiOrderedShutdownHook.get(),
            /*preallocate*/ false,
            /*resizeOnStart*/ true,
            /*masterKey*/ new byte[32])) {

      // The first call with longStart=false should return true (cannot complete quickly).
      boolean deferred = store.start(ticker, /*longStart*/ false);
      assertTrue(deferred, "start() should defer when longStart=false and files need padding");

      // Files exist but should still be length 0 as resizing/padding hasn't happened yet.
      File meta = new File(base, "dat.metadata");
      File hd = new File(base, "dat.hd");
      assertEquals(0L, meta.length(), "metadata length should be 0 before long start");
      assertEquals(0L, hd.length(), "hd length should be 0 before long start");

      // Now start with longStart=true; these pads/resizes and schedules cleaner through the ticker.
      boolean nowStarted = store.start(ticker, /*longStart*/ true);
      assertFalse(nowStarted, "start(longStart=true) should complete and return false");

      long expectedMeta = 0x80L * 8; // Entry.METADATA_LENGTH * maxKeys
      int block = HEADER_LEN + DATA_LEN;
      int pad = ((block + 512 - 1) & ~511) - block; // same formula used by the store
      long expectedHd = (long) (block + pad) * 8;

      assertEquals(expectedMeta, meta.length(), "metadata file size after start");
      assertEquals(expectedHd, hd.length(), "hd file size after start");

      store.close();
      store.destruct();
    }
  }

  @Test
  void probablyInStore_whenSlotFilterNew_returnsFalse() throws Exception {
    File base = tempDir.resolve("storeB").toFile();
    TestCallback cb = new TestCallback();
    try (SaltedHashFreenetStore<TestBlock> store =
        SaltedHashFreenetStore.construct(
            base,
            "dat2",
            cb,
            rnd,
            /*maxKeys*/ 16,
            /*useSlotFilter*/ true,
            SemiOrderedShutdownHook.get(),
            /*preallocate*/ false,
            /*resizeOnStart*/ true,
            /*masterKey*/ new byte[32])) {

      store.start(ticker, /*longStart*/ true);

      byte[] rk = new byte[KEY_LEN];
      rnd.nextBytes(rk);
      // Fresh slot filter is pre-filled with "checked and empty"; we should return false here.
      assertFalse(store.probablyInStore(rk));

      store.close();
      store.destruct();
    }
  }

  @Test
  void putAndFetch_whenInserted_returnsOriginalPayloadAndUpdatesStats() throws Exception {
    File base = tempDir.resolve("storeC").toFile();
    TestCallback cb = new TestCallback();
    try (SaltedHashFreenetStore<TestBlock> store =
        SaltedHashFreenetStore.construct(
            base,
            "dat3",
            cb,
            rnd,
            /*maxKeys*/ 32,
            /*useSlotFilter*/ true,
            SemiOrderedShutdownHook.get(),
            /*preallocate*/ false,
            /*resizeOnStart*/ true,
            /*masterKey*/ new byte[32])) {

      store.start(ticker, /*longStart*/ true);

      byte[] data = new byte[DATA_LEN];
      byte[] hdr = new byte[HEADER_LEN];
      byte[] rk = new byte[KEY_LEN];
      byte[] fk = new byte[KEY_LEN];
      rnd.nextBytes(data);
      rnd.nextBytes(hdr);
      rnd.nextBytes(rk);
      rnd.nextBytes(fk);

      TestBlock block = new TestBlock(rk, fk, data, hdr);

      store.put(block, data, hdr, /*overwrite*/ false, /*isOldBlock*/ false);

      // Quick presence signal should be true after put when the slot filter is enabled.
      assertTrue(store.probablyInStore(rk));

      TestBlock fetched =
          store.fetch(
              rk, fk, /*dontPromote*/ false, true, true, /*ignoreOld*/ false, new BlockMetadata());
      assertNotNull(fetched, "fetch should succeed for inserted key");
      assertArrayEquals(data, fetched.data, "payload round-trips");
      assertArrayEquals(hdr, fetched.header, "headers round-trip");

      assertEquals(1L, store.hits(), "hits updated");
      assertEquals(0L, store.misses(), "misses unchanged");
      assertEquals(1L, store.writes(), "writes updated");
      assertEquals(1L, store.keyCount(), "key count updated");

      store.close();
      store.destruct();
    }
  }

  @Test
  void fetch_whenUnknownKey_returnsNullAndIncrementsMisses() throws Exception {
    File base = tempDir.resolve("storeD").toFile();
    TestCallback cb = new TestCallback();
    try (SaltedHashFreenetStore<TestBlock> store =
        SaltedHashFreenetStore.construct(
            base,
            "dat4",
            cb,
            rnd,
            /*maxKeys*/ 8,
            /*useSlotFilter*/ false, // disable to simplify the read path
            SemiOrderedShutdownHook.get(),
            /*preallocate*/ false,
            /*resizeOnStart*/ true,
            /*masterKey*/ new byte[32])) {

      store.start(ticker, /*longStart*/ true);

      byte[] rk = new byte[KEY_LEN];
      byte[] fk = new byte[KEY_LEN];
      rnd.nextBytes(rk);
      rnd.nextBytes(fk);

      TestBlock fetched =
          store.fetch(
              rk, fk, /*dontPromote*/ false, true, true, /*ignoreOld*/ false, new BlockMetadata());
      assertNull(fetched, "unknown key should return null");
      assertEquals(0L, store.hits());
      assertEquals(1L, store.misses());
      assertEquals(0L, store.writes());

      store.close();
      store.destruct();
    }
  }

  @Test
  void setAltStore_whenTargetAlreadyHasAltStore_throws() throws Exception {
    File base = tempDir.resolve("alt-parent").toFile();
    File aDir = new File(base, "A");
    File bDir = new File(base, "B");
    File cDir = new File(base, "C");
    TestCallback cb = new TestCallback();

    try (SaltedHashFreenetStore<TestBlock> a =
            SaltedHashFreenetStore.construct(
                SaltedHashStoreParams.of(
                    new SaltedHashStoreLocation(aDir, "a"),
                    new SaltedHashStoreDependencies<>(
                        cb, rnd, SemiOrderedShutdownHook.get(), new byte[32]),
                    new SaltedHashStoreSizing(4, true, false, true)));
        SaltedHashFreenetStore<TestBlock> b =
            SaltedHashFreenetStore.construct(
                SaltedHashStoreParams.of(
                    new SaltedHashStoreLocation(bDir, "b"),
                    new SaltedHashStoreDependencies<>(
                        cb, rnd, SemiOrderedShutdownHook.get(), new byte[32]),
                    new SaltedHashStoreSizing(4, true, false, true)));
        SaltedHashFreenetStore<TestBlock> c =
            SaltedHashFreenetStore.construct(
                SaltedHashStoreParams.of(
                    new SaltedHashStoreLocation(cDir, "c"),
                    new SaltedHashStoreDependencies<>(
                        cb, rnd, SemiOrderedShutdownHook.get(), new byte[32]),
                    new SaltedHashStoreSizing(4, true, false, true)))) {

      a.start(ticker, true);
      b.start(ticker, true);
      c.start(ticker, true);

      // The first association is valid.
      b.setAltStore(a);
      // Now A -> B should fail because B already has an alt store.
      assertThrows(IllegalArgumentException.class, () -> a.setAltStore(b));

      a.close();
      b.close();
      c.close();
      a.destruct();
      b.destruct();
      c.destruct();
    }
  }

  @Test
  @Tag("slow")
  void put_whenFull_redirectsToAltStoreWithoutOverwritingPrimary() throws Exception {
    File base = tempDir.resolve("alt-case").toFile();
    TestCallback cb = new TestCallback();
    File aDir = new File(base, "A");
    File bDir = new File(base, "B");

    try (SaltedHashFreenetStore<TestBlock> a =
            SaltedHashFreenetStore.construct(
                aDir,
                "a",
                cb,
                rnd,
                1, /*useSlotFilter*/
                false,
                SemiOrderedShutdownHook.get(),
                false,
                true,
                new byte[32]);
        SaltedHashFreenetStore<TestBlock> b =
            SaltedHashFreenetStore.construct(
                bDir,
                "b",
                cb,
                rnd,
                1, /*useSlotFilter*/
                false,
                SemiOrderedShutdownHook.get(),
                false,
                true,
                new byte[32])) {

      a.start(ticker, true);
      b.start(ticker, true);
      a.setAltStore(b);

      byte[] d1 = new byte[DATA_LEN];
      byte[] h1 = new byte[HEADER_LEN];
      byte[] rk1 = new byte[KEY_LEN];
      byte[] fk1 = new byte[KEY_LEN];
      rnd.nextBytes(d1);
      rnd.nextBytes(h1);
      rnd.nextBytes(rk1);
      rnd.nextBytes(fk1);
      TestBlock blk1 = new TestBlock(rk1, fk1, d1, h1);
      a.put(blk1, d1, h1, false, false);

      byte[] d2 = new byte[DATA_LEN];
      byte[] h2 = new byte[HEADER_LEN];
      byte[] rk2 = new byte[KEY_LEN];
      byte[] fk2 = new byte[KEY_LEN];
      rnd.nextBytes(d2);
      rnd.nextBytes(h2);
      rnd.nextBytes(rk2);
      rnd.nextBytes(fk2);
      TestBlock blk2 = new TestBlock(rk2, fk2, d2, h2);
      a.put(blk2, d2, h2, false, false); // should redirect to alt store B, not overwrite A

      // Primary should still return the first block.
      TestBlock got1 = a.fetch(rk1, fk1, false, true, true, false, new BlockMetadata());
      assertNotNull(got1, "primary retains first block");

      // Primary must not have the second block.
      TestBlock got2FromA = a.fetch(rk2, fk2, false, true, true, false, new BlockMetadata());
      assertNull(got2FromA, "primary should not contain second block written when full");

      // Alt store should contain the second block.
      TestBlock got2 = b.fetch(rk2, fk2, false, true, true, false, new BlockMetadata());
      assertNotNull(got2, "alt store contains redirected block");
      assertArrayEquals(d2, got2.data);
      assertArrayEquals(h2, got2.header);

      // Stats: A has one writing; B has one writing.
      assertEquals(1L, a.writes(), "primary writes");
      assertEquals(1L, b.writes(), "alt writes");
      assertEquals(1L, a.keyCount(), "primary keys");
      assertEquals(1L, b.keyCount(), "alt keys");

      a.close();
      b.close();
      a.destruct();
      b.destruct();
    }
  }

  @Test
  @Tag("slow")
  void put_whenAltStoreAlreadyHasBlock_reportsSuccessAndDoesNotOverwritePrimary() throws Exception {
    File base = tempDir.resolve("alt-existing").toFile();
    TestCallback cb = new TestCallback();
    File aDir = new File(base, "A");
    File bDir = new File(base, "B");

    try (SaltedHashFreenetStore<TestBlock> a =
            SaltedHashFreenetStore.construct(
                SaltedHashStoreParams.of(
                    new SaltedHashStoreLocation(aDir, "a"),
                    new SaltedHashStoreDependencies<>(
                        cb, rnd, SemiOrderedShutdownHook.get(), new byte[32]),
                    new SaltedHashStoreSizing(1, false, false, true)));
        SaltedHashFreenetStore<TestBlock> b =
            SaltedHashFreenetStore.construct(
                SaltedHashStoreParams.of(
                    new SaltedHashStoreLocation(bDir, "b"),
                    new SaltedHashStoreDependencies<>(
                        cb, rnd, SemiOrderedShutdownHook.get(), new byte[32]),
                    new SaltedHashStoreSizing(1, false, false, true)))) {

      a.start(ticker, true);
      b.start(ticker, true);
      a.setAltStore(b);

      // Fill primary A with a different block so it is full.
      byte[] dA = new byte[DATA_LEN];
      byte[] hA = new byte[HEADER_LEN];
      byte[] rkA = new byte[KEY_LEN];
      byte[] fkA = new byte[KEY_LEN];
      rnd.nextBytes(dA);
      rnd.nextBytes(hA);
      rnd.nextBytes(rkA);
      rnd.nextBytes(fkA);
      TestBlock bA = new TestBlock(rkA, fkA, dA, hA);
      a.put(bA, dA, hA, false, false);

      long aWritesBefore = a.writes();
      long aKeysBefore = a.keyCount();

      // Prepare a block that already exists in the alt store B.
      byte[] dX = new byte[DATA_LEN];
      byte[] hX = new byte[HEADER_LEN];
      byte[] rkX = new byte[KEY_LEN];
      byte[] fkX = new byte[KEY_LEN];
      rnd.nextBytes(dX);
      rnd.nextBytes(hX);
      rnd.nextBytes(rkX);
      rnd.nextBytes(fkX);
      TestBlock bX = new TestBlock(rkX, fkX, dX, hX);

      // Insert into alt store first.
      b.put(bX, dX, hX, false, false);
      long bWritesBefore = b.writes();

      // Now attempt to put the SAME block via primary A while A is full.
      // With the fix, A will try the alt store, which will confirm presence and report success,
      // and A will NOT overwrite in its own store.
      a.put(bX, dX, hX, false, false);

      // Primary A should still contain its original block and should not have performed a new
      // write.
      assertEquals(aWritesBefore, a.writes(), "primary should not perform an overwrite write");
      assertEquals(aKeysBefore, a.keyCount(), "primary key count unchanged");
      assertNotNull(a.fetch(rkA, fkA, false, true, true, false, new BlockMetadata()));
      assertNull(a.fetch(rkX, fkX, false, true, true, false, new BlockMetadata()));

      // Alt store B still has the block; it may or may not update metadata, but should not lose it.
      assertNotNull(b.fetch(rkX, fkX, false, true, true, false, new BlockMetadata()));
      assertTrue(b.writes() >= bWritesBefore, "alt store writes should not decrease");

      a.close();
      b.close();
      a.destruct();
      b.destruct();
    }
  }

  // --- Minimal test block & callback used for this suite ---

  private static final class TestBlock implements StorableBlock {
    final byte[] routingKey;
    final byte[] fullKey;
    final byte[] data;
    final byte[] header;

    TestBlock(byte[] routingKey, byte[] fullKey, byte[] data, byte[] header) {
      this.routingKey = routingKey;
      this.fullKey = fullKey;
      this.data = data;
      this.header = header;
    }

    @Override
    public byte[] getRoutingKey() {
      return routingKey;
    }

    @Override
    public byte[] getFullKey() {
      return fullKey;
    }
  }

  private static class TestCallback extends StoreCallback<TestBlock> {
    @Override
    public int dataLength() {
      return DATA_LEN;
    }

    @Override
    public int headerLength() {
      return HEADER_LEN;
    }

    @Override
    public int routingKeyLength() {
      return KEY_LEN;
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
      return KEY_LEN;
    }

    @Override
    public boolean collisionPossible() {
      return false;
    }

    @Override
    public TestBlock construct(
        BlockPayload payload,
        ConstructOptions options,
        network.crypta.crypt.DSAPublicKey knownPubKey) {
      // Just wrap provided values; verification is performed earlier by the store.
      return new TestBlock(
          payload.routingKey(), payload.fullKey(), payload.data(), payload.headers());
    }

    @Override
    public byte[] routingKeyFromFullKey(byte[] keyBuf) {
      // For tests, treat full and routing keys as identical in size/semantics.
      return keyBuf;
    }
  }
}
