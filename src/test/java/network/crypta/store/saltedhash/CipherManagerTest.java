package network.crypta.store.saltedhash;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import network.crypta.crypt.SHA256;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({
  "java:S100",
  "java:S3011"
}) // naming; reflection accessibility for test scaffolding
class CipherManagerTest {

  @TempDir File tmp;

  private static final int RK_LEN = 32;
  private static final int HDR_LEN = 16;
  private static final int DATA_LEN = 32;

  private static byte[] seq(int len, int start) {
    byte[] b = new byte[len];
    for (int i = 0; i < len; i++) b[i] = (byte) (start + i);
    return b;
  }

  // ----- Basic helpers -----

  private CipherManager newCipherManager() {
    byte[] salt = seq(16, 0xA0);
    byte[] diskSalt = Arrays.copyOf(salt, salt.length);
    return new CipherManager(salt, diskSalt);
  }

  private SaltedHashFreenetStore<StubBlock> newStore(String name) throws Exception {
    StoreCallback<StubBlock> cb = new StubCallback();
    Random weak = new Random(1234);
    // Minimal store, not started; used only to instantiate Entry via reflection.
    return SaltedHashFreenetStore.construct(
        SaltedHashStoreParams.of(
            new SaltedHashStoreLocation(tmp, name),
            new SaltedHashStoreDependencies<>(cb, weak, SemiOrderedShutdownHook.get(), null),
            new SaltedHashStoreSizing(2, false, false, false)));
  }

  private SaltedHashFreenetStore<StubBlock>.Entry newEntry(
      SaltedHashFreenetStore<StubBlock> store, byte[] rk, byte[] header, byte[] data)
      throws Exception {
    @SuppressWarnings("rawtypes")
    Class inner = Class.forName("network.crypta.store.saltedhash.SaltedHashFreenetStore$Entry");
    @SuppressWarnings("unchecked")
    Constructor<SaltedHashFreenetStore<StubBlock>.Entry> ctor =
        inner.getDeclaredConstructor(
            SaltedHashFreenetStore.class,
            byte[].class,
            byte[].class,
            byte[].class,
            boolean.class,
            boolean.class);
    ctor.setAccessible(true);
    return ctor.newInstance(store, rk, header, data, false, false);
  }

  private void setStoreCipherManager(SaltedHashFreenetStore<?> store, CipherManager cm)
      throws Exception {
    Field f = SaltedHashFreenetStore.class.getDeclaredField("cipherManager");
    f.setAccessible(true);
    f.set(store, cm);
  }

  // ----- Tests: getDigestedKey -----

  @Test
  void getDigestedKey_deterministicAndCached() {
    CipherManager cm = newCipherManager();
    byte[] rk = seq(RK_LEN, 0x10);

    byte[] d1 = cm.getDigestedKey(rk);
    assertNotNull(d1);
    assertEquals(32, d1.length);

    // Same array → same cached instance
    byte[] d2 = cm.getDigestedKey(rk);
    assertSame(d1, d2, "should return cached array instance");

    // Equal content on a different array → same cached instance
    byte[] rkCopy = rk.clone();
    byte[] d3 = cm.getDigestedKey(rkCopy);
    assertSame(d1, d3, "cache should use value semantics for keys");

    // Content check: SHA-256(plainKey || salt)
    MessageDigest md = SHA256.getMessageDigest();
    md.update(rk);
    md.update(seq(16, 0xA0)); // salt used by newCipherManager()
    byte[] expected = md.digest();
    assertArrayEquals(expected, d1);
  }

  @Test
  void getDigestedKey_whenNull_throwsNPE() {
    CipherManager cm = newCipherManager();
    assertThrows(NullPointerException.class, () -> cm.getDigestedKey(null));
  }

  @Test
  void getDigestedKey_lruEvictsOldest() {
    CipherManager cm = newCipherManager();
    // Insert 128 distinct keys + 1 to trigger LRU eviction of the eldest
    byte[] firstKey = new byte[RK_LEN];
    firstKey[0] = 0;
    byte[] firstDigest = cm.getDigestedKey(firstKey);

    for (int i = 1; i <= 128; i++) {
      byte[] k = new byte[RK_LEN];
      k[0] = (byte) i;
      cm.getDigestedKey(k);
    }

    byte[] again = cm.getDigestedKey(firstKey);
    assertArrayEquals(firstDigest, again, "digest bytes remain the same");
    assertNotSame(firstDigest, again, "evicted eldest should produce a new array instance");
  }

  // ----- Tests: makeCipher -----

  @Test
  void makeCipher_roundTrip_success() {
    CipherManager cm = newCipherManager();
    byte[] iv = seq(16, 0x40);
    byte[] key = seq(RK_LEN, 0x20);
    byte[] data = seq(64, 0x55);
    byte[] enc = data.clone();

    cm.makeCipher(iv, key).blockEncipher(enc, 0, enc.length);
    assertFalse(Arrays.equals(data, enc), "ciphertext should differ from plaintext");

    cm.makeCipher(iv, key).blockDecipher(enc, 0, enc.length);
    assertArrayEquals(data, enc, "decipher should restore original bytes");
  }

  @Test
  void makeCipher_differentIvOrSalt_changesCiphertext() {
    byte[] key = seq(RK_LEN, 0x33);
    byte[] data = seq(48, 0x66);

    CipherManager cm1 = newCipherManager();
    byte[] iv1 = seq(16, 0x01);
    byte[] c1 = data.clone();
    cm1.makeCipher(iv1, key).blockEncipher(c1, 0, c1.length);

    // Different IV with the same salt
    byte[] iv2 = seq(16, 0x02);
    byte[] c2 = data.clone();
    cm1.makeCipher(iv2, key).blockEncipher(c2, 0, c2.length);
    assertFalse(Arrays.equals(c1, c2), "different IV must change ciphertext");

    // Different salt (new CipherManager)
    CipherManager cm2 = new CipherManager(seq(16, 0xB0), seq(16, 0xB0));
    byte[] c3 = data.clone();
    cm2.makeCipher(iv1, key).blockEncipher(c3, 0, c3.length);
    assertFalse(Arrays.equals(c1, c3), "different salt must change ciphertext");
  }

  // ----- Tests: encrypt / decrypt -----

  @Test
  void encrypt_thenDecrypt_withCorrectKey_roundTrips() throws Exception {
    CipherManager cm = newCipherManager();
    try (SaltedHashFreenetStore<StubBlock> store = newStore("cm-roundtrip")) {
      setStoreCipherManager(store, cm); // ensure Entry.getDigestedRoutingKey() uses the same salt

      byte[] rk = seq(RK_LEN, 0x10);
      byte[] header = seq(HDR_LEN, 0x70);
      byte[] data = seq(DATA_LEN, 0x80);
      SaltedHashFreenetStore<StubBlock>.Entry entry = newEntry(store, rk, header, data);

      byte[] headerOrig = entry.header.clone();
      byte[] dataOrig = entry.data.clone();

      Random rnd = new Random(1337);
      cm.encrypt(entry, rnd);
      assertTrue(entry.isEncrypted);
      assertEquals(16, entry.dataEncryptIV.length);
      assertFalse(Arrays.equals(headerOrig, entry.header));
      assertFalse(Arrays.equals(dataOrig, entry.data));

      assertTrue(cm.decrypt(entry, rk));
      assertFalse(entry.isEncrypted);
      assertArrayEquals(headerOrig, entry.header);
      assertArrayEquals(dataOrig, entry.data);
    }
  }

  @Test
  void decrypt_whenWrongKey_returnsFalseAndDoesNotMutate() throws Exception {
    CipherManager cm = newCipherManager();
    try (SaltedHashFreenetStore<StubBlock> store = newStore("cm-wrongkey")) {
      setStoreCipherManager(store, cm);
      byte[] rk = seq(RK_LEN, 0x22);
      byte[] wrong = rk.clone();
      wrong[0] ^= 0x7F;
      SaltedHashFreenetStore<StubBlock>.Entry entry =
          newEntry(store, rk, seq(HDR_LEN, 0x11), seq(DATA_LEN, 0x22));

      cm.encrypt(entry, new Random(7));
      byte[] encHeader = entry.header.clone();
      byte[] encData = entry.data.clone();

      assertFalse(cm.decrypt(entry, wrong));
      assertTrue(entry.isEncrypted, "entry must remain encrypted");
      assertArrayEquals(encHeader, entry.header, "header must not change on failed decrypt");
      assertArrayEquals(encData, entry.data, "data must not change on failed decrypt");
    }
  }

  @Test
  void decrypt_whenAlreadyDecrypted_returnsBooleanByKeyMatch() throws Exception {
    CipherManager cm = newCipherManager();
    try (SaltedHashFreenetStore<StubBlock> store = newStore("cm-notencrypted")) {
      byte[] rk = seq(RK_LEN, 0x44);
      SaltedHashFreenetStore<StubBlock>.Entry entry =
          newEntry(store, rk, seq(HDR_LEN, 0x33), seq(DATA_LEN, 0x55));

      // By constructor this entry is not encrypted.
      assertFalse(entry.isEncrypted);
      assertTrue(cm.decrypt(entry, rk));
      assertFalse(cm.decrypt(entry, seq(RK_LEN, 0x45)));
      assertFalse(entry.isEncrypted);
    }
  }

  // ----- Tests: shutdown & disk salt -----

  @Test
  void shutdown_clearsSaltAndDiskSalt() {
    byte[] salt = seq(16, 0x60);
    byte[] diskSalt = seq(16, 0x61);
    CipherManager cm = new CipherManager(salt, diskSalt);

    cm.shutdown();
    assertArrayEquals(new byte[16], salt, "salt must be zeroized");
    assertArrayEquals(new byte[16], diskSalt, "diskSalt must be zeroized");
  }

  @Test
  void getDiskSalt_returnsOriginalArray() {
    byte[] salt = seq(16, 0x10);
    byte[] diskSalt = seq(16, 0x11);
    CipherManager cm = new CipherManager(salt, diskSalt);

    byte[] got = cm.getDiskSalt();
    assertSame(diskSalt, got);
    assertArrayEquals(diskSalt, got);
  }

  // ----- Test scaffolding -----

  private static final class StubBlock implements StorableBlock {
    private final byte[] routingKey;
    private final byte[] fullKey;

    StubBlock(byte[] routingKey, byte[] fullKey) {
      this.routingKey = routingKey;
      this.fullKey = fullKey;
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

  private static final class StubCallback extends StoreCallback<StubBlock> {
    @Override
    public int dataLength() {
      return DATA_LEN;
    }

    @Override
    public int headerLength() {
      return HDR_LEN;
    }

    @Override
    public int routingKeyLength() {
      return RK_LEN;
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
      return 64;
    }

    @Override
    public boolean collisionPossible() {
      return false;
    }

    @Override
    public StubBlock construct(
        BlockPayload payload,
        ConstructOptions options,
        network.crypta.crypt.DSAPublicKey knownPubKey) {
      return new StubBlock(payload.routingKey(), payload.fullKey());
    }

    @Override
    public byte[] routingKeyFromFullKey(byte[] keyBuf) {
      return Arrays.copyOf(keyBuf, RK_LEN);
    }
  }

  // No per-test global setup/teardown needed; stores are closed in each test.
}
