package network.crypta.store.saltedhash;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.node.MasterKeys;
import network.crypta.support.ByteArrayWrapper;

/**
 * Manages key digestion and symmetric encryption for salted-hash stores.
 *
 * <p>This class derives and caches SHA-256 digests of routing keys, and encrypts/decrypts {@link
 * SaltedHashFreenetStore.Entry} payloads using AES (Rijndael-256) in {@link PCFBMode}. The
 * per-store {@code salt} is combined with a per-entry IV to form a 256-bit IV used by the cipher.
 *
 * <p>Thread safety: the digest cache is synchronized. The {@code encrypt} and {@code decrypt}
 * methods mutate the provided entry and must not be called concurrently for the same entry.
 */
public final class CipherManager {

  /** The actual salt. 16 bytes. */
  private final byte[] salt;

  /** The original on-disk salt, may be encrypted. 16 bytes. */
  private final byte[] diskSalt;

  /**
   * Creates a new manager bound to a specific store salt.
   *
   * <p>The {@code salt} is used for digest computation and as part of the cipher IV. The {@code
   * diskSalt} preserves the original 16-byte value as stored on disk (which may be encrypted) so it
   * can be persisted or exposed as needed by callers within the package.
   *
   * @param salt 16-byte salt used for digests and IV derivation; not copied.
   * @param diskSalt 16-byte salt as read from disk; not copied.
   */
  CipherManager(byte[] salt, byte[] diskSalt) {
    assert salt.length == 0x10;
    this.salt = salt;
    this.diskSalt = diskSalt;
  }

  /**
   * Returns the on-disk salt value.
   *
   * <p>The returned array is the internal reference and must be treated as read-only by callers in
   * the same package.
   *
   * @return the 16-byte on-disk salt (may be encrypted).
   */
  byte[] getDiskSalt() {
    return diskSalt;
  }

  /**
   * LRU-like cache of digested routing keys.
   *
   * <p>Bounded to 128 entries by overriding {@code removeEldestEntry} on a {@code LinkedHashMap} to
   * limit memory usage.
   */
  private final Map<ByteArrayWrapper, byte[]> digestRoutingKeyCache =
      new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<ByteArrayWrapper, byte[]> eldest) {
          return size() > 128;
        }
      };

  /**
   * Computes the salted SHA-256 digest of a routing key.
   *
   * <p>The digest is {@code SHA-256(plainKey || salt)} and is cached for reuse. The returned array
   * is a new 32-byte value owned by the cache; callers must not modify it.
   *
   * @param plainKey routing key in plaintext; not retained by this method
   * @return 32-byte digest of the routing key
   */
  byte[] getDigestedKey(byte[] plainKey) {
    ByteArrayWrapper key = new ByteArrayWrapper(plainKey);
    synchronized (digestRoutingKeyCache) {
      byte[] dk = digestRoutingKeyCache.get(key);
      if (dk != null) return dk;
    }

    MessageDigest digest = SHA256.getMessageDigest();
    digest.update(plainKey);
    digest.update(salt);

    byte[] hashedRoutingKey = digest.digest();
    assert hashedRoutingKey.length == 0x20;

    synchronized (digestRoutingKeyCache) {
      digestRoutingKeyCache.put(key, hashedRoutingKey);
    }

    return hashedRoutingKey;
  }

  /**
   * Encrypts an entry's header and data in place.
   *
   * <p>Generates a new 16-byte per-entry IV, derives the cipher IV as {@code salt || entryIV}, and
   * encrypts {@code header} and {@code data} using PCFB with AES-256 and the entry's plain routing
   * key. Marks the entry as encrypted and computes its digested key for later lookups.
   *
   * @param entry entry to encrypt; mutated on success
   * @param random source of randomness for IV generation
   * @throws UnsupportedOperationException if the cipher cannot be initialized
   */
  void encrypt(SaltedHashFreenetStore<?>.Entry entry, Random random) {
    if (entry.isEncrypted) return;

    entry.dataEncryptIV = new byte[16];
    random.nextBytes(entry.dataEncryptIV);

    encipher(makeCipher(entry.dataEncryptIV, entry.plainRoutingKey), entry.header, entry.data);

    entry.getDigestedRoutingKey();
    entry.isEncrypted = true;
  }

  /**
   * Verifies the routing key and decrypts an entry in place.
   *
   * <p>If the entry is already decrypted, simply checks that the plain routing key matches the
   * provided {@code routingKey}. Otherwise, it verifies the digested routing key (when the plain
   * key is unknown) or the plain key itself, and decrypts the header and data using the derived
   * PCFB/AES-256 cipher. On success, the entry is marked as decrypted.
   *
   * @param entry entry to verify and decrypt; mutated on success
   * @param routingKey candidate plain routing key
   * @return {@code true} if {@code routingKey} matches and decryption succeeds; {@code false}
   *     otherwise
   * @throws UnsupportedOperationException if the cipher cannot be initialized
   */
  boolean decrypt(SaltedHashFreenetStore<?>.Entry entry, byte[] routingKey) {
    assert entry.header != null;
    assert entry.data != null;

    if (!entry.isEncrypted) {
      // Entry is already decrypted; verify caller-provided key matches the stored one.
      return Arrays.equals(entry.plainRoutingKey, routingKey);
    }

    if (entry.plainRoutingKey != null) {
      // Plain key is known; require exact match.
      if (!Arrays.equals(entry.plainRoutingKey, routingKey)) {
        return false;
      }
    } else {
      // Plain key unknown; verify by comparing digests.
      if (!Arrays.equals(entry.digestedRoutingKey, getDigestedKey(routingKey))) return false;
    }

    entry.plainRoutingKey = routingKey;

    decipher(makeCipher(entry.dataEncryptIV, entry.plainRoutingKey), entry.header, entry.data);

    entry.isEncrypted = false;

    return true;
  }

  /*
   * Encrypts header and data buffers using the supplied cipher instance.
   * PCFB is stateful; the order of operations is preserved between encipher/decipher pairs.
   */
  private static void encipher(PCFBMode cipher, byte[] header, byte[] data) {
    Objects.requireNonNull(cipher).blockEncipher(header, 0, header.length);
    Objects.requireNonNull(cipher).blockEncipher(data, 0, data.length);
  }

  /*
   * Decrypts header and data buffers using the supplied cipher instance.
   * Mirrors {@link #encipher(PCFBMode, byte[], byte[])} in call order.
   */
  private static void decipher(PCFBMode cipher, byte[] header, byte[] data) {
    Objects.requireNonNull(cipher).blockDecipher(header, 0, header.length);
    Objects.requireNonNull(cipher).blockDecipher(data, 0, data.length);
  }

  /**
   * Creates a PCFB cipher configured for the given key and IV.
   *
   * <p>The 256-bit IV is {@code salt || iv}. The cipher uses Rijndael with a 256-bit block size and
   * a key as provided by the caller. The returned instance is ready for block operations.
   *
   * @param iv 16-byte per-entry IV
   * @param key key bytes for {@link Rijndael#initialize(byte[])}; not validated here
   * @return initialized {@link PCFBMode} instance
   * @throws UnsupportedOperationException if the platform does not support the configured cipher
   */
  PCFBMode makeCipher(byte[] iv, byte[] key) {
    byte[] iv2 = new byte[0x20]; // 256 bits

    System.arraycopy(salt, 0, iv2, 0, 0x10);
    System.arraycopy(iv, 0, iv2, 0x10, 0x10);

    try {
      BlockCipher aes = new Rijndael(256, 256);
      aes.initialize(key);

      return PCFBMode.create(aes, iv2);
    } catch (UnsupportedCipherException e) {
      // Rethrow with context; caller is responsible for handling/logging.
      throw new UnsupportedOperationException(
          "Failed to initialize PCFB/AES-256 cipher (Rijndael unsupported): keyLen="
              + (key == null ? -1 : key.length)
              + ", ivLen="
              + iv2.length,
          e);
    }
  }

  /**
   * Clears sensitive material held by this instance.
   *
   * <p>Overwrites the in-memory {@code salt} and {@code diskSalt} arrays via {@link
   * MasterKeys#clear(byte[])}. After shutdown, this instance should not be used.
   */
  public void shutdown() {
    MasterKeys.clear(salt);
    MasterKeys.clear(diskSalt);
  }
}
