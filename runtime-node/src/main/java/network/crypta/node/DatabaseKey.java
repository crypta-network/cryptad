package network.crypta.node;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import network.crypta.crypt.AEADCryptBucket;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.Bucket;

/**
 * Immutable wrapper around the node-local database secret.
 *
 * <p>Derives context-separated symmetric keys for persisted components using HMAC-SHA-256. The key
 * bytes are kept private, defensively copied on construction, and never returned directly.
 * Instances are thread-safe.
 */
public class DatabaseKey {

  // KDF context label (ASCII) for domain separation between derived keys.
  private static final byte[] CLIENT_LAYER = "CLIENT".getBytes(StandardCharsets.UTF_8);

  // Backing key material. Not exposed and never mutated after construction.
  private final byte[] key;

  /**
   * Constructs a new instance from raw key material.
   *
   * <p>The input array is defensively copied to prevent external mutation of the secret.
   *
   * @param key secret bytes; must not be {@code null}. Callers may clear the provided array after
   *     this call.
   */
  DatabaseKey(byte[] key) {
    this.key = Arrays.copyOf(key, key.length);
  }

  /**
   * Returns an AEAD-encrypted wrapper for client-layer persistence.
   *
   * <p>The returned bucket uses a key derived from this database secret with the {@code "CLIENT"}
   * context label. The AEAD mode and nonce handling are defined by {@link AEADCryptBucket}; this
   * method only supplies key material.
   *
   * @param underlying storage to wrap; must not be {@code null}.
   * @return a bucket that encrypts/decrypts data for the client layer.
   */
  public Bucket createEncryptedBucketForClientLayer(Bucket underlying) {
    return new AEADCryptBucket(underlying, getKeyForClientLayer());
  }

  /**
   * Generates a new database key using randomness from the provided source.
   *
   * <p>Reads 32 bytes from {@code random} and constructs a new immutable instance.
   *
   * @param random randomness provider; must not be {@code null}.
   * @return a new instance backed by 32 random bytes.
   */
  public static DatabaseKey createRandom(RandomSource random) {
    byte[] databaseKey = new byte[32];
    random.nextBytes(databaseKey);
    return new DatabaseKey(databaseKey);
  }

  /**
   * Derives the client-layer encryption key.
   *
   * <p>Formula: {@code HMAC-SHA-256(key, key || "CLIENT")}.
   *
   * @return a 32-byte key derived with HMAC-SHA-256.
   */
  public byte[] getKeyForClientLayer() {
    byte[] full = new byte[key.length + CLIENT_LAYER.length];
    int x = 0;
    System.arraycopy(key, 0, full, 0, key.length);
    x += key.length;
    System.arraycopy(CLIENT_LAYER, 0, full, x, CLIENT_LAYER.length);
    return HMAC.macWithSHA256(key, full);
  }

  /** Returns a hash code based on the key bytes. */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(key);
    return result;
  }

  /**
   * Compares for equality by key content.
   *
   * <p>Two instances are equal when their underlying key byte arrays are equal.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DatabaseKey other)) {
      return false;
    }
    return Arrays.equals(key, other.key);
  }
}
