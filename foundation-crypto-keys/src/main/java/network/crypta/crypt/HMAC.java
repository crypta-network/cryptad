package network.crypta.crypt;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utilities for computing and verifying HMAC (Keyed-Hash Message Authentication Code).
 *
 * <p>This enum defines supported HMAC variants and provides convenience methods that wrap the
 * standard JCA {@link javax.crypto.Mac} API. A new {@code Mac} instance is created per call, so all
 * methods are thread-safe.
 *
 * <p>Key length policy: this implementation requires a key whose length equals the tag/output size
 * of the selected algorithm (no key stretching). For {@link #SHA2_256}, the key must be 32 bytes.
 */
public enum HMAC {
  /** HMAC-SHA-256 (JCA name {@code HmacSHA256}); produces a 32-byte tag. */
  SHA2_256("HmacSHA256", 32);

  final String algo;
  final int digestSize;

  HMAC(String name, int size) {
    this.algo = name;
    this.digestSize = size;
  }

  /**
   * Computes the HMAC of {@code data} using {@code key} and the specified algorithm.
   *
   * <p>Data may be {@code null}; it is treated as an empty byte array. The returned array length is
   * {@code hash.digestSize}.
   *
   * @param hash the HMAC variant to use
   * @param key the HMAC key; must be exactly {@code hash.digestSize} bytes long
   * @param data the message to authenticate; {@code null} is treated as empty
   * @return the computed MAC bytes; length equals {@code hash.digestSize}
   * @throws NullPointerException if {@code hash} or {@code key} is {@code null}
   * @throws IllegalArgumentException if {@code key.length != hash.digestSize}
   * @throws IllegalStateException if the algorithm is unavailable or the key cannot initialize the
   *     underlying {@link javax.crypto.Mac}
   */
  public static byte[] mac(HMAC hash, byte[] key, byte[] data) {
    if (key.length != hash.digestSize)
      throw new IllegalArgumentException(
          "Wrong keysize! We're not doing key stretching "
              + key.length
              + " expected "
              + hash.digestSize);

    SecretKeySpec signingKey = new SecretKeySpec(key, hash.algo);
    Mac mac;
    try {
      mac = Mac.getInstance(hash.algo);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("HMAC algorithm not available: " + hash.algo, e);
    }
    try {
      mac.init(signingKey);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException(
          "Invalid key for HMAC initialization (algo=" + hash.algo + ")", e);
    }
    // Treat null data as empty for compatibility with callers and providers.
    byte[] input = (data == null) ? new byte[0] : data;
    return mac.doFinal(input);
  }

  /**
   * Verifies that {@code mac} matches the HMAC of {@code data} with {@code key} using {@code hash}.
   *
   * <p>Comparison uses {@link java.security.MessageDigest#isEqual(byte[], byte[])} to reduce timing
   * side channels. If {@code mac} is {@code null}, the method returns {@code false}. Data may be
   * {@code null} and is treated as empty.
   *
   * @param hash the HMAC variant to use
   * @param key the HMAC key; must be exactly {@code hash.digestSize} bytes long
   * @param data the message to authenticate; {@code null} is treated as empty
   * @param mac the expected MAC; may be {@code null}
   * @return {@code true} if the computed MAC equals {@code mac}; otherwise {@code false}
   * @throws NullPointerException if {@code hash} or {@code key} is {@code null}
   * @throws IllegalArgumentException if {@code key.length != hash.digestSize}
   * @throws IllegalStateException if the algorithm is unavailable or the key cannot initialize the
   *     underlying {@link javax.crypto.Mac}
   */
  public static boolean verify(HMAC hash, byte[] key, byte[] data, byte[] mac) {
    return MessageDigest.isEqual(mac, mac(hash, key, data));
  }

  /**
   * Convenience wrapper for {@link #mac(HMAC, byte[], byte[])} using {@link #SHA2_256}.
   *
   * @param key the HMAC key; must be 32 bytes
   * @param text the message to authenticate; {@code null} is treated as empty
   * @return the 32-byte HMAC-SHA-256 tag
   * @throws NullPointerException if {@code key} is {@code null}
   * @throws IllegalArgumentException if {@code key.length != 32}
   * @throws IllegalStateException if the algorithm is unavailable or the key cannot initialize the
   *     underlying {@link javax.crypto.Mac}
   */
  public static byte[] macWithSHA256(byte[] key, byte[] text) {
    return mac(HMAC.SHA2_256, key, text);
  }

  /**
   * Convenience wrapper for {@link #verify(HMAC, byte[], byte[], byte[])} using {@link #SHA2_256}.
   *
   * @param key the HMAC key; must be 32 bytes
   * @param text the message to authenticate; {@code null} is treated as empty
   * @param mac the expected MAC; may be {@code null}
   * @return {@code true} if the computed HMAC-SHA-256 equals {@code mac}; otherwise {@code false}
   * @throws NullPointerException if {@code key} is {@code null}
   * @throws IllegalArgumentException if {@code key.length != 32}
   * @throws IllegalStateException if the algorithm is unavailable or the key cannot initialize the
   *     underlying {@link javax.crypto.Mac}
   */
  public static boolean verifyWithSHA256(byte[] key, byte[] text, byte[] mac) {
    return verify(HMAC.SHA2_256, key, text, mac);
  }
}
