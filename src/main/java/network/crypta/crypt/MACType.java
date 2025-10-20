package network.crypta.crypt;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;

/**
 * Enumerates Message Authentication Code (MAC) algorithms used in Crypta and exposes the properties
 * needed to configure them with the Java Cryptography Architecture (JCA).
 *
 * <p>Each constant records the JCA algorithm name, the associated {@link KeyType} family, and the
 * required IV/nonce length in bytes when applicable. Algorithms that do not use an IV/nonce set
 * {@link #ivlen} to {@code -1}.
 *
 * <p>This enum provides a convenience method, {@link #get()}, that returns a ready-to-use {@link
 * javax.crypto.Mac} instance for the selected algorithm. Callers remain responsible for
 * initializing it with the appropriate key (and IV/nonce when required).
 *
 * @author unixninja92
 */
public enum MACType {
  HMAC_SHA256(1, "HmacSHA256", KeyType.HMAC_SHA256),
  HMAC_SHA384(2, "HmacSHA384", KeyType.HMAC_SHA384),
  HMAC_SHA512(2, "HmacSHA512", KeyType.HMAC_SHA512),
  POLY1305_AES(2, "POLY1305-AES", 16, KeyType.POLY1305_AES);

  /**
   * Version/feature bitmask for consumers that combine cryptographic selections. The specific
   * meaning of individual bits is defined by the calling code that persists or interprets it.
   */
  public final int bitmask;

  /** JCA standard algorithm name passed to {@link Mac#getInstance(String)}. */
  public final String mac;

  /**
   * IV/nonce length in bytes. A value of {@code -1} indicates that the algorithm does not use an
   * IV/nonce (e.g., HMAC variants).
   */
  public final int ivlen;

  /** Key family used to derive or validate compatible secret keys. */
  public final KeyType keyType;

  /**
   * Creates an enum constant for MAC algorithms that do not require an IV/nonce.
   *
   * @param bitmask version/feature bitmask for aggregation or serialization
   * @param mac JCA algorithm name (for example, {@code "HmacSHA256"})
   * @param type key family required by the algorithm
   */
  MACType(int bitmask, String mac, KeyType type) {
    this.bitmask = bitmask;
    this.mac = mac;
    ivlen = -1;
    keyType = type;
  }

  /**
   * Creates an enum constant for MAC algorithms that require an IV/nonce.
   *
   * @param bitmask version/feature bitmask for aggregation or serialization
   * @param mac JCA algorithm name
   * @param ivlen IV/nonce length in bytes
   * @param type key family required by the algorithm
   */
  MACType(int bitmask, String mac, int ivlen, KeyType type) {
    this.bitmask = bitmask;
    this.mac = mac;
    this.ivlen = ivlen;
    keyType = type;
  }

  /**
   * Obtains a new {@link Mac} instance configured for this algorithm.
   *
   * <p>The instance is not initialized. Callers must initialize it with a compatible key (and IV/
   * nonce when required by {@link #ivlen}).
   *
   * @return a new {@link Mac} instance
   * @throws IllegalStateException if the algorithm is unavailable in the current JCA providers
   */
  public final Mac get() {
    try {
      return Mac.getInstance(mac);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e); // Definitely a bug...
    }
  }
}
