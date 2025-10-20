package network.crypta.crypt;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;

/**
 * Algorithm suite and on-disk header layout used by {@link EncryptedRandomAccessBuffer} and
 * companions.
 *
 * <p>Each enum constant describes a concrete combination of stream cipher and MAC algorithm, the
 * version bitmask recorded on disk, and the computed cleartext <em>header</em> length in bytes. The
 * header length is the size of the metadata region placed at the start of the underlying buffer
 * before the encrypted data region begins.
 *
 * <p>Fields expose both high-level selections (cipher/MAC) and derived values that callers need for
 * layout and key generation, such as the cipher key family and MAC key family. Values that
 * represent sizes are expressed in <strong>bytes</strong> unless otherwise noted.
 *
 * <p><strong>Serialization and compatibility:</strong> The bitmask value is persisted by helper
 * methods (e.g., {@code storeTo(...)}); {@link #getByBitmask(int)} maps it back to a type when
 * resuming. Enum names may also be serialized by Java serialization in some contexts; avoid
 * renaming constants without a migration strategy.
 *
 * @author unixninja92
 */
public enum EncryptedRandomAccessBufferType {
  /**
   * ChaCha with a 128-bit key and HMAC-SHA-256 for header authentication.
   *
   * <p>The header format reserves 12 bytes for version and magic, then includes the encrypted base
   * key, IV/nonce, and a 32-byte MAC. See {@link #headerLen} for the total size in bytes.
   */
  CHACHA_128(1, 12, CryptByteBufferType.CHACHA_128, MACType.HMAC_SHA256, 32),

  /**
   * ChaCha with a 256-bit key and HMAC-SHA-256 for header authentication.
   *
   * <p>Same header structure as {@link #CHACHA_128} but with a 256-bit cipher key size.
   */
  CHACHA_256(2, 12, CryptByteBufferType.CHACHA_256, MACType.HMAC_SHA256, 32);

  /** Version bitmask written to persistent streams to identify this type. */
  public final int bitmask;

  /** Total cleartext header length in bytes. */
  public final int headerLen; // bytes

  /** Cipher configuration describing transformation, IV length, and key family. */
  public final CryptByteBufferType encryptType;

  /** Key family used to derive/generate the stream cipher key. */
  public final KeyType encryptKey;

  /** MAC algorithm used to authenticate header fields. */
  public final MACType macType;

  /** Key family used to derive/generate the MAC key. */
  public final KeyType macKey;

  /** Length of the MAC output in bytes. */
  public final int macLen; // bytes

  /**
   * Constructs an enum value describing a header/cipher/MAC combination.
   *
   * <p>The computed {@link #headerLen} equals {@code magAndVerLen + keyBytes + ivBytes + macLen},
   * where {@code keyBytes} and {@code ivBytes} are derived from {@link KeyType#keySize} and {@link
   * KeyType#ivSize} (both in bits) via a right shift by 3.
   *
   * @param bitmask version bitmask persisted alongside data
   * @param magAndVerLen number of bytes reserved for magic and version (typically 12)
   * @param type cipher configuration used for encrypting the data region
   * @param macType MAC algorithm used for authenticating the header
   * @param macLen MAC output length in bytes written into the header
   */
  EncryptedRandomAccessBufferType(
      int bitmask, int magAndVerLen, CryptByteBufferType type, MACType macType, int macLen) {
    this.bitmask = bitmask;
    this.encryptType = type;
    this.encryptKey = type.keyType;
    this.macType = macType;
    this.macKey = macType.keyType;
    this.macLen = macLen;
    this.headerLen = magAndVerLen + (encryptKey.keySize >> 3) + (encryptKey.ivSize >> 3) + macLen;
  }

  /**
   * Creates a new {@link SkippingStreamCipher} matching this type.
   *
   * <p>The returned instance is a fresh engine and is not thread-safe. Callers must configure it
   * with the appropriate key/IV parameters before use.
   *
   * @return a new, uninitialized stream cipher instance
   */
  public final SkippingStreamCipher get() {
    return new ChaChaEngine();
  }

  /** Lookup table from {@link #bitmask} to enum value for fast deserialization. */
  private static final Map<Integer, EncryptedRandomAccessBufferType> byBitmask;

  static {
    byBitmask = new HashMap<>();
    // Build the reverse mapping once; enum values are stable at runtime.
    for (EncryptedRandomAccessBufferType type : values()) {
      byBitmask.put(type.bitmask, type);
    }
  }

  /**
   * Resolves an enum value by its persisted version bitmask.
   *
   * @param val bitmask read from a persistent stream
   * @return the matching type, or {@code null} if the bitmask is unknown
   */
  public static EncryptedRandomAccessBufferType getByBitmask(int val) {
    return byBitmask.get(val);
  }
}
