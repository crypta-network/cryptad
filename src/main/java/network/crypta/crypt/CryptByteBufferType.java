package network.crypta.crypt;

import java.io.Serializable;

/**
 * Describes supported stream/stream-like ciphers used by {@code CryptByteBuffer}.
 *
 * <p>Each enum constant defines a concrete cipher family and its operational parameters used by the
 * codebase when constructing and configuring JCE {@code Cipher} instances and generating keys.
 * Fields capture the key family ({@link #keyType}), the JCE transformation string ({@link
 * #algName}), and the IV/nonce length in bytes ({@link #ivSize}).
 *
 * <p><strong>Serialization compatibility:</strong> This enum is part of objects that are serialized
 * to disk (e.g., {@code CryptByteBuffer}). Java serialization records enum constants by name.
 * Renaming, removing, or reordering constants will cause historical data to fail to deserialize. Do
 * not change enum constant names without a deliberate, versioned migration strategy that can load
 * data written with older names.
 *
 * <p>Notes on units and terminology:
 *
 * <ul>
 *   <li>{@link #blockSize} stores the key size in <em>bits</em> as provided by {@link
 *       KeyType#keySize}; despite the field name, it is not the block size of a block cipher.
 *       AES-CTR uses a block cipher internally, but we treat all entries here as stream/nonce-based
 *       for configuration purposes.
 *   <li>{@link #ivSize} is the IV/nonce length in <em>bytes</em> required by the transformation
 *       identified in {@link #algName}.
 * </ul>
 *
 * @author unixninja92
 */
public enum CryptByteBufferType implements Serializable {
  /**
   * AES in CTR mode with no padding.
   *
   * <p>Key size is 256 bits (via {@link KeyType#AES_256}); the IV/nonce length is 16 bytes. The JCE
   * transformation string is {@code AES/CTR/NOPADDING}.
   */
  AESCTR(16, 16, "AES/CTR/NOPADDING", KeyType.AES_256),

  /**
   * ChaCha with a 128-bit key and 8-byte nonce.
   *
   * <p>The JCE algorithm name is {@code CHACHA}. This entry models the historical configuration
   * that uses 8-byte nonce; newer variants commonly use larger nonce but must remain compatible
   * with persisted data in this codebase.
   */
  CHACHA_128(32, 8, "CHACHA", KeyType.CHACHA_128),

  /**
   * ChaCha with a 256-bit key and 8-byte nonce.
   *
   * <p>The JCE algorithm name is {@code CHACHA}. See {@link #CHACHA_128} for notes on nonce size
   * compatibility.
   */
  CHACHA_256(64, 8, "CHACHA", KeyType.CHACHA_256);

  /** Bitmask used when aggregating or filtering supported types. */
  public final int bitmask;

  /**
   * Key size in bits for this configuration as sourced from {@link KeyType#keySize}. Not the block
   * size of the underlying block cipher (if any).
   */
  public final int blockSize;

  /** IV/nonce length in bytes expected by the transformation in {@link #algName}. */
  public final Integer ivSize; // in bytes

  /** JCE transformation or algorithm string passed to {@code Cipher.getInstance(...)}. */
  public final String algName;

  /** Algorithm name used by the key generator; typically matches {@link KeyType#alg}. */
  public final String cipherName;

  /** Key family and sizes associated with this cipher configuration. */
  public final KeyType keyType;

  /** True when this entry represents a stream/nonce-based configuration. */
  public final boolean isStreamCipher;

  /**
   * Constructs a cipher descriptor.
   *
   * @param bitmask aggregation bitmask for the type
   * @param ivSize IV/nonce size in bytes
   * @param algName JCE transformation or algorithm name
   * @param keyType key family and sizes used for key generation
   */
  CryptByteBufferType(int bitmask, int ivSize, String algName, KeyType keyType) {
    this.bitmask = bitmask;
    this.ivSize = ivSize;
    this.cipherName = keyType.alg;
    this.blockSize = keyType.keySize;
    this.algName = algName;
    this.keyType = keyType;
    isStreamCipher = true;
  }

  /**
   * Indicates whether this configuration uses an IV/nonce.
   *
   * <p>At present all supported entries are stream/nonce-based and therefore return {@code true}.
   * If block-cipher modes without nonces are added in the future, this method will differentiate
   * those types.
   *
   * @return {@code true} when an IV/nonce is required
   */
  public boolean hasIV() {
    return isStreamCipher;
  }
}
