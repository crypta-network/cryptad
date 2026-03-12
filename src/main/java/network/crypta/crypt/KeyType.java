package network.crypta.crypt;

/**
 * Enumerates cryptographic algorithm families used by the node and provides their canonical
 * identifiers together with key and IV/nonce sizes (in bits).
 *
 * <p>The constants in this enum are referenced by key-derivation and cipher-selection code across
 * Crypta (and legacy Freenet-compatible components). Each entry supplies:
 *
 * <ul>
 *   <li>{@link #alg}: a canonical algorithm identifier (e.g., {@code AES}, {@code CHACHA}, {@code
 *       HMACSHA256}).
 *   <li>{@link #keySize}: the key size in bits.
 *   <li>{@link #ivSize}: the IV/nonce size in bits when the algorithm uses one. For algorithms that
 *       do not use an IV/nonce (e.g., HMAC), callers may ignore this value.
 *   <li>{@link #kdfLabel}: a stable, historical label used as part of key derivation inputs. It is
 *       independent of the enum constant name and must remain stable to preserve wire and on-disk
 *       compatibility when enum names change.
 * </ul>
 *
 * <p>Values are immutable and safe for concurrent use.
 *
 * @author unixninja92
 */
public enum KeyType {
  /**
   * Rijndael (AES family) with a 128-bit key size. Retained for historical compatibility where the
   * label distinguishes legacy use.
   */
  RIJNDAEL_128("RIJNDAEL", 128, "Rijndael128"),

  /**
   * Rijndael (AES family) with a 256-bit key size. Retained for historical compatibility where the
   * label distinguishes legacy use.
   */
  RIJNDAEL_256("RIJNDAEL", 256, "Rijndael256"),

  /** AES block cipher with a 128-bit key. */
  AES_128("AES", 128, "AES128"),

  /** AES block cipher with a 256-bit key. */
  AES_256("AES", 256, "AES256"),

  /** HMAC with SHA-256; key size is 256 bits. */
  HMAC_SHA256("HMACSHA256", 256, "HMACSHA256"),

  /** HMAC with SHA-384; key size is 384 bits. */
  HMAC_SHA384("HMACSHA384", 384, "HMACSHA384"),

  /** HMAC with SHA-512; key size is 512 bits. */
  HMAC_SHA512("HMACSHA512", 512, "HMACSHA512"),

  /**
   * Poly1305-AES one-time authenticator. Uses a 256-bit key with a 128-bit nonce/IV consistent with
   * the classic construction.
   */
  POLY1305_AES("POLY1305-AES", 256, 128, "POLY1305AES"),

  /** ChaCha stream cipher with a 128-bit key and 64-bit nonce. */
  CHACHA_128("CHACHA", 128, 64, "ChaCha128"),

  /** ChaCha stream cipher with a 256-bit key and 64-bit nonce. */
  CHACHA_256("CHACHA", 256, 64, "ChaCha256");

  /**
   * Canonical algorithm identifier used by key generation/KDF logic and cipher configuration (for
   * example, {@code AES}, {@code CHACHA}, or {@code HMACSHA256}).
   */
  public final String alg;

  /** Key size in bits. */
  public final int keySize; // bits

  /** IV/nonce size in bits for algorithms that use one; otherwise ignored by callers. */
  public final int ivSize; // bits

  /**
   * Stable label used in KDF inputs to preserve backward compatibility across enum renames.
   *
   * <p>The label forms part of a contextual string for KDFs and persistent formats; changing it can
   * break decryption or signature verification of existing data. Do not modify existing labels.
   */
  public final String kdfLabel;

  /**
   * Initializes an enum constant for the given algorithm and key size; the IV/nonce size is set to
   * the same value as {@code keySize}.
   *
   * <p>This overload is used where IV/nonce size is not specified separately.
   *
   * @param alg canonical algorithm identifier (e.g., {@code AES}, {@code HMACSHA256}).
   * @param keySize key size in bits.
   * @param kdfLabel stable label used by KDFs and persistent formats.
   */
  KeyType(String alg, int keySize, String kdfLabel) {
    this.alg = alg;
    this.keySize = keySize;
    this.ivSize = keySize;
    this.kdfLabel = kdfLabel;
  }

  /**
   * Initializes an enum constant for the given algorithm, key size, and IV/nonce size.
   *
   * @param alg canonical algorithm identifier (e.g., {@code AES}, {@code CHACHA}).
   * @param keySize key size in bits.
   * @param ivSize IV/nonce size in bits when applicable.
   * @param kdfLabel stable label used by KDFs and persistent formats.
   */
  KeyType(String alg, int keySize, int ivSize, String kdfLabel) {
    this.alg = alg;
    this.keySize = keySize;
    this.ivSize = ivSize;
    this.kdfLabel = kdfLabel;
  }
}
