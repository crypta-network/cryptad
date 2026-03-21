package network.crypta.keys;

import network.crypta.crypt.KeyType;

/**
 * Defines CHK-specific key sizes in the keys package.
 *
 * <p>This package-private helper keeps CHK byte-count decisions close to the code that validates
 * and allocates CHK crypto material. The values are still derived from shared cryptographic
 * definitions rather than hard-coded magic numbers, but callers no longer need to depend on
 * unrelated node-layer constants just to ask how many bytes an AES-256 CHK key requires.
 */
final class ChkKeySizes {
  /** Number of bytes required for CHK AES-256 crypto keys. */
  static final int AES_256_BYTES = KeyType.AES_256.keySize / Byte.SIZE;

  /** Prevents instantiation of this constants-only helper. */
  private ChkKeySizes() {
    throw new IllegalStateException("Utility class");
  }
}
