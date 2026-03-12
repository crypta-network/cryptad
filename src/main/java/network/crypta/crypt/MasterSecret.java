package network.crypta.crypt;

import java.io.Serial;
import java.io.Serializable;
import java.security.InvalidKeyException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Serializable master secret used to deterministically derive symmetric keys and initialization
 * vectors (IVs) for local storage.
 *
 * <p>Each instance holds a 512-bit HMAC‑SHA‑512 key and derives material via {@link KeyGenUtils}'
 * HMAC-based KDF. Domain separation is achieved by using this class' {@link Class#getName() name}
 * together with a context string (for example, {@code " key"} or {@code " iv"}).
 *
 * <p>This class is immutable and thread-safe.
 *
 * @author unixninja92
 */
public final class MasterSecret implements Serializable {
  @Serial private static final long serialVersionUID = -8411217325990445764L;
  private final SecretKey masterKey;

  /**
   * Creates a new instance with a freshly generated 512-bit HMAC‑SHA‑512 key.
   *
   * <p>Use this when no previously persisted secret exists.
   */
  public MasterSecret() {
    masterKey = KeyGenUtils.genSecretKey(KeyType.HMAC_SHA512);
  }

  /**
   * Creates a new instance backed by the provided key material.
   *
   * @param secret raw key bytes; must be exactly 64 bytes (512 bits)
   * @throws NullPointerException if {@code secret} is {@code null}
   * @throws IllegalArgumentException if {@code secret.length != 64}
   */
  public MasterSecret(byte[] secret) {
    if (secret.length != 64) throw new IllegalArgumentException();
    masterKey = KeyGenUtils.getSecretKey(KeyType.HMAC_SHA512, secret);
  }

  /**
   * Derives a {@link SecretKey} of the requested {@link KeyType} from this master secret.
   *
   * <p>The returned key uses {@code type.alg} and has a length of {@code type.keySize/8} bytes. For
   * a given instance and {@code type}, the derivation is deterministic.
   *
   * @param type key type to derive; must not be {@code null}
   * @return derived key
   * @throws NullPointerException if {@code type} is {@code null}
   * @throws IllegalStateException if the master key is not valid for the KDF
   */
  public SecretKey deriveKey(KeyType type) {
    try {
      // Use KeyType.kdfLabel to keep derived keys stable across enum renames
      return KeyGenUtils.deriveSecretKey(masterKey, getClass(), type.kdfLabel + " key", type);
    } catch (InvalidKeyException e) {
      // The HMAC‑SHA‑512 master key should always be valid; wrap for callers.
      throw new IllegalStateException(e);
    }
  }

  /**
   * Derives an {@link IvParameterSpec} of the requested {@link KeyType} from this master secret.
   *
   * <p>The returned IV has a length of {@code type.ivSize/8} bytes. For a given instance and {@code
   * type}, the derivation is deterministic.
   *
   * @param type IV type to derive; must not be {@code null}
   * @return derived IV
   * @throws NullPointerException if {@code type} is {@code null}
   * @throws IllegalStateException if the master key is not valid for the KDF
   */
  public IvParameterSpec deriveIv(KeyType type) {
    try {
      // Use KeyType.kdfLabel to keep derived IVs stable across enum renames
      return KeyGenUtils.deriveIvParameterSpec(masterKey, getClass(), type.kdfLabel + " iv", type);
    } catch (InvalidKeyException e) {
      // The HMAC‑SHA‑512 master key should always be valid; wrap for callers.
      throw new IllegalStateException(e);
    }
  }

  /**
   * Returns a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The value is derived from the underlying master key.
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((masterKey == null) ? 0 : masterKey.hashCode());
    return result;
  }

  /**
   * Compares this instance with another for equality.
   *
   * <p>Two instances are equal if and only if their underlying master keys are equal.
   *
   * @param obj the object to compare with
   * @return {@code true} if {@code obj} is a {@code MasterSecret} with an equal master key
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    MasterSecret other = (MasterSecret) obj;
    return masterKey.equals(other.masterKey);
  }
}
