package network.crypta.platform.appvault;

import java.io.IOException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Supplies the local wrapping key used by app-vault envelopes.
 *
 * <p>The vault service depends on this abstraction so the storage layer can be honest about the
 * actual protection in use. The default provider stores a local host key file, while a future
 * provider could wrap the same envelope format with master-password or hardware-backed material.
 * Implementations must never log or expose raw key bytes.
 */
public interface AppVaultKeyProvider {
  /**
   * Returns the active vault wrapping key.
   *
   * <p>The returned value includes both the key id serialized in envelopes and the raw AES bytes
   * used by {@link AppVaultEnvelope}. Providers may create the key on first use, but repeated calls
   * should return material that can decrypt existing envelopes for the same vault root.
   *
   * @return active local vault key with redacted {@code toString()} output
   * @throws IOException if key material cannot be loaded, created, or permission-hardened
   */
  VaultKey currentKey() throws IOException;

  /**
   * Returns the active key as a JCA AES key.
   *
   * <p>This compatibility helper keeps the minimal {@link AppVaultService} API independent of the
   * envelope key-id wrapper while preserving the existing {@link #currentKey()} contract.
   *
   * @return active local AES key built from the current vault key bytes
   * @throws IOException if key material cannot be loaded, created, or permission-hardened
   */
  @SuppressWarnings("unused")
  default SecretKey loadOrCreateKey() throws IOException {
    return new SecretKeySpec(currentKey().keyBytes(), "AES");
  }

  /**
   * Immutable sensitive key material returned by a vault key provider.
   *
   * <p>The value object defensively copies key bytes on input and output, includes the stable key
   * id needed for envelope matching, and redacts key bytes from diagnostic text. It does not zero
   * the internal byte array on garbage collection, so callers should keep instances short-lived
   * where practical.
   */
  @SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
  final class VaultKey {
    /** Stable key identifier written to app-vault envelope metadata. */
    private final String keyId;

    /** Raw AES key bytes; never include this value in logs or public JSON. */
    private final byte[] keyBytes;

    /**
     * Creates a key value.
     *
     * @param keyId stable key id stored in envelopes and used for decrypt matching
     * @param keyBytes raw AES key bytes copied into this value object
     */
    public VaultKey(String keyId, byte[] keyBytes) {
      this.keyId = java.util.Objects.requireNonNull(keyId, "keyId");
      this.keyBytes = java.util.Objects.requireNonNull(keyBytes, "keyBytes").clone();
    }

    /**
     * Returns the stable key id.
     *
     * @return key id serialized into newly written envelopes
     */
    public String keyId() {
      return keyId;
    }

    /**
     * Returns a defensive copy of the raw key bytes.
     *
     * @return copied AES key bytes for immediate cipher use
     */
    public byte[] keyBytes() {
      return keyBytes.clone();
    }

    @Override
    public String toString() {
      return "VaultKey[keyId=" + keyId + ", keyBytes=<redacted>]";
    }

    @Override
    public boolean equals(Object other) {
      if (!(other instanceof VaultKey that)) {
        return false;
      }
      return keyId.equals(that.keyId) && Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
      return 31 * keyId.hashCode() + Arrays.hashCode(keyBytes);
    }
  }
}
