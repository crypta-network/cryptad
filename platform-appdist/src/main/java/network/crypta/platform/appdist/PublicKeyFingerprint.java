package network.crypta.platform.appdist;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Computes stable fingerprints for already-parsed public keys.
 *
 * <p>Trust registries decode and validate their own supported key formats before calling this
 * utility. The utility hashes the canonical bytes returned by {@link PublicKey#getEncoded()} and
 * never parses key text, selects an algorithm, or makes an authorization decision. App-publisher,
 * catalog, reviewer, and recovery policies can therefore compare the same public-key identity while
 * retaining separate registries and lifecycle rules.
 *
 * <p>The class is stateless and thread-safe. A fingerprint is public identifying metadata, not a
 * substitute for signature verification or a grant of trust. Callers must compare it only inside an
 * explicit local role or scope policy.
 */
public final class PublicKeyFingerprint {
  /** Prevents construction of this stateless fingerprint utility. */
  private PublicKeyFingerprint() {
    // Utility class.
  }

  /**
   * Returns the lowercase SHA-256 fingerprint of a key's canonical X.509 encoding.
   *
   * <p>This method deliberately accepts a parsed {@link PublicKey}. Key registries remain
   * responsible for decoding and validating their supported algorithms, while role-separation and
   * policy layers can compare one canonical identity without duplicating key parsing. Repeated
   * calls for the same encoded key return the same 64-character lowercase hexadecimal value. The
   * method does not retain the key or its encoded bytes.
   *
   * @param publicKey parsed public key whose canonical encoding identifies the key
   * @return 64-character lowercase SHA-256 fingerprint of the canonical encoding
   * @throws NullPointerException if {@code publicKey} is {@code null}
   * @throws IllegalArgumentException if the public key has no canonical encoding
   */
  public static String sha256(PublicKey publicKey) {
    byte[] encoded = Objects.requireNonNull(publicKey, "publicKey").getEncoded();
    if (encoded == null || encoded.length == 0) {
      throw new IllegalArgumentException("trusted public key has no canonical encoding");
    }
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
