package network.crypta.platform.appdist;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * One explicit trusted public signing key.
 *
 * <p>A trusted key binds a stable key id from {@code cryptad-app.signature} to the public key used
 * for Ed25519 verification. The key id is not discovered from the key material; operators and build
 * tooling choose it so signatures can rotate keys without changing the bundle format. Trust remains
 * explicit because callers pass {@link TrustedAppKeys} into each verifier rather than relying on
 * global mutable state.
 *
 * <p>Public keys use standard X.509 SubjectPublicKeyInfo encoding. Text helpers accept raw base64
 * or PEM-wrapped material so configuration files and environment variables can use common
 * key-export formats.
 *
 * @param keyId stable key identifier used by bundle signatures
 * @param algorithm signature algorithm supported by the key
 * @param publicKey public verification key
 */
public record TrustedAppKey(String keyId, String algorithm, PublicKey publicKey) {
  /**
   * Creates a trusted Ed25519 public key from base64-encoded X.509 bytes or a PEM payload.
   *
   * <p>This overload is intended for operator configuration values. Whitespace and PEM wrapper
   * lines are ignored before base64 decoding; malformed key material is reported as a distribution
   * configuration error.
   *
   * @param keyId stable signature key identifier expected in signed bundle sidecars
   * @param publicKeyMaterial base64-encoded X.509 bytes or a PEM payload
   * @return decoded trusted Ed25519 public key
   * @throws AppDistributionException if the key material cannot be decoded
   */
  public static TrustedAppKey ed25519(String keyId, String publicKeyMaterial)
      throws AppDistributionException {
    try {
      return ed25519(
          keyId,
          AppDistributionSidecars.decodeBase64KeyMaterial(
              publicKeyMaterial, "public key material"));
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException("invalid public key material", exception);
    }
  }

  /**
   * Creates a trusted Ed25519 public key from X.509 key bytes.
   *
   * <p>This overload is useful when callers already read raw DER bytes from a trusted-key file. The
   * byte array is not retained after the JDK key factory decodes it.
   *
   * @param keyId stable signature key identifier expected in signed bundle sidecars
   * @param publicKeyBytes X.509 public key bytes
   * @return decoded trusted Ed25519 public key
   * @throws AppDistributionException if the key material cannot be decoded
   */
  public static TrustedAppKey ed25519(String keyId, byte[] publicKeyBytes)
      throws AppDistributionException {
    try {
      PublicKey publicKey =
          KeyFactory.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM)
              .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
      return new TrustedAppKey(keyId, AppBundleSignature.SIGNATURE_ALGORITHM, publicKey);
    } catch (GeneralSecurityException | IllegalArgumentException exception) {
      throw new AppDistributionException("failed to decode Ed25519 public key", exception);
    }
  }

  /**
   * Creates a validated trusted-key entry.
   *
   * <p>The constructor validates sidecar-safe text fields and requires a non-null public key. It
   * does not verify that the public key's JDK algorithm string matches {@code algorithm}; factory
   * methods should be preferred when constructing keys from encoded material.
   *
   * @param keyId stable key identifier used by bundle signatures
   * @param algorithm signature algorithm supported by the key
   * @param publicKey public verification key
   * @throws IllegalArgumentException if the key id or algorithm is blank or multi-line
   */
  public TrustedAppKey {
    keyId = AppDistributionSidecars.requireNonBlankSingleLine(keyId, "keyId");
    algorithm = AppDistributionSidecars.requireNonBlankSingleLine(algorithm, "algorithm");
    Objects.requireNonNull(publicKey, "publicKey");
  }
}
