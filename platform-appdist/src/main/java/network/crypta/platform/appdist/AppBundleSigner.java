package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Writes deterministic Ed25519 signatures for bundle digest sidecars.
 *
 * <p>The signer is the local build/tooling entry point for producing {@code cryptad-app.digests}
 * and {@code cryptad-app.signature}. It first regenerates the digest from the current bundle tree,
 * reads the exact UTF-8 sidecar bytes that were written, and signs those bytes with a
 * caller-supplied Ed25519 private key. Verification uses the same byte-for-byte payload, so callers
 * must not rewrite or normalize the digest file between signing and verification.
 *
 * <p>This class deliberately does not load production secrets from global state. Callers provide
 * key material explicitly, typically from an environment variable or a private key file outside the
 * repository. Do not pass production private keys through shell command arguments or commit them
 * with staged app bundles.
 */
public final class AppBundleSigner {
  private AppBundleSigner() {}

  /**
   * Loads an Ed25519 private key from base64-encoded PKCS#8 bytes or a PEM payload.
   *
   * <p>The accepted textual forms are raw base64 PKCS#8 bytes and PEM text with standard header and
   * footer lines. The returned key is suitable for {@link #sign(Path, String, PrivateKey)} but is
   * not cached or stored by this class.
   *
   * @param privateKeyMaterial base64-encoded PKCS#8 bytes or a PEM payload
   * @return decoded Ed25519 private key
   * @throws AppDistributionException if the key material is blank or cannot be decoded
   */
  public static PrivateKey loadPrivateKey(String privateKeyMaterial)
      throws AppDistributionException {
    return loadPrivateKey(
        AppDistributionSidecars.decodeBase64KeyMaterial(
            privateKeyMaterial, "private key material"));
  }

  /**
   * Loads an Ed25519 private key from PKCS#8 bytes.
   *
   * <p>This overload is useful when the caller already read key material from a file or secret
   * manager. The byte array is not retained after the key factory returns.
   *
   * @param privateKeyBytes PKCS#8 private key bytes
   * @return decoded Ed25519 private key
   * @throws AppDistributionException if the key material cannot be decoded as an Ed25519 key
   */
  public static PrivateKey loadPrivateKey(byte[] privateKeyBytes) throws AppDistributionException {
    try {
      return KeyFactory.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM)
          .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    } catch (GeneralSecurityException | IllegalArgumentException exception) {
      throw new AppDistributionException("failed to decode Ed25519 private key", exception);
    }
  }

  /**
   * Rewrites the digest sidecar and signs its exact bytes with Ed25519.
   *
   * <p>The bundle is validated and re-digested every time this method runs. Existing digest and
   * signature sidecars are excluded from the new digest and then replaced. The supplied {@code
   * keyId} is written into the signature sidecar so verifiers can select the corresponding trusted
   * public key.
   *
   * @param bundleRoot staged app bundle root directory to digest and sign
   * @param keyId stable signing-key identifier expected by trusted-key registries
   * @param privateKey private Ed25519 signing key supplied by the caller
   * @return signature snapshot written to disk
   * @throws IOException if the bundle cannot be read safely or sidecars cannot be written
   */
  public static AppBundleSignature sign(Path bundleRoot, String keyId, PrivateKey privateKey)
      throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    Objects.requireNonNull(privateKey, "privateKey");

    AppBundleDigestWriter.write(normalizedBundleRoot);
    byte[] digestBytes =
        AppDistributionSidecars.readRequiredBytes(
            normalizedBundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), "digest sidecar");
    byte[] signatureBytes = signDigestBytes(digestBytes, privateKey);
    AppBundleSignature signature;
    try {
      signature =
          new AppBundleSignature(
              AppBundleSignature.SIGNATURE_VERSION,
              AppBundleSignature.SIGNATURE_ALGORITHM,
              keyId,
              AppBundleDigest.DIGEST_FILE_NAME,
              Base64.getEncoder().encodeToString(signatureBytes));
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
    AppDistributionSidecars.writeUtf8File(
        normalizedBundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME), serialize(signature));
    return signature;
  }

  static String serialize(AppBundleSignature signature) {
    return "signature.version="
        + signature.version()
        + '\n'
        + "signature.algorithm="
        + signature.algorithm()
        + '\n'
        + "signature.key.id="
        + signature.keyId()
        + '\n'
        + "signature.payload="
        + signature.payload()
        + '\n'
        + "signature.value.base64="
        + signature.valueBase64()
        + '\n';
  }

  private static byte[] signDigestBytes(byte[] digestBytes, PrivateKey privateKey)
      throws AppDistributionException {
    try {
      Signature signer = Signature.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM);
      signer.initSign(privateKey);
      signer.update(digestBytes);
      return signer.sign();
    } catch (GeneralSecurityException exception) {
      throw new AppDistributionException("failed to sign digest sidecar", exception);
    }
  }
}
