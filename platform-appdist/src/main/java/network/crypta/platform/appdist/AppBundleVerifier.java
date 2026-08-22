package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies signed local app bundles against explicit trusted public keys.
 *
 * <p>The verifier is deliberately local and policy-driven. It does not consult global trust stores,
 * fetch catalogs, or download app artifacts. Callers supply a {@link TrustedAppKeys} registry and
 * choose whether unsigned bundles are forbidden or allowed only for development. Production-facing
 * paths should use {@link #requireSigned(TrustedAppKeys)}.
 *
 * <p>Normal verification authorizes only active keys within their declared validity window. The
 * separately named historical path permits non-revoked retiring or retired keys during their
 * support window so installed bundles can remain verifiable without allowing those keys to sign a
 * new release.
 *
 * <p>For signed bundles, verification has two phases. First, the signature sidecar is parsed and
 * checked against the exact bytes of {@code cryptad-app.digests}. Second, the digest sidecar is
 * parsed and compared with the current bundle contents. This order detects tampering with either
 * the digest metadata or the payload files before AppHost trusts the copied installation tree.
 */
public final class AppBundleVerifier {
  private final TrustedAppKeys trustedKeys;
  private final boolean allowUnsigned;
  private final VerificationPurpose verificationPurpose;

  private AppBundleVerifier(
      TrustedAppKeys trustedKeys, boolean allowUnsigned, VerificationPurpose verificationPurpose) {
    this.trustedKeys = Objects.requireNonNull(trustedKeys, "trustedKeys");
    this.allowUnsigned = allowUnsigned;
    this.verificationPurpose = Objects.requireNonNull(verificationPurpose, "verificationPurpose");
  }

  /**
   * Returns a verifier that rejects missing digest or signature sidecars.
   *
   * <p>This is the correct default for runtime install and update paths. An empty trusted-key set
   * is valid but will reject every signed bundle as unknown.
   *
   * @param trustedKeys explicit trusted public keys available for bundle verification
   * @return verifier that requires digest and signature sidecars
   */
  public static AppBundleVerifier requireSigned(TrustedAppKeys trustedKeys) {
    return new AppBundleVerifier(trustedKeys, false, VerificationPurpose.NEW_BUNDLE);
  }

  /**
   * Returns a verifier for an already installed or otherwise historically supported bundle.
   *
   * <p>This explicit path accepts active, retiring, or retired signing keys only while their
   * declared verification window remains valid. Revoked keys always fail. It must not be used for
   * install, update, or new-release admission because those paths require an active signing key.
   *
   * @param trustedKeys explicit trusted public keys available for historical bundle verification
   * @return verifier restricted to signed historical bundles
   */
  public static AppBundleVerifier requireSignedForHistoricalVerification(
      TrustedAppKeys trustedKeys) {
    return new AppBundleVerifier(trustedKeys, false, VerificationPurpose.HISTORICAL_BUNDLE);
  }

  /**
   * Returns a verifier that accepts completely unsigned bundles for development only.
   *
   * <p>If either sidecar is present, the bundle must still verify as signed. This prevents local
   * tests and development installs from hiding stale or broken sidecars that production would
   * reject. Use this mode only where the caller has made unsigned local bundles an explicit choice.
   *
   * @param trustedKeys explicit trusted public keys used when sidecars are present
   * @return verifier that accepts fully unsigned bundles for development only
   */
  public static AppBundleVerifier allowUnsignedForDevelopmentOnly(TrustedAppKeys trustedKeys) {
    return new AppBundleVerifier(trustedKeys, true, VerificationPurpose.NEW_BUNDLE);
  }

  /**
   * Returns whether a bundle root contains no reserved distribution sidecar.
   *
   * <p>The scan is case-insensitive and covers the reserved local distribution metadata names used
   * by digest, signature, and catalog sidecars. Unsigned-development paths use this positive query
   * because they may bypass signature verification only when every reserved sidecar is absent.
   *
   * @param bundleRoot staged app bundle root directory to inspect
   * @return {@code true} when no reserved sidecar name is present at the bundle root
   * @throws IOException if the root is missing, unsafe, or cannot be listed
   */
  public static boolean isDistributionSidecarFree(Path bundleRoot) throws IOException {
    return AppDistributionSidecars.isDistributionSidecarFree(bundleRoot);
  }

  /**
   * Reads and validates a signature sidecar.
   *
   * <p>This method validates only the signature sidecar format and supported algorithm/payload
   * values. It does not load trusted keys or verify the signature bytes.
   *
   * @param signatureFile path to {@code cryptad-app.signature}
   * @return parsed signature metadata
   * @throws IOException if the sidecar is missing, malformed, or unsupported
   */
  public static AppBundleSignature read(Path signatureFile) throws IOException {
    String content =
        AppDistributionSidecars.readRequiredUtf8File(signatureFile, "signature sidecar");
    Map<String, String> properties =
        AppDistributionSidecars.parseKeyValueSidecar(content, "signature sidecar");

    String versionText = properties.remove("signature.version");
    String algorithm = properties.remove("signature.algorithm");
    String keyId = properties.remove("signature.key.id");
    String payload = properties.remove("signature.payload");
    String signatureValue = properties.remove("signature.value.base64");

    if (versionText == null) {
      throw new AppDistributionException("missing signature.version");
    }
    if (algorithm == null) {
      throw new AppDistributionException("missing signature.algorithm");
    }
    if (keyId == null) {
      throw new AppDistributionException("missing signature.key.id");
    }
    if (payload == null) {
      throw new AppDistributionException("missing signature.payload");
    }
    if (signatureValue == null) {
      throw new AppDistributionException("missing signature.value.base64");
    }
    if (!AppBundleSignature.SIGNATURE_ALGORITHM.equals(algorithm)) {
      throw new AppDistributionException("unsupported signature.algorithm: " + algorithm);
    }
    if (!AppBundleDigest.DIGEST_FILE_NAME.equals(payload)) {
      throw new AppDistributionException("unsupported signature.payload: " + payload);
    }
    if (!properties.isEmpty()) {
      throw new AppDistributionException(
          "unsupported signature property: " + properties.keySet().iterator().next());
    }
    try {
      return new AppBundleSignature(
          Integer.parseInt(versionText), algorithm, keyId, payload, signatureValue);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid signature.version: " + versionText, exception);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  /**
   * Verifies a signed bundle against the supplied trusted public keys.
   *
   * <p>The verifier checks the signature sidecar first so mutations to the digest sidecar itself
   * are rejected before any bundle-content comparison. It then verifies that the digest sidecar
   * still matches the current bundle files.
   *
   * @param bundleRoot staged app bundle root directory containing both sidecars
   * @param trustedKeys explicit trusted public keys available for signature verification
   * @return parsed signature metadata when verification succeeds
   * @throws IOException if the signature or digest sidecars are missing, malformed, untrusted, or
   *     inconsistent with the bundle contents
   */
  public static AppBundleSignature verify(Path bundleRoot, TrustedAppKeys trustedKeys)
      throws IOException {
    return verify(bundleRoot, trustedKeys, VerificationPurpose.NEW_BUNDLE, Instant.now());
  }

  /**
   * Verifies an already installed or historically supported signed bundle.
   *
   * <p>Active, retiring, and retired keys are eligible during their declared verification window.
   * Revoked keys and keys outside that window fail closed. Install and update admission must use
   * {@link #verify(Path, TrustedAppKeys)} instead.
   *
   * @param bundleRoot historical bundle root directory containing both sidecars
   * @param trustedKeys explicit trusted public keys available for signature verification
   * @return parsed signature metadata when verification succeeds
   * @throws IOException if the signature or digest sidecars are missing, malformed, untrusted, or
   *     inconsistent with the bundle contents
   */
  public static AppBundleSignature verifyHistorical(Path bundleRoot, TrustedAppKeys trustedKeys)
      throws IOException {
    return verify(bundleRoot, trustedKeys, VerificationPurpose.HISTORICAL_BUNDLE, Instant.now());
  }

  private static AppBundleSignature verify(
      Path bundleRoot,
      TrustedAppKeys trustedKeys,
      VerificationPurpose verificationPurpose,
      Instant verifiedAt)
      throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    TrustedAppKeys keys = Objects.requireNonNull(trustedKeys, "trustedKeys");
    AppBundleSignature signature =
        read(normalizedBundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    TrustedAppKeyPolicy trustedKeyPolicy =
        keys.findPolicy(signature.keyId())
            .orElseThrow(
                () -> new AppDistributionException("unknown trusted key id: " + signature.keyId()));
    requireLifecycleAuthorization(
        trustedKeyPolicy,
        Objects.requireNonNull(verificationPurpose, "verificationPurpose"),
        Objects.requireNonNull(verifiedAt, "verifiedAt"));
    TrustedAppKey trustedKey = trustedKeyPolicy.key();
    if (!signature.algorithm().equals(trustedKey.algorithm())) {
      throw new AppDistributionException(
          "trusted key algorithm does not match bundle signature: " + signature.keyId());
    }

    byte[] digestBytes =
        AppDistributionSidecars.readRequiredBytes(
            normalizedBundleRoot.resolve(AppBundleDigest.DIGEST_FILE_NAME), "digest sidecar");
    verifySignature(digestBytes, signature, trustedKey);
    AppBundleDigest signedDigest = AppBundleDigestVerifier.read(digestBytes);
    AppBundleDigestVerifier.verify(normalizedBundleRoot, signedDigest);
    return signature;
  }

  /**
   * Verifies one bundle against the configured trust policy.
   *
   * <p>In development-unsigned mode, the only unsigned success case is a bundle with neither digest
   * nor signature sidecar. Any partial or complete sidecar set is treated as an attempted signed
   * bundle and must pass full verification.
   *
   * @param bundleRoot staged app bundle root directory to verify
   * @return signed verification metadata, or an explicit unsigned development result
   * @throws IOException if verification fails under the configured trust policy
   */
  public AppBundleVerification verify(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    if (allowUnsigned && isDistributionSidecarFree(normalizedBundleRoot)) {
      return AppBundleVerification.unsigned();
    }
    AppBundleSignature signature =
        verify(normalizedBundleRoot, trustedKeys, verificationPurpose, Instant.now());
    return AppBundleVerification.signed(signature.keyId(), signature.algorithm());
  }

  private static void requireLifecycleAuthorization(
      TrustedAppKeyPolicy policy, VerificationPurpose purpose, Instant verifiedAt)
      throws AppDistributionException {
    boolean authorized =
        purpose == VerificationPurpose.NEW_BUNDLE
            ? policy.allowsNewBundleVerification(verifiedAt)
            : policy.allowsHistoricalBundleVerification(verifiedAt);
    if (!authorized) {
      String verificationScope =
          purpose == VerificationPurpose.NEW_BUNDLE ? "new bundle" : "historical bundle";
      throw new AppDistributionException(
          "trusted key is not authorized for "
              + verificationScope
              + " verification: "
              + policy.key().keyId());
    }
  }

  private static void verifySignature(
      byte[] digestBytes, AppBundleSignature signature, TrustedAppKey trustedKey)
      throws AppDistributionException {
    try {
      Signature verifier = Signature.getInstance(signature.algorithm());
      verifier.initVerify(trustedKey.publicKey());
      verifier.update(digestBytes);
      if (!verifier.verify(signature.signatureBytes())) {
        throw new AppDistributionException("signature sidecar does not match digest sidecar");
      }
    } catch (GeneralSecurityException exception) {
      throw new AppDistributionException("failed to verify digest signature", exception);
    }
  }

  private enum VerificationPurpose {
    NEW_BUNDLE,
    HISTORICAL_BUNDLE
  }
}
