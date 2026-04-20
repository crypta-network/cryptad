package network.crypta.platform.appdist;

/**
 * Result of verifying one staged app bundle against the current trust policy.
 *
 * <p>This value describes the outcome of a single verifier call. It is intentionally small so
 * AppHost or API layers can expose conservative distribution status without carrying public keys,
 * signature bytes, or filesystem paths. A signed result means the digest and signature sidecars
 * were present, the digest matched the bundle contents, and the signature verified with a trusted
 * key.
 *
 * <p>An unsigned result is possible only when the caller selected an explicit development policy.
 * It should not be persisted or interpreted as a production trust decision.
 *
 * @param signed whether the bundle carried verified signature sidecars
 * @param keyId trusted key id that verified the signature, or {@code null} for unsigned
 * @param algorithm signature algorithm that verified the bundle, or {@code null} for unsigned
 */
public record AppBundleVerification(boolean signed, String keyId, String algorithm) {
  /**
   * Returns an unsigned verification result accepted only under an explicit development policy.
   *
   * <p>This result is used for completely unsigned local bundles. Partially signed bundles still
   * fail verification, even under development policy, because stale sidecars are more dangerous
   * than intentionally unsigned test fixtures.
   *
   * @return unsigned verification result
   */
  public static AppBundleVerification unsigned() {
    return new AppBundleVerification(false, null, null);
  }

  /**
   * Returns a verified signed-bundle result.
   *
   * <p>The caller is responsible for passing values from a successful cryptographic verification
   * path. This factory does not re-check the signature; it only builds the immutable result.
   *
   * @param keyId trusted key id that verified the bundle
   * @param algorithm signature algorithm that verified the bundle
   * @return signed verification result
   */
  public static AppBundleVerification signed(String keyId, String algorithm) {
    return new AppBundleVerification(true, keyId, algorithm);
  }
}
