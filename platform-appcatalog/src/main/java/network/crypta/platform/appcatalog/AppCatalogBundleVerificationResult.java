package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;

/**
 * Immutable identity of the publisher authorization used for a staged catalog bundle.
 *
 * <p>The installation planner records this result immediately after safe extraction and requires an
 * equal result when the retained plan is re-verified. Equality therefore covers the verified
 * publisher key, the policy or binding identity, its exact digest, and whether authorization was
 * catalog-scoped. A policy rotation cannot silently substitute a different local approval between
 * plan creation and use.
 *
 * <p>Legacy custom policies and the node-wide trusted app-key registry remain compatible, but their
 * results are explicitly unscoped. A federation-aware implementation sets {@code catalogScoped}
 * only when it supplies both a canonical publisher-key fingerprint and an exact local policy
 * digest. The value contains no public key bytes, signatures, bundle content, source URI, or
 * credentials.
 *
 * @param publisherKeyId verified bundle-signature key identifier
 * @param publisherKeyFingerprintSha256 canonical key fingerprint, or empty when unavailable
 * @param authorizationPolicyId stable identifier for the policy kind or local binding
 * @param authorizationPolicyDigestSha256 exact local policy digest, or empty when unavailable
 * @param catalogScoped whether authorization explicitly binds the catalog context
 * @param signedContentDigestSha256 SHA-256 of the exact signed digest-sidecar bytes, or empty when
 *     unavailable to a legacy adapter
 */
public record AppCatalogBundleVerificationResult(
    String publisherKeyId,
    String publisherKeyFingerprintSha256,
    String authorizationPolicyId,
    String authorizationPolicyDigestSha256,
    boolean catalogScoped,
    String signedContentDigestSha256) {
  private static final Pattern SHA256_PATTERN = Pattern.compile("[0-9a-f]{64}");
  private static final String LEGACY_POLICY_ID = "legacy-custom-bundle-policy";
  private static final String UNSIGNED_DEVELOPMENT_PUBLISHER_ID = "unsigned-development";
  private static final String UNSIGNED_DEVELOPMENT_POLICY_ID =
      "legacy-unsigned-development-bundle-policy";
  private static final String TRUSTED_APP_KEYS_POLICY_ID = "global-trusted-app-keys";
  private static final String UNRECORDED_POLICY_ID = "unrecorded-install-plan";

  /**
   * Creates a comparable publisher-authorization result.
   *
   * <p>An empty fingerprint or policy digest explicitly means that a compatibility policy did not
   * expose that identity. Such a result remains useful for retained-plan equality, but it is not a
   * catalog-scoped federation authorization.
   *
   * @param publisherKeyId verified bundle-signature key id
   * @param publisherKeyFingerprintSha256 canonical key fingerprint, or empty when unavailable
   * @param authorizationPolicyId stable identifier for the policy kind or binding
   * @param authorizationPolicyDigestSha256 exact policy digest, or empty when unavailable
   * @param catalogScoped whether the authorization explicitly binds the catalog context
   * @throws NullPointerException if any string component is {@code null}
   * @throws IllegalArgumentException if an identity is blank or multi-line, a digest is malformed,
   *     or a scoped result omits a required fingerprint or policy digest
   */
  public AppCatalogBundleVerificationResult {
    requireSingleLine(publisherKeyId, "publisherKeyId");
    requireOptionalSha256(publisherKeyFingerprintSha256, "publisherKeyFingerprintSha256");
    requireSingleLine(authorizationPolicyId, "authorizationPolicyId");
    requireOptionalSha256(authorizationPolicyDigestSha256, "authorizationPolicyDigestSha256");
    requireOptionalSha256(signedContentDigestSha256, "signedContentDigestSha256");
    if (catalogScoped
        && (publisherKeyFingerprintSha256.isEmpty()
            || authorizationPolicyDigestSha256.isEmpty()
            || signedContentDigestSha256.isEmpty())) {
      throw new IllegalArgumentException(
          "catalog-scoped authorization requires publisher, policy, and signed-content digests");
    }
  }

  /**
   * Preserves the pre-federation result constructor for explicitly unscoped adapters.
   *
   * @param publisherKeyId verified bundle-signature key identifier
   * @param publisherKeyFingerprintSha256 canonical key fingerprint, or empty when unavailable
   * @param authorizationPolicyId stable identifier for the policy kind or binding
   * @param authorizationPolicyDigestSha256 exact policy digest, or empty when unavailable
   * @param catalogScoped whether authorization explicitly binds the catalog context
   */
  public AppCatalogBundleVerificationResult(
      String publisherKeyId,
      String publisherKeyFingerprintSha256,
      String authorizationPolicyId,
      String authorizationPolicyDigestSha256,
      boolean catalogScoped) {
    this(
        publisherKeyId,
        publisherKeyFingerprintSha256,
        authorizationPolicyId,
        authorizationPolicyDigestSha256,
        catalogScoped,
        "");
  }

  /**
   * Creates the bounded result used by the source-compatible custom-policy adapter.
   *
   * <p>The result retains the verified signature key ID but has no public-key fingerprint or local
   * policy digest because the original one-argument policy contract did not expose them. It is
   * always marked unscoped and cannot represent federation-complete publisher authorization.
   *
   * @param signature verified bundle signature metadata from the staged root
   * @return unscoped compatibility result that preserves the publisher key ID
   * @throws NullPointerException if {@code signature} is {@code null}
   */
  public static AppCatalogBundleVerificationResult legacyCompatibility(
      AppBundleSignature signature) {
    return new AppCatalogBundleVerificationResult(
        Objects.requireNonNull(signature, "signature").keyId(),
        "",
        LEGACY_POLICY_ID,
        "",
        false,
        "");
  }

  /**
   * Creates the bounded result for a development policy that accepted a sidecar-free bundle.
   *
   * <p>The sentinel identity is deliberately unscoped and carries no signer, signed-content, or
   * local-policy digest. It preserves the pre-federation unsigned-development escape hatch without
   * representing publisher authorization or federation completion.
   *
   * @return unsigned and explicitly unscoped development compatibility result
   */
  public static AppCatalogBundleVerificationResult unsignedDevelopmentCompatibility() {
    return new AppCatalogBundleVerificationResult(
        UNSIGNED_DEVELOPMENT_PUBLISHER_ID, "", UNSIGNED_DEVELOPMENT_POLICY_ID, "", false, "");
  }

  /**
   * Creates a result for the existing node-wide trusted app-key policy.
   *
   * <p>The canonical fingerprint distinguishes different public keys that reuse a stable key ID.
   * The result remains unscoped because registry membership does not bind the publisher to a
   * catalog/app pair. Federation-aware callers should construct a scoped result with an exact local
   * policy digest after applying their own context decision.
   *
   * @param verification complete verified signer and signed-content identity from the staged root
   * @return unscoped global-registry result containing the verified publisher identity
   * @throws NullPointerException if {@code verification} is {@code null}
   * @throws IllegalArgumentException if verification is unsigned or omits an exact identity
   */
  public static AppCatalogBundleVerificationResult trustedAppKeys(
      AppBundleVerification verification) {
    AppBundleVerification checked = Objects.requireNonNull(verification, "verification");
    if (!checked.signed()
        || checked.keyFingerprintSha256() == null
        || checked.signedContentDigestSha256() == null) {
      throw new IllegalArgumentException("complete signed-bundle verification is required");
    }
    return new AppCatalogBundleVerificationResult(
        checked.keyId(),
        checked.keyFingerprintSha256(),
        TRUSTED_APP_KEYS_POLICY_ID,
        "",
        false,
        checked.signedContentDigestSha256());
  }

  /**
   * Returns the compatibility marker for a retained plan without recorded authorization.
   *
   * @return unscoped result with the stable unrecorded policy identity
   */
  static AppCatalogBundleVerificationResult unrecorded() {
    return new AppCatalogBundleVerificationResult(
        "unrecorded", "", UNRECORDED_POLICY_ID, "", false, "");
  }

  /**
   * Requires a nonblank single-line identity field.
   *
   * @param value identity value to validate
   * @param fieldName field name used in validation failures
   */
  private static void requireSingleLine(String value, String fieldName) {
    String checked = Objects.requireNonNull(value, fieldName);
    if (checked.isBlank() || checked.indexOf('\n') >= 0 || checked.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(fieldName + " must be a non-blank single line");
    }
  }

  /**
   * Requires an optional value to be empty or a lowercase SHA-256 digest.
   *
   * @param value optional digest value to validate
   * @param fieldName field name used in validation failures
   */
  private static void requireOptionalSha256(String value, String fieldName) {
    String checked = Objects.requireNonNull(value, fieldName);
    if (!checked.isEmpty() && !SHA256_PATTERN.matcher(checked).matches()) {
      throw new IllegalArgumentException(fieldName + " must be empty or lowercase SHA-256");
    }
  }
}
