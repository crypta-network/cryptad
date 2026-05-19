package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Local policy constraint attached to one trusted reviewer key.
 *
 * <p>Receipts already carry policy id and version metadata. This constraint lets a local registry
 * say which policy id, and optionally which policy version, a key may authenticate. It is a local
 * governance rule, not signed catalog metadata.
 *
 * <p>The constraint is evaluated after the receipt names a configured reviewer key and before the
 * verifier reports positive trust. A missing policy id means the key accepts any policy, but a
 * configured version requires a configured id so operators cannot accidentally trust every policy
 * with the same version number. This keeps small registry mistakes from broadening trust.
 *
 * <p>Instances are immutable and contain only bounded text. They are safe to expose through
 * redacted reviewer summaries because they do not include key bytes, signatures, registry paths, or
 * receipt bodies.
 *
 * @param policyId optional accepted receipt policy id
 * @param policyVersion optional accepted receipt policy version
 */
public record TrustedReviewerPolicyConstraint(
    Optional<String> policyId, Optional<String> policyVersion) {
  private static final int MAX_POLICY_ID_CHARS = 128;
  private static final int MAX_POLICY_VERSION_CHARS = 64;

  /**
   * Constraint that accepts any receipt policy id and version.
   *
   * <p>This value preserves v1 registry behavior. New v2 registries should normally configure an
   * explicit policy id, and optionally a version, so local governance can explain policy trust.
   */
  @SuppressWarnings("unused")
  public static final TrustedReviewerPolicyConstraint ANY =
      new TrustedReviewerPolicyConstraint(Optional.empty(), Optional.empty());

  /**
   * Creates a constraint from nullable registry values.
   *
   * <p>Registry loaders use this factory for properties-file values. Blank validation and
   * single-line bounds are enforced by the canonical constructor after nullable values are
   * converted to optionals.
   *
   * @param policyId optional policy id from the reviewer registry
   * @param policyVersion optional policy version from the reviewer registry
   * @return validated policy constraint for one reviewer key
   */
  public static TrustedReviewerPolicyConstraint of(String policyId, String policyVersion) {
    return new TrustedReviewerPolicyConstraint(
        Optional.ofNullable(policyId), Optional.ofNullable(policyVersion));
  }

  /**
   * Creates a validated constraint.
   *
   * <p>Policy ids and versions are bounded single-line strings. A version without an id is rejected
   * because policy versions are meaningful only within a policy namespace.
   */
  public TrustedReviewerPolicyConstraint {
    Objects.requireNonNull(policyId, "policyId");
    Objects.requireNonNull(policyVersion, "policyVersion");
    policyId =
        policyId.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "reviewer policy id",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_POLICY_ID_CHARS));
    policyVersion =
        policyVersion.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "reviewer policy version",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_POLICY_VERSION_CHARS));
    if (policyVersion.isPresent() && policyId.isEmpty()) {
      throw AppCatalogSidecars.invalidEntry("reviewer policy.version requires policy.id");
    }
  }

  /**
   * Returns whether this constraint accepts a receipt policy id/version pair.
   *
   * <p>Unconfigured fields are wildcards. Configured fields must match exactly because policy ids
   * and versions are part of the local governance contract and are not normalized by this method.
   *
   * @param receiptPolicyId policy id from the independent receipt payload
   * @param receiptPolicyVersion policy version from the independent receipt payload
   * @return {@code true} when every configured constraint matches the receipt
   */
  public boolean matches(String receiptPolicyId, String receiptPolicyVersion) {
    return policyId.map(value -> value.equals(receiptPolicyId)).orElse(true)
        && policyVersion.map(value -> value.equals(receiptPolicyVersion)).orElse(true);
  }
}
