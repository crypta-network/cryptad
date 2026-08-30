package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies exactly one direct catalog endorsement without traversing or activating trust.
 *
 * <p>The verifier authenticates the content digest, issuer fingerprint, signature algorithm, and
 * detached Ed25519 signature against caller-supplied local key material. A future-issued record or
 * unknown issuer fails closed. A known but inactive issuer can authenticate retained evidence, but
 * the returned contribution status remains inactive.
 *
 * <p>Verification never follows another endorsement, installs a key, adds a catalog source, or
 * changes local trust policy. The utility is stateless and safe for concurrent callers that supply
 * immutable key registries. Its result contains bounded public evidence suitable for local display
 * and persistence without exposing issuer private material or user subscription state.
 */
public final class CatalogEndorsementVerifier {
  /** Prevents construction of this stateless verification utility. */
  private CatalogEndorsementVerifier() {}

  /**
   * Parses and verifies one direct endorsement.
   *
   * @param endorsementBytes exact bounded endorsement JSON bytes
   * @param trustedIssuerKeys local issuer public-key and lifecycle registry
   * @param now local verification instant
   * @return authenticated direct endorsement with current contribution status
   */
  public static CatalogEndorsementVerification verifyDirect(
      byte[] endorsementBytes, TrustedAppKeys trustedIssuerKeys, Instant now) {
    return verifyDirect(CatalogEndorsement.parse(endorsementBytes), trustedIssuerKeys, now);
  }

  /**
   * Verifies one direct endorsement against local issuer material.
   *
   * <p>Revoked, retired, not-yet-valid, or otherwise inactive known issuer material may still
   * authenticate retained evidence, but the result is explicitly inactive. Unknown issuers,
   * fingerprint substitution, malformed signatures, and future-issued records fail closed.
   *
   * @param endorsement structurally validated direct endorsement
   * @param trustedIssuerKeys local issuer public-key and lifecycle registry
   * @param now local verification instant
   * @return authenticated direct endorsement with current contribution status
   */
  public static CatalogEndorsementVerification verifyDirect(
      CatalogEndorsement endorsement, TrustedAppKeys trustedIssuerKeys, Instant now) {
    CatalogEndorsement checked = Objects.requireNonNull(endorsement, "endorsement");
    TrustedAppKeys keys = Objects.requireNonNull(trustedIssuerKeys, "trustedIssuerKeys");
    Instant verifiedAt = Objects.requireNonNull(now, "now");
    CatalogEndorsement.Validity validity = checked.content().validity();
    if (validity
        .issuedAt()
        .isAfter(verifiedAt.plus(CatalogSignedDocumentSupport.MAX_FUTURE_SKEW))) {
      throw CatalogSignedDocumentSupport.invalid(
          CatalogSignedDocumentSupport.INVALID_ENDORSEMENT, "catalog endorsement is not yet fresh");
    }
    CatalogSignedDocumentSupport.requireSelfDigest(
        checked.authentication().selfDigestSha256(),
        checked.canonicalContentBytes(),
        CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
    TrustedAppKeyPolicy policy =
        keys.findPolicy(checked.issuerKeyId())
            .orElseThrow(
                () ->
                    CatalogSignedDocumentSupport.invalid(
                        CatalogSignedDocumentSupport.INVALID_SIGNATURE,
                        "endorsement issuer key is unknown"));
    TrustedAppKey trustedKey = policy.key();
    String fingerprint = CatalogSignedDocumentSupport.publicKeyFingerprint(trustedKey.publicKey());
    if (!fingerprint.equals(checked.content().issuer().keyFingerprintSha256())) {
      throw CatalogSignedDocumentSupport.invalid(
          CatalogSignedDocumentSupport.INVALID_SIGNATURE,
          "endorsement issuer key fingerprint does not match local key material");
    }
    if (!trustedKey.algorithm().equals(checked.authentication().signatureAlgorithm())) {
      throw CatalogSignedDocumentSupport.invalid(
          CatalogSignedDocumentSupport.INVALID_SIGNATURE,
          "endorsement signature algorithm does not match issuer key");
    }
    CatalogSignedDocumentSupport.verifySignature(
        trustedKey.publicKey(),
        checked.authentication().signatureAlgorithm(),
        checked.authentication().signatureValueBase64(),
        checked.canonicalSignaturePayloadBytes());
    CatalogEndorsementVerification.Status status = endorsementStatus(policy, validity, verifiedAt);
    return new CatalogEndorsementVerification(checked, status, verifiedAt, fingerprint);
  }

  /**
   * Determines the current local contribution status after authentication.
   *
   * @param policy local lifecycle policy for the authenticated issuer key
   * @param validity signed endorsement freshness interval
   * @param now local verification instant
   * @return active, inactive-issuer, or expired status
   */
  private static CatalogEndorsementVerification.Status endorsementStatus(
      TrustedAppKeyPolicy policy, CatalogEndorsement.Validity validity, Instant now) {
    if (!validity.expiresAt().isAfter(now)) {
      return CatalogEndorsementVerification.Status.EXPIRED;
    }
    if (!policy.allowsRoutineVerification(now)) {
      return CatalogEndorsementVerification.Status.INACTIVE_ISSUER;
    }
    return CatalogEndorsementVerification.Status.ACTIVE;
  }
}
