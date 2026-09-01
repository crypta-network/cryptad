package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies signed catalog discovery descriptors without activating any declared trust.
 *
 * <p>The verifier combines closed-schema parsing with freshness, content-digest, issuer lifecycle,
 * public-key fingerprint, algorithm, and Ed25519 signature checks. Issuer key material must already
 * exist in the operator-controlled trusted-key registry; a descriptor cannot install or replace
 * that material.
 *
 * <p>A successful call returns an explicitly pending {@link CatalogDiscoveryImportResult}. It does
 * not add a catalog source, create a trust binding, accept publisher or reviewer policy, or follow
 * endorsements. The utility is stateless and safe for concurrent verification when callers supply
 * immutable key registries and verification instants. Descriptor bytes and signature subjects are
 * not persisted by this class.
 */
public final class CatalogDiscoveryVerifier {
  /** Prevents construction of this stateless verification utility. */
  private CatalogDiscoveryVerifier() {}

  /**
   * Parses and authenticates one descriptor for pending local import.
   *
   * @param descriptorBytes exact bounded descriptor JSON bytes
   * @param trustedIssuerKeys local public-key and lifecycle registry for descriptor issuers
   * @param now local verification instant used for key lifecycle and descriptor freshness
   * @return explicitly pending, non-authoritative import result
   * @throws AppCatalogException if parsing, digest, freshness, lifecycle, fingerprint, or signature
   *     verification fails
   */
  public static CatalogDiscoveryImportResult verifyForImport(
      byte[] descriptorBytes, TrustedAppKeys trustedIssuerKeys, Instant now) {
    return verifyForImport(
        CatalogDiscoveryDescriptor.parse(descriptorBytes), trustedIssuerKeys, now);
  }

  /**
   * Authenticates one parsed descriptor for pending local import.
   *
   * @param descriptor structurally validated descriptor
   * @param trustedIssuerKeys local public-key and lifecycle registry for descriptor issuers
   * @param now local verification instant
   * @return explicitly pending import result that grants no trust
   */
  public static CatalogDiscoveryImportResult verifyForImport(
      CatalogDiscoveryDescriptor descriptor, TrustedAppKeys trustedIssuerKeys, Instant now) {
    CatalogDiscoveryDescriptor checked = Objects.requireNonNull(descriptor, "descriptor");
    TrustedAppKeys keys = Objects.requireNonNull(trustedIssuerKeys, "trustedIssuerKeys");
    Instant verifiedAt = Objects.requireNonNull(now, "now");
    CatalogDiscoveryDescriptor.Validity validity = checked.content().validity();
    CatalogSignedDocumentSupport.requireCurrent(
        validity.issuedAt(), validity.expiresAt(), verifiedAt);
    CatalogSignedDocumentSupport.requireSelfDigest(
        checked.authentication().selfDigestSha256(),
        checked.canonicalContentBytes(),
        CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
    TrustedAppKey trustedKey =
        keys.findActiveForVerification(checked.issuerKeyId(), verifiedAt)
            .orElseThrow(
                () ->
                    CatalogSignedDocumentSupport.invalid(
                        CatalogSignedDocumentSupport.INVALID_SIGNATURE,
                        "descriptor issuer key is unknown or not active"));
    String fingerprint = CatalogSignedDocumentSupport.publicKeyFingerprint(trustedKey.publicKey());
    if (!fingerprint.equals(checked.content().issuer().keyFingerprintSha256())) {
      throw CatalogSignedDocumentSupport.invalid(
          CatalogSignedDocumentSupport.INVALID_SIGNATURE,
          "descriptor issuer key fingerprint does not match local key material");
    }
    if (!trustedKey.algorithm().equals(checked.authentication().signatureAlgorithm())) {
      throw CatalogSignedDocumentSupport.invalid(
          CatalogSignedDocumentSupport.INVALID_SIGNATURE,
          "descriptor signature algorithm does not match issuer key");
    }
    CatalogSignedDocumentSupport.verifySignature(
        trustedKey.publicKey(),
        checked.authentication().signatureAlgorithm(),
        checked.authentication().signatureValueBase64(),
        checked.canonicalSignaturePayloadBytes());
    return new CatalogDiscoveryImportResult(
        checked, CatalogDiscoveryImportResult.Status.PENDING, verifiedAt, fingerprint);
  }
}
