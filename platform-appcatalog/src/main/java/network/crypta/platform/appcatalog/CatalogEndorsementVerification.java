package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;

/**
 * Cryptographically authenticated direct endorsement evidence with explicit non-trust semantics.
 *
 * <p>The value records the exact signed endorsement, the local verification instant, the canonical
 * issuer-key fingerprint, and whether the evidence currently contributes to operator display. An
 * inactive or expired issuer does not erase the authenticated historical statement; it changes only
 * its current contribution status.
 *
 * <p>The constants make the narrow semantics explicit: verification is direct, never transitive,
 * and never grants catalog trust. Callers may retain conflicting verified endorsements as local
 * evidence without deriving a score or modifying unrelated catalogs. The record is immutable and
 * contains public identities and digests rather than issuer private material or user trust choices.
 *
 * @param endorsement exact verified endorsement
 * @param status whether the direct evidence currently contributes locally
 * @param verifiedAt local verification instant
 * @param issuerKeyFingerprintSha256 canonical local issuer-key fingerprint
 */
public record CatalogEndorsementVerification(
    CatalogEndorsement endorsement,
    Status status,
    Instant verifiedAt,
    String issuerKeyFingerprintSha256) {
  /** The verifier authenticates exactly one directly supplied endorsement. */
  public static final boolean DIRECT = true;

  /** Direct endorsement verification never follows or infers an endorsement chain. */
  public static final boolean TRANSITIVE = false;

  /** An authenticated endorsement is evidence only and never creates local trust. */
  public static final boolean TRUST_GRANTED = false;

  /** Closed contribution states for a directly verified endorsement. */
  public enum Status {
    /** Issuer is active and the endorsement is fresh. */
    ACTIVE,
    /** Signature is authentic, but local issuer lifecycle does not permit active contribution. */
    INACTIVE_ISSUER,
    /** Signature is authentic, but the endorsement has expired. */
    EXPIRED
  }

  /** Validates direct evidence metadata. */
  public CatalogEndorsementVerification {
    Objects.requireNonNull(endorsement, "endorsement");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(verifiedAt, "verifiedAt");
    issuerKeyFingerprintSha256 =
        CatalogSignedDocumentSupport.requireSha256(
            issuerKeyFingerprintSha256,
            "issuerKeyFingerprintSha256",
            CatalogSignedDocumentSupport.INVALID_ENDORSEMENT);
  }

  /**
   * Returns whether this direct evidence currently contributes to local display.
   *
   * @return {@code true} only for fresh evidence from an active issuer
   */
  public boolean activeContribution() {
    return status == Status.ACTIVE;
  }
}
