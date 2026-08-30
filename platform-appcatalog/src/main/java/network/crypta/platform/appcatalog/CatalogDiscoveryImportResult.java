package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;

/**
 * Authenticated catalog discovery import that remains pending explicit local operator approval.
 *
 * <p>A successful result proves only descriptor integrity, freshness, and issuer authentication. It
 * never creates a catalog source, trusts a catalog signer, accepts publisher or reviewer policy,
 * follows endorsements, or installs an app.
 *
 * <p>The value is suitable for host-owned pending-discovery persistence and operator summaries. It
 * retains the exact verified descriptor, the local verification time, and the canonical issuer-key
 * fingerprint without storing private keys, credentials, source subscriptions, or app state. The
 * three public boolean constants make the non-authoritative semantics explicit to callers and
 * serializers. Instances are immutable and can be shared across operator API and Web Shell reads; a
 * separate trust-binding mutation is always required before routine catalog operations begin.
 *
 * @param descriptor exact verified public descriptor
 * @param status fixed pending lifecycle state
 * @param verifiedAt local instant at which verification succeeded
 * @param issuerKeyFingerprintSha256 canonical fingerprint of the verifying local public key
 */
public record CatalogDiscoveryImportResult(
    CatalogDiscoveryDescriptor descriptor,
    Status status,
    Instant verifiedAt,
    String issuerKeyFingerprintSha256) {
  /** Descriptor authentication never grants local catalog trust. */
  public static final boolean TRUST_GRANTED = false;

  /** Importing discovery metadata never configures its source hints. */
  public static final boolean SOURCE_CONFIGURED = false;

  /** Discovery verification never follows an endorsement chain. */
  public static final boolean TRANSITIVE = false;

  /** Discovery imports can only enter the pending state. */
  public enum Status {
    /** Awaiting a separate explicit local trust decision. */
    PENDING
  }

  /** Validates immutable pending import evidence. */
  public CatalogDiscoveryImportResult {
    Objects.requireNonNull(descriptor, "descriptor");
    if (status != Status.PENDING) {
      throw new IllegalArgumentException("catalog discovery import must remain pending");
    }
    Objects.requireNonNull(verifiedAt, "verifiedAt");
    issuerKeyFingerprintSha256 =
        CatalogSignedDocumentSupport.requireSha256(
            issuerKeyFingerprintSha256,
            "issuerKeyFingerprintSha256",
            CatalogSignedDocumentSupport.INVALID_DESCRIPTOR);
  }
}
