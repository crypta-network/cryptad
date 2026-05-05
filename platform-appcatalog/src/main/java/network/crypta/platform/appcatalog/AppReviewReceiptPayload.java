package network.crypta.platform.appcatalog;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Canonical, signed payload of an independent app review receipt.
 *
 * <p>The payload binds a reviewer decision to one app id, one app version, one artifact SHA-256,
 * one artifact size, and one review policy. The signature value is deliberately outside this
 * payload so verification always signs deterministic receipt fields rather than mutable object
 * state or a self-referential signature field.
 *
 * <p>The payload is the audit core of a review receipt. It names the reviewed artifact, the
 * reviewer key id, the policy id/version under which the review was made, optional expiry, and
 * optional evidence metadata. These fields are public metadata; they are safe to carry in signed
 * catalogs and Platform API summaries. They do not include reviewer private keys, local evidence
 * paths, catalog scratch directories, or staged bundle paths.
 *
 * <p>Construction normalizes and bounds all text fields before any signature is created. That keeps
 * canonical bytes stable across operating systems and makes tampering visible: changing any payload
 * field changes {@link #canonicalPayloadBytes()} and invalidates the detached signature.
 *
 * @param version receipt payload schema version, currently {@link #RECEIPT_VERSION}
 * @param appId reviewed app id, normalized with catalog app-id rules
 * @param appVersion reviewed app version as a bounded single-line value
 * @param artifactSha256 catalog artifact SHA-256 digest the review covers
 * @param artifactSizeBytes catalog artifact size in bytes that the review covers
 * @param bundleKeyId optional signed-bundle key id known to the reviewer
 * @param policyId review policy id used by the reviewer
 * @param policyVersion review policy version used by the reviewer
 * @param status reviewer policy decision for the named artifact
 * @param reviewerKeyId reviewer key id that must verify the receipt signature
 * @param reviewedAt instant when the reviewer produced the receipt
 * @param expiresAt optional instant after which the receipt is not trusted
 * @param evidenceSha256 optional SHA-256 digest of public review evidence
 * @param evidenceUri optional HTTPS or crypta URI for review evidence
 * @param note optional bounded single-line reviewer note for display
 */
public record AppReviewReceiptPayload(
    int version,
    String appId,
    String appVersion,
    String artifactSha256,
    long artifactSizeBytes,
    Optional<String> bundleKeyId,
    String policyId,
    String policyVersion,
    AppReviewReceiptStatus status,
    String reviewerKeyId,
    Instant reviewedAt,
    Optional<Instant> expiresAt,
    Optional<String> evidenceSha256,
    Optional<URI> evidenceUri,
    Optional<String> note) {
  /**
   * Supported receipt payload schema version.
   *
   * <p>The value is serialized into every receipt as {@code review.receipt.version}. A future
   * incompatible receipt format must use a different version so old nodes fail closed instead of
   * interpreting unknown fields.
   */
  public static final int RECEIPT_VERSION = 1;

  private static final int MAX_APP_VERSION_CHARS = 128;
  private static final int MAX_BUNDLE_KEY_ID_CHARS = 128;
  private static final int MAX_POLICY_ID_CHARS = 128;
  private static final int MAX_POLICY_VERSION_CHARS = 64;
  private static final int MAX_REVIEWER_KEY_ID_CHARS = 128;
  private static final int MAX_NOTE_CHARS = 512;

  /**
   * Creates a validated review receipt payload.
   *
   * <p>Validation is intentionally strict because these values become signed canonical bytes.
   * Application ids, digests, single-line bounds, evidence URI schemes, and optional fields are
   * normalized before assignment. The constructor does not sign the payload and does not evaluate
   * trust; it only creates the exact value that a signer or verifier will hash through Ed25519.
   *
   * @param version receipt payload schema version expected to equal {@link #RECEIPT_VERSION}
   * @param appId reviewed app id before catalog normalization
   * @param appVersion reviewed app version that must be bounded and single-line
   * @param artifactSha256 lowercase SHA-256 digest of the reviewed artifact
   * @param artifactSizeBytes non-negative artifact size in bytes
   * @param bundleKeyId optional signed-bundle key id associated with the artifact
   * @param policyId bounded review policy identifier
   * @param policyVersion bounded review policy version identifier
   * @param status reviewer decision stored in the receipt
   * @param reviewerKeyId bounded trusted-reviewer key id
   * @param reviewedAt instant when the receipt was produced
   * @param expiresAt optional expiry instant for trust evaluation
   * @param evidenceSha256 optional lowercase SHA-256 digest for evidence metadata
   * @param evidenceUri optional HTTPS or crypta evidence URI
   * @param note optional bounded single-line reviewer note
   */
  public AppReviewReceiptPayload {
    if (version != RECEIPT_VERSION) {
      throw AppCatalogSidecars.invalidEntry("unsupported review.receipt.version: " + version);
    }
    appId = AppCatalogEntry.normalizeAppId(appId);
    appVersion =
        AppCatalogSidecars.requireBoundedSingleLine(
            appVersion,
            "review.receipt.app.version",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_APP_VERSION_CHARS);
    artifactSha256 =
        AppCatalogSidecars.requireLowercaseSha256(artifactSha256, "review.receipt.artifact.sha256");
    if (artifactSizeBytes < 0L) {
      throw AppCatalogSidecars.invalidEntry("review.receipt.artifact.size must be >= 0");
    }
    Objects.requireNonNull(bundleKeyId, "bundleKeyId");
    bundleKeyId =
        bundleKeyId.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "review.receipt.bundle.key.id",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_BUNDLE_KEY_ID_CHARS));
    policyId =
        AppCatalogSidecars.requireBoundedSingleLine(
            policyId,
            "review.receipt.policy.id",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_POLICY_ID_CHARS);
    policyVersion =
        AppCatalogSidecars.requireBoundedSingleLine(
            policyVersion,
            "review.receipt.policy.version",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_POLICY_VERSION_CHARS);
    Objects.requireNonNull(status, "status");
    reviewerKeyId =
        AppCatalogSidecars.requireBoundedSingleLine(
            reviewerKeyId,
            "review.receipt.reviewer.key.id",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_REVIEWER_KEY_ID_CHARS);
    Objects.requireNonNull(reviewedAt, "reviewedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(evidenceSha256, "evidenceSha256");
    evidenceSha256 =
        evidenceSha256.map(
            value ->
                AppCatalogSidecars.requireLowercaseSha256(value, "review.receipt.evidence.sha256"));
    Objects.requireNonNull(evidenceUri, "evidenceUri");
    evidenceUri = evidenceUri.map(AppReviewReceiptPayload::requireEvidenceUri);
    Objects.requireNonNull(note, "note");
    note =
        note.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "review.receipt.note",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_NOTE_CHARS));
  }

  /**
   * Returns deterministic bytes that the review receipt signature covers.
   *
   * <p>The byte encoding is UTF-8 and is derived from {@link #canonicalPayloadText()}. Signers and
   * verifiers must use this method rather than serializing Java object state. The output excludes
   * signature fields by design so the signature never signs itself.
   *
   * @return UTF-8 canonical payload properties without signature fields
   */
  public byte[] canonicalPayloadBytes() {
    return canonicalPayloadText().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Returns deterministic canonical payload properties without signature fields.
   *
   * <p>Fields are emitted in the receipt schema order, with optional fields omitted when absent.
   * Every line uses {@code key=value} and ends with {@code \n}. The order is part of the signature
   * contract and must remain stable for version {@link #RECEIPT_VERSION}.
   *
   * @return canonical payload text used as the human-readable signing input
   */
  public String canonicalPayloadText() {
    StringBuilder builder = new StringBuilder();
    append(builder, "review.receipt.version", Integer.toString(version));
    append(builder, "review.receipt.app.id", appId);
    append(builder, "review.receipt.app.version", appVersion);
    append(builder, "review.receipt.artifact.sha256", artifactSha256);
    append(builder, "review.receipt.artifact.size", Long.toString(artifactSizeBytes));
    bundleKeyId.ifPresent(value -> append(builder, "review.receipt.bundle.key.id", value));
    append(builder, "review.receipt.policy.id", policyId);
    append(builder, "review.receipt.policy.version", policyVersion);
    append(builder, "review.receipt.status", status.catalogValue());
    append(builder, "review.receipt.reviewer.key.id", reviewerKeyId);
    append(builder, "review.receipt.reviewed.at", reviewedAt.toString());
    expiresAt.ifPresent(value -> append(builder, "review.receipt.expires.at", value.toString()));
    evidenceSha256.ifPresent(value -> append(builder, "review.receipt.evidence.sha256", value));
    evidenceUri.ifPresent(
        value -> append(builder, "review.receipt.evidence.uri", value.toString()));
    note.ifPresent(value -> append(builder, "review.receipt.note", value));
    return builder.toString();
  }

  private static void append(StringBuilder builder, String key, String value) {
    builder.append(key).append('=').append(value).append('\n');
  }

  private static URI requireEvidenceUri(URI uri) {
    URI normalized = Objects.requireNonNull(uri, "evidenceUri").normalize();
    if (!normalized.isAbsolute()) {
      throw AppCatalogSidecars.invalidEntry("review.receipt.evidence.uri must be absolute");
    }
    if (normalized.getFragment() != null || normalized.getUserInfo() != null) {
      throw AppCatalogSidecars.invalidEntry(
          "review.receipt.evidence.uri must not include a fragment or user info");
    }
    String scheme = normalized.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      if (normalized.getHost() == null || normalized.getHost().isBlank()) {
        throw AppCatalogSidecars.invalidEntry("review.receipt.evidence.uri must include a host");
      }
      return normalized;
    }
    if ("crypta".equalsIgnoreCase(scheme)) {
      requireUriSyntax(normalized.toString());
      return normalized;
    }
    throw AppCatalogSidecars.invalidEntry(
        "unsupported review.receipt.evidence.uri scheme: " + scheme);
  }

  private static void requireUriSyntax(String uriText) {
    try {
      new URI(uriText);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review.receipt.evidence.uri",
          exception);
    }
  }
}
