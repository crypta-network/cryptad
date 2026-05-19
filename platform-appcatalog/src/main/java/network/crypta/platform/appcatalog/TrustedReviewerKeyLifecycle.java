package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Local lifecycle governance metadata for a trusted reviewer key.
 *
 * <p>The lifecycle is intentionally small: it models active, retired, and revoked state; optional
 * validity bounds for receipt review timestamps; revocation metadata; and key rotation links. The
 * verifier uses only redacted metadata from this record when explaining trust decisions.
 *
 * <p>This state belongs to the local trusted-reviewer registry. It is not supplied by a remote
 * catalog and does not make a receipt trusted by itself. A lifecycle can only allow evaluation to
 * continue; signature verification, app/artifact binding, receipt expiry, and policy constraints
 * still have to pass. Revoked keys fail closed, while retired keys require an explicit historical
 * window before any receipt can remain trusted.
 *
 * <p>Instances are immutable and safe to expose through redacted summaries after public key
 * material has been removed by the caller. Rotation ids are explanatory links for operators and do
 * not create transitive trust between keys.
 *
 * @param status local lifecycle state for the reviewer key
 * @param validFrom optional inclusive start instant for receipt review timestamps
 * @param validUntil optional exclusive end instant for receipt review timestamps
 * @param revokedAt optional instant when a revoked key was recorded locally
 * @param revocationReason optional bounded reason explaining local revocation
 * @param rotatesFrom optional predecessor reviewer key id
 * @param rotatesTo optional successor reviewer key id
 */
public record TrustedReviewerKeyLifecycle(
    TrustedReviewerKeyStatus status,
    Optional<Instant> validFrom,
    Optional<Instant> validUntil,
    Optional<Instant> revokedAt,
    Optional<String> revocationReason,
    Optional<String> rotatesFrom,
    Optional<String> rotatesTo) {
  private static final int MAX_REASON_CHARS = 256;
  private static final int MAX_ROTATION_ID_CHARS = 128;

  /**
   * Active key with no explicit validity window.
   *
   * <p>This is the compatibility default for v1 registries and programmatic test keys. Production
   * v2 registries should prefer explicit windows so operators can audit reviewer rotations.
   */
  public static final TrustedReviewerKeyLifecycle ACTIVE =
      new TrustedReviewerKeyLifecycle(
          TrustedReviewerKeyStatus.ACTIVE,
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty(),
          Optional.empty());

  /**
   * Creates lifecycle metadata from nullable registry values.
   *
   * <p>Registry loaders use this factory because properties files naturally produce nullable
   * values. A missing status defaults to {@link TrustedReviewerKeyStatus#ACTIVE} for v1
   * compatibility. Optional text fields are validated by the canonical constructor after conversion
   * to {@link Optional}.
   *
   * @param status configured key lifecycle status, or {@code null} for active
   * @param validFrom optional inclusive validity start for reviewed-at timestamps
   * @param validUntil optional exclusive validity end for reviewed-at timestamps
   * @param revokedAt optional local revocation instant
   * @param revocationReason optional bounded single-line revocation reason
   * @param rotatesFrom optional predecessor reviewer key id
   * @param rotatesTo optional successor reviewer key id
   * @return validated immutable lifecycle metadata
   */
  public static TrustedReviewerKeyLifecycle of(
      TrustedReviewerKeyStatus status,
      Instant validFrom,
      Instant validUntil,
      Instant revokedAt,
      String revocationReason,
      String rotatesFrom,
      String rotatesTo) {
    return new TrustedReviewerKeyLifecycle(
        Objects.requireNonNullElse(status, TrustedReviewerKeyStatus.ACTIVE),
        Optional.ofNullable(validFrom),
        Optional.ofNullable(validUntil),
        Optional.ofNullable(revokedAt),
        Optional.ofNullable(revocationReason),
        Optional.ofNullable(rotatesFrom),
        Optional.ofNullable(rotatesTo));
  }

  /**
   * Creates validated lifecycle metadata.
   *
   * <p>The constructor enforces a valid time window, requires revocation metadata to appear only on
   * revoked keys, bounds revocation and rotation text, and preserves empty optionals as absent
   * values. It intentionally records warnings rather than rejecting retired keys without {@code
   * validUntil}; the verifier then fails those receipts closed at trust-evaluation time.
   */
  public TrustedReviewerKeyLifecycle {
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(validFrom, "validFrom");
    Objects.requireNonNull(validUntil, "validUntil");
    Objects.requireNonNull(revokedAt, "revokedAt");
    Objects.requireNonNull(revocationReason, "revocationReason");
    Objects.requireNonNull(rotatesFrom, "rotatesFrom");
    Objects.requireNonNull(rotatesTo, "rotatesTo");
    if (validFrom.isPresent()
        && validUntil.isPresent()
        && !validFrom.get().isBefore(validUntil.get())) {
      throw AppCatalogSidecars.invalidEntry("reviewer valid.until must be after valid.from");
    }
    if (status != TrustedReviewerKeyStatus.REVOKED
        && (revokedAt.isPresent() || revocationReason.isPresent())) {
      throw AppCatalogSidecars.invalidEntry("reviewer revocation metadata requires status=revoked");
    }
    revocationReason =
        revocationReason.map(
            value ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    value,
                    "reviewer revocation reason",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_REASON_CHARS));
    rotatesFrom = rotatesFrom.map(TrustedReviewerKeyLifecycle::validateRotationId);
    rotatesTo = rotatesTo.map(TrustedReviewerKeyLifecycle::validateRotationId);
  }

  /**
   * Evaluates lifecycle acceptability for a receipt review timestamp.
   *
   * <p>The returned status is the first lifecycle-specific reason a receipt cannot be trusted.
   * Revocation wins over all timestamp checks. A retired key without an explicit end of validity is
   * rejected because there is no safe historical window. Passing this method only means lifecycle
   * governance allows signature and policy checks to continue.
   *
   * @param reviewedAt timestamp from the independent receipt payload
   * @return lifecycle trust failure, or empty when later verifier checks may proceed
   */
  public Optional<AppReviewTrustStatus> trustFailureAt(Instant reviewedAt) {
    Objects.requireNonNull(reviewedAt, "reviewedAt");
    if (status == TrustedReviewerKeyStatus.REVOKED) {
      return Optional.of(AppReviewTrustStatus.REVOKED_REVIEWER);
    }
    if (validFrom.isPresent() && reviewedAt.isBefore(validFrom.get())) {
      return Optional.of(AppReviewTrustStatus.REVIEWER_NOT_YET_VALID);
    }
    if (status == TrustedReviewerKeyStatus.RETIRED && validUntil.isEmpty()) {
      return Optional.of(AppReviewTrustStatus.RETIRED_REVIEWER);
    }
    if (validUntil.isPresent() && !reviewedAt.isBefore(validUntil.get())) {
      return Optional.of(
          status == TrustedReviewerKeyStatus.RETIRED
              ? AppReviewTrustStatus.RETIRED_REVIEWER
              : AppReviewTrustStatus.REVIEWER_EXPIRED);
    }
    return Optional.empty();
  }

  /**
   * Returns display-safe validation warnings about lifecycle metadata.
   *
   * <p>Warnings are intended for registry summaries and operator diagnostics. They are not used to
   * downgrade trust by themselves; the verifier has explicit fail-closed checks for revoked and
   * retired-key edge cases.
   *
   * @return warnings suitable for API, CLI, and certification summaries
   */
  public List<String> warnings() {
    List<String> warnings = new ArrayList<>();
    if (status == TrustedReviewerKeyStatus.REVOKED && revokedAt.isEmpty()) {
      warnings.add("Revoked reviewer key has no revokedAt timestamp.");
    }
    if (status == TrustedReviewerKeyStatus.RETIRED && validUntil.isEmpty()) {
      warnings.add("Retired reviewer key has no validUntil timestamp.");
    }
    return List.copyOf(warnings);
  }

  private static String validateRotationId(String value) {
    return AppCatalogSidecars.requireBoundedSingleLine(
        value,
        "reviewer rotation key id",
        AppCatalogSidecars.INVALID_CATALOG_ENTRY,
        MAX_ROTATION_ID_CHARS);
  }
}
