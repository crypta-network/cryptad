package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Advisory human-review state carried by a signed app catalog entry.
 *
 * <p>This enum is the stable vocabulary for the optional {@code app.<id>.review.status} catalog
 * property. A catalog signature authenticates which trusted catalog source supplied the status, but
 * the status itself is publisher metadata. It does not replace signed catalog verification,
 * artifact digest checks, signed-bundle verification, AppHost validation, or operator policy.
 *
 * <p>The values are deliberately few so API clients and the Web Shell can render predictable badges
 * without inventing trust semantics. {@link #REJECTED}, for example, communicates the publisher's
 * recommendation, but the installation/update endpoints still use the same verified catalog and
 * bundle flow. Operators can decide how to treat that advisory signal.
 *
 * <p>Parsing is strict and case-insensitive after trimming. Unsupported values fail closed as
 * malformed catalog entries so typoed review metadata does not silently become a new status.
 *
 * @see AppCatalogReviewMetadata
 * @see AppCatalogEntry#review()
 */
public enum AppCatalogReviewStatus {
  /**
   * No human review status was declared by the catalog publisher.
   *
   * <p>This is the default for minimal or older catalogs. It means the catalog made no review
   * claim; it does not mean the app is unsafe or safe.
   */
  UNREVIEWED("unreviewed"),

  /**
   * A third-party submission package has been created or received but not fully reviewed.
   *
   * <p>This is intake workflow metadata. It is not a positive review and must not be treated as a
   * trusted receipt.
   */
  SUBMITTED("submitted"),

  /**
   * Automated pre-review completed without blocker findings.
   *
   * <p>Human review and independent receipt issuance are still separate steps.
   */
  PRE_REVIEW_PASSED("pre_review_passed"),

  /**
   * The catalog publisher says the app was reviewed for local operator use.
   *
   * <p>The exact review process is defined by the publisher's catalog policy, not by the catalog
   * format. Runtime verification remains unchanged.
   */
  REVIEWED("reviewed"),

  /**
   * The catalog publisher wants operators to inspect the app with extra care.
   *
   * <p>This status is suitable for apps with unusual permissions, compatibility uncertainty, or
   * other publisher-supplied caveats that should be visible before install or update.
   */
  CAUTION("caution"),

  /**
   * The catalog publisher does not recommend installing the app.
   *
   * <p>The value is advisory metadata rather than an endpoint-level block. UI clients should make
   * the warning visible while preserving the signed-catalog trust boundary.
   */
  REJECTED("rejected"),

  /**
   * A third-party submission supersedes an earlier submission id.
   *
   * <p>Catalog entries with this status should carry {@code review.resubmissionOf} metadata when
   * available so operators can follow the audit chain.
   */
  RESUBMITTED("resubmitted");

  /**
   * Stable lower-case value used in catalog sidecars and Platform API JSON.
   *
   * <p>The field is separate from the enum constant name so the wire/catalog spelling stays stable
   * even if Java naming or documentation changes.
   */
  private final String catalogValue;

  /**
   * Creates one enum constant with its serialized catalog spelling.
   *
   * @param catalogValue lower-case value accepted in sidecars and emitted through API responses
   */
  AppCatalogReviewStatus(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses a catalog review status from sidecar text.
   *
   * <p>The parser trims the raw value, rejects blank or multi-line input, then compares the
   * remaining text case-insensitively against the supported catalog spellings. It is used by both
   * signed-catalog parsing and descriptor authoring so typos fail before metadata reaches the Web
   * Shell or Platform API response surface.
   *
   * @param value raw status text read from a catalog or descriptor sidecar
   * @param fieldName catalog field name to include in validation diagnostics
   * @return parsed review status with stable catalog spelling
   * @throws AppCatalogException if the value is blank, multi-line, too long, or unsupported
   */
  public static AppCatalogReviewStatus parse(String value, String fieldName)
      throws AppCatalogException {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogReviewStatus status : values()) {
      if (status.catalogValue.equals(normalized)) {
        return status;
      }
    }
    throw AppCatalogSidecars.invalidEntry(fieldName + " is not a supported review status");
  }

  /**
   * Returns the lower-case value written into catalog sidecars and Platform API JSON.
   *
   * <p>Callers should use this method instead of {@link #name()} whenever they serialize review
   * metadata. The returned value is deterministic, lower-case, and independent of Java enum naming.
   *
   * @return stable lower-case catalog value for this review status
   */
  public String catalogValue() {
    return catalogValue;
  }

  /**
   * Returns whether this status belongs to the third-party submission review workflow.
   *
   * <p>These states were introduced with the submission workflow catalog schema. Catalogs carrying
   * them must use the schema version that older strict readers reject at the version field rather
   * than exposing an unknown enum value inside an otherwise familiar catalog schema.
   *
   * @return {@code true} when the status requires submission review catalog metadata support
   */
  public boolean requiresSubmissionReviewCatalogVersion() {
    return this == SUBMITTED || this == PRE_REVIEW_PASSED || this == RESUBMITTED;
  }
}
