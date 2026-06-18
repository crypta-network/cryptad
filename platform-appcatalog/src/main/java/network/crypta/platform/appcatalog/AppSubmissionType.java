package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Third-party app-store submission intent.
 *
 * <p>The value is stored in {@code crypta-app-submission.json} so reviewers can distinguish a first
 * submission from an update or a resubmission that intentionally links to an earlier rejected or
 * cautionary package. It does not grant trust by itself; final trust still comes from independent
 * review receipts and local reviewer-key policy.
 *
 * <p>Submission type affects metadata validation and audit presentation. Resubmissions must carry a
 * {@code resubmissionOf} link, while new-app and update submissions must not. Catalog policy may
 * use the type when deciding whether a candidate can be promoted, but the type never bypasses API
 * compatibility, redaction, or review-receipt checks.
 */
public enum AppSubmissionType {
  /**
   * A first submission for a new third-party app id.
   *
   * <p>Reviewers should treat this as the beginning of the app's review history. It has no required
   * predecessor link.
   */
  NEW_APP("new_app"),

  /**
   * A submission updating an already reviewed app id.
   *
   * <p>Updates still require a complete package and fresh review evidence. The value does not imply
   * compatibility with an installed version by itself.
   */
  UPDATE("update"),

  /**
   * A submission that supersedes an earlier submission id.
   *
   * <p>Resubmissions are used after rejection, caution, or requested changes. The metadata must
   * include the prior submission id so transparency logs and catalog candidates retain the audit
   * link.
   */
  RESUBMISSION("resubmission");

  private final String jsonValue;

  AppSubmissionType(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a submission type from metadata JSON text.
   *
   * <p>The parser accepts the stable lower-case JSON spellings and normalizes case for
   * hand-authored fixtures. Unknown values fail closed so future workflow states are not
   * misinterpreted by older tooling.
   *
   * @param raw raw metadata value from {@code submissionType}
   * @return matching submission type used by metadata validation
   */
  public static AppSubmissionType parse(String raw) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
                raw, "submissionType", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppSubmissionType type : values()) {
      if (type.jsonValue.equals(value)) {
        return type;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported submissionType: " + raw);
  }

  /**
   * Returns the stable JSON spelling.
   *
   * @return metadata value written into submission packages
   */
  public String jsonValue() {
    return jsonValue;
  }
}
