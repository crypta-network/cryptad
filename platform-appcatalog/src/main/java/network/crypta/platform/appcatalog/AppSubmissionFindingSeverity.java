package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Stable severity vocabulary for third-party app submission findings.
 *
 * <p>The severity controls how {@link AppSubmissionPreReviewReport} derives its aggregate status
 * and whether a submission can be promoted automatically. The values are intentionally small and
 * lower-case when serialized because reports are treated as deterministic evidence. Review tooling
 * can add new finding identifiers without changing this enum, but a new severity would be a schema
 * change and should be handled explicitly by parsers, catalog metadata, and release certification.
 *
 * <p>Parsing fails closed for unknown text. That keeps edited or forward-versioned reports from
 * being silently interpreted as non-blocking evidence.
 */
public enum AppSubmissionFindingSeverity {
  /**
   * Finding that blocks verification, promotion, or receipt issuance.
   *
   * <p>A blocker means the submission package, manifest, artifacts, or redaction evidence failed a
   * mandatory policy check. Pre-review reports containing this value derive {@code fail} status and
   * set {@code promotionReady=false}.
   */
  BLOCKER("blocker"),

  /**
   * Finding that requires reviewer attention but does not block by itself.
   *
   * <p>Warnings are preserved in reports and may justify a caution decision, but they do not stop
   * catalog-candidate generation when no blocker is present.
   */
  WARNING("warning"),

  /**
   * Informational evidence recorded for auditability.
   *
   * <p>Info findings explain checks that passed, optional metadata that was observed, or other
   * facts useful to reviewers. They do not affect promotion readiness.
   */
  INFO("info");

  private final String jsonValue;

  AppSubmissionFindingSeverity(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Parses a finding severity from report JSON.
   *
   * <p>The parser accepts the stable lower-case spellings emitted by {@link #jsonValue()} and
   * normalizes case for older hand-authored fixtures. Unknown, blank, multiline, or oversized
   * values are rejected with an invalid catalog-entry error instead of defaulting to a weaker
   * severity.
   *
   * @param raw raw report value read from a submission finding
   * @return matching severity used by pre-review status derivation
   */
  public static AppSubmissionFindingSeverity parse(String raw) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
                raw, "finding.severity", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 16)
            .toLowerCase(Locale.ROOT);
    for (AppSubmissionFindingSeverity severity : values()) {
      if (severity.jsonValue.equals(value)) {
        return severity;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported finding severity: " + raw);
  }

  /**
   * Returns the stable JSON spelling for deterministic reports.
   *
   * @return lower-case severity token stored in pre-review JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
