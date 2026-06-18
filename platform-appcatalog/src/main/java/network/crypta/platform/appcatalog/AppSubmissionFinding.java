package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Describes one redacted finding from submission verification or automated pre-review.
 *
 * <p>Findings are the stable evidence units that reviewers and release certification use when
 * deciding whether a third-party app can move from a submission package to a catalog candidate.
 * Each finding has a machine-readable identifier, a promotion severity, a short human summary, and
 * an optional details object. Details are deliberately constrained to simple JSON-compatible values
 * and are sorted by key during construction. That keeps pre-review JSON deterministic, which
 * matters because reviewer receipts and transparency-log records bind to report digests rather than
 * raw package contents.
 *
 * <p>The type is immutable after construction. It accepts only bounded single-line identifiers and
 * summaries so a malformed finding cannot corrupt properties files, JSON evidence, or operator UI
 * summaries.
 *
 * @param id stable machine-readable finding id used by tests, tools, and reviewers
 * @param severity promotion impact assigned by the verifier or pre-review engine
 * @param summary bounded single-line reviewer-facing summary with no raw secrets
 * @param details deterministic redacted JSON object for paths, digests, or small metadata
 */
public record AppSubmissionFinding(
    String id, AppSubmissionFindingSeverity severity, String summary, Map<String, Object> details) {
  private static final int MAX_FINDING_ID_CHARS = 128;
  private static final int MAX_SUMMARY_CHARS = 256;
  private static final String DETAILS_FIELD = "details";
  private static final String SEVERITY_FIELD = "severity";

  /**
   * Creates a validated immutable finding.
   *
   * <p>The constructor normalizes all externally supplied text before it can be serialized. Detail
   * keys are sorted lexicographically, and unsupported detail values fail closed with an invalid
   * catalog-entry error. Callers should pass already-redacted values here; this class preserves
   * deterministic shape and bounds but does not perform content redaction.
   */
  public AppSubmissionFinding {
    id =
        AppCatalogSidecars.requireBoundedSingleLine(
            id, "finding.id", AppCatalogSidecars.INVALID_CATALOG_ENTRY, MAX_FINDING_ID_CHARS);
    Objects.requireNonNull(severity, SEVERITY_FIELD);
    summary =
        AppCatalogSidecars.requireBoundedSingleLine(
            summary,
            "finding.summary",
            AppCatalogSidecars.INVALID_CATALOG_ENTRY,
            MAX_SUMMARY_CHARS);
    details = normalizeDetails(details);
  }

  /**
   * Returns whether this finding prevents promotion to a catalog candidate.
   *
   * <p>Only {@link AppSubmissionFindingSeverity#BLOCKER} stops promotion. Warning and info findings
   * still remain in the report so reviewers can issue caution decisions or document non-blocking
   * observations.
   *
   * @return {@code true} when the severity is a blocker
   */
  public boolean blocksPromotion() {
    return severity == AppSubmissionFindingSeverity.BLOCKER;
  }

  Map<String, Object> toJsonValue() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("id", id);
    value.put(SEVERITY_FIELD, severity.jsonValue());
    value.put("summary", summary);
    value.put(DETAILS_FIELD, details);
    return value;
  }

  static AppSubmissionFinding fromJsonValue(Object value) {
    Map<String, Object> object = AppSubmissionJson.requireObject(value, "finding");
    return new AppSubmissionFinding(
        AppSubmissionJson.requireString(object, "id", "finding.id"),
        AppSubmissionFindingSeverity.parse(
            AppSubmissionJson.requireString(object, SEVERITY_FIELD, "finding.severity")),
        AppSubmissionJson.requireString(object, "summary", "finding.summary"),
        AppSubmissionJson.optionalFindingDetails(object));
  }

  private static Map<String, Object> normalizeDetails(Map<String, Object> details) {
    TreeMap<String, Object> sorted = new TreeMap<>();
    for (Map.Entry<String, Object> entry :
        Objects.requireNonNull(details, DETAILS_FIELD).entrySet()) {
      String key =
          AppCatalogSidecars.requireBoundedSingleLine(
              entry.getKey(), "finding.details key", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 96);
      Object value = entry.getValue();
      if (!(value == null
          || value instanceof String
          || value instanceof Boolean
          || value instanceof Integer
          || value instanceof Long
          || value instanceof Iterable<?>)) {
        throw AppCatalogSidecars.invalidEntry("finding.details contains unsupported value");
      }
      sorted.put(key, value);
    }
    LinkedHashMap<String, Object> normalized = new LinkedHashMap<>(sorted);
    return java.util.Collections.unmodifiableMap(normalized);
  }
}
