package network.crypta.platform.appcatalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Deterministic JSON report emitted by automated third-party app pre-review.
 *
 * <p>The report contains only redacted metadata, findings, and digests. It intentionally excludes
 * raw bundle contents, rationale bodies, private keys, receipt signatures, local filesystem paths,
 * and fetched content. Reviewers can use the report as evidence when issuing a final review receipt
 * or a rejection record.
 *
 * <p>Status is derived from findings rather than accepted as independent author input: blockers
 * produce {@code fail}, warnings without blockers produce {@code warn}, and info-only or empty
 * finding lists produce {@code pass}. {@code promotionReady} is the boolean form of the same policy
 * and is true only when blockers are absent. The constructor re-checks both values so edited JSON
 * cannot claim a stronger automated review result than the findings support.
 *
 * <p>The {@code artifacts} map stores stable identifiers such as submission, bundle, and manifest
 * digests. Keys ending in {@code Digest} or {@code Sha256} must contain lowercase SHA-256 text.
 * Other values are bounded single-line metadata suitable for CLI JSON, catalog descriptors, and
 * transparency-log references.
 *
 * @param schemaVersion report schema version, currently {@value #SCHEMA_VERSION}
 * @param submissionId submission package id copied from verified metadata
 * @param appId normalized app id reviewed by pre-review checks
 * @param appVersion app version reviewed by pre-review checks
 * @param status aggregate pass, warn, or fail status derived from findings
 * @param promotionReady whether blocker findings are absent
 * @param findings deterministic redacted finding list in report order
 * @param artifacts digest and bounded metadata for the reviewed package
 */
public record AppSubmissionPreReviewReport(
    int schemaVersion,
    String submissionId,
    String appId,
    String appVersion,
    AppSubmissionPreReviewStatus status,
    boolean promotionReady,
    List<AppSubmissionFinding> findings,
    Map<String, String> artifacts) {
  /**
   * Current pre-review report schema version.
   *
   * <p>Report parsers reject unsupported versions because reviewer receipts may bind directly to
   * the serialized report digest.
   */
  public static final int SCHEMA_VERSION = 1;

  private static final String SUBMISSION_ID_FIELD = "submissionId";
  private static final String APP_ID_FIELD = "appId";
  private static final String APP_VERSION_FIELD = "appVersion";
  private static final String STATUS_FIELD = "status";
  private static final String PROMOTION_READY_FIELD = "promotionReady";
  private static final String FINDINGS_FIELD = "findings";
  private static final String ARTIFACTS_FIELD = "artifacts";

  /**
   * Creates a validated report.
   *
   * <p>The constructor normalizes app identity, defensively copies findings, validates artifact
   * metadata, and checks that the declared aggregate status matches the finding severities. Prefer
   * {@link #create(String, String, String, List, Map)} when generating reports from fresh findings.
   */
  public AppSubmissionPreReviewReport {
    if (schemaVersion != SCHEMA_VERSION) {
      throw AppCatalogSidecars.invalidEntry(
          "unsupported pre-review schemaVersion: " + schemaVersion);
    }
    submissionId =
        AppCatalogSidecars.requireBoundedSingleLine(
            submissionId, SUBMISSION_ID_FIELD, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 96);
    appId = AppCatalogEntry.normalizeAppId(appId);
    appVersion =
        AppCatalogSidecars.requireBoundedSingleLine(
            appVersion, APP_VERSION_FIELD, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 128);
    Objects.requireNonNull(status, STATUS_FIELD);
    findings = List.copyOf(Objects.requireNonNull(findings, FINDINGS_FIELD));
    artifacts = normalizeArtifacts(artifacts);
    boolean hasBlockers = findings.stream().anyMatch(AppSubmissionFinding::blocksPromotion);
    if (promotionReady == hasBlockers) {
      throw AppCatalogSidecars.invalidEntry("promotionReady must match pre-review blockers");
    }
    AppSubmissionPreReviewStatus derivedStatus = deriveStatus(findings);
    if (status != derivedStatus) {
      throw AppCatalogSidecars.invalidEntry("pre-review status must match findings");
    }
  }

  /**
   * Builds a report and derives status from the supplied findings.
   *
   * <p>This factory is the normal path for automated pre-review engines. It derives both {@code
   * status} and {@code promotionReady}, then delegates to the validating constructor so the
   * generated object follows the same rules as parsed JSON.
   *
   * @param submissionId submission package id copied from verified metadata
   * @param appId reviewed app id
   * @param appVersion reviewed app version
   * @param findings redacted findings produced by package and policy checks
   * @param artifacts digest metadata for the verified submission and bundle
   * @return deterministic report with derived status and promotion readiness
   */
  public static AppSubmissionPreReviewReport create(
      String submissionId,
      String appId,
      String appVersion,
      List<AppSubmissionFinding> findings,
      Map<String, String> artifacts) {
    AppSubmissionPreReviewStatus status = deriveStatus(findings);
    return new AppSubmissionPreReviewReport(
        SCHEMA_VERSION,
        submissionId,
        appId,
        appVersion,
        status,
        status != AppSubmissionPreReviewStatus.FAIL,
        findings,
        artifacts);
  }

  /**
   * Serializes this report as deterministic JSON.
   *
   * <p>Output fields are emitted in schema order. The result ends with a newline so the digest
   * bound into review receipts is stable across repeated writes.
   *
   * @return report JSON document ending with a newline
   */
  public String toJson() {
    return AppSubmissionJson.write(toJsonValue());
  }

  /**
   * Parses a report from JSON.
   *
   * <p>Parsed reports are validated against the same status, promotion, and artifact rules used for
   * generated reports. Malformed or internally inconsistent reports fail closed before reviewer
   * decision tooling can bind them into receipt evidence.
   *
   * @param json report JSON read from pre-review evidence
   * @return parsed and validated pre-review report
   */
  public static AppSubmissionPreReviewReport parse(String json) {
    Map<String, Object> object = AppSubmissionJson.parseObject(json, "pre-review report");
    List<AppSubmissionFinding> parsedFindings = new ArrayList<>();
    Object findingsValue = object.get(FINDINGS_FIELD);
    if (!(findingsValue instanceof List<?> findingValues)) {
      throw AppCatalogSidecars.invalidEntry(FINDINGS_FIELD + " must be an array");
    }
    for (Object findingValue : findingValues) {
      parsedFindings.add(AppSubmissionFinding.fromJsonValue(findingValue));
    }
    return new AppSubmissionPreReviewReport(
        AppSubmissionJson.requireSchemaVersion(object),
        AppSubmissionJson.requireString(object, SUBMISSION_ID_FIELD, SUBMISSION_ID_FIELD),
        AppSubmissionJson.requireString(object, APP_ID_FIELD, APP_ID_FIELD),
        AppSubmissionJson.requireString(object, APP_VERSION_FIELD, APP_VERSION_FIELD),
        AppSubmissionPreReviewStatus.parse(
            AppSubmissionJson.requireString(object, STATUS_FIELD, STATUS_FIELD)),
        AppSubmissionJson.requireBoolean(object, PROMOTION_READY_FIELD, PROMOTION_READY_FIELD),
        parsedFindings,
        parseArtifacts(object.get(ARTIFACTS_FIELD)));
  }

  Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> value = new LinkedHashMap<>();
    value.put("schemaVersion", schemaVersion);
    value.put(SUBMISSION_ID_FIELD, submissionId);
    value.put(APP_ID_FIELD, appId);
    value.put(APP_VERSION_FIELD, appVersion);
    value.put(STATUS_FIELD, status.jsonValue());
    value.put(PROMOTION_READY_FIELD, promotionReady);
    List<Object> findingValues = new ArrayList<>();
    for (AppSubmissionFinding finding : findings) {
      findingValues.add(finding.toJsonValue());
    }
    value.put(FINDINGS_FIELD, findingValues);
    value.put(ARTIFACTS_FIELD, artifacts);
    return value;
  }

  private static AppSubmissionPreReviewStatus deriveStatus(List<AppSubmissionFinding> findings) {
    boolean hasWarning = false;
    for (AppSubmissionFinding finding : findings) {
      if (finding.severity() == AppSubmissionFindingSeverity.BLOCKER) {
        return AppSubmissionPreReviewStatus.FAIL;
      }
      if (finding.severity() == AppSubmissionFindingSeverity.WARNING) {
        hasWarning = true;
      }
    }
    return hasWarning ? AppSubmissionPreReviewStatus.WARN : AppSubmissionPreReviewStatus.PASS;
  }

  private static Map<String, String> parseArtifacts(Object value) {
    Map<String, Object> object = AppSubmissionJson.requireObject(value, ARTIFACTS_FIELD);
    LinkedHashMap<String, String> artifacts = new LinkedHashMap<>();
    for (Map.Entry<String, Object> entry : object.entrySet()) {
      if (!(entry.getValue() instanceof String text)) {
        throw AppCatalogSidecars.invalidEntry("artifacts values must be strings");
      }
      artifacts.put(entry.getKey(), text);
    }
    return normalizeArtifacts(artifacts);
  }

  private static Map<String, String> normalizeArtifacts(Map<String, String> artifacts) {
    LinkedHashMap<String, String> normalized = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry :
        Objects.requireNonNull(artifacts, ARTIFACTS_FIELD).entrySet()) {
      String key =
          AppCatalogSidecars.requireBoundedSingleLine(
              entry.getKey(),
              ARTIFACTS_FIELD + " key",
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              64);
      String value =
          AppCatalogSidecars.requireBoundedSingleLine(
              entry.getValue(),
              ARTIFACTS_FIELD + "." + key,
              AppCatalogSidecars.INVALID_CATALOG_ENTRY,
              128);
      if (key.endsWith("Digest") || key.endsWith("Sha256")) {
        value = AppCatalogSidecars.requireLowercaseSha256(value, ARTIFACTS_FIELD + "." + key);
      }
      normalized.put(key, value);
    }
    return java.util.Collections.unmodifiableMap(normalized);
  }
}
