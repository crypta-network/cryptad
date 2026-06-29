package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Compact operator-safe summary for one intake record.
 *
 * <p>Summaries are suitable for CLI list output, Platform API responses, Web Shell rendering, and
 * release evidence because they contain only ids, statuses, digests, counts, and warnings.
 *
 * @param submissionId submission id
 * @param appId app id
 * @param appVersion app version
 * @param status current intake status
 * @param reviewerKeyId assigned reviewer key id when available
 * @param reviewerDisplayName assigned reviewer display name when available
 * @param preReviewStatus automated pre-review status when available
 * @param decision final reviewer decision when available
 * @param catalogCandidateCreated whether candidate metadata exists
 * @param betaCatalogChannel staged beta catalog channel when available
 * @param installSmokeStatus install-smoke status when available
 * @param transparencyLogDigest transparency log digest when available
 * @param nonProduction whether the record is non-production/test evidence
 * @param redactionStatus redaction scan status
 * @param warnings bounded warning list
 */
public record AppSubmissionIntakeSummary(
    String submissionId,
    String appId,
    String appVersion,
    AppSubmissionIntakeStatus status,
    String reviewerKeyId,
    String reviewerDisplayName,
    String preReviewStatus,
    String decision,
    boolean catalogCandidateCreated,
    String betaCatalogChannel,
    String installSmokeStatus,
    String transparencyLogDigest,
    boolean nonProduction,
    String redactionStatus,
    List<String> warnings) {
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(15);
    json.put("submissionId", submissionId);
    json.put("appId", appId);
    json.put("appVersion", appVersion);
    json.put("status", status.jsonValue());
    json.put("reviewerKeyId", reviewerKeyId);
    json.put("reviewerDisplayName", reviewerDisplayName);
    json.put("preReviewStatus", preReviewStatus);
    json.put("decision", decision);
    json.put("catalogCandidateCreated", catalogCandidateCreated);
    json.put("betaCatalogChannel", betaCatalogChannel);
    json.put("installSmokeStatus", installSmokeStatus);
    json.put("transparencyLogDigest", transparencyLogDigest);
    json.put("nonProduction", nonProduction);
    json.put("redactionStatus", redactionStatus);
    json.put("warnings", warnings);
    return json;
  }

  /** Serializes this summary as deterministic JSON. */
  public String toJson() {
    return AppSubmissionJson.write(toJsonValue());
  }
}
