package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Result of recomputing a local review transparency log hash chain.
 *
 * <p>The result is the display-safe output of transparency-log verification. It reports whether the
 * local sequence and hash chain are internally consistent, how many records were considered, the
 * latest verified hash when available, and a redacted failure reason. It intentionally omits local
 * file paths, raw JSONL lines, key material, receipt signatures, request bodies, and process state.
 *
 * <p>A successful result proves only local integrity for the records understood by this binary. It
 * is not a global transparency checkpoint and does not make a review decision trusted by itself.
 * Callers still need the corresponding {@link AppReviewTrustDecision} and reviewer-key governance
 * state to explain install or update trust.
 *
 * @param verified whether the local chain recomputed successfully
 * @param recordCount number of records inspected or known at failure time
 * @param latestRecordHash latest verified record hash, or {@code null} when unavailable
 * @param error redacted failure reason, or {@code null} for successful verification
 */
public record AppReviewTransparencyVerificationResult(
    boolean verified, long recordCount, String latestRecordHash, String error) {
  /**
   * Returns a successful verification result.
   *
   * <p>The latest hash may be {@code null} for an empty log. Callers should use {@link #verified()}
   * rather than hash presence alone when rendering status.
   *
   * @param recordCount number of records that verified successfully
   * @param latestRecordHash latest verified hash, or {@code null} for an empty log
   * @return success result with no error text
   */
  public static AppReviewTransparencyVerificationResult verified(
      long recordCount, String latestRecordHash) {
    return new AppReviewTransparencyVerificationResult(true, recordCount, latestRecordHash, null);
  }

  /**
   * Returns a failed verification result.
   *
   * <p>The error string should be stable and redacted so it can be shown in API, CLI, Web Shell,
   * and release-certification output. It must not include local paths or raw record content.
   *
   * @param recordCount number of records known or attempted at failure time
   * @param latestRecordHash latest hash verified before failure, when available
   * @param error display-safe failure reason
   * @return failed verification result with redacted error text
   */
  public static AppReviewTransparencyVerificationResult failed(
      long recordCount, String latestRecordHash, String error) {
    return new AppReviewTransparencyVerificationResult(false, recordCount, latestRecordHash, error);
  }

  /**
   * Converts this result to JSON-compatible values.
   *
   * <p>The field names match Platform API governance responses and developer CLI output. The map is
   * safe to serialize directly because this record never stores filesystem paths or raw log data.
   *
   * @return JSON-compatible verification summary
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("verified", verified);
    json.put("recordCount", recordCount);
    json.put("latestRecordHash", latestRecordHash);
    json.put("error", error);
    return json;
  }
}
