package network.crypta.platform.api.consent;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable, digestible consent preview for one install, update, or service-grant action.
 *
 * <p>A snapshot is the artifact an operator reviews before a material app-platform mutation. It
 * carries the action, app identity, installed and candidate versions, bundle digests, catalog
 * identity, rolled-up risk, blocking reason codes, grouped findings, and the recommended next
 * action. The public JSON shape also includes the request id and computed snapshot digest so a
 * client can submit an approval with the later mutation.
 *
 * <p>The digestable form intentionally excludes the request id and creation timestamp. That lets
 * the service issue a fresh request for the same material preview while still rejecting approvals
 * when candidate metadata, review evidence, permissions, security policy, migration details, or
 * service dependencies change. All optional display strings are trimmed and redacted at
 * construction time.
 *
 * @param consentRequestId process-local request id returned to the client
 * @param action action family represented by this preview
 * @param appId app id affected by the reviewed operation
 * @param appName optional redacted display name of the app
 * @param installedVersion optional installed version observed during preview generation
 * @param candidateVersion optional candidate version being reviewed
 * @param installedDigest optional installed bundle digest, normalized with {@code sha256:}
 * @param candidateDigest optional candidate bundle digest, normalized with {@code sha256:}
 * @param catalogId optional catalog id associated with the candidate
 * @param catalogSourceId optional path-free source id associated with the candidate
 * @param riskLevel maximum risk level across all sections
 * @param requiresApproval whether the snapshot cannot proceed unattended
 * @param blocksAutoUpdate whether scheduler policy must not stage or apply this candidate
 * @param blockingReasons unique material or blocking finding codes
 * @param recommendedAction stable recommendation token for Web Shell and API clients
 * @param sections immutable ordered finding groups shown to the operator
 * @param createdAt time when the preview was produced
 * @see ConsentSnapshotDigest
 */
public record ConsentSnapshot(
    String consentRequestId,
    ConsentActionType action,
    String appId,
    String appName,
    String installedVersion,
    String candidateVersion,
    String installedDigest,
    String candidateDigest,
    String catalogId,
    String catalogSourceId,
    ConsentRiskLevel riskLevel,
    boolean requiresApproval,
    boolean blocksAutoUpdate,
    List<String> blockingReasons,
    String recommendedAction,
    List<ConsentSection> sections,
    Instant createdAt) {
  /**
   * Creates a normalized consent snapshot.
   *
   * <p>Required identifiers and recommendation tokens are trimmed and validated. Optional display
   * strings are either normalized to {@code null} or redacted. Digest values may be supplied with
   * or without the {@code sha256:} prefix. Section and reason lists are copied so the snapshot
   * remains stable while cached or audited.
   *
   * @throws IllegalArgumentException when a required text field is blank
   * @throws NullPointerException when required components or lists are null
   */
  public ConsentSnapshot {
    consentRequestId = requireText(consentRequestId, "consentRequestId");
    Objects.requireNonNull(action, "action");
    appId = requireText(appId, "appId");
    appName = nullableTrim(appName);
    installedVersion = nullableTrim(installedVersion);
    candidateVersion = nullableTrim(candidateVersion);
    installedDigest = normalizeDigest(installedDigest);
    candidateDigest = normalizeDigest(candidateDigest);
    catalogId = nullableTrim(catalogId);
    catalogSourceId = nullableTrim(catalogSourceId);
    Objects.requireNonNull(riskLevel, "riskLevel");
    blockingReasons = List.copyOf(Objects.requireNonNull(blockingReasons, "blockingReasons"));
    recommendedAction = requireText(recommendedAction, "recommendedAction");
    sections = List.copyOf(Objects.requireNonNull(sections, "sections"));
    Objects.requireNonNull(createdAt, "createdAt");
  }

  /**
   * Returns the deterministic fingerprint for this snapshot's material contents.
   *
   * <p>The fingerprint is the value an approval must echo before a mutating route consumes it. It
   * excludes request-only metadata but includes the material fields an operator reviewed.
   *
   * @return stable SHA-256 digest token for consent approval matching
   */
  public String snapshotDigest() {
    return ConsentSnapshotDigest.digest(this);
  }

  /**
   * Converts this snapshot to the public Platform API JSON shape.
   *
   * <p>The response shape includes request metadata, the computed digest, section JSON, reason
   * codes, and the creation timestamp. It contains redacted summaries only and is safe for local
   * Web Shell display.
   *
   * @return ordered JSON-compatible preview object
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = baseJson(true);
    json.put("createdAt", createdAt.toString());
    return json;
  }

  Map<String, Object> toDigestJson() {
    return baseJson(false);
  }

  private LinkedHashMap<String, Object> baseJson(boolean includeRequestFields) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(18);
    if (includeRequestFields) {
      json.put("consentRequestId", consentRequestId);
    }
    json.put("action", action.jsonValue());
    json.put("appId", appId);
    json.put("appName", appName);
    json.put("installedVersion", installedVersion);
    json.put("candidateVersion", candidateVersion);
    json.put("installedDigest", installedDigest);
    json.put("candidateDigest", candidateDigest);
    json.put("catalogId", catalogId);
    json.put("catalogSourceId", catalogSourceId);
    json.put("riskLevel", riskLevel.jsonValue());
    json.put("requiresApproval", requiresApproval);
    json.put("blocksAutoUpdate", blocksAutoUpdate);
    if (includeRequestFields) {
      json.put("snapshotDigest", snapshotDigest());
    }
    json.put("sections", sections.stream().map(ConsentSection::toJsonValue).toList());
    json.put("blockingReasons", blockingReasons);
    json.put("recommendedAction", recommendedAction);
    return json;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  private static String nullableTrim(String value) {
    return value == null || value.isBlank() ? null : ConsentRedactor.redact(value.trim());
  }

  private static String normalizeDigest(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    String text = value.trim();
    return text.startsWith("sha256:") ? text : "sha256:" + text;
  }
}
