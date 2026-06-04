package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Path-free update candidate derived from one verified catalog entry and one installed app.
 *
 * <p>The update service creates this record after comparing an installed manifest with a signed
 * catalog entry. It is the review artifact shown to operators before staging or applying a bundle,
 * so every field is chosen for display and audit use. The record keeps catalog identifiers, version
 * comparison output, bundle digest metadata, review state, Platform API compatibility, and
 * permission deltas. It deliberately does not keep catalog scratch directories, staged bundle
 * paths, trusted-key material, app launch tokens, browser-session tokens, or private insert URIs.
 *
 * <p>Instances are immutable snapshots. They may become stale when a catalog is refreshed or an app
 * is updated through another route, so {@link AppUpdateService} revalidates candidates before
 * staging and applying them. The {@code status}, {@code autoStageAllowed}, {@code
 * autoApplyAllowed}, and {@code operatorActionRequired} fields in {@link #toJsonValue()} are policy
 * hints, not permission checks.
 *
 * @param appId installed app id that the catalog entry was compared against
 * @param catalogId verified catalog id that supplied the matching entry
 * @param catalogSourceId path-free source identifier suitable for API display
 * @param installedVersion installed manifest version observed during candidate detection
 * @param targetVersion catalog entry version that would be installed if applied
 * @param status stable lifecycle status for the candidate
 * @param versionComparison comparison label such as {@code newer}, {@code equal}, or {@code
 *     ambiguous}
 * @param channel signed catalog channel for the candidate
 * @param supportStatus signed catalog support status for the candidate
 * @param deprecation signed catalog deprecation metadata for the candidate
 * @param securityAdvisories signed catalog security-advisory references for the candidate
 * @param channelPolicyAllowed whether automatic policy may process this channel
 * @param policyBlockReason stable reason automatic policy would skip the candidate
 * @param bundleSha256 expected SHA-256 digest of the catalog bundle artifact
 * @param bundleSizeBytes expected bundle artifact size in bytes
 * @param bundleType catalog artifact type used by the verified staging path
 * @param review advisory catalog review metadata summarized for operator display
 * @param reviewTrust independent review receipt trust decision
 * @param apiCompatibility Platform API compatibility summary for the candidate
 * @param permissionDelta added, removed, and unchanged permissions versus the installed app
 * @param running whether the app was running when the candidate was detected
 * @param detectedAt timestamp when the candidate snapshot was computed
 * @see AppUpdateService
 */
public record AppUpdateCandidate(
    String appId,
    String catalogId,
    String catalogSourceId,
    String installedVersion,
    String targetVersion,
    AppUpdateCandidateStatus status,
    String versionComparison,
    String channel,
    String supportStatus,
    Map<String, Object> deprecation,
    List<Map<String, Object>> securityAdvisories,
    boolean channelPolicyAllowed,
    String policyBlockReason,
    String bundleSha256,
    long bundleSizeBytes,
    String bundleType,
    Map<String, Object> review,
    Map<String, Object> reviewTrust,
    Map<String, Object> apiCompatibility,
    Map<String, Object> permissionDelta,
    boolean running,
    Instant detectedAt) {
  private static final String JSON_STATUS = "status";
  private static final String JSON_POSITIVE = "positive";
  private static final String JSON_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";
  private static final String JSON_BLOCKS_UPDATE = "blocksUpdate";
  private static final String JSON_BLOCKS_POLICY_APPLY = "blocksPolicyApply";
  private static final String JSON_SECURITY_ADVISORIES = "securityAdvisories";
  private static final String API_STATUS_COMPATIBLE = "compatible";
  private static final String REVIEW_STATUS_REVIEWED = "reviewed";
  private static final String REVIEW_TRUST_STATUS_PUBLISHER_CLAIM_ONLY = "publisher_claim_only";

  /**
   * Creates a validated candidate.
   *
   * <p>String identifiers and version fields are trimmed and must remain non-blank. Map values are
   * copied into insertion-order-preserving immutable maps so callers can build summaries without
   * risking later mutation of the reviewed metadata. The constructor validates only structural
   * safety; semantic checks such as whether a candidate is newer, compatible, or review-approved
   * are performed before this record is built.
   *
   * @param appId installed app id being updated
   * @param catalogId verified catalog id that supplied the candidate
   * @param catalogSourceId safe source identifier, currently the catalog id
   * @param installedVersion version currently installed on the node
   * @param targetVersion candidate version from the signed catalog entry
   * @param status candidate lifecycle status at detection time
   * @param versionComparison deterministic version comparison label
   * @param channel signed catalog channel for the candidate
   * @param supportStatus signed catalog support status for the candidate
   * @param deprecation signed catalog deprecation metadata for the candidate
   * @param securityAdvisories signed catalog security-advisory references for the candidate
   * @param channelPolicyAllowed whether automatic policy may process this channel
   * @param policyBlockReason stable reason automatic policy would skip the candidate
   * @param bundleSha256 expected SHA-256 digest of the candidate bundle
   * @param bundleSizeBytes expected artifact size in bytes, never negative
   * @param bundleType catalog artifact type, for example a signed bundle archive
   * @param review advisory review summary copied for display and audit use
   * @param reviewTrust review receipt trust summary copied for display and audit use
   * @param apiCompatibility Platform API compatibility summary copied for display
   * @param permissionDelta permission delta map copied for display and gating
   * @param running whether the app was running when detection occurred
   * @param detectedAt timestamp attached to this immutable candidate snapshot
   */
  public AppUpdateCandidate {
    appId = requireText(appId, "appId");
    catalogId = requireText(catalogId, "catalogId");
    catalogSourceId = requireText(catalogSourceId, "catalogSourceId");
    installedVersion = requireText(installedVersion, "installedVersion");
    targetVersion = requireText(targetVersion, "targetVersion");
    Objects.requireNonNull(status, JSON_STATUS);
    versionComparison = requireText(versionComparison, "versionComparison");
    channel = requireText(channel, "channel");
    supportStatus = requireText(supportStatus, "supportStatus");
    deprecation = copyInOrder(deprecation, "deprecation");
    securityAdvisories = copySecurityAdvisories(securityAdvisories);
    if (policyBlockReason != null && policyBlockReason.isBlank()) {
      throw new IllegalArgumentException("policyBlockReason must not be blank");
    }
    policyBlockReason = policyBlockReason == null ? null : policyBlockReason.trim();
    bundleSha256 = requireText(bundleSha256, "bundleSha256");
    if (bundleSizeBytes < 0L) {
      throw new IllegalArgumentException("bundleSizeBytes must be >= 0");
    }
    bundleType = requireText(bundleType, "bundleType");
    review = copyInOrder(review, "review");
    reviewTrust = copyInOrder(reviewTrust, "reviewTrust");
    apiCompatibility = copyInOrder(apiCompatibility, "apiCompatibility");
    permissionDelta = copyInOrder(permissionDelta, "permissionDelta");
    Objects.requireNonNull(detectedAt, "detectedAt");
  }

  /**
   * Returns whether this candidate can be staged or applied by default.
   *
   * <p>Default eligibility is intentionally narrow: only {@link AppUpdateCandidateStatus#AVAILABLE}
   * qualifies. Ambiguous, incompatible, not-newer, blocked, and already-applied states require
   * fresh operator intent or are not actionable. This method is used for automatic staging and
   * baseline apply checks; route authorization and catalog verification remain separate controls.
   *
   * @return {@code true} when the candidate is a safely newer compatible version
   */
  public boolean eligibleByDefault() {
    return status == AppUpdateCandidateStatus.AVAILABLE;
  }

  /**
   * Returns whether policy-driven staging may use this candidate.
   *
   * @return {@code true} when the candidate is available and channel policy allows automation
   */
  public boolean eligibleForAutomaticStage() {
    return eligibleByDefault() && channelPolicyAllowed && policyBlockReason == null;
  }

  /**
   * Returns whether policy-driven apply may use this candidate without another operator decision.
   *
   * <p>Automatic apply is stricter than staging. The candidate must already be eligible by default,
   * local review policy must allow policy-driven apply without another acknowledgement, and the
   * Platform API compatibility summary must report {@code compatible}. A trusted positive review
   * receipt satisfies the review gate. For backward compatibility with older catalogs, publisher
   * advisory {@code reviewed} metadata can also satisfy the gate only when the local review policy
   * did not require independent receipt trust. Publisher advisory {@code caution}, {@code
   * rejected}, and {@code unreviewed} states are never enough for automatic apply by themselves.
   *
   * @return {@code true} when the candidate is safely newer, compatible, and reviewed
   */
  public boolean eligibleForAutomaticApply() {
    return eligibleForAutomaticStage()
        && reviewTrustAllowsAutomaticApply()
        && apiCompatibilityAllowsAutomaticApply();
  }

  boolean reviewTrustAllowsAutomaticApply() {
    return reviewTrustAllowsAutomaticApply(reviewTrust, review);
  }

  boolean apiCompatibilityAllowsAutomaticApply() {
    return apiCompatibilityAllowsAutomaticApply(apiCompatibility);
  }

  /**
   * Converts the candidate to a safe JSON-compatible summary.
   *
   * <p>The returned map is suitable for Platform API responses and Web Shell rendering. Nested maps
   * preserve the deterministic field order used by the service, and derived booleans are included
   * so clients do not need to duplicate policy decisions. The summary intentionally contains only
   * identifiers, versions, digest metadata, advisory gate results, and timestamps.
   *
   * @return path-free candidate summary for API responses
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(23);
    json.put("appId", appId);
    json.put("catalogId", catalogId);
    json.put("catalogSourceId", catalogSourceId);
    json.put("installedVersion", installedVersion);
    json.put("targetVersion", targetVersion);
    json.put(JSON_STATUS, status.jsonValue());
    json.put("versionComparison", versionComparison);
    json.put("channel", channel);
    json.put("supportStatus", supportStatus);
    json.put("deprecation", deprecation);
    json.put(JSON_SECURITY_ADVISORIES, securityAdvisories);
    json.put("channelPolicyAllowed", channelPolicyAllowed);
    json.put("policyBlockReason", policyBlockReason);
    json.put("bundle", bundleSummary());
    json.put("review", review);
    json.put("reviewTrust", reviewTrust);
    json.put("apiCompatibility", apiCompatibility);
    json.put("permissionDelta", permissionDelta);
    json.put("running", running);
    json.put("detectedAt", detectedAt.toString());
    json.put("autoStageAllowed", eligibleForAutomaticStage());
    json.put("autoApplyAllowed", eligibleForAutomaticApply());
    json.put("operatorActionRequired", operatorActionRequired());
    return json;
  }

  private boolean operatorActionRequired() {
    if (status == AppUpdateCandidateStatus.AVAILABLE && policyBlockReason != null) {
      return true;
    }
    if (status == AppUpdateCandidateStatus.AVAILABLE
        && (Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))
            || Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE)))) {
      return true;
    }
    return switch (status) {
      case AMBIGUOUS, BLOCKED, INCOMPATIBLE -> true;
      default -> false;
    };
  }

  private Map<String, Object> bundleSummary() {
    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(3);
    bundle.put("sha256", bundleSha256);
    bundle.put("sizeBytes", bundleSizeBytes);
    bundle.put("type", bundleType);
    return bundle;
  }

  private static boolean reviewTrustAllowsAutomaticApply(
      Map<String, Object> reviewTrust, Map<String, Object> review) {
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_POLICY_APPLY))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return false;
    }
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_POSITIVE))) {
      return true;
    }
    return REVIEW_TRUST_STATUS_PUBLISHER_CLAIM_ONLY.equals(reviewTrust.get(JSON_STATUS))
        && REVIEW_STATUS_REVIEWED.equals(review.get(JSON_STATUS));
  }

  private static boolean apiCompatibilityAllowsAutomaticApply(
      Map<String, Object> apiCompatibility) {
    Object statusValue = apiCompatibility.get(JSON_STATUS);
    if (!(statusValue instanceof String status)) {
      return false;
    }
    return API_STATUS_COMPATIBLE.equals(status);
  }

  static Map<String, Object> reviewSummary(String status, String note) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(JSON_STATUS, status);
    json.put("note", note);
    json.put("advisory", true);
    return json;
  }

  static Map<String, Object> permissionDelta(
      List<String> candidatePermissions, List<String> local) {
    java.util.Set<String> candidate = new java.util.LinkedHashSet<>(candidatePermissions);
    java.util.Set<String> installed = new java.util.LinkedHashSet<>(local);
    java.util.ArrayList<String> added = new java.util.ArrayList<>();
    java.util.ArrayList<String> removed = new java.util.ArrayList<>();
    java.util.ArrayList<String> unchanged = new java.util.ArrayList<>();
    for (String permission : candidate) {
      if (installed.contains(permission)) {
        unchanged.add(permission);
      } else {
        added.add(permission);
      }
    }
    for (String permission : installed) {
      if (!candidate.contains(permission)) {
        removed.add(permission);
      }
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("added", List.copyOf(added));
    json.put("removed", List.copyOf(removed));
    json.put("unchanged", List.copyOf(unchanged));
    return json;
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  private static Map<String, Object> copyInOrder(Map<String, Object> value, String fieldName) {
    Objects.requireNonNull(value, fieldName);
    return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(value));
  }

  private static List<Map<String, Object>> copySecurityAdvisories(List<Map<String, Object>> value) {
    Objects.requireNonNull(value, JSON_SECURITY_ADVISORIES);
    return value.stream()
        .map(item -> copyInOrder(item, JSON_SECURITY_ADVISORIES + " item"))
        .toList();
  }
}
