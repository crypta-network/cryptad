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
 * @param bundleSha256 expected SHA-256 digest of the catalog bundle artifact
 * @param bundleSizeBytes expected bundle artifact size in bytes
 * @param bundleType catalog artifact type used by the verified staging path
 * @param review advisory catalog review metadata summarized for operator display
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
    String bundleSha256,
    long bundleSizeBytes,
    String bundleType,
    Map<String, Object> review,
    Map<String, Object> apiCompatibility,
    Map<String, Object> permissionDelta,
    boolean running,
    Instant detectedAt) {
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
   * @param bundleSha256 expected SHA-256 digest of the candidate bundle
   * @param bundleSizeBytes expected artifact size in bytes, never negative
   * @param bundleType catalog artifact type, for example a signed bundle archive
   * @param review advisory review summary copied for display and audit use
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
    Objects.requireNonNull(status, "status");
    versionComparison = requireText(versionComparison, "versionComparison");
    bundleSha256 = requireText(bundleSha256, "bundleSha256");
    if (bundleSizeBytes < 0L) {
      throw new IllegalArgumentException("bundleSizeBytes must be >= 0");
    }
    bundleType = requireText(bundleType, "bundleType");
    review = copyInOrder(review, "review");
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
   * Returns whether policy-driven apply may use this candidate without another operator decision.
   *
   * <p>Automatic apply is stricter than staging. The candidate must already be eligible by default
   * and the catalog review metadata must report {@code reviewed}. Caution, rejected, missing, or
   * malformed review states are not auto-applied; they remain visible to the operator through the
   * same candidate summary.
   *
   * @return {@code true} when the candidate is safely newer, compatible, and reviewed
   */
  public boolean eligibleForAutomaticApply() {
    return eligibleByDefault() && reviewAllowsAutomaticApply(review);
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
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put("appId", appId);
    json.put("catalogId", catalogId);
    json.put("catalogSourceId", catalogSourceId);
    json.put("installedVersion", installedVersion);
    json.put("targetVersion", targetVersion);
    json.put("status", status.jsonValue());
    json.put("versionComparison", versionComparison);
    json.put("bundle", bundleSummary());
    json.put("review", review);
    json.put("apiCompatibility", apiCompatibility);
    json.put("permissionDelta", permissionDelta);
    json.put("running", running);
    json.put("detectedAt", detectedAt.toString());
    json.put("autoStageAllowed", eligibleByDefault());
    json.put("autoApplyAllowed", eligibleForAutomaticApply());
    json.put("operatorActionRequired", operatorActionRequired());
    return json;
  }

  private boolean operatorActionRequired() {
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

  private static boolean reviewAllowsAutomaticApply(Map<String, Object> review) {
    Object statusValue = review.get("status");
    if (!(statusValue instanceof String status)) {
      return false;
    }
    return "reviewed".equals(status);
  }

  static Map<String, Object> reviewSummary(String status, String note) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("status", status);
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
}
