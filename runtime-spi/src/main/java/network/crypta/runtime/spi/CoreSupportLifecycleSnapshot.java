package network.crypta.runtime.spi;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Public-safe local view of the running core build's Stable 1.0 support lifecycle.
 *
 * <p>The snapshot is detached from updater implementation classes and contains only bounded public
 * release metadata. It deliberately excludes raw descriptor bytes, update URIs, signing material,
 * filesystem paths, fetch errors, and update-key revocation state. Platform API, Web Shell, and
 * support-bundle code can therefore expose the same view without reaching into daemon internals.
 *
 * <p>{@code known=false} means no descriptor has passed validation for the configured update-key
 * scope. {@code stale=true} means a previously valid last-known-good descriptor has passed its
 * policy-derived {@code staleAt} timestamp; stale state must not be presented as current support.
 *
 * @param known whether a descriptor and running-build entry are locally verified
 * @param stale whether the last-known-good descriptor is past its authenticated stale deadline
 * @param running running-build support details, including deadlines and advisory identifiers
 * @param recommendation current and recommended build guidance derived from the descriptor
 * @param descriptor public digest and edition of the last descriptor verified locally
 * @param warnings bounded machine-readable warnings suitable for local operator surfaces
 */
public record CoreSupportLifecycleSnapshot(
    boolean known,
    boolean stale,
    RunningBuild running,
    Recommendation recommendation,
    DescriptorVerification descriptor,
    List<String> warnings) {

  /** Creates an immutable, null-safe detached lifecycle snapshot. */
  public CoreSupportLifecycleSnapshot {
    running = running == null ? RunningBuild.unknown(-1) : running;
    recommendation = recommendation == null ? Recommendation.unknown() : recommendation;
    descriptor = descriptor == null ? DescriptorVerification.unknown() : descriptor;
    warnings = warnings == null ? List.of() : List.copyOf(warnings);
  }

  /**
   * Creates the fail-closed state used before any lifecycle descriptor is accepted.
   *
   * @param runningBuild integer build currently running, or {@code -1} when unavailable
   * @param warnings bounded reason codes explaining why lifecycle state is unknown
   * @return immutable unknown lifecycle snapshot with no invented support status
   */
  public static CoreSupportLifecycleSnapshot unknown(int runningBuild, List<String> warnings) {
    return new CoreSupportLifecycleSnapshot(
        false,
        false,
        RunningBuild.unknown(runningBuild),
        Recommendation.unknown(),
        DescriptorVerification.unknown(),
        warnings);
  }

  /**
   * Projects the detached model into the flat, stable JSON shape used by local operator surfaces.
   *
   * <p>Nullable dates and descriptor fields remain JSON {@code null}; the projection never fills an
   * unknown deadline with a misleading default. The returned map is newly allocated and may be
   * safely extended by a transport layer.
   *
   * @return ordered JSON-compatible map containing only public-safe lifecycle fields
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(23);
    json.put("known", known);
    json.put("stale", stale);
    json.put("runningBuild", running.build());
    json.put("runningStatus", running.status() == null ? null : running.status().wireValue());
    json.put("statusEffectiveAt", running.statusEffectiveAt());
    json.put("fullSupportUntil", running.fullSupportUntil());
    json.put("securityFixesUntil", running.securityFixesUntil());
    json.put("deprecationEffectiveAt", running.deprecationEffectiveAt());
    json.put("endOfSupportAt", running.endOfSupportAt());
    json.put("currentStableBuild", recommendation.currentStableBuild());
    json.put("recommendedBuild", recommendation.recommendedBuild());
    json.put("requiredReplacementBuild", running.requiredReplacementBuild());
    json.put("recoveryGuidance", running.recoveryGuidance());
    json.put("upgradeAvailable", recommendation.upgradeAvailable());
    json.put("advisoryIds", running.advisoryIds());
    json.put("reasonCodes", running.reasonCodes());
    json.put("descriptorEdition", descriptor.edition());
    json.put("descriptorDigest", descriptor.digest());
    json.put("lastVerifiedAt", descriptor.lastVerifiedAt());
    json.put("warnings", warnings);
    return json;
  }

  /**
   * Support metadata for the exact integer build running on the local node.
   *
   * @param build running integer build, or {@code -1} when unavailable
   * @param status closed lifecycle status, or {@code null} when unknown
   * @param statusEffectiveAt canonical UTC timestamp at which the status became effective
   * @param fullSupportUntil canonical UTC full-maintenance deadline, when defined
   * @param securityFixesUntil canonical UTC security-fix deadline, when defined
   * @param deprecationEffectiveAt canonical UTC deprecation-notice effective timestamp
   * @param endOfSupportAt canonical UTC end-of-support timestamp, when defined
   * @param requiredReplacementBuild authenticated safe replacement build, when required
   * @param recoveryGuidance bounded authenticated recovery guidance when no safe build replacement
   *     exists
   * @param advisoryIds sorted public advisory or incident identifiers
   * @param reasonCodes sorted public lifecycle reason codes
   */
  public record RunningBuild(
      int build,
      CoreSupportLifecycleStatus status,
      String statusEffectiveAt,
      String fullSupportUntil,
      String securityFixesUntil,
      String deprecationEffectiveAt,
      String endOfSupportAt,
      Integer requiredReplacementBuild,
      String recoveryGuidance,
      List<String> advisoryIds,
      List<String> reasonCodes) {

    /** Defensively copies the two bounded metadata lists. */
    public RunningBuild {
      advisoryIds = advisoryIds == null ? List.of() : List.copyOf(advisoryIds);
      reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
    }

    /**
     * Creates a running-build projection with no claimed lifecycle state.
     *
     * @param runningBuild integer build currently running, or {@code -1} when unavailable
     * @return projection containing the build identity and null lifecycle metadata
     */
    public static RunningBuild unknown(int runningBuild) {
      return new RunningBuild(
          runningBuild, null, null, null, null, null, null, null, null, List.of(), List.of());
    }
  }

  /**
   * Authenticated upgrade guidance from the accepted descriptor.
   *
   * @param currentStableBuild single chain-tip build marked current stable, or {@code null} during
   *     an authenticated emergency tip revocation
   * @param recommendedBuild authenticated recommended replacement or current build, or {@code null}
   *     when only recovery guidance is available
   * @param upgradeAvailable whether the recommended build is newer than the running build
   */
  public record Recommendation(
      Integer currentStableBuild, Integer recommendedBuild, boolean upgradeAvailable) {
    private static Recommendation unknown() {
      return new Recommendation(null, null, false);
    }
  }

  /**
   * Public identity of the locally accepted lifecycle descriptor.
   *
   * @param edition monotonic descriptor edition, or {@code null} before first acceptance
   * @param digest semantic SHA-256 of the descriptor excluding its {@code descriptorDigest} field,
   *     or {@code null} when unknown
   * @param lastVerifiedAt canonical UTC time at which local validation most recently succeeded
   */
  public record DescriptorVerification(Long edition, String digest, String lastVerifiedAt) {
    private static DescriptorVerification unknown() {
      return new DescriptorVerification(null, null, null);
    }
  }
}
