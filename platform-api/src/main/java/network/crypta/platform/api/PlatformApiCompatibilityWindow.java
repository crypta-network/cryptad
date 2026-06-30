package network.crypta.platform.api;

import java.util.Objects;

/**
 * Machine-readable policy for the active Platform API 1.0 stable compatibility window.
 *
 * <p>The window metadata is emitted in contract snapshots so developer tooling, release
 * certification, and third-party app authors can evaluate the stable support promise without
 * scraping prose. It describes the frozen baseline identity, minimum deprecation and removal
 * runway, stable-removal release blockers, experimental-to-stable graduation requirements, and the
 * previous-snapshot rule for production beta.
 *
 * <p>The record contains policy metadata only. It does not add routes to the Platform API 1.0
 * baseline, and it does not authorize experimental or operator-only capabilities for stable apps.
 *
 * @param schemaVersion compatibility-window metadata schema version
 * @param baselineName stable baseline name, currently {@code 1.0}
 * @param baselineContractVersion contract version whose descriptors define the stable baseline
 * @param currentContractVersion current Platform API compatibility contract version
 * @param supportPhase active support phase for this baseline
 * @param supportWindowStartedRelease release or milestone where the support window started
 * @param minimumDeprecationWindowContractVersions minimum contract-version distance from
 *     deprecation to scheduled-removal status for stable baseline members
 * @param minimumScheduledRemovalWindowContractVersions minimum future contract-version runway from
 *     the current snapshot to a scheduled stable removal
 * @param stableRemovalRequiresNewBaseline whether stable removals require a future baseline
 * @param stableRemovalRequiresPreviousSnapshot whether release checks must compare previous
 *     snapshots before allowing a stable removal decision
 * @param stableRemovalRequiresExplicitWaiver whether non-critical history gaps require a structured
 *     release-manager waiver
 * @param criticalStableRemovalWaiverAllowed whether critical stable removals may be waived
 * @param experimentalGraduationRequiresReview whether experimental-to-stable graduation requires
 *     explicit review evidence
 * @param experimentalGraduationRequiresStableReferenceUpdate whether graduation requires stable
 *     reference documentation updates
 * @param previousSnapshotRequiredInProductionBeta whether production beta fails closed without
 *     previous contract history
 * @param policyDocument repo-relative policy document path
 */
public record PlatformApiCompatibilityWindow(
    int schemaVersion,
    String baselineName,
    int baselineContractVersion,
    int currentContractVersion,
    PlatformApiCompatibilityWindowStatus supportPhase,
    String supportWindowStartedRelease,
    int minimumDeprecationWindowContractVersions,
    int minimumScheduledRemovalWindowContractVersions,
    boolean stableRemovalRequiresNewBaseline,
    boolean stableRemovalRequiresPreviousSnapshot,
    boolean stableRemovalRequiresExplicitWaiver,
    boolean criticalStableRemovalWaiverAllowed,
    boolean experimentalGraduationRequiresReview,
    boolean experimentalGraduationRequiresStableReferenceUpdate,
    boolean previousSnapshotRequiredInProductionBeta,
    String policyDocument) {
  /** Current metadata schema version. */
  public static final int CURRENT_SCHEMA_VERSION = 1;

  /** Release or milestone label where Platform API 1.0 beta support started. */
  public static final String SUPPORT_WINDOW_STARTED_RELEASE = "production-beta";

  /** Minimum contract-version runway from deprecation to scheduled-removal status. */
  public static final int MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS = 2;

  /** Minimum future contract-version runway from a current snapshot to stable removal. */
  public static final int MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS = 2;

  /** Repo-relative support-window policy document. */
  public static final String POLICY_DOCUMENT = "docs/platform-api-compatibility-support-window.md";

  /** Creates a validated policy record. */
  public PlatformApiCompatibilityWindow {
    if (schemaVersion <= 0) {
      throw new IllegalArgumentException("compatibilityWindow.schemaVersion must be positive");
    }
    baselineName = requireText(baselineName, "compatibilityWindow.baselineName");
    if (baselineContractVersion <= 0) {
      throw new IllegalArgumentException(
          "compatibilityWindow.baselineContractVersion must be positive");
    }
    if (currentContractVersion <= 0) {
      throw new IllegalArgumentException(
          "compatibilityWindow.currentContractVersion must be positive");
    }
    Objects.requireNonNull(supportPhase, "compatibilityWindow.supportPhase");
    supportWindowStartedRelease =
        requireText(supportWindowStartedRelease, "compatibilityWindow.supportWindowStartedRelease");
    requireNonNegative(
        minimumDeprecationWindowContractVersions,
        "compatibilityWindow.minimumDeprecationWindowContractVersions");
    requireNonNegative(
        minimumScheduledRemovalWindowContractVersions,
        "compatibilityWindow.minimumScheduledRemovalWindowContractVersions");
    policyDocument = requireText(policyDocument, "compatibilityWindow.policyDocument");
  }

  /**
   * Returns the current Platform API 1.0 beta compatibility-window policy.
   *
   * @return immutable current compatibility-window metadata
   */
  public static PlatformApiCompatibilityWindow current() {
    return current(PlatformApiContract.CURRENT_CONTRACT_VERSION);
  }

  /**
   * Returns the default Platform API 1.0 compatibility-window policy for a parsed contract version.
   *
   * <p>Older snapshots that lack explicit policy metadata remain parseable. Release tooling still
   * inspects the raw snapshot to decide whether missing policy metadata is acceptable for the
   * selected mode.
   *
   * @param currentContractVersion parsed contract version
   * @return compatibility-window metadata using current policy defaults
   */
  public static PlatformApiCompatibilityWindow current(int currentContractVersion) {
    return new PlatformApiCompatibilityWindow(
        CURRENT_SCHEMA_VERSION,
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME,
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        currentContractVersion,
        PlatformApiCompatibilityWindowStatus.BETA,
        SUPPORT_WINDOW_STARTED_RELEASE,
        MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS,
        MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        POLICY_DOCUMENT);
  }

  private static void requireNonNegative(int value, String fieldName) {
    if (value < 0) {
      throw new IllegalArgumentException(fieldName + " must not be negative");
    }
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
