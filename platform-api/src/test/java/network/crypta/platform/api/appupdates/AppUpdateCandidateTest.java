package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings({"java:S100"})
class AppUpdateCandidateTest {
  @Test
  void toJsonValue_whenPermissionIsAdded_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(Map.of("added", List.of("content.fetch"), "removed", List.of()));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("new_permission"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenStableNoPermissionDelta_expectAutomaticUpdateAllowed() {
    AppUpdateCandidate candidate =
        candidate(Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(true, json.get("autoStageAllowed"));
    assertEquals(true, json.get("autoApplyAllowed"));
    assertEquals(false, json.get("blocksAutoUpdate"));
    assertEquals(List.of(), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenNoUpdateCandidate_expectNoAutoUpdateBlock() {
    AppUpdateCandidate candidate = candidateWithStatus(AppUpdateCandidateStatus.NONE);

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(false, json.get("blocksAutoUpdate"));
    assertEquals(false, json.get("operatorActionRequired"));
    assertEquals(List.of(), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenNotNewerCandidate_expectNoAutoUpdateBlock() {
    AppUpdateCandidate candidate = candidateWithStatus(AppUpdateCandidateStatus.NOT_NEWER);

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(false, json.get("blocksAutoUpdate"));
    assertEquals(false, json.get("operatorActionRequired"));
    assertEquals(List.of(), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenBetaChannelPolicyAllowed_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate = candidateWithCatalogMetadata("beta", "supported");

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(
        List.of("catalog_support_or_deprecation_change"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenMaintenanceSupportStatus_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate = candidateWithCatalogMetadata("stable", "maintenance");

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(
        List.of("catalog_support_or_deprecation_change"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenReviewTrustIsNotPositive_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(),
            Map.of("required", false),
            Map.of(
                "status",
                "trusted_caution",
                "positive",
                false,
                "requiresAcknowledgement",
                false,
                "blocksUpdate",
                false,
                "blocksPolicyApply",
                false));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("review_trust_delta"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenReviewTrustRequiresAcknowledgement_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(),
            Map.of("required", false),
            Map.of(
                "status",
                "trusted_caution",
                "positive",
                true,
                "requiresAcknowledgement",
                true,
                "blocksUpdate",
                false,
                "blocksPolicyApply",
                false));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("review_trust_delta"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenReviewTrustBlocksUpdate_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(),
            Map.of("required", false),
            Map.of(
                "status",
                "revoked",
                "positive",
                true,
                "requiresAcknowledgement",
                false,
                "blocksUpdate",
                true,
                "blocksPolicyApply",
                false));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("review_trust_delta"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenReviewTrustBlocksPolicyApply_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(),
            Map.of("required", false),
            Map.of(
                "status",
                "trusted",
                "positive",
                true,
                "requiresAcknowledgement",
                false,
                "blocksUpdate",
                false,
                "blocksPolicyApply",
                true));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("review_trust_delta"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenApiCompatibilityStatusUnknown_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()), "unknown");

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("platform_api_stability_change"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenApiTargetStabilityMissing_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidateWithApiCompatibility(
            Map.of(
                "status",
                "compatible",
                "targetStability",
                "experimental",
                "targetStabilityDeclared",
                false,
                "declared",
                true,
                "experimentalCapabilitiesAccepted",
                false));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(false, json.get("autoApplyAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("platform_api_stability_change"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenSecurityAdvisoryPresent_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(Map.of("id", "ADV-1", "uri", "crypta:CHK@example/advisory")));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("security_advisory"), json.get("materialConsentReasons"));
  }

  @Test
  void toJsonValue_whenMigrationRequiresOperatorReview_expectAutomaticUpdateBlockedByConsent() {
    AppUpdateCandidate candidate =
        candidate(
            Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
            "compatible",
            List.of(),
            Map.of("required", true, "operatorReviewRequired", true));

    Map<String, Object> json = candidate.toJsonValue();

    assertEquals(false, json.get("autoStageAllowed"));
    assertEquals(true, json.get("blocksAutoUpdate"));
    assertEquals(true, json.get("operatorActionRequired"));
    assertEquals(List.of("app_data_migration"), json.get("materialConsentReasons"));
  }

  private static AppUpdateCandidate candidate(Map<String, Object> permissionDelta) {
    return candidate(permissionDelta, "compatible");
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta, String apiCompatibilityStatus) {
    return candidate(permissionDelta, apiCompatibilityStatus, List.of());
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      String apiCompatibilityStatus,
      List<Map<String, Object>> securityAdvisories) {
    return candidate(
        permissionDelta, apiCompatibilityStatus, securityAdvisories, Map.of("required", false));
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      String apiCompatibilityStatus,
      List<Map<String, Object>> securityAdvisories,
      Map<String, Object> dataMigration) {
    return candidate(
        permissionDelta,
        apiCompatibilityStatus,
        securityAdvisories,
        dataMigration,
        Map.of("status", "trusted", "positive", true));
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      String apiCompatibilityStatus,
      List<Map<String, Object>> securityAdvisories,
      Map<String, Object> dataMigration,
      Map<String, Object> reviewTrust) {
    return candidate(
        permissionDelta,
        apiCompatibilityStatus,
        securityAdvisories,
        dataMigration,
        reviewTrust,
        "stable",
        "supported");
  }

  private static AppUpdateCandidate candidateWithCatalogMetadata(
      String channel, String supportStatus) {
    return candidate(
        Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
        "compatible",
        List.of(),
        Map.of("required", false),
        Map.of("status", "trusted", "positive", true),
        channel,
        supportStatus);
  }

  private static AppUpdateCandidate candidateWithApiCompatibility(
      Map<String, Object> apiCompatibility) {
    return candidate(
        Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
        List.of(),
        Map.of("required", false),
        Map.of("status", "trusted", "positive", true),
        "stable",
        "supported",
        apiCompatibility);
  }

  private static AppUpdateCandidate candidateWithStatus(AppUpdateCandidateStatus status) {
    String versionComparison =
        switch (status) {
          case NOT_NEWER -> "lower";
          case NONE -> "equal";
          default -> "newer";
        };
    return candidate(
        Map.of("added", List.of(), "removed", List.of(), "unchanged", List.of()),
        List.of(),
        Map.of("required", false),
        Map.of("status", "trusted", "positive", true),
        "stable",
        "supported",
        apiCompatibility("compatible"),
        status,
        versionComparison);
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      String apiCompatibilityStatus,
      List<Map<String, Object>> securityAdvisories,
      Map<String, Object> dataMigration,
      Map<String, Object> reviewTrust,
      String channel,
      String supportStatus) {
    return candidate(
        permissionDelta,
        securityAdvisories,
        dataMigration,
        reviewTrust,
        channel,
        supportStatus,
        apiCompatibility(apiCompatibilityStatus));
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      List<Map<String, Object>> securityAdvisories,
      Map<String, Object> dataMigration,
      Map<String, Object> reviewTrust,
      String channel,
      String supportStatus,
      Map<String, Object> apiCompatibility) {
    return candidate(
        permissionDelta,
        securityAdvisories,
        dataMigration,
        reviewTrust,
        channel,
        supportStatus,
        apiCompatibility,
        AppUpdateCandidateStatus.AVAILABLE,
        "newer");
  }

  private static AppUpdateCandidate candidate(
      Map<String, Object> permissionDelta,
      List<Map<String, Object>> securityAdvisories,
      Map<String, Object> dataMigration,
      Map<String, Object> reviewTrust,
      String channel,
      String supportStatus,
      Map<String, Object> apiCompatibility,
      AppUpdateCandidateStatus status,
      String versionComparison) {
    return new AppUpdateCandidate(
        "example.app",
        "first-party",
        "first-party",
        "1.0.0",
        "1.1.0",
        status,
        versionComparison,
        channel,
        supportStatus,
        Map.of("status", "none"),
        securityAdvisories,
        Map.of("status", "ok", "requiresAcknowledgement", false, "blocksUpdate", false),
        true,
        null,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        1024,
        "zip",
        Map.of("status", "reviewed"),
        reviewTrust,
        apiCompatibility,
        permissionDelta,
        dataMigration,
        false,
        Instant.parse("2026-05-01T00:00:00Z"));
  }

  private static Map<String, Object> apiCompatibility(String status) {
    return Map.of(
        "status",
        status,
        "targetStability",
        "stable",
        "targetStabilityDeclared",
        true,
        "declared",
        true,
        "experimentalCapabilitiesAccepted",
        false);
  }
}
