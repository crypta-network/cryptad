package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class AppUpdateDigestSupportTest {
  private static final String SCOPE_ONE = "scope-one";
  private static final String TRUSTED = "trusted";
  private static final String STATUS_FIELD = "status";
  private static final String BLOCKS_UPDATE_FIELD = "blocksUpdate";
  private static final String SEMANTIC_POLICY_DIGEST = "a".repeat(64);
  private static final String REVIEW_FALLBACK_DIGEST =
      "989ec89ed3de9098a99fe41c592a9d520464d74e2d144a51ec1aaa85643ed4b3";
  private static final String SECURITY_DECISION_DIGEST =
      "ed8b71124d0265c6c2ba67c0afc8023d70be227f1eb82a8185db2ac8c3cca2b4";
  private static final String CANDIDATE_METADATA_DIGEST =
      "35d9853b42bb39a142e1aec06165bb6822144b530bfc92900255c2335922b8c5";

  @Test
  void reviewPolicyDigest_whenSemanticDigestIsValid_expectExistingDigest() {
    Map<String, Object> reviewTrust = reviewTrust(SCOPE_ONE, "b".repeat(64), TRUSTED);
    reviewTrust.put("reviewerPolicySemanticDigestSha256", SEMANTIC_POLICY_DIGEST);

    String digest = AppUpdateDigestSupport.reviewPolicyDigest(candidate(reviewTrust));

    assertEquals(SEMANTIC_POLICY_DIGEST, digest);
  }

  @Test
  void conflictDigests_whenOnlyScopeRecordIdentityChanges_expectEqualDigests() {
    AppUpdateCandidate first = candidate(reviewTrust(SCOPE_ONE, "b".repeat(64), TRUSTED));
    AppUpdateCandidate second = candidate(reviewTrust("scope-two", "c".repeat(64), TRUSTED));

    String firstPolicyDigest = AppUpdateDigestSupport.reviewPolicyDigest(first);
    String secondPolicyDigest = AppUpdateDigestSupport.reviewPolicyDigest(second);
    String firstMetadataDigest = AppUpdateDigestSupport.candidateMetadataDigest(first);
    String secondMetadataDigest = AppUpdateDigestSupport.candidateMetadataDigest(second);

    assertEquals(REVIEW_FALLBACK_DIGEST, firstPolicyDigest);
    assertEquals(firstPolicyDigest, secondPolicyDigest);
    assertEquals(CANDIDATE_METADATA_DIGEST, firstMetadataDigest);
    assertEquals(firstMetadataDigest, secondMetadataDigest);
  }

  @Test
  void conflictDigests_whenReviewPolicySemanticsChange_expectDifferentDigests() {
    AppUpdateCandidate trusted = candidate(reviewTrust(SCOPE_ONE, "b".repeat(64), TRUSTED));
    AppUpdateCandidate blocked = candidate(reviewTrust("scope-two", "c".repeat(64), "blocked"));

    String trustedPolicyDigest = AppUpdateDigestSupport.reviewPolicyDigest(trusted);
    String blockedPolicyDigest = AppUpdateDigestSupport.reviewPolicyDigest(blocked);
    String trustedMetadataDigest = AppUpdateDigestSupport.candidateMetadataDigest(trusted);
    String blockedMetadataDigest = AppUpdateDigestSupport.candidateMetadataDigest(blocked);

    assertNotEquals(trustedPolicyDigest, blockedPolicyDigest);
    assertNotEquals(trustedMetadataDigest, blockedMetadataDigest);
  }

  @Test
  void securityDecisionDigest_whenDecisionChanges_expectDifferentDigest() {
    Map<String, Object> allowed = new LinkedHashMap<>();
    allowed.put(STATUS_FIELD, "ok");
    allowed.put(BLOCKS_UPDATE_FIELD, false);
    Map<String, Object> blocked = new LinkedHashMap<>(allowed);
    blocked.put(BLOCKS_UPDATE_FIELD, true);

    String allowedDigest = AppUpdateDigestSupport.securityDecisionDigest(allowed);
    String blockedDigest = AppUpdateDigestSupport.securityDecisionDigest(blocked);

    assertEquals(SECURITY_DECISION_DIGEST, allowedDigest);
    assertNotEquals(allowedDigest, blockedDigest);
  }

  private static Map<String, Object> reviewTrust(
      String scopeId, String scopeDigest, String status) {
    Map<String, Object> reviewTrust = new LinkedHashMap<>();
    reviewTrust.put("reviewerScopeId", scopeId);
    reviewTrust.put("reviewerScopeDigestSha256", scopeDigest);
    reviewTrust.put(STATUS_FIELD, status);
    reviewTrust.put("reviewerPolicyMode", "scoped");
    return reviewTrust;
  }

  private static AppUpdateCandidate candidate(Map<String, Object> reviewTrust) {
    Map<String, Object> permissionDelta = new LinkedHashMap<>();
    permissionDelta.put("added", List.of());
    permissionDelta.put("removed", List.of());
    return new AppUpdateCandidate(
        "app-one",
        "catalog-one",
        "catalog-one",
        "1",
        "2",
        AppUpdateCandidateStatus.AVAILABLE,
        "newer",
        "stable",
        "supported",
        Map.of(STATUS_FIELD, "none"),
        List.of(Map.of("id", "ADV-1")),
        Map.of(STATUS_FIELD, "ok", BLOCKS_UPDATE_FIELD, false),
        true,
        null,
        "1".repeat(64),
        1L,
        "cryptad-app-bundle-v1",
        Map.of(STATUS_FIELD, "reviewed"),
        reviewTrust,
        Map.of(STATUS_FIELD, "compatible"),
        permissionDelta,
        Map.of(STATUS_FIELD, "not-required"),
        false,
        Instant.parse("2026-08-30T00:00:00Z"));
  }
}
