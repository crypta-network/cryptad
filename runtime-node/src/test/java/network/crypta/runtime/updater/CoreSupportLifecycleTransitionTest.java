package network.crypta.runtime.updater;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class CoreSupportLifecycleTransitionTest {
  private static final String SHA_256_PREFIX = "sha256:";
  private static final String IDENTITY_DIGEST =
      SHA_256_PREFIX + "b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7";
  private static final String SUPPORTED_MAINTENANCE = "supported-maintenance";
  private static final String END_OF_SUPPORT = "end-of-support";
  private static final String REVOKED = "revoked";
  private static final String JANUARY_2 = "2026-01-02T00:00:00Z";
  private static final String JANUARY_3 = "2026-01-03T00:00:00Z";
  private static final String ENTRIES_FIELD = "entries";
  private static final String LIFECYCLE_STATUS_FIELD = "lifecycleStatus";
  private static final String STATUS_EFFECTIVE_AT_FIELD = "statusEffectiveAt";
  private static final String SECURITY_REVOCATION_EFFECTIVE_AT_FIELD =
      "securityRevocationEffectiveAt";
  private static final String REPLACEMENT_BUILD_FIELD = "replacementBuild";
  private static final String RECOVERY_GUIDANCE_FIELD = "recoveryGuidance";
  private static final String ADVISORY_IDS_FIELD = "advisoryIds";
  private static final String REASON_CODES_FIELD = "reasonCodes";
  private static final String DESCRIPTOR_DIGEST_FIELD = "descriptorDigest";

  @Test
  void accept_whenProjectionJumpsForwardAcrossLedgerEvents_expectAccepted(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir);
    byte[] previous = descriptor(SUPPORTED_MAINTENANCE, 1, null);
    state.accept(previous, 1);
    String previousDigest =
        new CoreSupportLifecycleParser().parse(previous, 1, trust()).descriptorDigest();

    state.accept(descriptor(END_OF_SUPPORT, 2, previousDigest), 2);

    assertEquals(END_OF_SUPPORT, state.snapshot().running().status().wireValue());
  }

  @Test
  void accept_whenNormalProjectionMovesBackward_expectRejected(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir);
    byte[] previous = descriptor("deprecated", 1, null);
    state.accept(previous, 1);
    String previousDigest =
        new CoreSupportLifecycleParser().parse(previous, 1, trust()).descriptorDigest();
    byte[] candidate = descriptor(SUPPORTED_MAINTENANCE, 2, previousDigest);

    assertThrows(IllegalArgumentException.class, () -> state.accept(candidate, 2));
  }

  @Test
  void accept_whenRevokedProjectionAttemptsRecovery_expectTerminalRejection(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir);
    byte[] previous = descriptor(REVOKED, 1, null);
    state.accept(previous, 1);
    String previousDigest =
        new CoreSupportLifecycleParser().parse(previous, 1, trust()).descriptorDigest();
    byte[] candidate = descriptor(SUPPORTED_MAINTENANCE, 2, previousDigest);

    assertThrows(IllegalArgumentException.class, () -> state.accept(candidate, 2));
  }

  @Test
  void accept_whenFormerReplacementIsRecoveryOnlyRevoked_expectTerminalGuidanceAdvances(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir);
    byte[] previous = descriptor(REVOKED, 1, null);
    state.accept(previous, 1);
    String previousDigest =
        new CoreSupportLifecycleParser().parse(previous, 1, trust()).descriptorDigest();

    state.accept(recoveryOnlyTipRevocation(previous, previousDigest), 2);

    assertEquals(2, state.snapshot().descriptor().edition());
    assertNull(state.snapshot().running().requiredReplacementBuild());
    assertEquals(
        "Restore a verified package from offline recovery media.",
        state.snapshot().running().recoveryGuidance());
  }

  @Test
  void accept_whenSafeSuccessorFollowsRecoveryOnlyRevocation_expectGuidanceTargetsSuccessor(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir);
    byte[] previous = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(previous, 1);
    String previousDigest =
        new CoreSupportLifecycleParser().parse(previous, 1, trust()).descriptorDigest();

    state.accept(safeSuccessor(previous, previousDigest), 2);

    assertEquals(2, state.snapshot().descriptor().edition());
    assertEquals(200, state.snapshot().running().requiredReplacementBuild());
    assertNull(state.snapshot().running().recoveryGuidance());
    assertEquals(200, state.snapshot().recommendation().recommendedBuild());
  }

  private static CoreSupportLifecycleState state(Path tempDir) {
    return new CoreSupportLifecycleState(
        new CoreSupportLifecycleStore(tempDir.resolve("updates/core/lifecycle.json")),
        new CoreSupportLifecycleParser(),
        Clock.fixed(Instant.parse(JANUARY_3), ZoneOffset.UTC),
        100,
        "a".repeat(40),
        trust());
  }

  private static CoreSupportLifecycleParser.TrustBinding trust() {
    return new CoreSupportLifecycleParser.TrustBinding(
        IDENTITY_DIGEST, IDENTITY_DIGEST + "/support-lifecycle/0", "support-lifecycle");
  }

  private static byte[] descriptor(String oldBuildStatus, int edition, String previousDigest)
      throws Exception {
    Map<String, Object> root = JsonMini.parseObject(CoreSupportLifecycleParserTest.fixtureText());
    @SuppressWarnings("unchecked")
    List<Object> entries = (List<Object>) root.get(ENTRIES_FIELD);
    @SuppressWarnings("unchecked")
    Map<String, Object> oldBuild = (Map<String, Object>) entries.getFirst();
    applyStatus(oldBuild, oldBuildStatus, edition);

    Map<String, Object> currentBuild = new LinkedHashMap<>(oldBuild);
    currentBuild.put("releaseId", "stable-1.0-maintenance-v200");
    currentBuild.put("buildVersion", "200");
    currentBuild.put("tag", "v200");
    currentBuild.put("sourceCommit", "b".repeat(40));
    currentBuild.put("productDigest", SHA_256_PREFIX + "6".repeat(64));
    currentBuild.put("publicationReceiptDigest", SHA_256_PREFIX + "7".repeat(64));
    currentBuild.put("baselineDigest", SHA_256_PREFIX + "8".repeat(64));
    currentBuild.put(LIFECYCLE_STATUS_FIELD, "current-stable");
    currentBuild.put(STATUS_EFFECTIVE_AT_FIELD, JANUARY_2);
    currentBuild.put(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD, null);
    currentBuild.put(REPLACEMENT_BUILD_FIELD, null);
    currentBuild.put(RECOVERY_GUIDANCE_FIELD, null);
    currentBuild.put(ADVISORY_IDS_FIELD, new ArrayList<>());
    currentBuild.put(REASON_CODES_FIELD, new ArrayList<>());

    entries.add(currentBuild);
    root.put("currentStableBuild", "200");
    root.put("recommendedBuild", "200");
    root.put("minimumSupportedBuild", "100");
    root.put("minimumSecuritySupportedBuild", "100");
    root.put("descriptorEdition", (long) edition);
    root.put("previousDescriptorEdition", edition == 1 ? null : (long) edition - 1);
    root.put("previousDescriptorDigest", previousDigest);
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }

  private static void applyStatus(Map<String, Object> entry, String status, int edition) {
    entry.put(LIFECYCLE_STATUS_FIELD, status);
    entry.put(STATUS_EFFECTIVE_AT_FIELD, edition == 1 ? "2026-01-01T00:00:00Z" : JANUARY_2);
    boolean replacementRequired =
        "deprecated".equals(status) || END_OF_SUPPORT.equals(status) || REVOKED.equals(status);
    entry.put(REPLACEMENT_BUILD_FIELD, replacementRequired ? "200" : null);
    entry.put(RECOVERY_GUIDANCE_FIELD, null);
    if (REVOKED.equals(status)) {
      entry.put(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD, JANUARY_2);
      entry.put(ADVISORY_IDS_FIELD, new ArrayList<>(List.of("CRYPTA-2026-001")));
      entry.put(REASON_CODES_FIELD, new ArrayList<>(List.of("critical-release-defect")));
    } else {
      entry.put(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD, null);
      entry.put(ADVISORY_IDS_FIELD, new ArrayList<>());
      entry.put(REASON_CODES_FIELD, new ArrayList<>());
    }
  }

  private static byte[] recoveryOnlyTipRevocation(byte[] previous, String previousDigest) {
    Map<String, Object> root = JsonMini.parseObject(new String(previous, StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> entries = (List<Map<String, Object>>) root.get(ENTRIES_FIELD);
    String guidance = "Restore a verified package from offline recovery media.";
    Map<String, Object> oldRevoked = entries.getFirst();
    oldRevoked.put(REPLACEMENT_BUILD_FIELD, null);
    oldRevoked.put(RECOVERY_GUIDANCE_FIELD, guidance);
    Map<String, Object> revokedTip = entries.getLast();
    revokedTip.put(LIFECYCLE_STATUS_FIELD, REVOKED);
    revokedTip.put(STATUS_EFFECTIVE_AT_FIELD, JANUARY_3);
    revokedTip.put(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD, JANUARY_3);
    revokedTip.put(REPLACEMENT_BUILD_FIELD, null);
    revokedTip.put(RECOVERY_GUIDANCE_FIELD, guidance);
    revokedTip.put(ADVISORY_IDS_FIELD, new ArrayList<>(List.of("CRYPTA-2026-002")));
    revokedTip.put(REASON_CODES_FIELD, new ArrayList<>(List.of("unsafe-current-build")));
    setDescriptorSuccessor(root, previousDigest, null, null, null, null);
    return canonicalBytes(root);
  }

  private static byte[] safeSuccessor(byte[] previous, String previousDigest) {
    Map<String, Object> root = JsonMini.parseObject(new String(previous, StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> entries = (List<Map<String, Object>>) root.get(ENTRIES_FIELD);
    Map<String, Object> revoked = entries.getFirst();
    revoked.put(REPLACEMENT_BUILD_FIELD, "200");
    revoked.put(RECOVERY_GUIDANCE_FIELD, null);
    Map<String, Object> current = new LinkedHashMap<>(revoked);
    current.put("releaseId", "stable-1.0-maintenance-v200");
    current.put("buildVersion", "200");
    current.put("tag", "v200");
    current.put("sourceCommit", "b".repeat(40));
    current.put("productDigest", SHA_256_PREFIX + "6".repeat(64));
    current.put("publicationReceiptDigest", SHA_256_PREFIX + "7".repeat(64));
    current.put("baselineDigest", SHA_256_PREFIX + "8".repeat(64));
    current.put("publishedAt", JANUARY_3);
    current.put(LIFECYCLE_STATUS_FIELD, "current-stable");
    current.put(STATUS_EFFECTIVE_AT_FIELD, JANUARY_3);
    current.put(SECURITY_REVOCATION_EFFECTIVE_AT_FIELD, null);
    current.put(REPLACEMENT_BUILD_FIELD, null);
    current.put(RECOVERY_GUIDANCE_FIELD, null);
    current.put(ADVISORY_IDS_FIELD, new ArrayList<>());
    current.put(REASON_CODES_FIELD, new ArrayList<>());
    entries.add(current);
    setDescriptorSuccessor(root, previousDigest, "200", "200", "200", "200");
    return canonicalBytes(root);
  }

  private static void setDescriptorSuccessor(
      Map<String, Object> root,
      String previousDigest,
      String current,
      String recommended,
      String minimumSupported,
      String minimumSecuritySupported) {
    root.put("generatedAt", JANUARY_3);
    root.put("effectiveAt", JANUARY_3);
    root.put("staleAt", "2026-01-10T00:00:00Z");
    root.put("descriptorEdition", 2L);
    root.put("previousDescriptorEdition", 1L);
    root.put("previousDescriptorDigest", previousDigest);
    root.put("currentStableBuild", current);
    root.put("recommendedBuild", recommended);
    root.put("minimumSupportedBuild", minimumSupported);
    root.put("minimumSecuritySupportedBuild", minimumSecuritySupported);
  }

  private static byte[] canonicalBytes(Map<String, Object> root) {
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }
}
