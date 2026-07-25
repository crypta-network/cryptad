package network.crypta.runtime.updater;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class CoreSupportLifecycleParserTest {
  private static final String IDENTITY_DIGEST =
      "sha256:b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7";
  private static final String SCOPE = IDENTITY_DIGEST + "/support-lifecycle/0";
  private static final String SEMANTIC_DIGEST =
      "sha256:9ee26a76598bf0a9a3a9f4b5aaf1b6583f0a4229fffc044e262905404cd554da";
  private static final String SHA256_PREFIX = "sha256:";
  private static final String CURRENT_STABLE = "current-stable";
  private static final String RECOVERY_GUIDANCE =
      "Restore from a verified backup and wait for an authenticated replacement.";
  private static final String REVOCATION_EFFECTIVE_AT = "2026-01-02T00:00:00Z";
  private static final String ENTRIES_FIELD = "entries";
  private static final String RELEASE_ID_FIELD = "releaseId";
  private static final String DESCRIPTOR_DIGEST_FIELD = "descriptorDigest";
  private static final String LIFECYCLE_STATUS_FIELD = "lifecycleStatus";
  private static final String STATUS_EFFECTIVE_AT_FIELD = "statusEffectiveAt";
  private static final String CURRENT_STABLE_BUILD_FIELD = "currentStableBuild";
  private static final String MINIMUM_SUPPORTED_BUILD_FIELD = "minimumSupportedBuild";
  private static final String MINIMUM_SECURITY_SUPPORTED_BUILD_FIELD =
      "minimumSecuritySupportedBuild";
  private static final String RECOMMENDED_BUILD_FIELD = "recommendedBuild";
  private static final String REPLACEMENT_BUILD_FIELD = "replacementBuild";
  private static final String RECOVERY_GUIDANCE_FIELD = "recoveryGuidance";

  private final CoreSupportLifecycleParser parser = new CoreSupportLifecycleParser();

  @Test
  void parse_whenCertificationFixtureIsValid_expectExactRuntimeProjection() throws IOException {
    byte[] bytes = fixtureBytes();

    CoreSupportLifecycleDescriptor descriptor = parser.parse(bytes, 1, trust());

    assertEquals(1, descriptor.schemaVersion());
    assertEquals(1, descriptor.descriptorEdition());
    assertEquals(100, descriptor.currentStableBuild());
    assertEquals(SEMANTIC_DIGEST, descriptor.descriptorDigest());
    assertEquals(CoreSupportLifecycleParser.exactBytesDigest(bytes), descriptor.exactBytesDigest());
    assertEquals(CURRENT_STABLE, descriptor.entries().getFirst().lifecycleStatus().wireValue());
  }

  @Test
  void parse_whenDescriptorHasUnknownField_expectClosedSchemaRejection() throws IOException {
    byte[] fixture =
        fixtureText()
            .replaceFirst("\\{", "{\n  \"unexpected\": true,")
            .getBytes(StandardCharsets.UTF_8);

    assertDescriptorRejected(fixture);
  }

  @Test
  void parse_whenLifecycleStatusIsUnknown_expectRejection() throws IOException {
    byte[] fixture =
        fixtureText()
            .replace(CURRENT_STABLE, "future-supported-state")
            .getBytes(StandardCharsets.UTF_8);

    assertDescriptorRejected(fixture);
  }

  @Test
  void parse_whenEntryStatusFollowsDescriptorActivation_expectRejection() throws IOException {
    byte[] fixture = descriptorWithFutureEffectiveStatus();

    assertDescriptorRejected(fixture);
  }

  @Test
  void parse_whenFetchedEditionDiffers_expectRollbackRejection() throws IOException {
    byte[] fixture = fixtureBytes();
    CoreSupportLifecycleParser.TrustBinding binding = trust();

    assertThrows(IllegalArgumentException.class, () -> parser.parse(fixture, 2, binding));
  }

  @Test
  void parse_whenConfiguredScopeDiffers_expectAuthorityConfusionRejection() throws IOException {
    CoreSupportLifecycleParser.TrustBinding otherTrust =
        new CoreSupportLifecycleParser.TrustBinding(
            SHA256_PREFIX + "0".repeat(64),
            SHA256_PREFIX + "0".repeat(64) + "/support-lifecycle/0",
            "support-lifecycle");
    byte[] fixture = fixtureBytes();

    assertThrows(IllegalArgumentException.class, () -> parser.parse(fixture, 1, otherTrust));
  }

  @Test
  void parse_whenSemanticDigestIsAltered_expectIntegrityRejection() throws IOException {
    byte[] fixture =
        fixtureText()
            .replace(SEMANTIC_DIGEST, SHA256_PREFIX + "f".repeat(64))
            .getBytes(StandardCharsets.UTF_8);

    assertDescriptorRejected(fixture);
  }

  @Test
  void parse_whenReleaseIdCrossesProducerBound_expectExactRuntimeLimit() throws IOException {
    byte[] maximum = descriptorWithReleaseId("r".repeat(128));
    byte[] oversized = descriptorWithReleaseId("r".repeat(129));

    assertEquals(128, parser.parse(maximum, 1, trust()).entries().getFirst().releaseId().length());
    assertDescriptorRejected(oversized);
  }

  @Test
  void parse_whenEntryCountCrossesPolicyBound_expectExactRuntimeLimit() throws IOException {
    byte[] maximum = descriptorWithEntryCount(256);
    byte[] oversized = descriptorWithEntryCount(257);

    assertEquals(256, parser.parse(maximum, 1, trust()).entries().size());
    assertDescriptorRejected(oversized);
  }

  @Test
  void parse_whenCurrentTipHasRecoveryOnlyRevocation_expectNoSafeBuildInvented()
      throws IOException {
    byte[] descriptorBytes = emergencyRevocationDescriptor(false, true);

    CoreSupportLifecycleDescriptor descriptor = parser.parse(descriptorBytes, 1, trust());

    assertNull(descriptor.currentStableBuild());
    assertNull(descriptor.recommendedBuild());
    assertNull(descriptor.entries().getFirst().replacementBuild());
    assertEquals(RECOVERY_GUIDANCE, descriptor.entries().getFirst().recoveryGuidance());
  }

  @Test
  void parse_whenOlderBuildUsesTipRecoveryGuidance_expectNoRevokedReplacement() throws IOException {
    byte[] descriptorBytes = multiBuildEmergencyRevocationDescriptor(false);

    CoreSupportLifecycleDescriptor descriptor = parser.parse(descriptorBytes, 1, trust());

    assertNull(descriptor.recommendedBuild());
    assertNull(descriptor.entries().getFirst().replacementBuild());
    assertEquals(
        descriptor.entries().getLast().recoveryGuidance(),
        descriptor.entries().getFirst().recoveryGuidance());
  }

  @Test
  void parse_whenOlderBuildPointsAtRevokedTip_expectUnsafeReplacementRejected() throws IOException {
    byte[] descriptorBytes = multiBuildEmergencyRevocationDescriptor(true);

    assertDescriptorRejected(descriptorBytes);
  }

  @Test
  void parse_whenRevokedTipStillClaimsCurrentStable_expectEmergencyCardinalityRejection()
      throws IOException {
    byte[] descriptorBytes = emergencyRevocationDescriptor(true, true);

    assertDescriptorRejected(descriptorBytes);
  }

  @Test
  void parse_whenRevokedTipHasNeitherReplacementNorRecovery_expectGuidanceRejection()
      throws IOException {
    byte[] descriptorBytes = emergencyRevocationDescriptor(false, false);

    assertDescriptorRejected(descriptorBytes);
  }

  @Test
  void parse_whenRevocationSecurityTimestampDiffersFromStatusTimestamp_expectRejection()
      throws IOException {
    byte[] descriptorBytes = emergencyRevocationDescriptorWithMismatchedSecurityTimestamp();

    assertDescriptorRejected(descriptorBytes);
  }

  @Test
  void parse_whenRecoveryGuidanceCrossesUtf16Bound_expectExactRuntimeLimit() throws IOException {
    byte[] maximum = emergencyRevocationDescriptor(false, "x".repeat(256));
    byte[] oversized = emergencyRevocationDescriptor(false, "x".repeat(257));

    assertEquals(
        256, parser.parse(maximum, 1, trust()).entries().getFirst().recoveryGuidance().length());
    assertDescriptorRejected(oversized);
  }

  @Test
  void parse_whenRecoveryGuidanceContainsSurrogateUnits_expectRejection() throws IOException {
    byte[] supplementaryEmoji = emergencyRevocationDescriptor(false, "Use shield \uD83D\uDEE1");
    byte[] isolatedSurrogate = emergencyRevocationDescriptor(false, "Unsafe \uD800 text");

    assertAll(
        () -> assertDescriptorRejected(supplementaryEmoji),
        () -> assertDescriptorRejected(isolatedSurrogate));
  }

  @Test
  void parse_whenRecoveryGuidanceContainsFormatOrIsoControl_expectRejection() throws IOException {
    byte[] unicodeFormat = emergencyRevocationDescriptor(false, "Recover\u200E safely");
    byte[] c0Control = emergencyRevocationDescriptor(false, "Unsafe\ntext");
    byte[] c1Control = emergencyRevocationDescriptor(false, "Unsafe\u0085text");

    assertAll(
        () -> assertDescriptorRejected(unicodeFormat),
        () -> assertDescriptorRejected(c0Control),
        () -> assertDescriptorRejected(c1Control));
  }

  private static CoreSupportLifecycleParser.TrustBinding trust() {
    return new CoreSupportLifecycleParser.TrustBinding(IDENTITY_DIGEST, SCOPE, "support-lifecycle");
  }

  private void assertDescriptorRejected(byte[] descriptorBytes) {
    CoreSupportLifecycleParser.TrustBinding binding = trust();
    assertThrows(IllegalArgumentException.class, () -> parser.parse(descriptorBytes, 1, binding));
  }

  static byte[] fixtureBytes() throws IOException {
    return Files.readAllBytes(fixturePath());
  }

  static String fixtureText() throws IOException {
    return Files.readString(fixturePath(), StandardCharsets.UTF_8);
  }

  private static byte[] descriptorWithReleaseId(String releaseId) throws IOException {
    Map<String, Object> descriptor = JsonMini.parseObject(fixtureText());
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    entry.put(RELEASE_ID_FIELD, releaseId);
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] descriptorWithFutureEffectiveStatus() throws IOException {
    Map<String, Object> descriptor = JsonMini.parseObject(fixtureText());
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    entry.put(STATUS_EFFECTIVE_AT_FIELD, REVOCATION_EFFECTIVE_AT);
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] descriptorWithEntryCount(int entryCount) throws IOException {
    Map<String, Object> descriptor = JsonMini.parseObject(fixtureText());
    @SuppressWarnings("unchecked")
    Map<String, Object> template =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    List<Map<String, Object>> entries = new ArrayList<>(entryCount);
    for (int build = 1; build <= entryCount; build++) {
      Map<String, Object> entry = new LinkedHashMap<>(template);
      entry.put(RELEASE_ID_FIELD, "stable-1.0-build-" + build);
      entry.put("buildVersion", Integer.toString(build));
      entry.put("tag", "v" + build);
      entry.put(
          LIFECYCLE_STATUS_FIELD, build == entryCount ? CURRENT_STABLE : "supported-maintenance");
      entries.add(entry);
    }
    descriptor.put(ENTRIES_FIELD, entries);
    descriptor.put(CURRENT_STABLE_BUILD_FIELD, Integer.toString(entryCount));
    descriptor.put(MINIMUM_SUPPORTED_BUILD_FIELD, "1");
    descriptor.put(MINIMUM_SECURITY_SUPPORTED_BUILD_FIELD, "1");
    descriptor.put(RECOMMENDED_BUILD_FIELD, Integer.toString(entryCount));
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  static byte[] emergencyRevocationDescriptor(boolean claimCurrent, boolean includeGuidance)
      throws IOException {
    return emergencyRevocationDescriptor(claimCurrent, includeGuidance ? RECOVERY_GUIDANCE : null);
  }

  private static byte[] emergencyRevocationDescriptor(boolean claimCurrent, String guidance)
      throws IOException {
    Map<String, Object> descriptor = JsonMini.parseObject(fixtureText());
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    entry.put(LIFECYCLE_STATUS_FIELD, "revoked");
    entry.put(STATUS_EFFECTIVE_AT_FIELD, REVOCATION_EFFECTIVE_AT);
    entry.put("securityRevocationEffectiveAt", REVOCATION_EFFECTIVE_AT);
    entry.put(REPLACEMENT_BUILD_FIELD, null);
    entry.put(RECOVERY_GUIDANCE_FIELD, guidance);
    entry.put("advisoryIds", List.of("CRYPTA-2026-001"));
    entry.put("reasonCodes", List.of("critical-release-defect"));
    descriptor.put("effectiveAt", REVOCATION_EFFECTIVE_AT);
    descriptor.put(CURRENT_STABLE_BUILD_FIELD, claimCurrent ? "100" : null);
    descriptor.put(RECOMMENDED_BUILD_FIELD, claimCurrent ? "100" : null);
    descriptor.put(MINIMUM_SUPPORTED_BUILD_FIELD, null);
    descriptor.put(MINIMUM_SECURITY_SUPPORTED_BUILD_FIELD, null);
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    String canonical = CoreSupportLifecycleParser.canonicalJson(descriptor);
    if (guidance != null) {
      for (int index = 0; index < guidance.length(); index++) {
        char character = guidance.charAt(index);
        boolean pairedWithPrevious =
            Character.isLowSurrogate(character)
                && index > 0
                && Character.isSurrogatePair(guidance.charAt(index - 1), character);
        boolean pairedWithNext =
            Character.isHighSurrogate(character)
                && index + 1 < guidance.length()
                && Character.isSurrogatePair(character, guidance.charAt(index + 1));
        if (Character.isSurrogate(character) && !pairedWithPrevious && !pairedWithNext) {
          canonical =
              canonical.replace(
                  String.valueOf(character), String.format("\\u%04x", (int) character));
        }
      }
    }
    return canonical.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] multiBuildEmergencyRevocationDescriptor(boolean pointAtRevokedTip)
      throws IOException {
    Map<String, Object> descriptor = JsonMini.parseObject(fixtureText());
    @SuppressWarnings("unchecked")
    Map<String, Object> template =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    String guidance = RECOVERY_GUIDANCE;
    Map<String, Object> older = new LinkedHashMap<>(template);
    older.put(RELEASE_ID_FIELD, "stable-1.0-maintenance-v99");
    older.put("buildVersion", "99");
    older.put("tag", "v99");
    older.put(LIFECYCLE_STATUS_FIELD, "supported-maintenance");
    older.put(REPLACEMENT_BUILD_FIELD, pointAtRevokedTip ? "100" : null);
    older.put(RECOVERY_GUIDANCE_FIELD, pointAtRevokedTip ? null : guidance);

    Map<String, Object> tip = new LinkedHashMap<>(template);
    tip.put(LIFECYCLE_STATUS_FIELD, "revoked");
    tip.put(STATUS_EFFECTIVE_AT_FIELD, REVOCATION_EFFECTIVE_AT);
    tip.put("securityRevocationEffectiveAt", REVOCATION_EFFECTIVE_AT);
    tip.put(REPLACEMENT_BUILD_FIELD, null);
    tip.put(RECOVERY_GUIDANCE_FIELD, guidance);
    tip.put("advisoryIds", List.of("CRYPTA-2026-001"));
    tip.put("reasonCodes", List.of("critical-release-defect"));

    descriptor.put("effectiveAt", REVOCATION_EFFECTIVE_AT);
    descriptor.put(ENTRIES_FIELD, List.of(older, tip));
    descriptor.put(CURRENT_STABLE_BUILD_FIELD, null);
    descriptor.put(RECOMMENDED_BUILD_FIELD, null);
    descriptor.put(MINIMUM_SUPPORTED_BUILD_FIELD, "99");
    descriptor.put(MINIMUM_SECURITY_SUPPORTED_BUILD_FIELD, "99");
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] emergencyRevocationDescriptorWithMismatchedSecurityTimestamp()
      throws IOException {
    Map<String, Object> descriptor =
        JsonMini.parseObject(
            new String(
                emergencyRevocationDescriptor(false, RECOVERY_GUIDANCE), StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) descriptor.get(ENTRIES_FIELD)).getFirst();
    entry.put("securityRevocationEffectiveAt", "2026-01-01T23:59:59Z");
    descriptor.remove(DESCRIPTOR_DIGEST_FIELD);
    descriptor.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  private static Path fixturePath() {
    Path directory = Path.of("").toAbsolutePath();
    while (directory != null && !Files.exists(directory.resolve("settings.gradle.kts"))) {
      directory = directory.getParent();
    }
    if (directory == null) {
      throw new IllegalStateException("repository root is unavailable");
    }
    return directory.resolve(
        "tools/release-certification/fixtures/stable-lifecycle/runtime-descriptor-v1.json");
  }
}
