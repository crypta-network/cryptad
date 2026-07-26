package network.crypta.runtime.spi;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class CoreSupportLifecycleSnapshotTest {
  @Test
  void fromWireValue_whenVocabularyEnumerated_expectOnlyClosedValuesAccepted() {
    assertEquals(
        List.of(
            "current-stable",
            "supported-maintenance",
            "security-fixes-only",
            "deprecated",
            "end-of-support",
            "revoked"),
        java.util.Arrays.stream(CoreSupportLifecycleStatus.values())
            .map(CoreSupportLifecycleStatus::wireValue)
            .toList());
    assertFalse(CoreSupportLifecycleStatus.fromWireValue("supported").isPresent());
    assertFalse(CoreSupportLifecycleStatus.fromWireValue("REVOKED").isPresent());
  }

  @Test
  void toJsonValue_whenStateIsUnknown_expectNoInventedSupportOrUpgrade() {
    CoreSupportLifecycleSnapshot snapshot =
        CoreSupportLifecycleSnapshot.unknown(42, List.of("lifecycle_unknown"));

    Map<String, Object> json = snapshot.toJsonValue();

    assertEquals(false, json.get("known"));
    assertEquals(42, json.get("runningBuild"));
    assertNull(json.get("runningStatus"));
    assertEquals(false, json.get("upgradeAvailable"));
    assertNull(json.get("descriptorDigest"));
    assertEquals(List.of("lifecycle_unknown"), json.get("warnings"));
  }

  @Test
  void toJsonValue_whenRecoveryOnlyRevocation_expectSafeGuidanceWithoutReplacement() {
    CoreSupportLifecycleSnapshot snapshot =
        new CoreSupportLifecycleSnapshot(
            true,
            false,
            new CoreSupportLifecycleSnapshot.RunningBuild(
                42,
                CoreSupportLifecycleStatus.REVOKED,
                "2026-07-21T00:00:00Z",
                null,
                null,
                null,
                null,
                null,
                "Restore a verified backup and await an authenticated replacement.",
                List.of("CRYPTA-2026-001"),
                List.of("critical-release-defect")),
            new CoreSupportLifecycleSnapshot.Recommendation(null, null, false),
            new CoreSupportLifecycleSnapshot.DescriptorVerification(
                2L, "sha256:" + "a".repeat(64), "2026-07-21T00:05:00Z"),
            List.of("build_revoked"));

    Map<String, Object> json = snapshot.toJsonValue();

    assertNull(json.get("currentStableBuild"));
    assertNull(json.get("recommendedBuild"));
    assertNull(json.get("requiredReplacementBuild"));
    assertEquals(
        "Restore a verified backup and await an authenticated replacement.",
        json.get("recoveryGuidance"));
  }
}
