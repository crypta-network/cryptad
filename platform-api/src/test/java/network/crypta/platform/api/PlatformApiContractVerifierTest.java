package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFindingSeverity;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityVerificationResult;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiContractVerifierTest {
  @Test
  void summarize_whenMetadataIsMissing_expectUnknownCompatibilityStatus() {
    Map<String, Object> summary =
        PlatformApiContractVerifier.summarize(
            null, List.of("queue.read"), PlatformApiContract.current());

    assertEquals("unknown", summary.get("status"));
    assertEquals(false, summary.get("declared"));
    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION, summary.get("currentVersion"));
    assertEquals(List.of(), summary.get("warnings"));
  }

  @Test
  void summarize_whenTargetIsNewerThanMaximumTested_expectNewerThanTestedStatus() {
    AppApiCompatibilityMetadata metadata = new AppApiCompatibilityMetadata(1, 1, List.of(), false);
    PlatformApiContract targetContract =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            PlatformApiContract.current().capabilities(),
            PlatformApiContract.current().endpoints());

    Map<String, Object> summary =
        PlatformApiContractVerifier.summarize(metadata, List.of("queue.read"), targetContract);

    assertEquals("newer_than_tested", summary.get("status"));
    assertEquals(
        List.of(
            "Target Platform API contract 2 is newer than the app's maximum tested contract 1."),
        summary.get("warnings"));
  }

  @Test
  void summarize_whenRangeWarningAndVerifierErrorExist_expectIncompatibleStatus() {
    AppApiCompatibilityMetadata metadata = new AppApiCompatibilityMetadata(1, 1, List.of(), false);
    PlatformApiContract targetContract =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(capability("internal.cap", PlatformApiStabilityLevel.INTERNAL)),
            List.of());

    Map<String, Object> summary =
        PlatformApiContractVerifier.summarize(metadata, List.of("internal.cap"), targetContract);

    assertEquals("incompatible", summary.get("status"));
    assertEquals(
        List.of(
            "Target Platform API contract 2 is newer than the app's maximum tested contract 1.",
            "Internal capability must not be declared by apps: internal.cap."),
        summary.get("warnings"));
  }

  @Test
  void verify_whenStrictRangeAndUnknownCapabilities_expectErrorFindings() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            List.of("future.optional"),
            false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata, List.of("future.permission"), PlatformApiContract.current(), true);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "minimum_version_above_target",
            "unknown_manifest_permission",
            "unknown_optional_capability"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(3L, result.toJsonValue().get("errors"));
  }

  @Test
  void verify_whenCapabilityStabilityIsRisky_expectStabilityFindings() {
    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability("deprecated.cap", PlatformApiStabilityLevel.DEPRECATED),
                capability("experimental.cap", PlatformApiStabilityLevel.EXPERIMENTAL),
                capability("internal.cap", PlatformApiStabilityLevel.INTERNAL),
                capability("scheduled.cap", PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL),
                capability("stable.cap", PlatformApiStabilityLevel.STABLE)),
            List.of());
    AppApiCompatibilityMetadata metadata = new AppApiCompatibilityMetadata(1, 1, List.of(), false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata,
            List.of(
                "stable.cap",
                "experimental.cap",
                "deprecated.cap",
                "scheduled.cap",
                "internal.cap"),
            contract,
            false);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "deprecated_capability",
            "experimental_capability",
            "internal_capability",
            "scheduled_for_removal_capability"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(
            CompatibilityFindingSeverity.WARNING,
            CompatibilityFindingSeverity.WARNING,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.WARNING),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
    assertFalse(
        result.findings().stream().anyMatch(finding -> finding.message().contains("stable.cap")));
  }

  private static PlatformApiCapabilityDescriptor capability(
      String name, PlatformApiStabilityLevel stability) {
    return new PlatformApiCapabilityDescriptor(name, stability, 1, null, name + " description");
  }
}
