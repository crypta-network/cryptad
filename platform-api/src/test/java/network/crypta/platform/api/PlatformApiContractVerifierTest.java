package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityFindingSeverity;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityVerificationResult;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
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
    assertEquals(PlatformApiContract.current().contractVersion(), summary.get("currentVersion"));
    assertEquals(List.of(), summary.get("warnings"));
  }

  @Test
  void summarize_whenTargetIsNewerThanMaximumTested_expectNewerThanTestedStatus() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.STABLE, false);
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
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.EXPERIMENTAL, false);
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
            PlatformApiContract.current().contractVersion() + 1,
            PlatformApiContract.current().contractVersion() + 1,
            List.of("future.optional"),
            TargetStability.STABLE,
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
                capability("operator.cap", PlatformApiStabilityLevel.OPERATOR_ONLY),
                capability("scheduled.cap", PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL),
                capability("stable.cap", PlatformApiStabilityLevel.STABLE)),
            List.of());
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.EXPERIMENTAL, false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata,
            List.of(
                "stable.cap",
                "experimental.cap",
                "deprecated.cap",
                "scheduled.cap",
                "internal.cap",
                "operator.cap"),
            contract,
            false);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "deprecated_capability",
            "experimental_capability_without_acceptance",
            "app_uses_internal_platform_api",
            "app_uses_operator_only_platform_api",
            "scheduled_for_removal_capability"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(
            CompatibilityFindingSeverity.WARNING,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.WARNING),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
    assertFalse(
        result.findings().stream().anyMatch(finding -> finding.message().contains("stable.cap")));
  }

  @Test
  void verify_whenStableTargetUsesExperimentalCapability_expectErrorFinding() {
    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(capability("experimental.cap", PlatformApiStabilityLevel.EXPERIMENTAL)),
            List.of());
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.STABLE, true);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(metadata, List.of("experimental.cap"), contract, false);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_target_uses_experimental_capability"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void verify_whenStableTargetUsesStableNonBaselineCapability_expectErrorFinding() {
    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(capability("config.read", PlatformApiStabilityLevel.STABLE)),
            List.of());
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.STABLE, false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(metadata, List.of("config.read"), contract, false);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_target_uses_non_baseline_capability"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void verify_whenDeclaredMetadataOmitsTargetStability_expectMissingTargetFinding() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            1, PlatformApiContract.current().contractVersion(), List.of(), false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata, List.of("queue.read"), PlatformApiContract.current(), false);

    assertEquals(
        List.of("api_target_stability_missing"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableCapabilityIsRemoved_expectBreakingChangeFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.APP_DATA_READ, PlatformApiStabilityLevel.STABLE),
                capability(
                    PlatformApiCapabilities.APP_DATA_WRITE, PlatformApiStabilityLevel.STABLE)),
            List.of(
                appDataEndpoint("GET", PlatformApiCapabilities.APP_DATA_READ),
                appDataEndpoint("POST", PlatformApiCapabilities.APP_DATA_WRITE)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(
                    PlatformApiCapabilities.APP_DATA_READ, PlatformApiStabilityLevel.EXPERIMENTAL),
                capability(
                    PlatformApiCapabilities.APP_DATA_WRITE, PlatformApiStabilityLevel.STABLE)),
            List.of(appDataEndpoint("POST", PlatformApiCapabilities.APP_DATA_WRITE)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_breaking_change", "stable_api_breaking_change"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableEndpointAppAccessChanges_expectBreakingChangeFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(endpoint("GET", "/queue", PlatformApiCapabilities.QUEUE_READ, true)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(endpoint("GET", "/queue", PlatformApiCapabilities.QUEUE_READ, false)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_breaking_change"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  private static PlatformApiCapabilityDescriptor capability(
      String name, PlatformApiStabilityLevel stability) {
    return new PlatformApiCapabilityDescriptor(name, stability, 1, null, name + " description");
  }

  private static PlatformApiEndpointDescriptor appDataEndpoint(String method, String capability) {
    return endpoint(method, "/app-data/records", capability, true);
  }

  private static PlatformApiEndpointDescriptor endpoint(
      String method, String routeTemplate, String capability, boolean appProcess) {
    return new PlatformApiEndpointDescriptor(
        "test",
        method,
        routeTemplate,
        capability,
        List.of(capability),
        true,
        appProcess,
        true,
        PlatformApiStabilityLevel.STABLE,
        1,
        null,
        capability + " endpoint");
  }
}
