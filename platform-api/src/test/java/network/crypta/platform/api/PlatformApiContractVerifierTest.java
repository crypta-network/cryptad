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
  void summarize_whenLegacyMetadataUsesExperimentalCapability_expectUnknownStatusWithWarning() {
    Map<String, Object> summary =
        PlatformApiContractVerifier.summarize(
            null,
            List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
            PlatformApiContract.current());

    assertEquals("unknown", summary.get("status"));
    assertEquals(false, summary.get("declared"));
    assertEquals(
        List.of(
            "Experimental capability requires api.experimentalCapabilitiesAccepted=true: "
                + PlatformApiCapabilities.VAULT_IDENTITIES_READ
                + "."),
        summary.get("warnings"));
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
  void verify_whenVersion23AppTargetsCurrentContractWithOperatorRoute_expectCompatible() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(1, 23, List.of(), TargetStability.STABLE, false);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata,
            List.of(PlatformApiCapabilities.QUEUE_READ),
            PlatformApiContract.current(),
            true);

    assertFalse(result.hasErrors());
    assertFalse(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("target_newer_than_tested")));
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
  void verify_whenLegacyMetadataUsesExperimentalCapabilityInStrictMode_expectErrorFinding() {
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            null,
            List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
            PlatformApiContract.current(),
            true);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("experimental_capability_without_acceptance"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(CompatibilityFindingSeverity.ERROR),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
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
                    PlatformApiCapabilities.APP_DATA_WRITE, PlatformApiStabilityLevel.STABLE)),
            List.of(appDataEndpoint("POST", PlatformApiCapabilities.APP_DATA_WRITE)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_capability_removed", "stable_api_endpoint_removed"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(false, result.findings().get(1).details().get("waiverAllowed"));
  }

  @Test
  void compareStableBaseline_whenStableCapabilityIsReclassified_expectSpecificFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.APP_DATA_READ, PlatformApiStabilityLevel.STABLE),
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                appDataEndpoint("GET", PlatformApiCapabilities.APP_DATA_READ),
                endpoint("GET", "/queue", PlatformApiCapabilities.QUEUE_READ, true)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(
                    PlatformApiCapabilities.APP_DATA_READ, PlatformApiStabilityLevel.EXPERIMENTAL),
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET",
                    "/app-data/records",
                    PlatformApiCapabilities.APP_DATA_READ,
                    PlatformApiCapabilities.APP_DATA_READ,
                    true,
                    PlatformApiStabilityLevel.EXPERIMENTAL,
                    null),
                endpoint("GET", "/queue", PlatformApiCapabilities.QUEUE_READ, true)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_capability_reclassified", "stable_api_endpoint_reclassified"),
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
        List.of("stable_api_endpoint_app_principal_changed"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableEndpointRequiredCapabilitiesChange_expectSpecificFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE),
                capability(PlatformApiCapabilities.QUEUE_WRITE, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET", "/queue", "queue.snapshot", PlatformApiCapabilities.QUEUE_READ, true)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE),
                capability(PlatformApiCapabilities.QUEUE_WRITE, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET", "/queue", "queue.snapshot", PlatformApiCapabilities.QUEUE_WRITE, true)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_endpoint_required_capabilities_changed"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableEndpointIdentityChanges_expectSpecificFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET", "/queue", "queue.snapshot", PlatformApiCapabilities.QUEUE_READ, true)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET",
                    "/queue-v2",
                    "queue.snapshot",
                    PlatformApiCapabilities.QUEUE_READ,
                    true)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_endpoint_identity_changed"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableEndpointRemovedWithSharedActionLabel_expectRemovedFinding() {
    PlatformApiContract previous =
        new PlatformApiContract(
            "v1",
            1,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint("GET", "/queue", "queue.read", PlatformApiCapabilities.QUEUE_READ, true),
                endpoint(
                    "GET",
                    "/queue/count",
                    "queue.read",
                    PlatformApiCapabilities.QUEUE_READ,
                    true)));
    PlatformApiContract current =
        new PlatformApiContract(
            "v1",
            2,
            "test",
            "test policy",
            List.of(
                capability(PlatformApiCapabilities.QUEUE_READ, PlatformApiStabilityLevel.STABLE)),
            List.of(
                endpoint(
                    "GET",
                    "/queue/count",
                    "queue.read",
                    PlatformApiCapabilities.QUEUE_READ,
                    true)));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_api_endpoint_removed"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(false, result.findings().getFirst().details().get("waiverAllowed"));
  }

  @Test
  void compareStableBaseline_whenPreviousMetadataMissingInProduction_expectErrorFinding() {
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(
            PlatformApiContract.current(), PlatformApiContract.current(), true, false, true);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("stable_baseline_metadata_missing"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(CompatibilityFindingSeverity.ERROR, result.findings().getFirst().severity());
  }

  @Test
  void compareStableBaseline_whenPreviousMetadataMissingOutsideProduction_expectWarningFinding() {
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(
            PlatformApiContract.current(), PlatformApiContract.current(), false, false, true);

    assertFalse(result.hasErrors());
    assertEquals(
        List.of("stable_baseline_metadata_missing"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(CompatibilityFindingSeverity.WARNING, result.findings().getFirst().severity());
  }

  @Test
  void
      compareStableBaseline_whenPreviousCompatibilityWindowMissingInProduction_expectErrorFinding() {
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(
            PlatformApiContract.current(),
            PlatformApiContract.current(),
            true,
            true,
            true,
            false,
            true);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of("compatibility_window_metadata_missing"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(CompatibilityFindingSeverity.ERROR, result.findings().getFirst().severity());
  }

  @Test
  void
      compareStableBaseline_whenPreviousCompatibilityWindowMissingOutsideProduction_expectWarning() {
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(
            PlatformApiContract.current(),
            PlatformApiContract.current(),
            false,
            true,
            true,
            false,
            true);

    assertFalse(result.hasErrors());
    assertEquals(
        List.of("compatibility_window_metadata_missing"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(CompatibilityFindingSeverity.WARNING, result.findings().getFirst().severity());
  }

  @Test
  void compareStableBaseline_whenStableCapabilityScheduledWithoutMetadata_expectPolicyBlocker() {
    PlatformApiContract previous = queueContract(1, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(2, PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL, null);

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "stable_api_deprecation_window_too_short", "stable_api_deprecation_window_too_short"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableRemovalWindowIsTooShort_expectPolicyBlockers() {
    PlatformApiContract previous = queueContract(23, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(
            23,
            PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL,
            new PlatformApiDeprecation(22, 23, "Use a future baseline."));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "stable_api_deprecation_window_too_short",
            "stable_api_removal_window_too_short",
            "stable_api_deprecation_window_too_short",
            "stable_api_removal_window_too_short"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableApiIsDeprecatedWithMetadata_expectWarning() {
    PlatformApiContract previous = queueContract(23, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(
            23,
            PlatformApiStabilityLevel.DEPRECATED,
            new PlatformApiDeprecation(23, null, "Use a future baseline."));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertFalse(result.hasErrors());
    assertEquals(
        List.of("stable_api_deprecation_warning", "stable_api_deprecation_warning"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(CompatibilityFindingSeverity.WARNING, CompatibilityFindingSeverity.WARNING),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
  }

  @Test
  void compareStableBaseline_whenDeprecatedStableApiNamesTooSoonRemoval_expectPolicyBlockers() {
    PlatformApiContract previous = queueContract(23, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(
            23,
            PlatformApiStabilityLevel.DEPRECATED,
            new PlatformApiDeprecation(23, 24, "Use a future baseline."));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "stable_api_deprecation_window_too_short",
            "stable_api_removal_window_too_short",
            "stable_api_deprecation_window_too_short",
            "stable_api_removal_window_too_short"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.ERROR,
            CompatibilityFindingSeverity.ERROR),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
  }

  @Test
  void compareStableBaseline_whenStableApiDeprecationStartsInFuture_expectPolicyBlockers() {
    PlatformApiContract previous = queueContract(23, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(
            23,
            PlatformApiStabilityLevel.DEPRECATED,
            new PlatformApiDeprecation(24, null, "Use a future baseline."));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "stable_api_deprecation_window_too_short", "stable_api_deprecation_window_too_short"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(CompatibilityFindingSeverity.ERROR, CompatibilityFindingSeverity.ERROR),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
  }

  @Test
  void compareStableBaseline_whenScheduledRemovalStartsInFuture_expectPolicyBlockers() {
    PlatformApiContract previous = queueContract(23, PlatformApiStabilityLevel.STABLE, null);
    PlatformApiContract current =
        queueContract(
            23,
            PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL,
            new PlatformApiDeprecation(24, 27, "Use a future baseline."));

    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareStableBaseline(previous, current);

    assertTrue(result.hasErrors());
    assertEquals(
        List.of(
            "stable_api_deprecation_window_too_short", "stable_api_deprecation_window_too_short"),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::code)
            .toList());
    assertEquals(
        List.of(CompatibilityFindingSeverity.ERROR, CompatibilityFindingSeverity.ERROR),
        result.findings().stream()
            .map(PlatformApiContractVerifier.CompatibilityFinding::severity)
            .toList());
  }

  private static PlatformApiCapabilityDescriptor capability(
      String name, PlatformApiStabilityLevel stability) {
    return new PlatformApiCapabilityDescriptor(name, stability, 1, null, name + " description");
  }

  private static PlatformApiCapabilityDescriptor queueReadCapability(
      PlatformApiStabilityLevel stability, PlatformApiDeprecation deprecation) {
    String name = PlatformApiCapabilities.QUEUE_READ;
    return new PlatformApiCapabilityDescriptor(
        name, stability, 1, deprecation, name + " description");
  }

  private static PlatformApiContract queueContract(
      int contractVersion,
      PlatformApiStabilityLevel stability,
      PlatformApiDeprecation deprecation) {
    return new PlatformApiContract(
        "v1",
        contractVersion,
        "test",
        "test policy",
        List.of(queueReadCapability(stability, deprecation)),
        List.of(
            endpoint(
                "GET",
                "/queue",
                PlatformApiCapabilities.QUEUE_READ,
                PlatformApiCapabilities.QUEUE_READ,
                true,
                stability,
                deprecation)));
  }

  private static PlatformApiEndpointDescriptor appDataEndpoint(String method, String capability) {
    return endpoint(method, "/app-data/records", capability, true);
  }

  private static PlatformApiEndpointDescriptor endpoint(
      String method, String routeTemplate, String capability, boolean appProcess) {
    return endpoint(method, routeTemplate, capability, capability, appProcess);
  }

  private static PlatformApiEndpointDescriptor endpoint(
      String method,
      String routeTemplate,
      String actionLabel,
      String capability,
      boolean appProcess) {
    return endpoint(
        method,
        routeTemplate,
        actionLabel,
        capability,
        appProcess,
        PlatformApiStabilityLevel.STABLE,
        null);
  }

  private static PlatformApiEndpointDescriptor endpoint(
      String method,
      String routeTemplate,
      String actionLabel,
      String capability,
      boolean appProcess,
      PlatformApiStabilityLevel stability,
      PlatformApiDeprecation deprecation) {
    return new PlatformApiEndpointDescriptor(
        "test",
        method,
        routeTemplate,
        actionLabel,
        List.of(capability),
        true,
        appProcess,
        true,
        stability,
        1,
        deprecation,
        capability + " endpoint");
  }
}
