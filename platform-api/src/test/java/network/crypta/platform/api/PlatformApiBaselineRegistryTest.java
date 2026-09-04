package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiBaselineRegistryTest {
  private static final String ADDITIVE_CAPABILITY = "future.additive.read";
  private static final String ACTIVATION_COORDINATES_CHANGE = "cannot change after activation";
  private static final String QUEUE_READ_CAPABILITY = "queue.read";
  private static final String DIGEST_A = "a".repeat(64);
  private static final String DIGEST_B = "b".repeat(64);
  private static final String DIGEST_C = "c".repeat(64);
  private static final String DIGEST_D = "d".repeat(64);

  @Test
  void parse_whenIdentityIsAliasedOrUnsupported_expectRejected() {
    for (String value : List.of(" 1.0", "1.0 ", "01.0", "1.00", "1", "1.0.0", "2.0")) {
      assertThrows(IllegalArgumentException.class, () -> PlatformApiBaselineId.parse(value), value);
    }
    assertEquals("1.1", PlatformApiBaselineId.parse("1.1").toString());
  }

  @Test
  void current_whenImported_expectFrozenOnePointZeroProjectionOnly() {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition definition = registry.definitions().getFirst();

    assertEquals(PlatformApiBaselineId.parse("1.0"), definition.id());
    assertEquals(
        PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256,
        definition.sourceArtifactDigest());
    assertEquals(9, definition.capabilities().size());
    assertEquals(32, definition.endpoints().size());
    assertEquals(List.of(PlatformApiBaselineId.parse("1.0")), registry.supportedBaselineIds());
    assertEquals(List.of(PlatformApiBaselineId.parse("1.0")), registry.activeBaselineIds());
    assertEquals(
        PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE,
        registry.lineage().getFirst().evidenceKind());
    assertEquals(
        PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256,
        definition.definitionDigest());
    assertEquals(
        PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_LINEAGE_SHA256,
        registry.lineage().getFirst().lineageDigest());
    assertFalse(
        definition.endpoints().stream()
            .anyMatch(endpoint -> endpoint.identity().contains("catalog-federation")));
  }

  @Test
  @SuppressWarnings("unchecked")
  void activeBaselineIds_whenPredecessorIsDeprecated_expectLifecycleViewsRemainDistinct() {
    PlatformApiBaselineRegistry active11 = registryWithActiveBaseline(additiveDefinition());
    PlatformApiBaselineDefinition stable10 = active11.definitions().getFirst();
    PlatformApiBaselineLineage previous10 =
        active11.latestLineageById().get(PlatformApiBaselineId.parse("1.0"));
    PlatformApiBaselineLineage deprecated10 =
        PlatformApiBaselineLineage.create(
            stable10.id(),
            stable10.definitionDigest(),
            PlatformApiBaselineStatus.DEPRECATED,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "f".repeat(64),
            previous10.activationRelease(),
            previous10.activationBuild(),
            previous10.supportStartedRelease(),
            null,
            previous10.lineageDigest());
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>(active11.lineage());
    lineage.add(deprecated10);
    PlatformApiBaselineRegistry registry =
        PlatformApiBaselineRegistry.create(active11.definitions(), lineage);

    assertEquals(
        List.of(PlatformApiBaselineId.parse("1.0"), PlatformApiBaselineId.parse("1.1")),
        registry.supportedBaselineIds());
    assertEquals(List.of(PlatformApiBaselineId.parse("1.1")), registry.activeBaselineIds());
    Map<String, Object> summary =
        PlatformApiContractJson.baselineRegistrySummaryToJsonValue(registry);
    List<Map<String, Object>> supported =
        (List<Map<String, Object>>) summary.get("supportedBaselines");
    assertEquals(List.of("1.0", "1.1"), supported.stream().map(row -> row.get("id")).toList());
    assertEquals(
        List.of("deprecated", "active"), supported.stream().map(row -> row.get("status")).toList());
  }

  @Test
  void create_whenDeprecationRewritesActivationCoordinates_expectRejected() {
    PlatformApiBaselineRegistry active = registryWithActiveBaseline(additiveDefinition());
    PlatformApiBaselineDefinition definition = active.definitions().getLast();
    PlatformApiBaselineLineage previous = active.latestLineageById().get(definition.id());
    PlatformApiBaselineLineage rewritten =
        PlatformApiBaselineLineage.create(
            definition.id(),
            definition.definitionDigest(),
            PlatformApiBaselineStatus.DEPRECATED,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "f".repeat(64),
            "rewritten-release",
            previous.activationBuild(),
            previous.supportStartedRelease(),
            null,
            previous.lineageDigest());
    IllegalArgumentException thrown =
        assertThrows(IllegalArgumentException.class, () -> createRegistry(active, rewritten));

    assertTrue(thrown.getMessage().contains(ACTIVATION_COORDINATES_CHANGE));
  }

  @Test
  void create_whenFrozenImportDeprecationInventsActivationCoordinates_expectRejected() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition definition = current.definitions().getFirst();
    PlatformApiBaselineLineage imported = current.lineage().getFirst();
    PlatformApiBaselineLineage deprecated =
        PlatformApiBaselineLineage.create(
            definition.id(),
            definition.definitionDigest(),
            PlatformApiBaselineStatus.DEPRECATED,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "f".repeat(64),
            "invented-activation-release",
            24,
            "invented-support-start",
            null,
            imported.lineageDigest());
    List<PlatformApiBaselineDefinition> definitions = current.definitions();
    List<PlatformApiBaselineLineage> lineage = List.of(imported, deprecated);

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () -> PlatformApiBaselineRegistry.create(definitions, lineage));

    assertTrue(thrown.getMessage().contains(ACTIVATION_COORDINATES_CHANGE));
  }

  @Test
  void create_whenEndOfSupportErasesActivationCoordinates_expectRejected() {
    PlatformApiBaselineRegistry active = registryWithActiveBaseline(additiveDefinition());
    PlatformApiBaselineDefinition definition = active.definitions().getLast();
    PlatformApiBaselineLineage activation = active.latestLineageById().get(definition.id());
    PlatformApiBaselineLineage deprecated =
        PlatformApiBaselineLineage.create(
            definition.id(),
            definition.definitionDigest(),
            PlatformApiBaselineStatus.DEPRECATED,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "f".repeat(64),
            activation.activationRelease(),
            activation.activationBuild(),
            activation.supportStartedRelease(),
            null,
            activation.lineageDigest());
    PlatformApiBaselineLineage ended =
        PlatformApiBaselineLineage.create(
            definition.id(),
            definition.definitionDigest(),
            PlatformApiBaselineStatus.END_OF_SUPPORT,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "9".repeat(64),
            null,
            null,
            null,
            "support-ended-release",
            deprecated.lineageDigest());
    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> createRegistry(active, deprecated, ended));

    assertTrue(thrown.getMessage().contains(ACTIVATION_COORDINATES_CHANGE));
  }

  @Test
  void baselineRegistryJson_whenRoundTripped_expectDeterministicArtifact() {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    String json = PlatformApiContractJson.writeBaselineRegistry(registry);

    PlatformApiBaselineRegistry parsed = PlatformApiContractJson.parseBaselineRegistry(json);

    assertEquals(registry, parsed);
    assertEquals(json, PlatformApiContractJson.writeBaselineRegistry(parsed));
  }

  @Test
  void parseBaselineRegistry_whenBareCanonicalObjectProvided_expectAccepted() {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    String envelope = PlatformApiContractJson.writeBaselineRegistry(registry);
    String bare = envelope.substring("{\"baselineRegistry\":".length(), envelope.length() - 1);

    PlatformApiBaselineRegistry parsed = PlatformApiContractJson.parseBaselineRegistry(bare);

    assertEquals(registry, parsed);
  }

  @Test
  void parseBaselineRegistry_whenUnknownFieldExists_expectRejectedAtEveryClosedLevel() {
    String json =
        PlatformApiContractJson.writeBaselineRegistry(PlatformApiBaselineRegistry.current());
    List<String> malformed =
        List.of(
            json.replaceFirst("\\{", "{\"unknown\":true,"),
            json.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"unknown\":true"),
            json.replaceFirst("\"definitions\":\\[\\{", "\"definitions\":[{\"unknown\":true,"),
            json.replaceFirst("\"endpoints\":\\[\\{", "\"endpoints\":[{\"unknown\":true,"),
            json.replaceFirst("\"lineage\":\\[\\{", "\"lineage\":[{\"unknown\":true,"));

    for (String candidate : malformed) {
      assertThrows(
          IllegalArgumentException.class,
          () -> PlatformApiContractJson.parseBaselineRegistry(candidate));
    }
  }

  @Test
  void parseBaselineRegistry_whenRequiredNullableFieldIsAbsent_expectRejected() {
    String json =
        PlatformApiContractJson.writeBaselineRegistry(PlatformApiBaselineRegistry.current());
    List<String> malformed =
        List.of(
            json.replace("\"proposalDigest\":null,", ""),
            json.replace("\"activationRelease\":null,", ""));

    for (String candidate : malformed) {
      assertThrows(
          IllegalArgumentException.class,
          () -> PlatformApiContractJson.parseBaselineRegistry(candidate));
    }
  }

  @Test
  void parseBaselineRegistry_whenObjectMemberIsDuplicated_expectRejected() {
    String json =
        PlatformApiContractJson.writeBaselineRegistry(PlatformApiBaselineRegistry.current());
    String malformed =
        json.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1");

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiContractJson.parseBaselineRegistry(malformed));
  }

  @Test
  void contractJson_whenRegistrySummaryAdded_expectLegacyParserRemainsReadable() {
    String legacy = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String extended =
        PlatformApiContractJson.writeEnvelope(
            PlatformApiContract.current(), PlatformApiBaselineRegistry.current());

    PlatformApiContract parsed = PlatformApiContractJson.parse(extended);

    assertFalse(legacy.contains("baselineRegistrySummary"));
    assertTrue(extended.contains("\"supportedBaselines\":[{\"id\":\"1.0\""));
    assertEquals(legacy, PlatformApiContractJson.writeEnvelope(parsed));
  }

  @Test
  void verifyBaselineRegistrySummary_whenSummaryMatchesRegistry_expectAccepted() {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry);

    PlatformApiContractJson.verifyBaselineRegistrySummary(json, registry);
  }

  @Test
  void verifyBaselineRegistrySummary_whenCurrentSummaryIsMissingOrMismatched_expectRejected() {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    String missing = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String mismatched =
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry)
            .replace(registry.registryDigest(), DIGEST_A);

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiContractJson.verifyBaselineRegistrySummary(missing, registry));
    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiContractJson.verifyBaselineRegistrySummary(mismatched, registry));
  }

  @Test
  void lineage_whenFixtureAttemptsActivation_expectRejected() {
    PlatformApiBaselineDefinition definition = candidateDefinition(false, false);
    PlatformApiBaselineId baselineId = definition.id();
    String definitionDigest = definition.definitionDigest();

    assertThrows(
        IllegalArgumentException.class,
        () ->
            PlatformApiBaselineLineage.create(
                baselineId,
                definitionDigest,
                PlatformApiBaselineStatus.ACTIVE,
                PlatformApiBaselineEvidenceKind.FIXTURE,
                DIGEST_A,
                "fixture-release",
                1,
                "fixture-release",
                null,
                null));
  }

  @Test
  void lineage_whenPreActivationStateCarriesActivationCoordinates_expectRejected() {
    PlatformApiBaselineDefinition definition = candidateDefinition(false, false);
    PlatformApiBaselineId baselineId = definition.id();
    String definitionDigest = definition.definitionDigest();

    for (PlatformApiBaselineStatus status :
        List.of(
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineStatus.CANDIDATE,
            PlatformApiBaselineStatus.REVIEWED,
            PlatformApiBaselineStatus.DOCUMENTED,
            PlatformApiBaselineStatus.REJECTED)) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              PlatformApiBaselineLineage.create(
                  baselineId,
                  definitionDigest,
                  status,
                  PlatformApiBaselineEvidenceKind.FIXTURE,
                  DIGEST_A,
                  "not-activated",
                  24,
                  "not-supported",
                  null,
                  null),
          status::toString);
    }
  }

  @Test
  void lineage_whenReleaseCoordinatesAreNotCanonical_expectRejected() {
    PlatformApiBaselineDefinition definition = candidateDefinition(false, false);
    PlatformApiBaselineId baselineId = definition.id();
    String definitionDigest = definition.definitionDigest();
    String oversizedReleaseId = "x".repeat(129);

    assertThrows(
        IllegalArgumentException.class,
        () ->
            PlatformApiBaselineLineage.create(
                baselineId,
                definitionDigest,
                PlatformApiBaselineStatus.ACTIVE,
                PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
                DIGEST_A,
                "release/24",
                24,
                "release-24",
                null,
                null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            PlatformApiBaselineLineage.create(
                baselineId,
                definitionDigest,
                PlatformApiBaselineStatus.ACTIVE,
                PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
                DIGEST_A,
                "release-24",
                24,
                " release-24",
                null,
                null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            PlatformApiBaselineLineage.create(
                baselineId,
                definitionDigest,
                PlatformApiBaselineStatus.END_OF_SUPPORT,
                PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
                DIGEST_A,
                null,
                null,
                null,
                oversizedReleaseId,
                null));
  }

  @Test
  void lineage_whenImportedEvidenceDoesNotMatchFrozenAuthority_expectRejected() {
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    PlatformApiBaselineId baselineId = stable10.id();
    String definitionDigest = stable10.definitionDigest();

    assertThrows(
        IllegalArgumentException.class,
        () ->
            PlatformApiBaselineLineage.create(
                baselineId,
                definitionDigest,
                PlatformApiBaselineStatus.ACTIVE,
                PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE,
                DIGEST_A,
                null,
                null,
                null,
                null,
                null));
  }

  @Test
  void create_whenOnePointZeroMembershipIsForged_expectRejected() {
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    List<String> forgedCapabilities = new ArrayList<>(stable10.capabilities());
    forgedCapabilities.removeLast();
    List<PlatformApiBaselineEndpoint> forgedEndpoints =
        stable10.endpoints().stream()
            .filter(endpoint -> forgedCapabilities.containsAll(endpoint.requiredCapabilities()))
            .toList();
    PlatformApiBaselineDefinition forged =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.0"),
            null,
            forgedCapabilities,
            forgedEndpoints,
            PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256,
            null,
            null,
            null,
            PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION);
    PlatformApiBaselineLineage proposed =
        PlatformApiBaselineLineage.create(
            forged.id(),
            forged.definitionDigest(),
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            DIGEST_A,
            null,
            null,
            null,
            null,
            null);
    List<PlatformApiBaselineDefinition> definitions = List.of(forged);
    List<PlatformApiBaselineLineage> lineage = List.of(proposed);

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiBaselineRegistry.create(definitions, lineage));
  }

  @Test
  void create_whenOnePointZeroSourceDigestIsForged_expectRejected() {
    PlatformApiContract contract = PlatformApiContract.current();

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiBaselineDefinition.importStable10(contract, DIGEST_A));
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    PlatformApiBaselineDefinition forged =
        PlatformApiBaselineDefinition.create(
            stable10.id(),
            null,
            stable10.capabilities(),
            stable10.endpoints(),
            DIGEST_A,
            null,
            null,
            null,
            stable10.firstCompleteContractVersion());
    PlatformApiBaselineLineage proposed =
        PlatformApiBaselineLineage.create(
            forged.id(),
            forged.definitionDigest(),
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            DIGEST_B,
            null,
            null,
            null,
            null,
            null);
    List<PlatformApiBaselineDefinition> definitions = List.of(forged);
    List<PlatformApiBaselineLineage> lineage = List.of(proposed);

    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformApiBaselineRegistry.create(definitions, lineage));
  }

  @Test
  void create_whenCandidateOmitsSupportedMember_expectRejected() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition candidate = candidateDefinition(true, false);

    assertThrows(IllegalArgumentException.class, () -> registryWithCandidate(current, candidate));
  }

  @Test
  void create_whenCandidateChangesInheritedAuthorizationSemantics_expectRejected() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition candidate = candidateDefinition(false, true);

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> registryWithCandidate(current, candidate));

    assertTrue(thrown.getMessage().contains("authorization semantics"), thrown.getMessage());
  }

  @Test
  void create_whenCandidateBranchesAroundSupportedIntermediateBaseline_expectRejected() {
    PlatformApiBaselineRegistry withSupported11 = registryWithActiveBaseline(additiveDefinition());
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    PlatformApiBaselineDefinition branched12 =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.2"),
            stable10.id(),
            stable10.capabilities(),
            stable10.endpoints(),
            DIGEST_A,
            DIGEST_B,
            DIGEST_C,
            DIGEST_D,
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1);

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class,
            () -> registryWithCandidate(withSupported11, branched12));

    assertTrue(thrown.getMessage().contains("supported predecessor capability"));
  }

  @Test
  void compareBaselineRegistries_whenHistoryIsReplaced_expectDeterministicError() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineRegistry extended =
        registryWithCandidate(current, candidateDefinition(false, false));

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.compareBaselineRegistries(extended, current);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_definition_changed")));
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_history_rewritten")));
  }

  @Test
  void verify_whenStableAppTargetsCandidate_expectUnsupportedBaseline() {
    PlatformApiBaselineRegistry registry =
        registryWithCandidate(
            PlatformApiBaselineRegistry.current(), candidateDefinition(false, false));
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19,
            PlatformApiContract.CURRENT_CONTRACT_VERSION,
            List.of(),
            TargetStability.STABLE,
            true,
            "1.1",
            true,
            false,
            true);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata,
            PlatformApiContract.current().stableBaseline().capabilities(),
            PlatformApiContract.current(),
            registry,
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("target_baseline_inactive")));
    assertEquals(
        "unsupported-baseline",
        PlatformApiContractVerifier.summarize(
                metadata,
                PlatformApiContract.current().stableBaseline().capabilities(),
                PlatformApiContract.current(),
                registry)
            .get("status"));
  }

  @Test
  void verify_whenExperimentalAppTargetsIncompleteCandidate_expectDefinitionRejected() {
    PlatformApiBaselineRegistry registry =
        registryWithCandidate(PlatformApiBaselineRegistry.current(), additiveDefinition());
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19,
            PlatformApiContract.CURRENT_CONTRACT_VERSION,
            List.of(),
            TargetStability.EXPERIMENTAL,
            true,
            "1.1",
            true,
            true,
            true);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            metadata,
            List.of(QUEUE_READ_CAPABILITY),
            PlatformApiContract.current(),
            registry,
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("target_baseline_preview_only")));
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_descriptor_missing")));
  }

  @Test
  void verify_whenActiveSuccessorContainsAdditiveCapability_expectNamedBaselineAllowsIt() {
    PlatformApiContract contract = contractWithCapability(PlatformApiStabilityLevel.EXPERIMENTAL);
    PlatformApiBaselineDefinition successor = additiveDefinition();
    PlatformApiBaselineRegistry registry = registryWithActiveBaseline(successor);
    AppApiCompatibilityMetadata metadata = stableMetadata("1.1");

    PlatformApiContractVerifier.CompatibilityVerificationResult legacyResult =
        PlatformApiContractVerifier.verify(metadata, List.of(ADDITIVE_CAPABILITY), contract, true);
    PlatformApiContractVerifier.CompatibilityVerificationResult namedResult =
        PlatformApiContractVerifier.verify(
            metadata, List.of(ADDITIVE_CAPABILITY), contract, registry, true);

    assertTrue(legacyResult.hasErrors());
    assertTrue(
        legacyResult.findings().stream()
            .anyMatch(
                finding -> finding.code().equals("stable_target_uses_experimental_capability")));
    assertFalse(namedResult.hasErrors(), namedResult.messages().toString());
  }

  @Test
  void verify_whenOnePointZeroAppUsesAdditiveStableCapability_expectFrozenMembershipRejectsIt() {
    PlatformApiContract contract = contractWithCapability(PlatformApiStabilityLevel.STABLE);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            stableMetadata("1.0"),
            List.of(ADDITIVE_CAPABILITY),
            contract,
            PlatformApiBaselineRegistry.current(),
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(
                finding -> finding.code().equals("stable_target_uses_non_baseline_capability")));
  }

  @Test
  void verify_whenActiveBaselineIsNewerThanTargetContract_expectIncompleteBaselineRejected() {
    PlatformApiContract current = PlatformApiContract.current();
    PlatformApiContract oldContract =
        new PlatformApiContract(
            current.apiVersion(),
            18,
            current.generatedBy(),
            current.stabilityPolicy(),
            current.stableBaseline(),
            PlatformApiCompatibilityWindow.current(18),
            current.capabilities(),
            current.endpoints());

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            stableMetadata("1.0"),
            List.of(QUEUE_READ_CAPABILITY),
            oldContract,
            PlatformApiBaselineRegistry.current(),
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_contract_version_incomplete")));
  }

  @Test
  void verify_whenUnrequestedSupportedBaselineCapabilityIsMissing_expectContractRejected() {
    PlatformApiBaselineDefinition successor = additiveDefinition();
    PlatformApiBaselineRegistry registry = registryWithActiveBaseline(successor);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            stableMetadata("1.1"),
            List.of(QUEUE_READ_CAPABILITY),
            PlatformApiContract.current(),
            registry,
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_descriptor_missing")));
  }

  @Test
  void verify_whenUnrequestedSupportedEndpointSemanticsChange_expectContractRejected() {
    PlatformApiContract current = PlatformApiContract.current();
    String targetIdentity =
        PlatformApiBaselineRegistry.current()
            .definitions()
            .getFirst()
            .endpoints()
            .getFirst()
            .identity();
    List<PlatformApiEndpointDescriptor> endpoints = new ArrayList<>();
    for (PlatformApiEndpointDescriptor endpoint : current.endpoints()) {
      if (PlatformApiContract.endpointIdentity(endpoint).equals(targetIdentity)) {
        endpoints.add(
            new PlatformApiEndpointDescriptor(
                endpoint.routeFamily(),
                endpoint.method(),
                endpoint.routeTemplate(),
                endpoint.actionLabel() + ".changed",
                endpoint.requiredCapabilities(),
                endpoint.hostOperatorBypassAllowed(),
                endpoint.appProcessAllowed(),
                endpoint.appBrowserAllowed(),
                endpoint.stability(),
                endpoint.sinceContractVersion(),
                endpoint.deprecation(),
                endpoint.description()));
      } else {
        endpoints.add(endpoint);
      }
    }
    PlatformApiContract changedContract =
        new PlatformApiContract(
            current.apiVersion(),
            current.contractVersion(),
            current.generatedBy(),
            current.stabilityPolicy(),
            current.stableBaseline(),
            current.compatibilityWindow(),
            current.capabilities(),
            endpoints);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            stableMetadata("1.0"),
            List.of(QUEUE_READ_CAPABILITY),
            changedContract,
            PlatformApiBaselineRegistry.current(),
            true);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_descriptor_semantics_changed")));
  }

  @Test
  void verifyBaselineDefinition_whenEndpointBecomesRestricted_expectBoundedFinding() {
    PlatformApiContract current = PlatformApiContract.current();
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    PlatformApiEndpointDescriptor restricted =
        current.endpoints().stream()
            .filter(endpoint -> endpoint.stability().isRestrictedAudience())
            .findFirst()
            .orElseThrow();
    List<String> capabilities = new ArrayList<>(stable10.capabilities());
    capabilities.addAll(restricted.requiredCapabilities());
    List<PlatformApiBaselineEndpoint> endpoints = new ArrayList<>(stable10.endpoints());
    endpoints.add(
        new PlatformApiBaselineEndpoint(
            PlatformApiContract.endpointIdentity(restricted),
            restricted.routeFamily(),
            restricted.actionLabel(),
            restricted.requiredCapabilities(),
            restricted.hostOperatorBypassAllowed(),
            true,
            false));
    PlatformApiBaselineDefinition definition =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.1"),
            stable10.id(),
            capabilities,
            endpoints,
            DIGEST_A,
            DIGEST_B,
            DIGEST_C,
            DIGEST_D,
            current.contractVersion());

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verifyBaselineDefinition(definition, current);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(finding -> finding.code().equals("baseline_descriptor_restricted")));
  }

  @Test
  void verifyBaselineDefinition_whenCapabilityAppearsAfterCompleteVersion_expectRejected() {
    int laterContractVersion = PlatformApiContract.CURRENT_CONTRACT_VERSION + 1;
    PlatformApiContract contract =
        contractWithCapability(
            PlatformApiStabilityLevel.EXPERIMENTAL, laterContractVersion, laterContractVersion);
    PlatformApiBaselineDefinition definition = additiveDefinition();

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verifyBaselineDefinition(definition, contract);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(
                finding ->
                    finding
                        .code()
                        .equals("baseline_descriptor_introduced_after_complete_version")));
  }

  @Test
  void verifyBaselineDefinition_whenEndpointAppearsAfterCompleteVersion_expectRejected() {
    int laterContractVersion = PlatformApiContract.CURRENT_CONTRACT_VERSION + 1;
    PlatformApiContract current = PlatformApiContract.current();
    PlatformApiEndpointDescriptor additiveEndpoint =
        new PlatformApiEndpointDescriptor(
            "future",
            "GET",
            "/future/additive",
            ADDITIVE_CAPABILITY,
            List.of(QUEUE_READ_CAPABILITY),
            false,
            true,
            true,
            PlatformApiStabilityLevel.EXPERIMENTAL,
            laterContractVersion,
            null,
            "Additive future-baseline test endpoint.");
    List<PlatformApiEndpointDescriptor> contractEndpoints = new ArrayList<>(current.endpoints());
    contractEndpoints.add(additiveEndpoint);
    PlatformApiContract contract =
        new PlatformApiContract(
            current.apiVersion(),
            laterContractVersion,
            current.generatedBy(),
            current.stabilityPolicy(),
            current.stableBaseline(),
            PlatformApiCompatibilityWindow.current(laterContractVersion),
            current.capabilities(),
            contractEndpoints);
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    List<PlatformApiBaselineEndpoint> definitionEndpoints = new ArrayList<>(stable10.endpoints());
    definitionEndpoints.add(PlatformApiBaselineEndpoint.fromDescriptor(additiveEndpoint));
    PlatformApiBaselineDefinition definition =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.1"),
            stable10.id(),
            stable10.capabilities(),
            definitionEndpoints,
            DIGEST_A,
            DIGEST_B,
            DIGEST_C,
            DIGEST_D,
            PlatformApiContract.CURRENT_CONTRACT_VERSION);

    PlatformApiContractVerifier.CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verifyBaselineDefinition(definition, contract);

    assertTrue(result.hasErrors());
    assertTrue(
        result.findings().stream()
            .anyMatch(
                finding ->
                    finding
                        .code()
                        .equals("baseline_descriptor_introduced_after_complete_version")));
  }

  private static PlatformApiBaselineDefinition candidateDefinition(
      boolean omitCapability, boolean changeSemantics) {
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    List<String> capabilities = new ArrayList<>(stable10.capabilities());
    if (omitCapability) {
      capabilities.removeLast();
    }
    List<PlatformApiBaselineEndpoint> endpoints = new ArrayList<>();
    for (PlatformApiBaselineEndpoint endpoint : stable10.endpoints()) {
      if (omitCapability && !capabilities.containsAll(endpoint.requiredCapabilities())) {
        continue;
      }
      endpoints.add(endpoint);
    }
    if (changeSemantics) {
      PlatformApiBaselineEndpoint endpoint = endpoints.getFirst();
      endpoints.set(
          0,
          new PlatformApiBaselineEndpoint(
              endpoint.identity(),
              endpoint.routeFamily(),
              endpoint.actionLabel() + ".changed",
              endpoint.requiredCapabilities(),
              endpoint.hostOperatorBypassAllowed(),
              endpoint.appProcessAllowed(),
              endpoint.appBrowserAllowed()));
    }
    return PlatformApiBaselineDefinition.create(
        PlatformApiBaselineId.parse("1.1"),
        PlatformApiBaselineId.parse("1.0"),
        capabilities,
        endpoints,
        DIGEST_A,
        DIGEST_B,
        DIGEST_C,
        DIGEST_D,
        PlatformApiContract.CURRENT_CONTRACT_VERSION);
  }

  private static PlatformApiBaselineDefinition additiveDefinition() {
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineRegistry.current().definitions().getFirst();
    List<String> capabilities = new ArrayList<>(stable10.capabilities());
    capabilities.add(ADDITIVE_CAPABILITY);
    return PlatformApiBaselineDefinition.create(
        PlatformApiBaselineId.parse("1.1"),
        stable10.id(),
        capabilities,
        stable10.endpoints(),
        DIGEST_A,
        DIGEST_B,
        DIGEST_C,
        DIGEST_D,
        PlatformApiContract.CURRENT_CONTRACT_VERSION);
  }

  private static PlatformApiContract contractWithCapability(PlatformApiStabilityLevel stability) {
    return contractWithCapability(
        stability,
        PlatformApiContract.CURRENT_CONTRACT_VERSION,
        PlatformApiContract.CURRENT_CONTRACT_VERSION);
  }

  private static PlatformApiContract contractWithCapability(
      PlatformApiStabilityLevel stability, int contractVersion, int sinceContractVersion) {
    PlatformApiContract current = PlatformApiContract.current();
    List<PlatformApiCapabilityDescriptor> capabilities = new ArrayList<>(current.capabilities());
    capabilities.add(
        new PlatformApiCapabilityDescriptor(
            ADDITIVE_CAPABILITY,
            stability,
            sinceContractVersion,
            null,
            "Additive future-baseline test capability."));
    return new PlatformApiContract(
        current.apiVersion(),
        contractVersion,
        current.generatedBy(),
        current.stabilityPolicy(),
        current.stableBaseline(),
        PlatformApiCompatibilityWindow.current(contractVersion),
        capabilities,
        current.endpoints());
  }

  private static AppApiCompatibilityMetadata stableMetadata(String targetBaseline) {
    return new AppApiCompatibilityMetadata(
        19,
        PlatformApiContract.CURRENT_CONTRACT_VERSION,
        List.of(),
        TargetStability.STABLE,
        true,
        targetBaseline,
        true,
        false,
        true);
  }

  private static void createRegistry(
      PlatformApiBaselineRegistry source, PlatformApiBaselineLineage... appendedLineage) {
    List<PlatformApiBaselineLineage> lineage =
        Stream.concat(source.lineage().stream(), Stream.of(appendedLineage)).toList();
    PlatformApiBaselineRegistry.create(source.definitions(), lineage);
  }

  private static PlatformApiBaselineRegistry registryWithActiveBaseline(
      PlatformApiBaselineDefinition definition) {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>(current.lineage());
    PlatformApiBaselineLineage previous = null;
    for (PlatformApiBaselineStatus status :
        List.of(
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineStatus.CANDIDATE,
            PlatformApiBaselineStatus.REVIEWED,
            PlatformApiBaselineStatus.DOCUMENTED,
            PlatformApiBaselineStatus.ACTIVE)) {
      boolean active = status == PlatformApiBaselineStatus.ACTIVE;
      PlatformApiBaselineLineage next =
          PlatformApiBaselineLineage.create(
              definition.id(),
              definition.definitionDigest(),
              status,
              active
                  ? PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE
                  : PlatformApiBaselineEvidenceKind.FIXTURE,
              active ? "e".repeat(64) : digestForStatus(status),
              active ? "test-protected-release" : null,
              active ? 24 : null,
              active ? "test-protected-release" : null,
              null,
              previous == null ? null : previous.lineageDigest());
      lineage.add(next);
      previous = next;
    }
    List<PlatformApiBaselineDefinition> definitions = new ArrayList<>(current.definitions());
    definitions.add(definition);
    return PlatformApiBaselineRegistry.create(definitions, lineage);
  }

  private static String digestForStatus(PlatformApiBaselineStatus status) {
    return switch (status) {
      case PROPOSED -> DIGEST_A;
      case CANDIDATE -> DIGEST_B;
      case REVIEWED -> DIGEST_C;
      case DOCUMENTED -> DIGEST_D;
      default -> throw new IllegalArgumentException("unsupported fixture status: " + status);
    };
  }

  private static PlatformApiBaselineRegistry registryWithCandidate(
      PlatformApiBaselineRegistry current, PlatformApiBaselineDefinition candidate) {
    PlatformApiBaselineLineage proposed =
        PlatformApiBaselineLineage.create(
            candidate.id(),
            candidate.definitionDigest(),
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            DIGEST_A,
            null,
            null,
            null,
            null,
            null);
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>(current.lineage());
    lineage.add(proposed);
    lineage.add(
        PlatformApiBaselineLineage.create(
            candidate.id(),
            candidate.definitionDigest(),
            PlatformApiBaselineStatus.CANDIDATE,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            DIGEST_B,
            null,
            null,
            null,
            null,
            proposed.lineageDigest()));
    List<PlatformApiBaselineDefinition> definitions = new ArrayList<>(current.definitions());
    definitions.add(candidate);
    return PlatformApiBaselineRegistry.create(definitions, lineage);
  }
}
