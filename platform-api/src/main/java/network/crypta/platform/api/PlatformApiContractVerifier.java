package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

/**
 * Offline verifier for app-declared Platform API compatibility metadata.
 *
 * <p>The verifier is shared by developer tooling, Platform API summaries, and release
 * certification. It checks manifest permissions and advisory {@code api.*} metadata against a
 * deterministic target contract without contacting a running node.
 *
 * <p>Verification has two modes. Non-strict mode is intended for operator-facing install/update
 * review and local development feedback; most compatibility risks become warnings. Strict mode is
 * intended for release gates and explicit CLI verification; future minimum-contract requirements,
 * unknown capabilities, and newer-than-tested targets become errors. Internal capabilities are
 * always errors because app manifests must never request them.
 *
 * <p>The verifier does not mutate manifests, catalogs, or app installation state. It only compares
 * declared metadata and permission names with a supplied contract snapshot, which keeps it usable
 * in offline tooling and repeatable release-certification self-tests.
 */
public final class PlatformApiContractVerifier {
  private static final String STATUS_COMPATIBLE = "compatible";
  private static final String STATUS_BELOW_MINIMUM = "below_minimum";
  private static final String STATUS_NEWER_THAN_TESTED = "newer_than_tested";
  private static final String STATUS_UNKNOWN = "unknown";
  private static final String STATUS_INCOMPATIBLE = "incompatible";
  private static final String STATUS_UNSUPPORTED_BASELINE = "unsupported-baseline";
  private static final String CONTRACT_PARAMETER = "contract";
  private static final String CONTRACT_VERSION_INFIX = " contract ";
  private static final String FINDINGS_FIELD = "findings";
  private static final String FIELD_CONTRACT_VERSION = "contractVersion";
  private static final String FIELD_CURRENT_CONTRACT_VERSION = "currentContractVersion";
  private static final String FIELD_DEPRECATED_SINCE_CONTRACT_VERSION =
      "deprecatedSinceContractVersion";
  private static final String FIELD_REMOVAL_CONTRACT_VERSION = "removalContractVersion";
  private static final String STABLE_ENDPOINT_MESSAGE_PREFIX = "Stable endpoint ";
  private static final String DETAIL_KIND = "kind";
  private static final String DETAIL_IDENTITY = "identity";
  private static final String DETAIL_CAPABILITY = "capability";
  private static final String DETAIL_ENDPOINT = "endpoint";
  private static final String DETAIL_PREVIOUS = "previous";
  private static final String DETAIL_CURRENT = "current";
  private static final String DETAIL_WAIVER_ALLOWED = "waiverAllowed";
  private static final String CODE_STABLE_BASELINE_METADATA_MISSING =
      "stable_baseline_metadata_missing";
  private static final String CODE_STABLE_BASELINE_IDENTITY_CHANGED =
      "stable_baseline_identity_changed";
  private static final String CODE_STABLE_API_CAPABILITY_REMOVED = "stable_api_capability_removed";
  private static final String CODE_STABLE_API_ENDPOINT_REMOVED = "stable_api_endpoint_removed";
  private static final String CODE_STABLE_API_CAPABILITY_RECLASSIFIED =
      "stable_api_capability_reclassified";
  private static final String CODE_STABLE_API_ENDPOINT_RECLASSIFIED =
      "stable_api_endpoint_reclassified";
  private static final String CODE_STABLE_API_ENDPOINT_REQUIRED_CAPABILITIES_CHANGED =
      "stable_api_endpoint_required_capabilities_changed";
  private static final String CODE_STABLE_API_ENDPOINT_APP_PRINCIPAL_CHANGED =
      "stable_api_endpoint_app_principal_changed";
  private static final String CODE_STABLE_API_ENDPOINT_IDENTITY_CHANGED =
      "stable_api_endpoint_identity_changed";
  private static final String CODE_STABLE_API_DEPRECATION_WINDOW_TOO_SHORT =
      "stable_api_deprecation_window_too_short";
  private static final String CODE_STABLE_API_REMOVAL_WINDOW_TOO_SHORT =
      "stable_api_removal_window_too_short";
  private static final String CODE_COMPATIBILITY_WINDOW_METADATA_MISSING =
      "compatibility_window_metadata_missing";
  private static final String CODE_BASELINE_DEFINITION_CHANGED = "baseline_definition_changed";
  private static final String CODE_BASELINE_HISTORY_REWRITTEN = "baseline_history_rewritten";
  private static final String CODE_BASELINE_DESCRIPTOR_MISSING = "baseline_descriptor_missing";
  private static final String CODE_BASELINE_DESCRIPTOR_RESTRICTED =
      "baseline_descriptor_restricted";
  private static final String CODE_BASELINE_DESCRIPTOR_INTRODUCED_AFTER_COMPLETE_VERSION =
      "baseline_descriptor_introduced_after_complete_version";
  private static final String CODE_BASELINE_DESCRIPTOR_SEMANTICS_CHANGED =
      "baseline_descriptor_semantics_changed";
  private static final String CODE_BASELINE_CONTRACT_VERSION_INCOMPLETE =
      "baseline_contract_version_incomplete";
  private static final String CODE_TARGET_BASELINE_INACTIVE = "target_baseline_inactive";

  private PlatformApiContractVerifier() {}

  /**
   * Verifies one app manifest or catalog compatibility declaration.
   *
   * <p>The supplied manifest permissions remain the authoritative capability request. Optional
   * capabilities from {@code apiCompatibility} are checked as advisory metadata only; they do not
   * grant access, and they do not replace {@code app.permissions}. Inputs are sorted before
   * capability checks so repeated runs produce stable finding order.
   *
   * @param apiCompatibility app-declared API compatibility metadata, or {@code null} for old
   *     manifests without {@code api.*} fields
   * @param manifestPermissions authoritative manifest permission request from {@code
   *     app.permissions}
   * @param contract target Platform API contract used for offline comparison
   * @param strict whether compatibility risks that are warnings in review mode should become errors
   * @return deterministic verification result containing all findings in stable order
   */
  public static CompatibilityVerificationResult verify(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract,
      boolean strict) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, CONTRACT_PARAMETER);
    return verify(
        metadata,
        manifestPermissions,
        checkedContract,
        Set.copyOf(checkedContract.stableBaseline().capabilities()),
        strict);
  }

  private static CompatibilityVerificationResult verify(
      AppApiCompatibilityMetadata metadata,
      Collection<String> manifestPermissions,
      PlatformApiContract contract,
      Set<String> stableBaselineCapabilities,
      boolean strict) {
    List<String> permissions = sorted(manifestPermissions);
    Map<String, PlatformApiCapabilityDescriptor> descriptors = contract.capabilitiesByName();
    List<CompatibilityFinding> findings = new ArrayList<>();
    checkTargetStability(metadata, strict, findings);
    checkContractRange(metadata, contract.contractVersion(), strict, findings);
    CapabilityCheckContext capabilityCheck =
        new CapabilityCheckContext(
            "manifest permission",
            "unknown_manifest_permission",
            descriptors,
            Set.copyOf(stableBaselineCapabilities),
            metadata,
            strict,
            findings);
    checkCapabilities(permissions, capabilityCheck);
    checkCapabilities(metadata.optionalCapabilities(), capabilityCheck.forOptionalCapabilities());
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  /**
   * Verifies app compatibility against both an integer contract and named-baseline registry.
   *
   * <p>The target baseline is an admission promise only. This overload delegates all manifest
   * permission checks to the established verifier and adds lifecycle/range findings; it never adds
   * a permission or changes endpoint authorization.
   */
  public static CompatibilityVerificationResult verify(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract,
      PlatformApiBaselineRegistry registry,
      boolean strict) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, CONTRACT_PARAMETER);
    PlatformApiBaselineRegistry checkedRegistry = Objects.requireNonNull(registry, "registry");
    Set<String> targetBaselineCapabilities =
        targetBaselineCapabilities(metadata, checkedContract, checkedRegistry);
    CompatibilityVerificationResult contractResult =
        verify(metadata, manifestPermissions, checkedContract, targetBaselineCapabilities, strict);
    List<CompatibilityFinding> findings = new ArrayList<>(contractResult.findings());
    checkTargetBaseline(metadata, checkedRegistry, strict, findings);
    PlatformApiBaselineDefinition targetDefinition =
        targetBaselineDefinitionForContractValidation(metadata, checkedRegistry);
    if (targetDefinition != null) {
      findings.addAll(verifyBaselineDefinition(targetDefinition, checkedContract).findings());
    }
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  /**
   * Builds the concise API compatibility summary used by Platform API responses.
   *
   * <p>The summary is intentionally smaller than the full verifier output. It exposes the declared
   * version range, the target contract version, optional capabilities, experimental opt-in state, a
   * coarse status, and human-readable warnings. Old apps without compatibility metadata report
   * {@code unknown} rather than failing install or update review.
   *
   * @param apiCompatibility app-declared API compatibility metadata, or {@code null} for legacy
   *     manifests
   * @param manifestPermissions authoritative manifest permission request used for warnings
   * @param contract current or target Platform API contract used for status calculation
   * @return deterministic JSON-compatible summary object for Platform API responses
   */
  public static Map<String, Object> summarize(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, CONTRACT_PARAMETER);
    CompatibilityVerificationResult result =
        verify(metadata, manifestPermissions, checkedContract, false);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("minimumVersion", metadata.minimumVersion());
    json.put("maximumTestedVersion", metadata.maximumTestedVersion());
    json.put("currentVersion", checkedContract.contractVersion());
    json.put("optionalCapabilities", metadata.optionalCapabilities());
    json.put("targetStability", metadata.targetStability().manifestValue());
    json.put("targetStabilityDeclared", metadata.targetStabilityDeclared());
    json.put("experimentalCapabilitiesAccepted", metadata.experimentalCapabilitiesAccepted());
    json.put("declared", metadata.declared());
    json.put("status", status(metadata, checkedContract.contractVersion(), result));
    json.put("warnings", result.messages());
    return json;
  }

  /** Builds a compatibility summary including named-baseline admission metadata. */
  public static Map<String, Object> summarize(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract,
      PlatformApiBaselineRegistry registry) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, CONTRACT_PARAMETER);
    PlatformApiBaselineRegistry checkedRegistry = Objects.requireNonNull(registry, "registry");
    CompatibilityVerificationResult result =
        verify(metadata, manifestPermissions, checkedContract, checkedRegistry, false);
    LinkedHashMap<String, Object> json =
        new LinkedHashMap<>(summarize(metadata, manifestPermissions, checkedContract));
    json.put("targetBaseline", metadata.targetBaseline());
    json.put("targetBaselineDeclared", metadata.targetBaselineDeclared());
    json.put(
        "supportedBaselines",
        checkedRegistry.supportedBaselineIds().stream()
            .map(PlatformApiBaselineId::toString)
            .toList());
    json.put("baselineRegistryDigest", checkedRegistry.registryDigest());
    json.put("status", baselineStatus(metadata, checkedContract.contractVersion(), result));
    json.put("warnings", result.messages());
    return Collections.unmodifiableMap(json);
  }

  /**
   * Compares two contract snapshots for stable Platform API 1.0 breaking changes.
   *
   * <p>The comparison uses the previous snapshot's stable baseline as the compatibility promise.
   * Removing a stable capability or endpoint, moving it out of the stable app-facing baseline,
   * changing endpoint identity, changing the required capability set or app-principal access flags,
   * and violating deprecation/removal windows produce deterministic stable finding codes. Missing
   * baseline metadata is reported separately so release certification can fail closed for malformed
   * current snapshots.
   *
   * @param previousContract previous production or certified contract snapshot
   * @param currentContract current candidate contract snapshot
   * @return deterministic stable-baseline comparison findings
   */
  public static CompatibilityVerificationResult compareStableBaseline(
      PlatformApiContract previousContract, PlatformApiContract currentContract) {
    return compareStableBaseline(previousContract, currentContract, false, true, true, true, true);
  }

  /**
   * Compares two contract snapshots with explicit metadata-presence policy.
   *
   * <p>Callers that load raw snapshot files can pass whether the previous and current JSON
   * explicitly carried stable-baseline metadata. Developer dry-runs may allow older pre-freeze
   * snapshots with a warning; production beta must fail closed when previous or current stable
   * baseline metadata is unavailable.
   *
   * @param previousContract previous production or certified contract snapshot
   * @param currentContract current candidate contract snapshot
   * @param productionMode whether missing metadata should be a release-blocking error
   * @param previousStableBaselineMetadataPresent whether the previous raw snapshot included
   *     stableBaseline metadata
   * @param currentStableBaselineMetadataPresent whether the current raw snapshot included
   *     stableBaseline metadata
   * @return deterministic stable-baseline comparison findings
   */
  public static CompatibilityVerificationResult compareStableBaseline(
      PlatformApiContract previousContract,
      PlatformApiContract currentContract,
      boolean productionMode,
      boolean previousStableBaselineMetadataPresent,
      boolean currentStableBaselineMetadataPresent) {
    return compareStableBaseline(
        previousContract,
        currentContract,
        productionMode,
        previousStableBaselineMetadataPresent,
        currentStableBaselineMetadataPresent,
        true,
        true);
  }

  /**
   * Compares two contract snapshots with explicit stable-baseline and compatibility-window metadata
   * presence policy.
   *
   * <p>Raw snapshots from before PR-274 may parse because the JSON parser synthesizes default
   * compatibility-window metadata. Production beta cannot rely on synthesized history, so callers
   * that read raw JSON should pass whether the fields were present in the source documents.
   *
   * @param previousContract previous production or certified contract snapshot
   * @param currentContract current candidate contract snapshot
   * @param productionMode whether missing metadata should be a release-blocking error
   * @param previousStableBaselineMetadataPresent whether the previous raw snapshot included
   *     stableBaseline metadata
   * @param currentStableBaselineMetadataPresent whether the current raw snapshot included
   *     stableBaseline metadata
   * @param previousCompatibilityWindowMetadataPresent whether the previous raw snapshot included
   *     compatibilityWindow metadata
   * @param currentCompatibilityWindowMetadataPresent whether the current raw snapshot included
   *     compatibilityWindow metadata
   * @return deterministic stable-baseline comparison findings
   */
  public static CompatibilityVerificationResult compareStableBaseline(
      PlatformApiContract previousContract,
      PlatformApiContract currentContract,
      boolean productionMode,
      boolean previousStableBaselineMetadataPresent,
      boolean currentStableBaselineMetadataPresent,
      boolean previousCompatibilityWindowMetadataPresent,
      boolean currentCompatibilityWindowMetadataPresent) {
    PlatformApiContract previous = Objects.requireNonNull(previousContract, "previousContract");
    PlatformApiContract current = Objects.requireNonNull(currentContract, "currentContract");
    List<CompatibilityFinding> findings = new ArrayList<>();
    SnapshotMetadataPresence metadataPresence =
        new SnapshotMetadataPresence(
            previousStableBaselineMetadataPresent,
            currentStableBaselineMetadataPresent,
            previousCompatibilityWindowMetadataPresent,
            currentCompatibilityWindowMetadataPresent);
    checkStableBaselineMetadata(previous, current, productionMode, metadataPresence, findings);
    compareStableCapabilities(previous, current, findings);
    compareStableEndpoints(previous, current, findings);
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  /**
   * Verifies that a named-baseline definition is an exact projection of one contract snapshot.
   *
   * <p>This check does not activate the definition. Experimental app-facing descriptors may be
   * present in a future candidate definition only after the separate graduation authority has
   * approved them; operator-only and internal descriptors are always rejected here. Endpoint
   * findings compare the authorization semantics that a compatible 1.x successor must inherit.
   *
   * @param definition immutable named-baseline definition to inspect
   * @param contract exact contract snapshot that is claimed to carry the definition
   * @return deterministic descriptor and semantics findings
   */
  public static CompatibilityVerificationResult verifyBaselineDefinition(
      PlatformApiBaselineDefinition definition, PlatformApiContract contract) {
    PlatformApiBaselineDefinition checkedDefinition =
        Objects.requireNonNull(definition, "definition");
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, CONTRACT_PARAMETER);
    List<CompatibilityFinding> findings = new ArrayList<>();
    if (checkedContract.contractVersion() < checkedDefinition.firstCompleteContractVersion()) {
      findings.add(
          finding(
              CODE_BASELINE_CONTRACT_VERSION_INCOMPLETE,
              CompatibilityFindingSeverity.ERROR,
              "Target contract predates the complete baseline definition: "
                  + checkedDefinition.id()
                  + ".",
              detail(
                  "baseline",
                  checkedDefinition.id().toString(),
                  "firstCompleteContractVersion",
                  checkedDefinition.firstCompleteContractVersion(),
                  FIELD_CONTRACT_VERSION,
                  checkedContract.contractVersion())));
    }
    checkBaselineCapabilities(checkedDefinition, checkedContract, findings);
    checkBaselineEndpoints(checkedDefinition, checkedContract, findings);
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  private static void checkBaselineCapabilities(
      PlatformApiBaselineDefinition definition,
      PlatformApiContract contract,
      List<CompatibilityFinding> findings) {
    Map<String, PlatformApiCapabilityDescriptor> capabilities = contract.capabilitiesByName();
    for (String capability : definition.capabilities()) {
      PlatformApiCapabilityDescriptor descriptor = capabilities.get(capability);
      if (descriptor == null) {
        findings.add(
            finding(
                CODE_BASELINE_DESCRIPTOR_MISSING,
                CompatibilityFindingSeverity.ERROR,
                "Baseline capability is absent from the target contract: " + capability + ".",
                detail(DETAIL_KIND, DETAIL_CAPABILITY, DETAIL_IDENTITY, capability)));
        continue;
      }
      checkBaselineMemberIntroductionVersion(
          DETAIL_CAPABILITY,
          capability,
          descriptor.sinceContractVersion(),
          definition.firstCompleteContractVersion(),
          findings);
      if (descriptor.stability().isRestrictedAudience()) {
        findings.add(
            finding(
                CODE_BASELINE_DESCRIPTOR_RESTRICTED,
                CompatibilityFindingSeverity.ERROR,
                "Restricted capability cannot enter an app stable baseline: " + capability + ".",
                detail(DETAIL_KIND, DETAIL_CAPABILITY, DETAIL_IDENTITY, capability)));
      }
    }
  }

  private static void checkBaselineEndpoints(
      PlatformApiBaselineDefinition definition,
      PlatformApiContract contract,
      List<CompatibilityFinding> findings) {
    Map<String, PlatformApiEndpointDescriptor> endpoints = endpointsByIdentity(contract);
    for (PlatformApiBaselineEndpoint expected : definition.endpoints()) {
      checkBaselineEndpoint(definition, expected, endpoints.get(expected.identity()), findings);
    }
  }

  private static void checkBaselineEndpoint(
      PlatformApiBaselineDefinition definition,
      PlatformApiBaselineEndpoint expected,
      PlatformApiEndpointDescriptor descriptor,
      List<CompatibilityFinding> findings) {
    if (descriptor == null) {
      findings.add(
          finding(
              CODE_BASELINE_DESCRIPTOR_MISSING,
              CompatibilityFindingSeverity.ERROR,
              "Baseline endpoint is absent from the target contract: " + expected.identity() + ".",
              detail(DETAIL_KIND, DETAIL_ENDPOINT, DETAIL_IDENTITY, expected.identity())));
      return;
    }
    checkBaselineMemberIntroductionVersion(
        DETAIL_ENDPOINT,
        expected.identity(),
        descriptor.sinceContractVersion(),
        definition.firstCompleteContractVersion(),
        findings);
    boolean restricted =
        descriptor.stability().isRestrictedAudience()
            || (!descriptor.appProcessAllowed() && !descriptor.appBrowserAllowed());
    if (restricted) {
      findings.add(
          finding(
              CODE_BASELINE_DESCRIPTOR_RESTRICTED,
              CompatibilityFindingSeverity.ERROR,
              "Restricted endpoint cannot enter an app stable baseline: "
                  + expected.identity()
                  + ".",
              detail(DETAIL_KIND, DETAIL_ENDPOINT, DETAIL_IDENTITY, expected.identity())));
      return;
    }
    PlatformApiBaselineEndpoint actual = PlatformApiBaselineEndpoint.fromDescriptor(descriptor);
    if (!expected.equals(actual)) {
      findings.add(
          finding(
              CODE_BASELINE_DESCRIPTOR_SEMANTICS_CHANGED,
              CompatibilityFindingSeverity.ERROR,
              "Baseline endpoint semantics do not match the target contract: "
                  + expected.identity()
                  + ".",
              detail(DETAIL_KIND, DETAIL_ENDPOINT, DETAIL_IDENTITY, expected.identity())));
    }
  }

  private static void checkBaselineMemberIntroductionVersion(
      String kind,
      String identity,
      int sinceContractVersion,
      int firstCompleteContractVersion,
      List<CompatibilityFinding> findings) {
    if (sinceContractVersion <= firstCompleteContractVersion) {
      return;
    }
    findings.add(
        finding(
            CODE_BASELINE_DESCRIPTOR_INTRODUCED_AFTER_COMPLETE_VERSION,
            CompatibilityFindingSeverity.ERROR,
            "Baseline "
                + kind
                + " was introduced after the claimed complete contract version: "
                + identity
                + ".",
            detail(
                DETAIL_KIND,
                kind,
                DETAIL_IDENTITY,
                identity,
                "sinceContractVersion",
                sinceContractVersion,
                "firstCompleteContractVersion",
                firstCompleteContractVersion)));
  }

  /**
   * Compares two valid registries for append-only lifecycle and immutable-definition history.
   *
   * <p>Registry construction already checks lineage gaps and monotonic compatibility with every
   * supported predecessor. This comparison additionally prevents a later artifact from dropping or
   * replacing an earlier definition or lifecycle record.
   *
   * @param previousRegistry authenticated previous registry
   * @param currentRegistry current candidate registry
   * @return deterministic history-rewrite findings
   */
  public static CompatibilityVerificationResult compareBaselineRegistries(
      PlatformApiBaselineRegistry previousRegistry, PlatformApiBaselineRegistry currentRegistry) {
    PlatformApiBaselineRegistry previous =
        Objects.requireNonNull(previousRegistry, "previousRegistry");
    PlatformApiBaselineRegistry current =
        Objects.requireNonNull(currentRegistry, "currentRegistry");
    List<CompatibilityFinding> findings = new ArrayList<>();
    Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> currentDefinitions =
        current.definitionsById();
    for (PlatformApiBaselineDefinition oldDefinition : previous.definitions()) {
      PlatformApiBaselineDefinition candidate = currentDefinitions.get(oldDefinition.id());
      if (candidate == null
          || !oldDefinition.definitionDigest().equals(candidate.definitionDigest())) {
        findings.add(
            finding(
                CODE_BASELINE_DEFINITION_CHANGED,
                CompatibilityFindingSeverity.ERROR,
                "An existing baseline definition was removed or edited: "
                    + oldDefinition.id()
                    + ".",
                detail(DETAIL_IDENTITY, oldDefinition.id().toString())));
      }
    }
    if (current.lineage().size() < previous.lineage().size()
        || !current.lineage().subList(0, previous.lineage().size()).equals(previous.lineage())) {
      findings.add(
          finding(
              CODE_BASELINE_HISTORY_REWRITTEN,
              CompatibilityFindingSeverity.ERROR,
              "Platform API baseline lifecycle history is not an append-only extension."));
    }
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  private static void checkStableBaselineMetadata(
      PlatformApiContract previous,
      PlatformApiContract current,
      boolean productionMode,
      SnapshotMetadataPresence metadataPresence,
      List<CompatibilityFinding> findings) {
    if (current.stableBaseline().capabilityCount() == 0
        || current.stableBaseline().endpointCount() == 0
        || !metadataPresence.currentStableBaselineMetadataPresent()) {
      findings.add(
          finding(
              CODE_STABLE_BASELINE_METADATA_MISSING,
              CompatibilityFindingSeverity.ERROR,
              "Current Platform API contract does not publish usable stable baseline metadata.",
              detail(DETAIL_KIND, DETAIL_CURRENT)));
    }
    if (!metadataPresence.previousStableBaselineMetadataPresent()) {
      findings.add(
          finding(
              CODE_STABLE_BASELINE_METADATA_MISSING,
              productionMode
                  ? CompatibilityFindingSeverity.ERROR
                  : CompatibilityFindingSeverity.WARNING,
              "Previous Platform API contract did not publish stable baseline metadata; "
                  + "production beta requires previous stable-baseline history.",
              detail(DETAIL_KIND, DETAIL_PREVIOUS)));
    }
    checkCompatibilityWindowMetadata(
        DETAIL_PREVIOUS,
        metadataPresence.previousCompatibilityWindowMetadataPresent(),
        productionMode,
        findings);
    checkCompatibilityWindowMetadata(
        DETAIL_CURRENT,
        metadataPresence.currentCompatibilityWindowMetadataPresent(),
        productionMode,
        findings);
    if (!previous.stableBaseline().name().equals(current.stableBaseline().name())
        || previous.stableBaseline().contractVersion()
            != current.stableBaseline().contractVersion()) {
      findings.add(
          finding(
              CODE_STABLE_BASELINE_IDENTITY_CHANGED,
              CompatibilityFindingSeverity.ERROR,
              "Stable baseline identity changed from "
                  + previous.stableBaseline().name()
                  + CONTRACT_VERSION_INFIX
                  + previous.stableBaseline().contractVersion()
                  + " to "
                  + current.stableBaseline().name()
                  + CONTRACT_VERSION_INFIX
                  + current.stableBaseline().contractVersion()
                  + ".",
              detail(
                  DETAIL_PREVIOUS,
                  baselineIdentity(previous),
                  DETAIL_CURRENT,
                  baselineIdentity(current))));
    }
    PlatformApiCompatibilityWindow window = current.compatibilityWindow();
    if (!window.baselineName().equals(current.stableBaseline().name())
        || window.baselineContractVersion() != current.stableBaseline().contractVersion()) {
      findings.add(
          finding(
              CODE_STABLE_BASELINE_IDENTITY_CHANGED,
              CompatibilityFindingSeverity.ERROR,
              "Compatibility-window baseline identity does not match stableBaseline metadata.",
              detail(DETAIL_CURRENT, window.baselineName())));
    }
  }

  private static void checkCompatibilityWindowMetadata(
      String side,
      boolean compatibilityWindowMetadataPresent,
      boolean productionMode,
      List<CompatibilityFinding> findings) {
    if (compatibilityWindowMetadataPresent) {
      return;
    }
    findings.add(
        finding(
            CODE_COMPATIBILITY_WINDOW_METADATA_MISSING,
            productionMode
                ? CompatibilityFindingSeverity.ERROR
                : CompatibilityFindingSeverity.WARNING,
            Character.toUpperCase(side.charAt(0))
                + side.substring(1)
                + " Platform API contract did not publish compatibility-window metadata; "
                + "production beta requires explicit compatibility-window history.",
            detail(DETAIL_KIND, side, "metadata", "compatibilityWindow")));
  }

  private static void compareStableCapabilities(
      PlatformApiContract previous,
      PlatformApiContract current,
      List<CompatibilityFinding> findings) {
    Map<String, PlatformApiCapabilityDescriptor> currentCapabilities = current.capabilitiesByName();
    for (String capability : previous.stableBaseline().capabilities()) {
      PlatformApiCapabilityDescriptor descriptor = currentCapabilities.get(capability);
      if (descriptor == null) {
        findings.add(
            stableFinding(
                CODE_STABLE_API_CAPABILITY_REMOVED,
                "Stable capability was removed: " + capability + ".",
                detail(
                    DETAIL_KIND,
                    DETAIL_CAPABILITY,
                    DETAIL_CAPABILITY,
                    capability,
                    DETAIL_WAIVER_ALLOWED,
                    false)));
      } else if (!PlatformApiContract.isStableBaselineCapability(descriptor)) {
        findings.add(
            stableFinding(
                CODE_STABLE_API_CAPABILITY_RECLASSIFIED,
                "Stable capability "
                    + capability
                    + " moved out of the Platform API 1.0 stable baseline as "
                    + descriptor.stability().jsonValue()
                    + ".",
                detail(
                    DETAIL_KIND,
                    DETAIL_CAPABILITY,
                    DETAIL_CAPABILITY,
                    capability,
                    DETAIL_CURRENT,
                    descriptor.stability().jsonValue())));
      } else {
        checkStableCapabilityDeprecationPolicy(
            capability, descriptor.stability(), descriptor.deprecation(), current, findings);
      }
    }
  }

  private static void compareStableEndpoints(
      PlatformApiContract previous,
      PlatformApiContract current,
      List<CompatibilityFinding> findings) {
    Map<String, PlatformApiEndpointDescriptor> previousEndpoints =
        previous.stableBaselineEndpointsByIdentity();
    Map<String, PlatformApiEndpointDescriptor> currentEndpoints =
        current.stableBaselineEndpointsByIdentity();
    Map<String, PlatformApiEndpointDescriptor> allCurrentEndpoints = endpointsByIdentity(current);
    for (Map.Entry<String, PlatformApiEndpointDescriptor> previousEntry :
        previousEndpoints.entrySet()) {
      compareStableEndpoint(
          previousEntry,
          current,
          previousEndpoints,
          currentEndpoints,
          allCurrentEndpoints,
          findings);
    }
  }

  private static void compareStableEndpoint(
      Map.Entry<String, PlatformApiEndpointDescriptor> previousEntry,
      PlatformApiContract current,
      Map<String, PlatformApiEndpointDescriptor> previousEndpoints,
      Map<String, PlatformApiEndpointDescriptor> currentEndpoints,
      Map<String, PlatformApiEndpointDescriptor> allCurrentEndpoints,
      List<CompatibilityFinding> findings) {
    String identity = previousEntry.getKey();
    PlatformApiEndpointDescriptor currentStable = currentEndpoints.get(identity);
    if (currentStable == null) {
      reportMissingStableEndpoint(
          identity,
          previousEntry.getValue(),
          allCurrentEndpoints.get(identity),
          previousEndpoints,
          allCurrentEndpoints,
          findings);
      return;
    }
    PlatformApiEndpointDescriptor previousStable = previousEntry.getValue();
    compareStableEndpointShape(identity, previousStable, currentStable, findings);
    checkStableDescriptorDeprecationPolicy(
        DETAIL_ENDPOINT,
        identity,
        currentStable.stability(),
        currentStable.deprecation(),
        current.contractVersion(),
        current.compatibilityWindow(),
        findings);
  }

  private static void reportMissingStableEndpoint(
      String identity,
      PlatformApiEndpointDescriptor previousStable,
      PlatformApiEndpointDescriptor currentAny,
      Map<String, PlatformApiEndpointDescriptor> previousEndpoints,
      Map<String, PlatformApiEndpointDescriptor> allCurrentEndpoints,
      List<CompatibilityFinding> findings) {
    PlatformApiEndpointDescriptor currentByAction =
        uniqueCurrentEndpointByActionLabel(
            previousStable.actionLabel(), previousEndpoints.values(), allCurrentEndpoints.values());
    if (currentAny == null) {
      if (currentByAction != null) {
        findings.add(
            stableFinding(
                CODE_STABLE_API_ENDPOINT_IDENTITY_CHANGED,
                STABLE_ENDPOINT_MESSAGE_PREFIX
                    + identity
                    + " changed method or route identity to "
                    + PlatformApiContract.endpointIdentity(currentByAction)
                    + ".",
                detail(
                    DETAIL_KIND,
                    DETAIL_ENDPOINT,
                    DETAIL_PREVIOUS,
                    identity,
                    DETAIL_CURRENT,
                    PlatformApiContract.endpointIdentity(currentByAction))));
        return;
      }
      findings.add(
          stableFinding(
              CODE_STABLE_API_ENDPOINT_REMOVED,
              STABLE_ENDPOINT_MESSAGE_PREFIX + "was removed: " + identity + ".",
              detail(
                  DETAIL_KIND,
                  DETAIL_ENDPOINT,
                  DETAIL_ENDPOINT,
                  identity,
                  DETAIL_WAIVER_ALLOWED,
                  false)));
      return;
    }
    findings.add(
        stableFinding(
            CODE_STABLE_API_ENDPOINT_RECLASSIFIED,
            STABLE_ENDPOINT_MESSAGE_PREFIX
                + identity
                + " moved out of the Platform API 1.0 stable baseline as "
                + currentAny.stability().jsonValue()
                + ".",
            detail(
                DETAIL_KIND,
                DETAIL_ENDPOINT,
                DETAIL_ENDPOINT,
                identity,
                DETAIL_CURRENT,
                currentAny.stability().jsonValue())));
  }

  private static PlatformApiEndpointDescriptor uniqueCurrentEndpointByActionLabel(
      String actionLabel,
      Collection<PlatformApiEndpointDescriptor> previousEndpoints,
      Collection<PlatformApiEndpointDescriptor> currentEndpoints) {
    if (endpointActionLabelCount(actionLabel, previousEndpoints) != 1) {
      return null;
    }
    PlatformApiEndpointDescriptor match = null;
    for (PlatformApiEndpointDescriptor endpoint : currentEndpoints) {
      if (endpoint.actionLabel().equals(actionLabel)) {
        if (match != null) {
          return null;
        }
        match = endpoint;
      }
    }
    return match;
  }

  private static int endpointActionLabelCount(
      String actionLabel, Collection<PlatformApiEndpointDescriptor> endpoints) {
    int count = 0;
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      if (endpoint.actionLabel().equals(actionLabel)) {
        count++;
      }
    }
    return count;
  }

  private static void compareStableEndpointShape(
      String identity,
      PlatformApiEndpointDescriptor previousStable,
      PlatformApiEndpointDescriptor currentStable,
      List<CompatibilityFinding> findings) {
    if (!previousStable.actionLabel().equals(currentStable.actionLabel())) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_ENDPOINT_IDENTITY_CHANGED,
              STABLE_ENDPOINT_MESSAGE_PREFIX
                  + identity
                  + " changed action label from "
                  + previousStable.actionLabel()
                  + " to "
                  + currentStable.actionLabel()
                  + ".",
              detail(
                  DETAIL_KIND,
                  DETAIL_ENDPOINT,
                  DETAIL_ENDPOINT,
                  identity,
                  DETAIL_PREVIOUS,
                  previousStable.actionLabel(),
                  DETAIL_CURRENT,
                  currentStable.actionLabel())));
    }
    if (!previousStable.requiredCapabilities().equals(currentStable.requiredCapabilities())) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_ENDPOINT_REQUIRED_CAPABILITIES_CHANGED,
              STABLE_ENDPOINT_MESSAGE_PREFIX
                  + identity
                  + " changed required capabilities from "
                  + previousStable.requiredCapabilities()
                  + " to "
                  + currentStable.requiredCapabilities()
                  + ".",
              detail(
                  DETAIL_KIND,
                  DETAIL_ENDPOINT,
                  DETAIL_ENDPOINT,
                  identity,
                  DETAIL_PREVIOUS,
                  previousStable.requiredCapabilities(),
                  DETAIL_CURRENT,
                  currentStable.requiredCapabilities())));
    }
    if (previousStable.appProcessAllowed() != currentStable.appProcessAllowed()
        || previousStable.appBrowserAllowed() != currentStable.appBrowserAllowed()) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_ENDPOINT_APP_PRINCIPAL_CHANGED,
              STABLE_ENDPOINT_MESSAGE_PREFIX
                  + identity
                  + " changed app-principal access from process="
                  + previousStable.appProcessAllowed()
                  + ", browser="
                  + previousStable.appBrowserAllowed()
                  + " to process="
                  + currentStable.appProcessAllowed()
                  + ", browser="
                  + currentStable.appBrowserAllowed()
                  + ".",
              detail(
                  DETAIL_KIND,
                  DETAIL_ENDPOINT,
                  DETAIL_ENDPOINT,
                  identity,
                  DETAIL_PREVIOUS,
                  endpointAccess(previousStable),
                  DETAIL_CURRENT,
                  endpointAccess(currentStable))));
    }
  }

  private static void checkStableCapabilityDeprecationPolicy(
      String identity,
      PlatformApiStabilityLevel stability,
      PlatformApiDeprecation deprecation,
      PlatformApiContract current,
      List<CompatibilityFinding> findings) {
    checkStableDescriptorDeprecationPolicy(
        DETAIL_CAPABILITY,
        identity,
        stability,
        deprecation,
        current.contractVersion(),
        current.compatibilityWindow(),
        findings);
  }

  private static void checkStableDescriptorDeprecationPolicy(
      String kind,
      String identity,
      PlatformApiStabilityLevel stability,
      PlatformApiDeprecation deprecation,
      int currentContractVersion,
      PlatformApiCompatibilityWindow policy,
      List<CompatibilityFinding> findings) {
    if (stability != PlatformApiStabilityLevel.DEPRECATED
        && stability != PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL) {
      return;
    }
    Integer deprecatedSince =
        deprecation == null ? null : deprecation.deprecatedSinceContractVersion();
    Integer removalVersion = deprecation == null ? null : deprecation.removalContractVersion();
    if (deprecatedSince == null) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_DEPRECATION_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " is "
                  + stability.jsonValue()
                  + " without "
                  + FIELD_DEPRECATED_SINCE_CONTRACT_VERSION
                  + " metadata.",
              detail(DETAIL_KIND, kind, DETAIL_IDENTITY, identity)));
      return;
    }
    if (deprecatedSince > currentContractVersion) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_DEPRECATION_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " "
                  + FIELD_DEPRECATED_SINCE_CONTRACT_VERSION
                  + " "
                  + deprecatedSince
                  + " is greater than current contract version "
                  + currentContractVersion
                  + ".",
              detail(
                  DETAIL_KIND,
                  kind,
                  DETAIL_IDENTITY,
                  identity,
                  FIELD_DEPRECATED_SINCE_CONTRACT_VERSION,
                  deprecatedSince,
                  FIELD_CURRENT_CONTRACT_VERSION,
                  currentContractVersion)));
      return;
    }
    if (stability == PlatformApiStabilityLevel.DEPRECATED && removalVersion == null) {
      findings.add(
          finding(
              "stable_api_deprecation_warning",
              CompatibilityFindingSeverity.WARNING,
              stableItemLabel(kind, identity)
                  + " is deprecated since contract "
                  + deprecatedSince
                  + ".",
              detail(DETAIL_KIND, kind, DETAIL_IDENTITY, identity)));
      return;
    }
    if (removalVersion == null) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_REMOVAL_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " is scheduled for removal without "
                  + FIELD_REMOVAL_CONTRACT_VERSION
                  + " metadata.",
              detail(DETAIL_KIND, kind, DETAIL_IDENTITY, identity)));
      return;
    }
    if (removalVersion <= deprecatedSince) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_DEPRECATION_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " "
                  + FIELD_REMOVAL_CONTRACT_VERSION
                  + " must be greater than "
                  + FIELD_DEPRECATED_SINCE_CONTRACT_VERSION
                  + ".",
              detail(
                  DETAIL_KIND,
                  kind,
                  DETAIL_IDENTITY,
                  identity,
                  FIELD_DEPRECATED_SINCE_CONTRACT_VERSION,
                  deprecatedSince,
                  FIELD_REMOVAL_CONTRACT_VERSION,
                  removalVersion)));
      return;
    }
    int deprecationWindow = removalVersion - deprecatedSince;
    if (deprecationWindow < policy.minimumDeprecationWindowContractVersions()) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_DEPRECATION_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " deprecation window is "
                  + deprecationWindow
                  + " contract version(s), below the policy minimum of "
                  + policy.minimumDeprecationWindowContractVersions()
                  + ".",
              detail(
                  DETAIL_KIND,
                  kind,
                  DETAIL_IDENTITY,
                  identity,
                  "windowContractVersions",
                  deprecationWindow,
                  "minimum",
                  policy.minimumDeprecationWindowContractVersions())));
    }
    int removalRunway = removalVersion - currentContractVersion;
    if (removalRunway < policy.minimumScheduledRemovalWindowContractVersions()) {
      findings.add(
          stableFinding(
              CODE_STABLE_API_REMOVAL_WINDOW_TOO_SHORT,
              stableItemLabel(kind, identity)
                  + " scheduled-removal runway is "
                  + removalRunway
                  + " contract version(s), below the policy minimum of "
                  + policy.minimumScheduledRemovalWindowContractVersions()
                  + ".",
              detail(
                  DETAIL_KIND,
                  kind,
                  DETAIL_IDENTITY,
                  identity,
                  "runwayContractVersions",
                  removalRunway,
                  "minimum",
                  policy.minimumScheduledRemovalWindowContractVersions())));
      return;
    }
    findings.add(
        finding(
            "stable_api_scheduled_removal_warning",
            CompatibilityFindingSeverity.WARNING,
            stableItemLabel(kind, identity)
                + " is scheduled for removal in contract "
                + removalVersion
                + ".",
            detail(
                DETAIL_KIND,
                kind,
                DETAIL_IDENTITY,
                identity,
                FIELD_DEPRECATED_SINCE_CONTRACT_VERSION,
                deprecatedSince,
                FIELD_REMOVAL_CONTRACT_VERSION,
                removalVersion)));
  }

  private static Map<String, PlatformApiEndpointDescriptor> endpointsByIdentity(
      PlatformApiContract contract) {
    LinkedHashMap<String, PlatformApiEndpointDescriptor> byIdentity = new LinkedHashMap<>();
    for (PlatformApiEndpointDescriptor endpoint : contract.endpoints()) {
      byIdentity.put(PlatformApiContract.endpointIdentity(endpoint), endpoint);
    }
    return java.util.Collections.unmodifiableMap(byIdentity);
  }

  private static CompatibilityFinding stableFinding(
      String code, String message, Map<String, Object> details) {
    return finding(code, CompatibilityFindingSeverity.ERROR, message, details);
  }

  private static Map<String, Object> baselineIdentity(PlatformApiContract contract) {
    return detail(
        "name",
        contract.stableBaseline().name(),
        FIELD_CONTRACT_VERSION,
        contract.stableBaseline().contractVersion());
  }

  private static Map<String, Object> endpointAccess(PlatformApiEndpointDescriptor endpoint) {
    return detail(
        "appProcessPrincipalsAllowed",
        endpoint.appProcessAllowed(),
        "appBrowserPrincipalsAllowed",
        endpoint.appBrowserAllowed());
  }

  private static String stableItemLabel(String kind, String identity) {
    return (DETAIL_CAPABILITY.equals(kind) ? "Stable capability " : STABLE_ENDPOINT_MESSAGE_PREFIX)
        + identity;
  }

  private static Map<String, Object> detail(Object... keyValues) {
    if (keyValues.length % 2 != 0) {
      throw new IllegalArgumentException("detail requires key/value pairs");
    }
    LinkedHashMap<String, Object> details = LinkedHashMap.newLinkedHashMap(keyValues.length / 2);
    for (int index = 0; index < keyValues.length; index += 2) {
      Object key = keyValues[index];
      if (!(key instanceof String name) || name.isBlank()) {
        throw new IllegalArgumentException("detail key must be a non-blank string");
      }
      details.put(name, keyValues[index + 1]);
    }
    return Collections.unmodifiableMap(details);
  }

  private static void checkTargetStability(
      AppApiCompatibilityMetadata metadata, boolean strict, List<CompatibilityFinding> findings) {
    if (!metadata.declared() || metadata.targetStabilityDeclared()) {
      return;
    }
    findings.add(
        finding(
            "api_target_stability_missing",
            releaseRiskSeverity(strict),
            "api.targetStability is missing; legacy manifests default to experimental"
                + " compatibility review."));
  }

  private static void checkContractRange(
      AppApiCompatibilityMetadata metadata,
      int targetContractVersion,
      boolean strict,
      List<CompatibilityFinding> findings) {
    Integer minimumVersion = metadata.minimumVersion();
    if (minimumVersion != null && minimumVersion > targetContractVersion) {
      findings.add(
          finding(
              "minimum_version_above_target",
              releaseRiskSeverity(strict),
              "App requires Platform API contract "
                  + minimumVersion
                  + " but target contract is "
                  + targetContractVersion
                  + "."));
    }
    Integer maximumTestedVersion = metadata.maximumTestedVersion();
    if (maximumTestedVersion != null && maximumTestedVersion < targetContractVersion) {
      findings.add(
          finding(
              "target_newer_than_tested",
              releaseRiskSeverity(strict),
              "Target Platform API contract "
                  + targetContractVersion
                  + " is newer than the app's maximum tested contract "
                  + maximumTestedVersion
                  + "."));
    }
  }

  private static void checkTargetBaseline(
      AppApiCompatibilityMetadata metadata,
      PlatformApiBaselineRegistry registry,
      boolean strict,
      List<CompatibilityFinding> findings) {
    String target = metadata.targetBaseline();
    if (target == null) {
      return;
    }
    PlatformApiBaselineId id;
    try {
      id = PlatformApiBaselineId.parse(target);
    } catch (IllegalArgumentException _) {
      findings.add(
          finding(
              "target_baseline_malformed",
              CompatibilityFindingSeverity.ERROR,
              "App target baseline is malformed: " + target + "."));
      return;
    }
    PlatformApiBaselineDefinition definition = registry.definitionsById().get(id);
    PlatformApiBaselineLineage lifecycle = registry.latestLineageById().get(id);
    if (definition == null || lifecycle == null) {
      findings.add(
          finding(
              "target_baseline_unknown",
              CompatibilityFindingSeverity.ERROR,
              "App targets an unknown Platform API baseline: " + id + "."));
      return;
    }
    switch (lifecycle.status()) {
      case END_OF_SUPPORT ->
          findings.add(
              finding(
                  "target_baseline_end_of_support",
                  CompatibilityFindingSeverity.ERROR,
                  "App targets a Platform API baseline that reached end of support: " + id + "."));
      case REJECTED ->
          findings.add(
              finding(
                  CODE_TARGET_BASELINE_INACTIVE,
                  CompatibilityFindingSeverity.ERROR,
                  "App targets a rejected Platform API baseline: " + id + "."));
      case PROPOSED, CANDIDATE, REVIEWED, DOCUMENTED -> {
        if (metadata.targetStability() == TargetStability.STABLE) {
          findings.add(
              finding(
                  CODE_TARGET_BASELINE_INACTIVE,
                  CompatibilityFindingSeverity.ERROR,
                  "Stable app targets a baseline that is not active: " + id + "."));
        } else {
          findings.add(
              finding(
                  "target_baseline_preview_only",
                  releaseRiskSeverity(strict),
                  "Experimental app target is preview-only and does not activate baseline support: "
                      + id
                      + "."));
        }
      }
      case ACTIVE -> checkExperimentalActiveBaseline(metadata, id, findings);
      case DEPRECATED ->
          findings.add(
              finding(
                  "target_baseline_deprecated",
                  releaseRiskSeverity(strict),
                  "App targets a deprecated but still-supported Platform API baseline: "
                      + id
                      + "."));
    }
    Integer minimum = metadata.minimumVersion();
    Integer maximum = metadata.maximumTestedVersion();
    int baselineContract = definition.firstCompleteContractVersion();
    if ((minimum != null && minimum > baselineContract)
        || (maximum != null && maximum < baselineContract)) {
      findings.add(
          finding(
              "target_baseline_outside_contract_range",
              releaseRiskSeverity(strict),
              "App contract range does not include target baseline "
                  + id
                  + CONTRACT_VERSION_INFIX
                  + baselineContract
                  + "."));
    }
  }

  private static void checkExperimentalActiveBaseline(
      AppApiCompatibilityMetadata metadata,
      PlatformApiBaselineId id,
      List<CompatibilityFinding> findings) {
    if (metadata.targetStability() != TargetStability.EXPERIMENTAL) {
      return;
    }
    findings.add(
        finding(
            "experimental_target_does_not_claim_stable_support",
            CompatibilityFindingSeverity.WARNING,
            "Experimental target does not claim the active stable baseline guarantee: "
                + id
                + "."));
  }

  private static Set<String> targetBaselineCapabilities(
      AppApiCompatibilityMetadata metadata,
      PlatformApiContract contract,
      PlatformApiBaselineRegistry registry) {
    String target = metadata.targetBaseline();
    if (target != null) {
      try {
        PlatformApiBaselineDefinition definition =
            registry.definitionsById().get(PlatformApiBaselineId.parse(target));
        if (definition != null) {
          return Set.copyOf(definition.capabilities());
        }
      } catch (IllegalArgumentException _) {
        // The lifecycle check emits the bounded malformed-baseline finding.
      }
    }
    return Set.copyOf(contract.stableBaseline().capabilities());
  }

  private static PlatformApiBaselineDefinition targetBaselineDefinitionForContractValidation(
      AppApiCompatibilityMetadata metadata, PlatformApiBaselineRegistry registry) {
    String target = metadata.targetBaseline();
    if (target == null) {
      return null;
    }
    try {
      PlatformApiBaselineId id = PlatformApiBaselineId.parse(target);
      PlatformApiBaselineLineage lifecycle = registry.latestLineageById().get(id);
      if (lifecycle == null
          || !requiresContractProjectionValidation(metadata, lifecycle.status())) {
        return null;
      }
      return registry.definitionsById().get(id);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  private static boolean requiresContractProjectionValidation(
      AppApiCompatibilityMetadata metadata, PlatformApiBaselineStatus status) {
    return status.isSupported()
        || (metadata.targetStability() == TargetStability.EXPERIMENTAL
            && switch (status) {
              case PROPOSED, CANDIDATE, REVIEWED, DOCUMENTED -> true;
              case ACTIVE, DEPRECATED, END_OF_SUPPORT, REJECTED -> false;
            });
  }

  private static void checkCapabilities(List<String> capabilities, CapabilityCheckContext context) {
    for (String capability : capabilities) {
      PlatformApiCapabilityDescriptor descriptor = context.descriptors().get(capability);
      if (descriptor == null) {
        context
            .findings()
            .add(
                finding(
                    context.unknownCode(),
                    releaseRiskSeverity(context.strict()),
                    "Unknown " + context.label() + ": " + capability + "."));
        continue;
      }
      checkCapabilityStability(descriptor, context);
    }
  }

  private static void checkCapabilityStability(
      PlatformApiCapabilityDescriptor descriptor, CapabilityCheckContext context) {
    List<CompatibilityFinding> findings = context.findings();
    TargetStability targetStability = context.metadata().targetStability();
    switch (descriptor.stability()) {
      case PlatformApiStabilityLevel stability
          when stability == PlatformApiStabilityLevel.EXPERIMENTAL
              && targetStability == TargetStability.STABLE
              && context.stableBaselineCapabilities().contains(descriptor.name()) -> {
        // Authenticated active-baseline membership is the named 1.x stability authority.
      }
      case PlatformApiStabilityLevel stability
          when stability == PlatformApiStabilityLevel.EXPERIMENTAL
              && targetStability == TargetStability.STABLE ->
          findings.add(
              finding(
                  "stable_target_uses_experimental_capability",
                  CompatibilityFindingSeverity.ERROR,
                  "Stable Platform API target must not declare experimental capability: "
                      + descriptor.name()
                      + "."));
      case PlatformApiStabilityLevel stability
          when stability == PlatformApiStabilityLevel.EXPERIMENTAL
              && !context.metadata().experimentalCapabilitiesAccepted() ->
          findings.add(
              finding(
                  "experimental_capability_without_acceptance",
                  context.experimentalAcceptanceSeverity(),
                  "Experimental capability requires api.experimentalCapabilitiesAccepted=true: "
                      + descriptor.name()
                      + "."));
      case PlatformApiStabilityLevel stability
          when stability == PlatformApiStabilityLevel.STABLE
              && targetStability == TargetStability.STABLE
              && !context.stableBaselineCapabilities().contains(descriptor.name()) ->
          findings.add(
              finding(
                  "stable_target_uses_non_baseline_capability",
                  CompatibilityFindingSeverity.ERROR,
                  "Stable Platform API target must not declare non-baseline capability: "
                      + descriptor.name()
                      + "."));
      case PlatformApiStabilityLevel stability
          when (stability == PlatformApiStabilityLevel.DEPRECATED
                  || stability == PlatformApiStabilityLevel.SCHEDULED_FOR_REMOVAL)
              && targetStability == TargetStability.STABLE
              && !context.stableBaselineCapabilities().contains(descriptor.name()) ->
          findings.add(
              finding(
                  "stable_target_uses_non_baseline_capability",
                  CompatibilityFindingSeverity.ERROR,
                  "Stable Platform API target must not declare non-baseline capability: "
                      + descriptor.name()
                      + "."));
      case STABLE, EXPERIMENTAL -> {
        // Stable-baseline and accepted-experimental declarations require no additional finding.
      }
      case DEPRECATED ->
          findings.add(
              finding(
                  "deprecated_capability",
                  releaseRiskSeverity(context.strict()),
                  "Deprecated capability is declared: " + descriptor.name() + "."));
      case SCHEDULED_FOR_REMOVAL ->
          findings.add(
              finding(
                  "scheduled_for_removal_capability",
                  targetStability == TargetStability.STABLE
                      ? CompatibilityFindingSeverity.ERROR
                      : releaseRiskSeverity(context.strict()),
                  "Capability is scheduled for removal: " + descriptor.name() + "."));
      case OPERATOR_ONLY ->
          findings.add(
              finding(
                  "app_uses_operator_only_platform_api",
                  CompatibilityFindingSeverity.ERROR,
                  "Operator-only Platform API capability must not be declared by apps: "
                      + descriptor.name()
                      + "."));
      case INTERNAL ->
          findings.add(
              finding(
                  "app_uses_internal_platform_api",
                  CompatibilityFindingSeverity.ERROR,
                  "Internal capability must not be declared by apps: " + descriptor.name() + "."));
    }
  }

  private record SnapshotMetadataPresence(
      boolean previousStableBaselineMetadataPresent,
      boolean currentStableBaselineMetadataPresent,
      boolean previousCompatibilityWindowMetadataPresent,
      boolean currentCompatibilityWindowMetadataPresent) {}

  private record CapabilityCheckContext(
      String label,
      String unknownCode,
      Map<String, PlatformApiCapabilityDescriptor> descriptors,
      Set<String> stableBaselineCapabilities,
      AppApiCompatibilityMetadata metadata,
      boolean strict,
      List<CompatibilityFinding> findings) {
    CapabilityCheckContext {
      Objects.requireNonNull(label, "label");
      Objects.requireNonNull(unknownCode, "unknownCode");
      Objects.requireNonNull(descriptors, "descriptors");
      Objects.requireNonNull(stableBaselineCapabilities, "stableBaselineCapabilities");
      Objects.requireNonNull(metadata, "metadata");
      Objects.requireNonNull(findings, FINDINGS_FIELD);
    }

    CapabilityCheckContext forOptionalCapabilities() {
      return new CapabilityCheckContext(
          "optional capability",
          "unknown_optional_capability",
          descriptors,
          stableBaselineCapabilities,
          metadata,
          strict,
          findings);
    }

    CompatibilityFindingSeverity experimentalAcceptanceSeverity() {
      return !strict && !metadata.declared()
          ? CompatibilityFindingSeverity.WARNING
          : CompatibilityFindingSeverity.ERROR;
    }
  }

  private static String status(
      AppApiCompatibilityMetadata metadata,
      int targetContractVersion,
      CompatibilityVerificationResult result) {
    if (result.hasErrors()) {
      return STATUS_INCOMPATIBLE;
    }
    if (!metadata.declared()) {
      return STATUS_UNKNOWN;
    }
    Integer minimumVersion = metadata.minimumVersion();
    if (minimumVersion != null && minimumVersion > targetContractVersion) {
      return STATUS_BELOW_MINIMUM;
    }
    Integer maximumTestedVersion = metadata.maximumTestedVersion();
    if (maximumTestedVersion != null && maximumTestedVersion < targetContractVersion) {
      return STATUS_NEWER_THAN_TESTED;
    }
    return STATUS_COMPATIBLE;
  }

  private static String baselineStatus(
      AppApiCompatibilityMetadata metadata,
      int targetContractVersion,
      CompatibilityVerificationResult result) {
    if (result.findings().stream()
        .map(CompatibilityFinding::code)
        .anyMatch(
            code ->
                code.equals("target_baseline_unknown")
                    || code.equals(CODE_TARGET_BASELINE_INACTIVE)
                    || code.equals("target_baseline_end_of_support")
                    || code.equals("target_baseline_malformed"))) {
      return STATUS_UNSUPPORTED_BASELINE;
    }
    return status(metadata, targetContractVersion, result);
  }

  private static CompatibilityFindingSeverity releaseRiskSeverity(boolean strict) {
    return strict ? CompatibilityFindingSeverity.ERROR : CompatibilityFindingSeverity.WARNING;
  }

  private static CompatibilityFinding finding(
      String code, CompatibilityFindingSeverity severity, String message) {
    return new CompatibilityFinding(code, severity, message);
  }

  private static CompatibilityFinding finding(
      String code,
      CompatibilityFindingSeverity severity,
      String message,
      Map<String, Object> details) {
    return new CompatibilityFinding(code, severity, message, details);
  }

  private static List<String> sorted(Collection<String> values) {
    Set<String> sorted = new TreeSet<>();
    for (String value : Objects.requireNonNull(values, "values")) {
      sorted.add(Objects.requireNonNull(value, "values item"));
    }
    return List.copyOf(sorted);
  }

  /**
   * Severity attached to one compatibility verifier finding.
   *
   * <p>The enum values are converted to lowercase JSON strings for CLI output, Platform API review
   * summaries, and release-certification evidence. Callers should use the enum value for control
   * flow and {@link #jsonValue()} only when producing user-visible or machine-readable reports.
   */
  public enum CompatibilityFindingSeverity {
    /**
     * Finding should be reviewed but does not fail non-strict verification.
     *
     * <p>Warnings are used for advisory risks such as deprecated capability use or a target
     * contract newer than the app has declared as tested when the verifier is not running in strict
     * mode.
     */
    WARNING("warning"),

    /**
     * Finding fails strict or release-mode verification.
     *
     * <p>Errors represent malformed or unacceptable compatibility state for the selected mode.
     * Release certification treats these as blockers unless a higher-level workflow explicitly
     * records a waiver.
     */
    ERROR("error");

    private final String jsonValue;

    CompatibilityFindingSeverity(String jsonValue) {
      this.jsonValue = jsonValue;
    }

    /**
     * Returns the stable JSON/CLI severity label.
     *
     * @return lowercase severity value
     */
    public String jsonValue() {
      return jsonValue;
    }
  }

  /**
   * One compatibility verifier finding.
   *
   * <p>A finding is both human-readable and machine-readable. The {@code code} field is stable for
   * tests, CLI filtering, and release evidence, while {@code message} is phrased for app authors
   * and operators. Findings are immutable and trim their text fields during construction.
   *
   * @param code stable machine-readable finding code such as {@code unknown_manifest_permission}
   * @param severity warning or error severity selected for the verifier mode
   * @param message human-readable diagnostic text suitable for CLI and review UI display
   * @param details optional deterministic machine-readable details
   */
  public record CompatibilityFinding(
      String code,
      CompatibilityFindingSeverity severity,
      String message,
      Map<String, Object> details) {
    /**
     * Creates a finding without structured details.
     *
     * @param code stable finding code
     * @param severity warning or error severity
     * @param message human-readable diagnostic
     */
    public CompatibilityFinding(
        String code, CompatibilityFindingSeverity severity, String message) {
      this(code, severity, message, Map.of());
    }

    /**
     * Creates a normalized finding.
     *
     * <p>Blank codes and messages are rejected so downstream JSON reports are useful without extra
     * validation. The constructor does not reinterpret severity; callers choose warning or error
     * before creating the finding.
     */
    public CompatibilityFinding {
      code = Objects.requireNonNull(code, "code").trim();
      if (code.isEmpty()) {
        throw new IllegalArgumentException("code must not be blank");
      }
      Objects.requireNonNull(severity, "severity");
      message = Objects.requireNonNull(message, "message").trim();
      if (message.isEmpty()) {
        throw new IllegalArgumentException("message must not be blank");
      }
      details =
          Collections.unmodifiableMap(
              new LinkedHashMap<>(Objects.requireNonNull(details, "details")));
    }

    /**
     * Converts this finding to a JSON-compatible map.
     *
     * <p>The map uses stable field names and insertion order. It is suitable for direct use with
     * the Platform API JSON writer and for embedding in release-certification evidence.
     *
     * @return deterministic finding map containing code, severity, and message
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json =
          LinkedHashMap.newLinkedHashMap(details.isEmpty() ? 3 : 4);
      json.put("code", code);
      json.put("severity", severity.jsonValue());
      json.put("message", message);
      if (!details.isEmpty()) {
        json.put("details", details);
      }
      return json;
    }
  }

  /**
   * Aggregate compatibility verification result.
   *
   * <p>The result keeps every finding rather than stopping at the first error. Developer tooling
   * can therefore show all obvious compatibility problems in one run, and release certification can
   * record the complete evidence set for first-party apps.
   *
   * @param findings deterministic verifier findings produced by one verification pass
   */
  public record CompatibilityVerificationResult(List<CompatibilityFinding> findings) {
    /**
     * Creates an immutable verification result.
     *
     * <p>The supplied list is copied in its current order. Callers should pass
     * already-deterministic findings when stable JSON output matters.
     */
    public CompatibilityVerificationResult {
      findings = List.copyOf(Objects.requireNonNull(findings, FINDINGS_FIELD));
    }

    /**
     * Returns whether verification produced any error findings.
     *
     * <p>Warnings never make this method return {@code true}. That distinction lets non-strict
     * install/update review surface compatibility risks without forcing the caller into failure
     * behavior.
     *
     * @return {@code true} when at least one error finding exists
     */
    public boolean hasErrors() {
      return findings.stream()
          .anyMatch(finding -> finding.severity() == CompatibilityFindingSeverity.ERROR);
    }

    /**
     * Returns all finding messages in deterministic order.
     *
     * <p>This convenience projection is used by concise Platform API summaries where the full code
     * and severity structure would be too large for install-review panels.
     *
     * @return immutable diagnostic messages in the same order as {@link #findings()}
     */
    public List<String> messages() {
      return findings.stream().map(CompatibilityFinding::message).toList();
    }

    /**
     * Converts this result to a JSON-compatible object.
     *
     * <p>The object contains an {@code ok} boolean, an error count, and the complete finding list.
     * That shape is compact enough for CLI output while preserving the information release tooling
     * needs for blocking decisions.
     *
     * @return deterministic verification result map suitable for CLI and release evidence
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put("ok", !hasErrors());
      json.put(
          "errors",
          findings.stream()
              .filter(finding -> finding.severity() == CompatibilityFindingSeverity.ERROR)
              .count());
      json.put(FINDINGS_FIELD, findings.stream().map(CompatibilityFinding::toJsonValue).toList());
      return json;
    }
  }
}
