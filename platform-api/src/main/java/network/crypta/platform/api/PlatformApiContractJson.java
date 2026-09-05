package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * JSON encoder and decoder for Platform API compatibility contract snapshots.
 *
 * <p>The encoder produces only deterministic JDK map/list/scalar shapes accepted by the existing
 * Platform API JSON writer. The decoder is intentionally small and dependency-free; it reads the
 * same contract envelope used by {@code GET /api/v1/platform/contract} and by the developer CLI's
 * offline snapshot command.
 *
 * <p>This class is not a general JSON framework. It knows only the contract snapshot schema and the
 * JSON primitives that schema uses. That narrow scope keeps offline developer tooling and release
 * certification free of extra schema-generation dependencies while still allowing snapshots to
 * round-trip in tests. Field order follows the public contract order so checked-in fixtures,
 * release evidence, and catalog review reports remain stable across runs.
 *
 * <p>The emitted JSON is metadata only. It includes route templates, action labels, capability
 * names, and stability annotations, but it never serializes request bodies, query strings,
 * filesystem paths, process command lines, app tokens, browser-session tokens, passwords, or
 * private key material.
 */
public final class PlatformApiContractJson {
  private static final String FIELD_ACTION_LABEL = "actionLabel";
  private static final String FIELD_API_VERSION = "apiVersion";
  private static final String FIELD_AUDIENCE = "audience";
  private static final String FIELD_APP_BROWSER_PRINCIPALS_ALLOWED = "appBrowserPrincipalsAllowed";
  private static final String FIELD_APP_PROCESS_PRINCIPALS_ALLOWED = "appProcessPrincipalsAllowed";
  private static final String FIELD_CAPABILITIES = "capabilities";
  private static final String FIELD_CAPABILITY_COUNT = "capabilityCount";
  private static final String FIELD_COMPATIBILITY_WINDOW = "compatibilityWindow";
  private static final String FIELD_CONTRACT = "contract";
  private static final String FIELD_CONTRACT_VERSION = "contractVersion";
  private static final String FIELD_BASELINE_CONTRACT_VERSION = "baselineContractVersion";
  private static final String FIELD_BASELINE_NAME = "baselineName";
  private static final String FIELD_CRITICAL_STABLE_REMOVAL_WAIVER_ALLOWED =
      "criticalStableRemovalWaiverAllowed";
  private static final String FIELD_DEPRECATED_SINCE_CONTRACT_VERSION =
      "deprecatedSinceContractVersion";
  private static final String FIELD_DEPRECATION = "deprecation";
  private static final String FIELD_DESCRIPTION = "description";
  private static final String FIELD_ENDPOINTS = "endpoints";
  private static final String FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_REVIEW =
      "experimentalGraduationRequiresReview";
  private static final String FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_STABLE_REFERENCE_UPDATE =
      "experimentalGraduationRequiresStableReferenceUpdate";
  private static final String FIELD_GENERATED_BY = "generatedBy";
  private static final String FIELD_HOST_OPERATOR_BYPASS_ALLOWED = "hostOperatorBypassAllowed";
  private static final String FIELD_METHOD = "method";
  private static final String FIELD_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS =
      "minimumDeprecationWindowContractVersions";
  private static final String FIELD_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS =
      "minimumScheduledRemovalWindowContractVersions";
  private static final String FIELD_NAME = "name";
  private static final String FIELD_NOTE = "note";
  private static final String FIELD_POLICY_DOCUMENT = "policyDocument";
  private static final String FIELD_PREVIOUS_SNAPSHOT_REQUIRED_IN_PRODUCTION_BETA =
      "previousSnapshotRequiredInProductionBeta";
  private static final String FIELD_REMOVAL_CONTRACT_VERSION = "removalContractVersion";
  private static final String FIELD_REQUIRED_CAPABILITIES = "requiredCapabilities";
  private static final String FIELD_ROUTE_FAMILY = "routeFamily";
  private static final String FIELD_ROUTE_TEMPLATE = "routeTemplate";
  private static final String FIELD_SCHEMA_VERSION = "schemaVersion";
  private static final String FIELD_SINCE_CONTRACT_VERSION = "sinceContractVersion";
  private static final String FIELD_STABLE_BASELINE = "stableBaseline";
  private static final String FIELD_STABLE_BASELINE_MEMBER = "stableBaselineMember";
  private static final String FIELD_STABLE_REMOVAL_REQUIRES_EXPLICIT_WAIVER =
      "stableRemovalRequiresExplicitWaiver";
  private static final String FIELD_STABLE_REMOVAL_REQUIRES_NEW_BASELINE =
      "stableRemovalRequiresNewBaseline";
  private static final String FIELD_STABLE_REMOVAL_REQUIRES_PREVIOUS_SNAPSHOT =
      "stableRemovalRequiresPreviousSnapshot";
  private static final String FIELD_STABILITY = "stability";
  private static final String FIELD_STABILITY_POLICY = "stabilityPolicy";
  private static final String FIELD_SUPPORT_PHASE = "supportPhase";
  private static final String FIELD_SUPPORT_WINDOW_STARTED_RELEASE = "supportWindowStartedRelease";
  private static final String FIELD_CURRENT_CONTRACT_VERSION = "currentContractVersion";
  private static final String FIELD_ENDPOINT_COUNT = "endpointCount";
  private static final String FIELD_BASELINE_REGISTRY = "baselineRegistry";
  private static final String FIELD_BASELINE_REGISTRY_SUMMARY = "baselineRegistrySummary";
  private static final String FIELD_REGISTRY_DIGEST = "registryDigest";
  private static final String FIELD_DEFINITIONS = "definitions";
  private static final String FIELD_LINEAGE = "lineage";
  private static final String FIELD_ID = "id";
  private static final String FIELD_PREDECESSOR_ID = "predecessorId";
  private static final String FIELD_SOURCE_ARTIFACT_DIGEST = "sourceArtifactDigest";
  private static final String FIELD_PROPOSAL_DIGEST = "proposalDigest";
  private static final String FIELD_REVIEW_DIGEST = "reviewDigest";
  private static final String FIELD_DOCUMENTATION_DIGEST = "documentationDigest";
  private static final String FIELD_FIRST_COMPLETE_CONTRACT_VERSION =
      "firstCompleteContractVersion";
  private static final String FIELD_DEFINITION_DIGEST = "definitionDigest";
  private static final String FIELD_STATUS = "status";
  private static final String FIELD_EVIDENCE_KIND = "evidenceKind";
  private static final String FIELD_EVIDENCE_DIGEST = "evidenceDigest";
  private static final String FIELD_ACTIVATION_RELEASE = "activationRelease";
  private static final String FIELD_ACTIVATION_BUILD = "activationBuild";
  private static final String FIELD_SUPPORT_STARTED_RELEASE = "supportStartedRelease";
  private static final String FIELD_SUPPORT_ENDED_RELEASE = "supportEndedRelease";
  private static final String FIELD_PREVIOUS_LINEAGE_DIGEST = "previousLineageDigest";
  private static final String FIELD_LINEAGE_DIGEST = "lineageDigest";
  private static final String FIELD_SUPPORTED_BASELINES = "supportedBaselines";
  private static final Set<String> BASELINE_REGISTRY_ENVELOPE_FIELDS =
      Set.of(FIELD_BASELINE_REGISTRY);
  private static final Set<String> BASELINE_REGISTRY_FIELDS =
      Set.of(FIELD_SCHEMA_VERSION, FIELD_DEFINITIONS, FIELD_LINEAGE, FIELD_REGISTRY_DIGEST);
  private static final Set<String> BASELINE_DEFINITION_FIELDS =
      Set.of(
          FIELD_ID,
          FIELD_PREDECESSOR_ID,
          FIELD_CAPABILITIES,
          FIELD_ENDPOINTS,
          FIELD_SOURCE_ARTIFACT_DIGEST,
          FIELD_PROPOSAL_DIGEST,
          FIELD_REVIEW_DIGEST,
          FIELD_DOCUMENTATION_DIGEST,
          FIELD_FIRST_COMPLETE_CONTRACT_VERSION,
          FIELD_DEFINITION_DIGEST);
  private static final Set<String> BASELINE_ENDPOINT_FIELDS =
      Set.of(
          FIELD_ID,
          FIELD_ROUTE_FAMILY,
          FIELD_ACTION_LABEL,
          FIELD_REQUIRED_CAPABILITIES,
          FIELD_HOST_OPERATOR_BYPASS_ALLOWED,
          FIELD_APP_PROCESS_PRINCIPALS_ALLOWED,
          FIELD_APP_BROWSER_PRINCIPALS_ALLOWED);
  private static final Set<String> BASELINE_LINEAGE_FIELDS =
      Set.of(
          FIELD_ID,
          FIELD_DEFINITION_DIGEST,
          FIELD_STATUS,
          FIELD_EVIDENCE_KIND,
          FIELD_EVIDENCE_DIGEST,
          FIELD_ACTIVATION_RELEASE,
          FIELD_ACTIVATION_BUILD,
          FIELD_SUPPORT_STARTED_RELEASE,
          FIELD_SUPPORT_ENDED_RELEASE,
          FIELD_PREVIOUS_LINEAGE_DIGEST,
          FIELD_LINEAGE_DIGEST);
  private static final Set<String> BASELINE_REGISTRY_SUMMARY_FIELDS =
      Set.of(FIELD_SCHEMA_VERSION, FIELD_REGISTRY_DIGEST, FIELD_SUPPORTED_BASELINES);
  private static final Set<String> SUPPORTED_BASELINE_SUMMARY_FIELDS =
      Set.of(FIELD_ID, FIELD_STATUS, FIELD_DEFINITION_DIGEST);

  private PlatformApiContractJson() {}

  /**
   * Builds the public endpoint response envelope.
   *
   * <p>The envelope mirrors the HTTP response body for {@code GET /api/v1/platform/contract}. It is
   * also the shape written by the developer CLI snapshot command, which means consumers can compare
   * endpoint output and offline artifacts without another wrapping step.
   *
   * @param contract contract to encode into the public response envelope
   * @return deterministic JSON-compatible envelope map with a {@code contract} field
   */
  public static Map<String, Object> envelope(PlatformApiContract contract) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(FIELD_CONTRACT, toJsonValue(contract));
    return envelope;
  }

  /**
   * Builds a contract envelope with a bounded optional supported-baseline summary.
   *
   * <p>The legacy {@link #envelope(PlatformApiContract)} shape remains byte-for-byte unchanged.
   * Callers opt into this additive metadata only when the surrounding contract/release artifact
   * explicitly carries the matching registry. The summary grants no capabilities and contains no
   * app inventory or release credentials.
   */
  public static Map<String, Object> envelope(
      PlatformApiContract contract, PlatformApiBaselineRegistry registry) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    LinkedHashMap<String, Object> contractJson =
        new LinkedHashMap<>(toJsonValue(Objects.requireNonNull(contract, FIELD_CONTRACT)));
    contractJson.put(
        FIELD_BASELINE_REGISTRY_SUMMARY,
        baselineRegistrySummaryJson(Objects.requireNonNull(registry, FIELD_BASELINE_REGISTRY)));
    envelope.put(FIELD_CONTRACT, contractJson);
    return envelope;
  }

  /**
   * Serializes a contract snapshot envelope.
   *
   * <p>The method delegates to the Platform API JSON writer after building the same map shape
   * returned by {@link #envelope(PlatformApiContract)}. It is the preferred entry point for
   * snapshot files because it preserves the canonical response envelope.
   *
   * @param contract contract to encode into canonical snapshot JSON
   * @return deterministic JSON text suitable for offline compatibility verification
   */
  public static String writeEnvelope(PlatformApiContract contract) {
    return PlatformApiJsonWriter.write(envelope(contract));
  }

  /** Writes the additive contract envelope carrying a bounded baseline-registry summary. */
  public static String writeEnvelope(
      PlatformApiContract contract, PlatformApiBaselineRegistry registry) {
    return PlatformApiJsonWriter.write(envelope(contract, registry));
  }

  /** Writes a complete deterministic named-baseline registry artifact. */
  public static String writeBaselineRegistry(PlatformApiBaselineRegistry registry) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put(
        FIELD_BASELINE_REGISTRY,
        baselineRegistryToJsonValue(Objects.requireNonNull(registry, FIELD_BASELINE_REGISTRY)));
    return PlatformApiJsonWriter.write(envelope);
  }

  /** Returns the complete deterministic JSON-compatible registry object without an envelope. */
  public static Map<String, Object> baselineRegistryToJsonValue(
      PlatformApiBaselineRegistry registry) {
    return baselineRegistryJson(Objects.requireNonNull(registry, FIELD_BASELINE_REGISTRY));
  }

  /** Returns the bounded supported-baseline summary used by contract and operator views. */
  public static Map<String, Object> baselineRegistrySummaryToJsonValue(
      PlatformApiBaselineRegistry registry) {
    return baselineRegistrySummaryJson(Objects.requireNonNull(registry, FIELD_BASELINE_REGISTRY));
  }

  /** Parses a complete named-baseline registry artifact, with or without its outer envelope. */
  public static PlatformApiBaselineRegistry parseBaselineRegistry(String json) {
    Object root = new Parser(Objects.requireNonNull(json, "json")).parse();
    Map<String, Object> rootObject = asObject(root, "baseline registry root");
    Object registryObject;
    if (rootObject.containsKey(FIELD_BASELINE_REGISTRY)) {
      requireExactFields(rootObject, BASELINE_REGISTRY_ENVELOPE_FIELDS, "baseline registry root");
      registryObject = rootObject.get(FIELD_BASELINE_REGISTRY);
    } else {
      registryObject = rootObject;
    }
    return parseBaselineRegistryValue(asObject(registryObject, FIELD_BASELINE_REGISTRY));
  }

  /**
   * Verifies that a contract snapshot is bound to the supplied named-baseline registry.
   *
   * <p>Contract snapshots from before named-baseline metadata remain valid without a summary. A
   * version that carries named-baseline metadata must include the closed summary shape, and any
   * summary that is present must exactly match the registry's digest, supported baseline order,
   * lifecycle status, and definition digests. This check is intended for consumers that accept a
   * contract and registry as separate artifacts, such as the offline preview command.
   *
   * @param json exact contract snapshot JSON, either enveloped or as the nested contract object
   * @param registry registry that the snapshot must identify
   * @throws IllegalArgumentException if required metadata is absent, malformed, or mismatched
   */
  public static void verifyBaselineRegistrySummary(
      String json, PlatformApiBaselineRegistry registry) {
    Object root = new Parser(Objects.requireNonNull(json, "json")).parse();
    Map<String, Object> rootObject = asObject(root, "contract root");
    Object contractObject = rootObject.get(FIELD_CONTRACT);
    if (contractObject == null && !rootObject.containsKey(FIELD_CONTRACT)) {
      contractObject = rootObject;
    }
    Map<String, Object> contract = asObject(contractObject, FIELD_CONTRACT);
    int contractVersion = integer(contract, FIELD_CONTRACT_VERSION);
    Object summaryValue = contract.get(FIELD_BASELINE_REGISTRY_SUMMARY);
    if (summaryValue == null) {
      if (contractVersion >= PlatformApiContract.NAMED_BASELINE_METADATA_CONTRACT_VERSION) {
        throw new IllegalArgumentException(
            FIELD_BASELINE_REGISTRY_SUMMARY + " is required for this contract version");
      }
      return;
    }

    Map<String, Object> summary = asObject(summaryValue, FIELD_BASELINE_REGISTRY_SUMMARY);
    requireExactFields(summary, BASELINE_REGISTRY_SUMMARY_FIELDS, FIELD_BASELINE_REGISTRY_SUMMARY);
    LinkedHashMap<String, Object> normalized = LinkedHashMap.newLinkedHashMap(3);
    normalized.put(FIELD_SCHEMA_VERSION, integer(summary, FIELD_SCHEMA_VERSION));
    normalized.put(FIELD_REGISTRY_DIGEST, string(summary, FIELD_REGISTRY_DIGEST));
    List<Map<String, Object>> supported = new ArrayList<>();
    for (Object item : asArray(summary.get(FIELD_SUPPORTED_BASELINES), FIELD_SUPPORTED_BASELINES)) {
      Map<String, Object> baseline = asObject(item, "supported baseline summary");
      requireExactFields(baseline, SUPPORTED_BASELINE_SUMMARY_FIELDS, "supported baseline summary");
      LinkedHashMap<String, Object> normalizedBaseline = LinkedHashMap.newLinkedHashMap(3);
      normalizedBaseline.put(FIELD_ID, string(baseline, FIELD_ID));
      normalizedBaseline.put(FIELD_STATUS, string(baseline, FIELD_STATUS));
      normalizedBaseline.put(FIELD_DEFINITION_DIGEST, string(baseline, FIELD_DEFINITION_DIGEST));
      supported.add(normalizedBaseline);
    }
    normalized.put(FIELD_SUPPORTED_BASELINES, List.copyOf(supported));
    if (!normalized.equals(
        baselineRegistrySummaryJson(Objects.requireNonNull(registry, FIELD_BASELINE_REGISTRY)))) {
      throw new IllegalArgumentException(
          FIELD_BASELINE_REGISTRY_SUMMARY + " does not match the candidate baseline registry");
    }
  }

  /**
   * Converts one contract to a JSON-compatible object.
   *
   * <p>The returned object is the nested {@code contract} value, not the outer endpoint envelope.
   * It is useful when composing larger evidence documents, such as release-certification reports,
   * that already provide their own top-level object.
   *
   * @param contract contract to encode into the nested contract object
   * @return deterministic JSON-compatible map containing only public compatibility metadata
   */
  public static Map<String, Object> toJsonValue(PlatformApiContract contract) {
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, FIELD_CONTRACT);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(FIELD_API_VERSION, checkedContract.apiVersion());
    json.put(FIELD_CONTRACT_VERSION, checkedContract.contractVersion());
    json.put(FIELD_GENERATED_BY, checkedContract.generatedBy());
    json.put(FIELD_STABILITY_POLICY, checkedContract.stabilityPolicy());
    json.put(FIELD_STABLE_BASELINE, stableBaselineJson(checkedContract.stableBaseline()));
    json.put(
        FIELD_COMPATIBILITY_WINDOW, compatibilityWindowJson(checkedContract.compatibilityWindow()));
    Set<String> stableBaselineCapabilities =
        Set.copyOf(checkedContract.stableBaseline().capabilities());
    json.put(
        FIELD_CAPABILITIES,
        checkedContract.capabilities().stream()
            .map(descriptor -> capabilityJson(descriptor, stableBaselineCapabilities))
            .toList());
    json.put(
        FIELD_ENDPOINTS,
        checkedContract.endpoints().stream().map(PlatformApiContractJson::endpointJson).toList());
    return json;
  }

  /**
   * Parses a contract snapshot produced by this class.
   *
   * <p>Both the public envelope shape and the raw nested {@code contract} object are accepted so
   * tests and local tooling can reuse this parser without adding wrapper code. The parser validates
   * field types before constructing the model, and the model constructor then checks descriptor
   * invariants such as positive contract versions and endpoint capability references.
   *
   * <p>Only the subset of JSON used by contract snapshots is accepted. Numbers must be integers,
   * objects preserve insertion order, and malformed text reports the approximate JSON offset to
   * make CLI diagnostics actionable.
   *
   * @param json JSON text containing a Platform API contract
   * @return parsed immutable contract model
   * @throws IllegalArgumentException if the JSON text or contract fields are malformed
   */
  public static PlatformApiContract parse(String json) {
    Object root = new Parser(Objects.requireNonNull(json, "json")).parse();
    Map<String, Object> rootObject = asObject(root, "contract root");
    //noinspection Java8MapApi
    Object contractObject =
        rootObject.containsKey(FIELD_CONTRACT) ? rootObject.get(FIELD_CONTRACT) : rootObject;
    Map<String, Object> contract = asObject(contractObject, FIELD_CONTRACT);
    int contractVersion = integer(contract, FIELD_CONTRACT_VERSION);
    return new PlatformApiContract(
        string(contract, FIELD_API_VERSION),
        contractVersion,
        string(contract, FIELD_GENERATED_BY),
        string(contract, FIELD_STABILITY_POLICY),
        parseStableBaseline(contract, contractVersion),
        parseCompatibilityWindow(contract, contractVersion),
        parseCapabilities(contract.get(FIELD_CAPABILITIES)),
        parseEndpoints(contract.get(FIELD_ENDPOINTS)));
  }

  private static Map<String, Object> capabilityJson(
      PlatformApiCapabilityDescriptor descriptor, Set<String> stableBaselineCapabilities) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    boolean stableBaselineMember = stableBaselineCapabilities.contains(descriptor.name());
    json.put(FIELD_NAME, descriptor.name());
    json.put(FIELD_STABILITY, descriptor.stability().jsonValue());
    json.put(FIELD_AUDIENCE, audience(descriptor.stability()));
    json.put(FIELD_STABLE_BASELINE_MEMBER, stableBaselineMember);
    json.put(
        FIELD_STABLE_BASELINE,
        stableBaselineMember ? PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME : null);
    json.put(FIELD_SINCE_CONTRACT_VERSION, descriptor.sinceContractVersion());
    json.put(FIELD_DEPRECATION, deprecationJson(descriptor.deprecation()));
    json.put(FIELD_DESCRIPTION, descriptor.description());
    return json;
  }

  private static Map<String, Object> endpointJson(PlatformApiEndpointDescriptor descriptor) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(15);
    json.put(FIELD_ROUTE_FAMILY, descriptor.routeFamily());
    json.put(FIELD_METHOD, descriptor.method());
    json.put(FIELD_ROUTE_TEMPLATE, descriptor.routeTemplate());
    json.put(FIELD_ACTION_LABEL, descriptor.actionLabel());
    json.put(FIELD_REQUIRED_CAPABILITIES, descriptor.requiredCapabilities());
    json.put(FIELD_HOST_OPERATOR_BYPASS_ALLOWED, descriptor.hostOperatorBypassAllowed());
    json.put(FIELD_APP_PROCESS_PRINCIPALS_ALLOWED, descriptor.appProcessAllowed());
    json.put(FIELD_APP_BROWSER_PRINCIPALS_ALLOWED, descriptor.appBrowserAllowed());
    json.put(FIELD_STABILITY, descriptor.stability().jsonValue());
    json.put(FIELD_AUDIENCE, endpointAudience(descriptor));
    json.put(
        FIELD_STABLE_BASELINE_MEMBER, PlatformApiContract.isStableBaselineEndpoint(descriptor));
    json.put(
        FIELD_STABLE_BASELINE,
        PlatformApiContract.isStableBaselineEndpoint(descriptor)
            ? PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME
            : null);
    json.put(FIELD_SINCE_CONTRACT_VERSION, descriptor.sinceContractVersion());
    json.put(FIELD_DEPRECATION, deprecationJson(descriptor.deprecation()));
    json.put(FIELD_DESCRIPTION, descriptor.description());
    return json;
  }

  private static Map<String, Object> stableBaselineJson(
      PlatformApiContract.StableBaseline stableBaseline) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put(FIELD_NAME, stableBaseline.name());
    json.put(FIELD_CONTRACT_VERSION, stableBaseline.contractVersion());
    json.put(FIELD_CAPABILITY_COUNT, stableBaseline.capabilityCount());
    json.put(FIELD_ENDPOINT_COUNT, stableBaseline.endpointCount());
    json.put(FIELD_CAPABILITIES, stableBaseline.capabilities());
    json.put(FIELD_ENDPOINTS, stableBaseline.endpoints());
    return json;
  }

  private static Map<String, Object> baselineRegistrySummaryJson(
      PlatformApiBaselineRegistry registry) {
    Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions =
        registry.definitionsById();
    Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latest = registry.latestLineageById();
    List<Map<String, Object>> supported = new ArrayList<>();
    for (PlatformApiBaselineId id : registry.supportedBaselineIds()) {
      LinkedHashMap<String, Object> baseline = LinkedHashMap.newLinkedHashMap(3);
      baseline.put(FIELD_ID, id.toString());
      baseline.put(FIELD_STATUS, latest.get(id).status().jsonValue());
      baseline.put(FIELD_DEFINITION_DIGEST, definitions.get(id).definitionDigest());
      supported.add(baseline);
    }
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(3);
    summary.put(FIELD_SCHEMA_VERSION, registry.schemaVersion());
    summary.put(FIELD_REGISTRY_DIGEST, registry.registryDigest());
    summary.put(FIELD_SUPPORTED_BASELINES, List.copyOf(supported));
    return summary;
  }

  private static Map<String, Object> baselineRegistryJson(PlatformApiBaselineRegistry registry) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(FIELD_SCHEMA_VERSION, registry.schemaVersion());
    json.put(
        FIELD_DEFINITIONS,
        registry.definitions().stream()
            .map(PlatformApiContractJson::baselineDefinitionJson)
            .toList());
    json.put(
        FIELD_LINEAGE,
        registry.lineage().stream().map(PlatformApiContractJson::baselineLineageJson).toList());
    json.put(FIELD_REGISTRY_DIGEST, registry.registryDigest());
    return json;
  }

  private static Map<String, Object> baselineDefinitionJson(
      PlatformApiBaselineDefinition definition) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put(FIELD_ID, definition.id().toString());
    json.put(
        FIELD_PREDECESSOR_ID,
        definition.predecessorId() == null ? null : definition.predecessorId().toString());
    json.put(FIELD_CAPABILITIES, definition.capabilities());
    json.put(
        FIELD_ENDPOINTS,
        definition.endpoints().stream()
            .map(PlatformApiContractJson::baselineEndpointJson)
            .toList());
    json.put(FIELD_SOURCE_ARTIFACT_DIGEST, definition.sourceArtifactDigest());
    json.put(FIELD_PROPOSAL_DIGEST, definition.proposalDigest());
    json.put(FIELD_REVIEW_DIGEST, definition.reviewDigest());
    json.put(FIELD_DOCUMENTATION_DIGEST, definition.documentationDigest());
    json.put(FIELD_FIRST_COMPLETE_CONTRACT_VERSION, definition.firstCompleteContractVersion());
    json.put(FIELD_DEFINITION_DIGEST, definition.definitionDigest());
    return json;
  }

  private static Map<String, Object> baselineEndpointJson(PlatformApiBaselineEndpoint endpoint) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(FIELD_ID, endpoint.identity());
    json.put(FIELD_ROUTE_FAMILY, endpoint.routeFamily());
    json.put(FIELD_ACTION_LABEL, endpoint.actionLabel());
    json.put(FIELD_REQUIRED_CAPABILITIES, endpoint.requiredCapabilities());
    json.put(FIELD_HOST_OPERATOR_BYPASS_ALLOWED, endpoint.hostOperatorBypassAllowed());
    json.put(FIELD_APP_PROCESS_PRINCIPALS_ALLOWED, endpoint.appProcessAllowed());
    json.put(FIELD_APP_BROWSER_PRINCIPALS_ALLOWED, endpoint.appBrowserAllowed());
    return json;
  }

  private static Map<String, Object> baselineLineageJson(PlatformApiBaselineLineage lineage) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put(FIELD_ID, lineage.baselineId().toString());
    json.put(FIELD_DEFINITION_DIGEST, lineage.definitionDigest());
    json.put(FIELD_STATUS, lineage.status().jsonValue());
    json.put(FIELD_EVIDENCE_KIND, lineage.evidenceKind().jsonValue());
    json.put(FIELD_EVIDENCE_DIGEST, lineage.evidenceDigest());
    json.put(FIELD_ACTIVATION_RELEASE, lineage.activationRelease());
    json.put(FIELD_ACTIVATION_BUILD, lineage.activationBuild());
    json.put(FIELD_SUPPORT_STARTED_RELEASE, lineage.supportStartedRelease());
    json.put(FIELD_SUPPORT_ENDED_RELEASE, lineage.supportEndedRelease());
    json.put(FIELD_PREVIOUS_LINEAGE_DIGEST, lineage.previousLineageDigest());
    json.put(FIELD_LINEAGE_DIGEST, lineage.lineageDigest());
    return json;
  }

  private static PlatformApiBaselineRegistry parseBaselineRegistryValue(Map<String, Object> json) {
    requireExactFields(json, BASELINE_REGISTRY_FIELDS, FIELD_BASELINE_REGISTRY);
    List<PlatformApiBaselineDefinition> definitions = new ArrayList<>();
    for (Object value : asArray(json.get(FIELD_DEFINITIONS), FIELD_DEFINITIONS)) {
      definitions.add(parseBaselineDefinition(asObject(value, "baseline definition")));
    }
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>();
    for (Object value : asArray(json.get(FIELD_LINEAGE), FIELD_LINEAGE)) {
      lineage.add(parseBaselineLineage(asObject(value, "baseline lineage")));
    }
    return new PlatformApiBaselineRegistry(
        integer(json, FIELD_SCHEMA_VERSION),
        definitions,
        lineage,
        string(json, FIELD_REGISTRY_DIGEST));
  }

  private static PlatformApiBaselineDefinition parseBaselineDefinition(Map<String, Object> json) {
    requireExactFields(json, BASELINE_DEFINITION_FIELDS, "baseline definition");
    List<PlatformApiBaselineEndpoint> endpoints = new ArrayList<>();
    for (Object value : asArray(json.get(FIELD_ENDPOINTS), FIELD_ENDPOINTS)) {
      Map<String, Object> endpoint = asObject(value, "baseline endpoint");
      requireExactFields(endpoint, BASELINE_ENDPOINT_FIELDS, "baseline endpoint");
      endpoints.add(
          new PlatformApiBaselineEndpoint(
              string(endpoint, FIELD_ID),
              string(endpoint, FIELD_ROUTE_FAMILY),
              string(endpoint, FIELD_ACTION_LABEL),
              stringArray(endpoint.get(FIELD_REQUIRED_CAPABILITIES), FIELD_REQUIRED_CAPABILITIES),
              bool(endpoint, FIELD_HOST_OPERATOR_BYPASS_ALLOWED),
              bool(endpoint, FIELD_APP_PROCESS_PRINCIPALS_ALLOWED),
              bool(endpoint, FIELD_APP_BROWSER_PRINCIPALS_ALLOWED)));
    }
    String predecessor = optionalString(json, FIELD_PREDECESSOR_ID);
    return new PlatformApiBaselineDefinition(
        PlatformApiBaselineId.parse(string(json, FIELD_ID)),
        predecessor == null ? null : PlatformApiBaselineId.parse(predecessor),
        stringArray(json.get(FIELD_CAPABILITIES), FIELD_CAPABILITIES),
        endpoints,
        string(json, FIELD_SOURCE_ARTIFACT_DIGEST),
        optionalString(json, FIELD_PROPOSAL_DIGEST),
        optionalString(json, FIELD_REVIEW_DIGEST),
        optionalString(json, FIELD_DOCUMENTATION_DIGEST),
        integer(json, FIELD_FIRST_COMPLETE_CONTRACT_VERSION),
        string(json, FIELD_DEFINITION_DIGEST));
  }

  private static PlatformApiBaselineLineage parseBaselineLineage(Map<String, Object> json) {
    requireExactFields(json, BASELINE_LINEAGE_FIELDS, "baseline lineage");
    return new PlatformApiBaselineLineage(
        PlatformApiBaselineId.parse(string(json, FIELD_ID)),
        string(json, FIELD_DEFINITION_DIGEST),
        PlatformApiBaselineStatus.parse(string(json, FIELD_STATUS)),
        PlatformApiBaselineEvidenceKind.parse(string(json, FIELD_EVIDENCE_KIND)),
        string(json, FIELD_EVIDENCE_DIGEST),
        optionalString(json, FIELD_ACTIVATION_RELEASE),
        optionalInteger(json, FIELD_ACTIVATION_BUILD),
        optionalString(json, FIELD_SUPPORT_STARTED_RELEASE),
        optionalString(json, FIELD_SUPPORT_ENDED_RELEASE),
        optionalString(json, FIELD_PREVIOUS_LINEAGE_DIGEST),
        string(json, FIELD_LINEAGE_DIGEST));
  }

  private static Map<String, Object> compatibilityWindowJson(
      PlatformApiCompatibilityWindow window) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
    json.put(FIELD_SCHEMA_VERSION, window.schemaVersion());
    json.put(FIELD_BASELINE_NAME, window.baselineName());
    json.put(FIELD_BASELINE_CONTRACT_VERSION, window.baselineContractVersion());
    json.put(FIELD_CURRENT_CONTRACT_VERSION, window.currentContractVersion());
    json.put(FIELD_SUPPORT_PHASE, window.supportPhase().jsonValue());
    json.put(FIELD_SUPPORT_WINDOW_STARTED_RELEASE, window.supportWindowStartedRelease());
    json.put(
        FIELD_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS,
        window.minimumDeprecationWindowContractVersions());
    json.put(
        FIELD_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS,
        window.minimumScheduledRemovalWindowContractVersions());
    json.put(FIELD_STABLE_REMOVAL_REQUIRES_NEW_BASELINE, window.stableRemovalRequiresNewBaseline());
    json.put(
        FIELD_STABLE_REMOVAL_REQUIRES_PREVIOUS_SNAPSHOT,
        window.stableRemovalRequiresPreviousSnapshot());
    json.put(
        FIELD_STABLE_REMOVAL_REQUIRES_EXPLICIT_WAIVER,
        window.stableRemovalRequiresExplicitWaiver());
    json.put(
        FIELD_CRITICAL_STABLE_REMOVAL_WAIVER_ALLOWED, window.criticalStableRemovalWaiverAllowed());
    json.put(
        FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_REVIEW,
        window.experimentalGraduationRequiresReview());
    json.put(
        FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_STABLE_REFERENCE_UPDATE,
        window.experimentalGraduationRequiresStableReferenceUpdate());
    json.put(
        FIELD_PREVIOUS_SNAPSHOT_REQUIRED_IN_PRODUCTION_BETA,
        window.previousSnapshotRequiredInProductionBeta());
    json.put(FIELD_POLICY_DOCUMENT, window.policyDocument());
    return json;
  }

  private static String audience(PlatformApiStabilityLevel stability) {
    if (stability == PlatformApiStabilityLevel.INTERNAL) {
      return "internal";
    }
    if (stability == PlatformApiStabilityLevel.OPERATOR_ONLY) {
      return "operator-only";
    }
    return "app";
  }

  private static String endpointAudience(PlatformApiEndpointDescriptor descriptor) {
    if (descriptor.stability() == PlatformApiStabilityLevel.INTERNAL) {
      return "internal";
    }
    if (descriptor.stability() == PlatformApiStabilityLevel.OPERATOR_ONLY
        || (!descriptor.appProcessAllowed() && !descriptor.appBrowserAllowed())) {
      return "operator-only";
    }
    return "app";
  }

  private static Object deprecationJson(PlatformApiDeprecation deprecation) {
    if (deprecation == null) {
      return null;
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(FIELD_DEPRECATED_SINCE_CONTRACT_VERSION, deprecation.deprecatedSinceContractVersion());
    json.put(FIELD_REMOVAL_CONTRACT_VERSION, deprecation.removalContractVersion());
    json.put(FIELD_NOTE, deprecation.note());
    return json;
  }

  private static List<PlatformApiCapabilityDescriptor> parseCapabilities(Object value) {
    List<Object> items = asArray(value, FIELD_CAPABILITIES);
    List<PlatformApiCapabilityDescriptor> descriptors = new ArrayList<>(items.size());
    for (Object item : items) {
      Map<String, Object> json = asObject(item, "capability");
      descriptors.add(
          new PlatformApiCapabilityDescriptor(
              string(json, FIELD_NAME),
              PlatformApiStabilityLevel.parse(string(json, FIELD_STABILITY)),
              integer(json, FIELD_SINCE_CONTRACT_VERSION),
              parseDeprecation(json.get(FIELD_DEPRECATION)),
              string(json, FIELD_DESCRIPTION)));
    }
    return List.copyOf(descriptors);
  }

  private static List<PlatformApiEndpointDescriptor> parseEndpoints(Object value) {
    List<Object> items = asArray(value, FIELD_ENDPOINTS);
    List<PlatformApiEndpointDescriptor> descriptors = new ArrayList<>(items.size());
    for (Object item : items) {
      Map<String, Object> json = asObject(item, "endpoint");
      descriptors.add(
          new PlatformApiEndpointDescriptor(
              string(json, FIELD_ROUTE_FAMILY),
              string(json, FIELD_METHOD),
              string(json, FIELD_ROUTE_TEMPLATE),
              string(json, FIELD_ACTION_LABEL),
              requiredCapabilities(json.get(FIELD_REQUIRED_CAPABILITIES)),
              bool(json, FIELD_HOST_OPERATOR_BYPASS_ALLOWED),
              bool(json, FIELD_APP_PROCESS_PRINCIPALS_ALLOWED),
              bool(json, FIELD_APP_BROWSER_PRINCIPALS_ALLOWED),
              PlatformApiStabilityLevel.parse(string(json, FIELD_STABILITY)),
              integer(json, FIELD_SINCE_CONTRACT_VERSION),
              parseDeprecation(json.get(FIELD_DEPRECATION)),
              string(json, FIELD_DESCRIPTION)));
    }
    return List.copyOf(descriptors);
  }

  private static PlatformApiContract.StableBaseline parseStableBaseline(
      Map<String, Object> contract, int contractVersion) {
    Object value = contract.get(FIELD_STABLE_BASELINE);
    if (value == null) {
      if (contractVersion > PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION) {
        throw new IllegalArgumentException(FIELD_STABLE_BASELINE + " must be a JSON object");
      }
      return null;
    }
    Map<String, Object> json = asObject(value, FIELD_STABLE_BASELINE);
    return new PlatformApiContract.StableBaseline(
        string(json, FIELD_NAME),
        integer(json, FIELD_CONTRACT_VERSION),
        integer(json, FIELD_CAPABILITY_COUNT),
        integer(json, FIELD_ENDPOINT_COUNT),
        stringArray(json.get(FIELD_CAPABILITIES), FIELD_STABLE_BASELINE + "." + FIELD_CAPABILITIES),
        stringArray(json.get(FIELD_ENDPOINTS), FIELD_STABLE_BASELINE + "." + FIELD_ENDPOINTS));
  }

  private static PlatformApiCompatibilityWindow parseCompatibilityWindow(
      Map<String, Object> contract, int contractVersion) {
    Object value = contract.get(FIELD_COMPATIBILITY_WINDOW);
    if (value == null) {
      return PlatformApiCompatibilityWindow.current(contractVersion);
    }
    Map<String, Object> json = asObject(value, FIELD_COMPATIBILITY_WINDOW);
    return new PlatformApiCompatibilityWindow(
        integer(json, FIELD_SCHEMA_VERSION),
        string(json, FIELD_BASELINE_NAME),
        integer(json, FIELD_BASELINE_CONTRACT_VERSION),
        integer(json, FIELD_CURRENT_CONTRACT_VERSION),
        PlatformApiCompatibilityWindowStatus.parse(string(json, FIELD_SUPPORT_PHASE)),
        string(json, FIELD_SUPPORT_WINDOW_STARTED_RELEASE),
        integer(json, FIELD_MINIMUM_DEPRECATION_WINDOW_CONTRACT_VERSIONS),
        integer(json, FIELD_MINIMUM_SCHEDULED_REMOVAL_WINDOW_CONTRACT_VERSIONS),
        bool(json, FIELD_STABLE_REMOVAL_REQUIRES_NEW_BASELINE),
        bool(json, FIELD_STABLE_REMOVAL_REQUIRES_PREVIOUS_SNAPSHOT),
        bool(json, FIELD_STABLE_REMOVAL_REQUIRES_EXPLICIT_WAIVER),
        bool(json, FIELD_CRITICAL_STABLE_REMOVAL_WAIVER_ALLOWED),
        bool(json, FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_REVIEW),
        bool(json, FIELD_EXPERIMENTAL_GRADUATION_REQUIRES_STABLE_REFERENCE_UPDATE),
        bool(json, FIELD_PREVIOUS_SNAPSHOT_REQUIRED_IN_PRODUCTION_BETA),
        string(json, FIELD_POLICY_DOCUMENT));
  }

  private static PlatformApiDeprecation parseDeprecation(Object value) {
    if (value == null) {
      return null;
    }
    Map<String, Object> json = asObject(value, FIELD_DEPRECATION);
    return new PlatformApiDeprecation(
        optionalInteger(json, FIELD_DEPRECATED_SINCE_CONTRACT_VERSION),
        optionalInteger(json, FIELD_REMOVAL_CONTRACT_VERSION),
        optionalString(json, FIELD_NOTE));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asObject(Object value, String fieldName) {
    if (value instanceof Map<?, ?> map) {
      return (Map<String, Object>) map;
    }
    throw new IllegalArgumentException(fieldName + " must be a JSON object");
  }

  @SuppressWarnings("unchecked")
  private static List<Object> asArray(Object value, String fieldName) {
    if (value instanceof List<?> list) {
      return (List<Object>) list;
    }
    throw new IllegalArgumentException(fieldName + " must be a JSON array");
  }

  private static String string(Map<String, Object> json, String fieldName) {
    String value = optionalString(json, fieldName);
    if (value == null) {
      throw new IllegalArgumentException(fieldName + " must be a string");
    }
    return value;
  }

  private static String optionalString(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    if (value == null) {
      return null;
    }
    if (value instanceof String text) {
      return text;
    }
    throw new IllegalArgumentException(fieldName + " must be a string");
  }

  private static int integer(Map<String, Object> json, String fieldName) {
    Integer value = optionalInteger(json, fieldName);
    if (value == null) {
      throw new IllegalArgumentException(fieldName + " must be an integer");
    }
    return value;
  }

  private static Integer optionalInteger(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    return switch (value) {
      case null -> null;
      case Integer integer -> integer;
      case Long longValue when longValue >= Integer.MIN_VALUE && longValue <= Integer.MAX_VALUE ->
          longValue.intValue();
      default -> throw new IllegalArgumentException(fieldName + " must be an integer");
    };
  }

  private static boolean bool(Map<String, Object> json, String fieldName) {
    Object value = json.get(fieldName);
    if (value instanceof Boolean booleanValue) {
      return booleanValue;
    }
    throw new IllegalArgumentException(fieldName + " must be a boolean");
  }

  private static void requireExactFields(
      Map<String, Object> json, Set<String> expectedFields, String fieldName) {
    if (!json.keySet().equals(expectedFields)) {
      throw new IllegalArgumentException(fieldName + " has missing or unsupported fields");
    }
  }

  private static List<String> requiredCapabilities(Object value) {
    return stringArray(value, FIELD_REQUIRED_CAPABILITIES);
  }

  private static List<String> stringArray(Object value, String fieldName) {
    List<Object> items = asArray(value, fieldName);
    List<String> strings = new ArrayList<>(items.size());
    for (Object item : items) {
      if (item instanceof String text) {
        strings.add(text);
      } else {
        throw new IllegalArgumentException(fieldName + " must contain only strings");
      }
    }
    return List.copyOf(strings);
  }

  private static final class Parser {
    private final String text;
    private int index;

    private Parser(String text) {
      this.text = text;
    }

    private Object parse() {
      Object value = parseValue();
      skipWhitespace();
      if (index != text.length()) {
        throw error("unexpected trailing JSON content");
      }
      return value;
    }

    private Object parseValue() {
      skipWhitespace();
      if (index >= text.length()) {
        throw error("unexpected end of JSON");
      }
      return switch (text.charAt(index)) {
        case '{' -> parseObject();
        case '[' -> parseArray();
        case '"' -> parseString();
        case 't' -> parseLiteral("true", Boolean.TRUE);
        case 'f' -> parseLiteral("false", Boolean.FALSE);
        case 'n' -> parseLiteral("null", null);
        default -> parseNumber();
      };
    }

    private Map<String, Object> parseObject() {
      expect('{');
      LinkedHashMap<String, Object> object = new LinkedHashMap<>();
      skipWhitespace();
      if (consume('}')) {
        return object;
      }
      do {
        skipWhitespace();
        String key = parseString();
        skipWhitespace();
        expect(':');
        if (object.containsKey(key)) {
          throw error("duplicate JSON object member");
        }
        object.put(key, parseValue());
        skipWhitespace();
      } while (consume(','));
      expect('}');
      return object;
    }

    private List<Object> parseArray() {
      expect('[');
      List<Object> values = new ArrayList<>();
      skipWhitespace();
      if (consume(']')) {
        return values;
      }
      do {
        values.add(parseValue());
        skipWhitespace();
      } while (consume(','));
      expect(']');
      return values;
    }

    private String parseString() {
      expect('"');
      StringBuilder builder = new StringBuilder();
      while (index < text.length()) {
        char ch = text.charAt(index++);
        if (ch == '"') {
          return builder.toString();
        }
        if (ch == '\\') {
          builder.append(parseEscape());
        } else {
          if (ch < 0x20) {
            throw error("unescaped control character in JSON string");
          }
          builder.append(ch);
        }
      }
      throw error("unterminated JSON string");
    }

    private char parseEscape() {
      if (index >= text.length()) {
        throw error("unterminated JSON escape");
      }
      char escaped = text.charAt(index++);
      return switch (escaped) {
        case '"' -> '"';
        case '\\' -> '\\';
        case '/' -> '/';
        case 'b' -> '\b';
        case 'f' -> '\f';
        case 'n' -> '\n';
        case 'r' -> '\r';
        case 't' -> '\t';
        case 'u' -> parseUnicodeEscape();
        default -> throw error("invalid JSON escape");
      };
    }

    private char parseUnicodeEscape() {
      if (index + 4 > text.length()) {
        throw error("truncated JSON unicode escape");
      }
      int value = 0;
      for (int offset = 0; offset < 4; offset++) {
        int digit = Character.digit(text.charAt(index++), 16);
        if (digit < 0) {
          throw error("invalid JSON unicode escape");
        }
        value = (value << 4) + digit;
      }
      return (char) value;
    }

    private Object parseLiteral(String literal, Object value) {
      if (!text.startsWith(literal, index)) {
        throw error("invalid JSON literal");
      }
      index += literal.length();
      return value;
    }

    private Number parseNumber() {
      int start = index;
      if (text.charAt(index) == '-') {
        index++;
      }
      if (index >= text.length() || !Character.isDigit(text.charAt(index))) {
        throw error("invalid JSON value");
      }
      while (index < text.length() && Character.isDigit(text.charAt(index))) {
        index++;
      }
      if (index < text.length()
          && (text.charAt(index) == '.'
              || text.charAt(index) == 'e'
              || text.charAt(index) == 'E')) {
        throw error("Platform API contract numbers must be integers");
      }
      String value = text.substring(start, index);
      try {
        long parsed = Long.parseLong(value);
        if (parsed >= Integer.MIN_VALUE && parsed <= Integer.MAX_VALUE) {
          return (int) parsed;
        }
        return parsed;
      } catch (NumberFormatException exception) {
        throw new IllegalArgumentException(
            "invalid JSON integer at JSON offset " + index, exception);
      }
    }

    private void skipWhitespace() {
      while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
        index++;
      }
    }

    private boolean consume(char expected) {
      if (index < text.length() && text.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    private void expect(char expected) {
      if (!consume(expected)) {
        throw error("expected '" + expected + "'");
      }
    }

    private IllegalArgumentException error(String message) {
      return new IllegalArgumentException(message + " at JSON offset " + index);
    }
  }
}
