package network.crypta.platform.api;

import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Provides the immutable registry and append-only lifecycle authority for Platform API {@code 1.x}
 * baselines.
 *
 * <p>The registry joins immutable definitions with their ordered lifecycle evidence. Construction
 * validates unique IDs, complete predecessor chains, definition binding, gap-free lifecycle
 * digests, closed state transitions, and monotonic inheritance from every still-supported
 * predecessor. Every lower-numbered active or deprecated definition is checked independently of the
 * declared predecessor graph. A later baseline therefore cannot omit a supported member or silently
 * change an inherited endpoint's authorization semantics by branching around it.
 *
 * <p>{@link #current} is a bootstrap registry: it imports the existing frozen {@code 1.0}
 * projection and does not assert that any later baseline or protected operation exists. Registry
 * instances are immutable, deterministically ordered, self-digested, and safe to share across
 * contract reporting, app admission, developer tooling, and certification.
 *
 * @param schemaVersion the closed persisted registry schema version
 * @param definitions the complete, immutable definitions in semantic order
 * @param lineage the append-only lifecycle transitions in evidence order
 * @param registryDigest the canonical digest binding definitions and lifecycle history
 */
public record PlatformApiBaselineRegistry(
    int schemaVersion,
    List<PlatformApiBaselineDefinition> definitions,
    List<PlatformApiBaselineLineage> lineage,
    String registryDigest) {

  /**
   * Returns every immutable baseline definition in semantic version order.
   *
   * <p>The returned list is a detached immutable copy. It includes proposed and terminal
   * definitions as retained history; callers that need an admission view should use {@link
   * #supportedBaselineIds()} instead.
   *
   * @return the canonical immutable list of all retained baseline definitions
   */
  @Override
  public List<PlatformApiBaselineDefinition> definitions() {
    return List.copyOf(definitions);
  }

  /**
   * Current closed registry artifact schema.
   *
   * <p>Readers reject other values rather than guessing migration semantics. A schema change must
   * therefore introduce an explicit parser and persisted-artifact migration.
   */
  public static final int CURRENT_SCHEMA_VERSION = 1;

  /**
   * Digest of the checked-in immutable Platform API {@code 1.0} freeze artifact.
   *
   * <p>The value anchors the imported definition; changing it would be baseline drift rather than a
   * registry update. Registry construction requires an exact match for both the definition and its
   * genesis evidence.
   */
  public static final String PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256 =
      "297f09dbe3d0a9206dd7ea2b2e6ddfd1a05cf2af77951e81320e829330c89396";

  /**
   * Canonical definition digest for the exact frozen {@code 1.0} membership and semantics.
   *
   * <p>This value binds capability membership and endpoint authorization projections independently
   * of later lifecycle evidence.
   */
  public static final String PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256 =
      "f94a06f06e929e655c4481bea92d02b90fbcac7b28f3628f5538dd073d5c71d6";

  /**
   * Canonical genesis-lineage digest importing the frozen {@code 1.0} authority.
   *
   * <p>The registry requires this exact first transition so later entries cannot replace the
   * completed freeze with a newly self-asserted genesis.
   */
  public static final String PLATFORM_API_1_0_FROZEN_LINEAGE_SHA256 =
      "3578b57e292a74dd023bc72d76f883b945e594e126d920a0f0af3fe148a24aba";

  private static final Map<PlatformApiBaselineStatus, Set<PlatformApiBaselineStatus>> TRANSITIONS =
      transitionRules();

  /**
   * Creates and validates a registry.
   *
   * <p>The canonical constructor verifies a supplied digest and is intended for parsed artifacts.
   * Producers should use {@link #create} to normalize definitions and compute the digest. A
   * successful construction verifies the frozen {@code 1.0} root, every definition and lifecycle
   * binding, legal state transitions, immutable activation coordinates, and monotonic inheritance
   * from all earlier supported baselines.
   *
   * @throws NullPointerException if required definitions, lineage, or digests are {@code null}
   * @throws IllegalArgumentException if schema, lineage, monotonicity, or digest checks fail
   */
  public PlatformApiBaselineRegistry {
    if (schemaVersion != CURRENT_SCHEMA_VERSION) {
      throw new IllegalArgumentException("unsupported Platform API baseline registry schema");
    }
    definitions = sortedDefinitions(definitions);
    lineage = List.copyOf(Objects.requireNonNull(lineage, "lineage"));
    Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitionsById =
        indexDefinitions(definitions);
    requirePredecessorLineage(definitionsById);
    Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latest =
        validateLifecycle(definitionsById, lineage);
    requireFrozen10Import(definitionsById, lineage);
    if (!latest.keySet().equals(definitionsById.keySet())) {
      throw new IllegalArgumentException("every baseline definition requires lifecycle evidence");
    }
    requireMonotonicSupportedLineage(definitionsById, latest);
    registryDigest = PlatformApiBaselineDigest.requireSha256(registryDigest, "registryDigest");
    String expected = computeDigest(schemaVersion, definitions, lineage);
    if (!registryDigest.equals(expected)) {
      throw new IllegalArgumentException("registryDigest does not match baseline registry");
    }
  }

  /**
   * Creates a registry and computes its canonical digest.
   *
   * <p>Definitions are placed in semantic baseline order. Lifecycle entries retain caller order
   * because that order is the append-only evidence chain. The resulting object is validated by the
   * canonical constructor before it is returned, so malformed predecessor graphs, fixture
   * activations, and incompatible supported definitions fail during creation.
   *
   * @param definitions every immutable baseline definition carried by the registry
   * @param lineage the complete append-only lifecycle evidence sequence
   * @return a fully validated registry with its deterministic self-digest
   * @throws IllegalArgumentException if any registry or compatibility invariant fails
   */
  public static PlatformApiBaselineRegistry create(
      List<PlatformApiBaselineDefinition> definitions, List<PlatformApiBaselineLineage> lineage) {
    List<PlatformApiBaselineDefinition> sorted = sortedDefinitions(definitions);
    List<PlatformApiBaselineLineage> immutableLineage =
        List.copyOf(Objects.requireNonNull(lineage, "lineage"));
    return new PlatformApiBaselineRegistry(
        CURRENT_SCHEMA_VERSION,
        sorted,
        immutableLineage,
        computeDigest(CURRENT_SCHEMA_VERSION, sorted, immutableLineage));
  }

  /**
   * Returns the bootstrap registry that imports, but never rewrites, the frozen {@code 1.0}
   * promise.
   *
   * <p>The result has one active imported definition. It contains no future-baseline proposal and
   * no claim of protected operational activation. Each invocation derives the same definition,
   * lineage, and registry digests from the current contract's exact frozen projection; callers may
   * safely compare that deterministic value with persisted registry summaries.
   *
   * @return the deterministic registry for the repository's current frozen baseline
   */
  public static PlatformApiBaselineRegistry current() {
    PlatformApiBaselineDefinition stable10 =
        PlatformApiBaselineDefinition.importStable10(
            PlatformApiContract.current(), PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256);
    PlatformApiBaselineLineage imported =
        PlatformApiBaselineLineage.create(
            stable10.id(),
            stable10.definitionDigest(),
            PlatformApiBaselineStatus.ACTIVE,
            PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE,
            PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256,
            null,
            null,
            null,
            null,
            null);
    return create(List.of(stable10), List.of(imported));
  }

  /**
   * Returns definitions keyed by typed baseline identity.
   *
   * <p>The map contains every retained definition, including proposal and terminal history, in
   * semantic version order. It is a derived immutable view and changing it cannot mutate the
   * registry or its digest.
   *
   * @return an immutable map preserving semantic baseline order
   */
  public Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitionsById() {
    return Collections.unmodifiableMap(indexDefinitions(definitions));
  }

  /**
   * Returns the last append-only lifecycle entry for each definition.
   *
   * <p>The result is a derived view and does not discard entries from the registry's retained
   * history. Iteration order follows the first appearance of each baseline in the lineage, while a
   * later transition replaces only that baseline's value in the returned index.
   *
   * @return an immutable map from baseline identity to its current lifecycle entry
   */
  public Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latestLineageById() {
    LinkedHashMap<PlatformApiBaselineId, PlatformApiBaselineLineage> latest = new LinkedHashMap<>();
    for (PlatformApiBaselineLineage entry : lineage) {
      latest.put(entry.baselineId(), entry);
    }
    return Collections.unmodifiableMap(latest);
  }

  /**
   * Returns active or deprecated baseline identities in semantic order.
   *
   * <p>Candidate, reviewed, documented, rejected, and end-of-support definitions are excluded. This
   * supported set is an admission promise, not an authorization grant. Apps must still satisfy
   * contract ranges, declared capabilities, consent, principal, and endpoint authorization checks.
   *
   * @return immutable supported baseline identities ordered from oldest to newest
   */
  public List<PlatformApiBaselineId> supportedBaselineIds() {
    Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latest = latestLineageById();
    return definitions.stream()
        .map(PlatformApiBaselineDefinition::id)
        .filter(id -> latest.get(id).status().isSupported())
        .toList();
  }

  /**
   * Returns exactly active baseline identities in semantic order.
   *
   * <p>Unlike {@link #supportedBaselineIds()}, this view excludes deprecated baselines. A
   * deprecated baseline remains a supported admission promise until end of support, but operator
   * status must not describe that lifecycle state as active. Candidate and documented definitions
   * are also excluded even when their complete descriptor projection is present in the contract.
   *
   * @return immutable active baseline identities ordered from oldest to newest
   */
  public List<PlatformApiBaselineId> activeBaselineIds() {
    Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latest = latestLineageById();
    return definitions.stream()
        .map(PlatformApiBaselineDefinition::id)
        .filter(id -> latest.get(id).status() == PlatformApiBaselineStatus.ACTIVE)
        .toList();
  }

  private static List<PlatformApiBaselineDefinition> sortedDefinitions(
      List<PlatformApiBaselineDefinition> values) {
    TreeMap<PlatformApiBaselineId, PlatformApiBaselineDefinition> sorted = new TreeMap<>();
    for (PlatformApiBaselineDefinition definition : Objects.requireNonNull(values, "definitions")) {
      PlatformApiBaselineDefinition checked = Objects.requireNonNull(definition, "definition");
      if (sorted.putIfAbsent(checked.id(), checked) != null) {
        throw new IllegalArgumentException("duplicate baseline definition: " + checked.id());
      }
    }
    if (sorted.isEmpty()) {
      throw new IllegalArgumentException("baseline registry definitions must not be empty");
    }
    return List.copyOf(sorted.values());
  }

  private static Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> indexDefinitions(
      List<PlatformApiBaselineDefinition> values) {
    LinkedHashMap<PlatformApiBaselineId, PlatformApiBaselineDefinition> result =
        LinkedHashMap.newLinkedHashMap(values.size());
    for (PlatformApiBaselineDefinition definition : values) {
      if (result.putIfAbsent(definition.id(), definition) != null) {
        throw new IllegalArgumentException("duplicate baseline definition: " + definition.id());
      }
    }
    return result;
  }

  private static void requirePredecessorLineage(
      Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions) {
    for (PlatformApiBaselineDefinition definition : definitions.values()) {
      PlatformApiBaselineId predecessor = definition.predecessorId();
      if (predecessor != null && !definitions.containsKey(predecessor)) {
        throw new IllegalArgumentException("unknown baseline predecessor: " + predecessor);
      }
    }
    for (PlatformApiBaselineDefinition definition : definitions.values()) {
      HashSet<PlatformApiBaselineId> visited = new HashSet<>();
      PlatformApiBaselineDefinition current = definition;
      while (current != null && current.predecessorId() != null) {
        if (!visited.add(current.id())) {
          throw new IllegalArgumentException("baseline predecessor lineage contains a cycle");
        }
        current = definitions.get(current.predecessorId());
      }
    }
  }

  private static Map<PlatformApiBaselineId, PlatformApiBaselineLineage> validateLifecycle(
      Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions,
      List<PlatformApiBaselineLineage> lineage) {
    HashMap<PlatformApiBaselineId, PlatformApiBaselineLineage> latest = new HashMap<>();
    HashSet<String> seenDigests = new HashSet<>();
    for (PlatformApiBaselineLineage entry : lineage) {
      requireValidLifecycleEntry(definitions, seenDigests, entry);
      PlatformApiBaselineLineage previous = latest.get(entry.baselineId());
      requireValidLifecycleTransition(previous, entry);
      latest.put(entry.baselineId(), entry);
    }
    return latest;
  }

  private static void requireValidLifecycleEntry(
      Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions,
      Set<String> seenDigests,
      PlatformApiBaselineLineage entry) {
    PlatformApiBaselineDefinition definition = definitions.get(entry.baselineId());
    if (definition == null) {
      throw new IllegalArgumentException("lifecycle record names an unknown baseline");
    }
    if (!definition.definitionDigest().equals(entry.definitionDigest())) {
      throw new IllegalArgumentException("lifecycle definition digest does not match definition");
    }
    if (!seenDigests.add(entry.lineageDigest())) {
      throw new IllegalArgumentException("duplicate baseline lifecycle record digest");
    }
  }

  private static void requireValidLifecycleTransition(
      PlatformApiBaselineLineage previous, PlatformApiBaselineLineage entry) {
    if (previous == null) {
      if (entry.previousLineageDigest() != null) {
        throw new IllegalArgumentException("first lifecycle record cannot name a predecessor");
      }
      requireInitialState(entry);
      return;
    }
    if (!previous.lineageDigest().equals(entry.previousLineageDigest())) {
      throw new IllegalArgumentException("baseline lifecycle chain is not gap-free");
    }
    if (!TRANSITIONS.get(previous.status()).contains(entry.status())) {
      throw new IllegalArgumentException(
          "invalid baseline lifecycle transition: "
              + previous.status().jsonValue()
              + " -> "
              + entry.status().jsonValue());
    }
    requireActivationCoordinatesPreserved(previous, entry);
  }

  private static void requireActivationCoordinatesPreserved(
      PlatformApiBaselineLineage previous, PlatformApiBaselineLineage entry) {
    if (previous.status().isSupported()
        && (!Objects.equals(previous.activationRelease(), entry.activationRelease())
            || !Objects.equals(previous.activationBuild(), entry.activationBuild())
            || !Objects.equals(previous.supportStartedRelease(), entry.supportStartedRelease()))) {
      throw new IllegalArgumentException(
          "baseline activation and support-start coordinates cannot change after activation");
    }
  }

  private static void requireFrozen10Import(
      Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions,
      List<PlatformApiBaselineLineage> lineage) {
    PlatformApiBaselineId stable10Id = PlatformApiBaselineId.parse("1.0");
    PlatformApiBaselineDefinition stable10 = definitions.get(stable10Id);
    if (stable10 == null
        || !PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256.equals(stable10.sourceArtifactDigest())
        || !PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256.equals(stable10.definitionDigest())) {
      throw new IllegalArgumentException(
          "Platform API 1.0 definition must exactly match the frozen baseline authority");
    }
    if (lineage.isEmpty()) {
      throw new IllegalArgumentException("Platform API 1.0 frozen import lineage is missing");
    }
    PlatformApiBaselineLineage genesis = lineage.getFirst();
    if (!stable10Id.equals(genesis.baselineId())
        || genesis.evidenceKind() != PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE
        || genesis.status() != PlatformApiBaselineStatus.ACTIVE
        || !PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256.equals(genesis.evidenceDigest())
        || !PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256.equals(genesis.definitionDigest())
        || !PLATFORM_API_1_0_FROZEN_LINEAGE_SHA256.equals(genesis.lineageDigest())) {
      throw new IllegalArgumentException(
          "Platform API 1.0 genesis lineage must exactly match the frozen import authority");
    }
  }

  private static void requireInitialState(PlatformApiBaselineLineage entry) {
    if (entry.evidenceKind() == PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE) {
      return;
    }
    if (entry.status() != PlatformApiBaselineStatus.PROPOSED) {
      throw new IllegalArgumentException("a new baseline lifecycle must begin as proposed");
    }
  }

  private static void requireMonotonicSupportedLineage(
      Map<PlatformApiBaselineId, PlatformApiBaselineDefinition> definitions,
      Map<PlatformApiBaselineId, PlatformApiBaselineLineage> latest) {
    for (PlatformApiBaselineDefinition candidate : definitions.values()) {
      for (PlatformApiBaselineDefinition predecessor : definitions.values()) {
        if (predecessor.id().compareTo(candidate.id()) >= 0) {
          continue;
        }
        PlatformApiBaselineLineage predecessorState = latest.get(predecessor.id());
        if (predecessorState != null && predecessorState.status().isSupported()) {
          requireCompatibleExtension(predecessor, candidate);
        }
      }
    }
  }

  private static void requireCompatibleExtension(
      PlatformApiBaselineDefinition predecessor, PlatformApiBaselineDefinition candidate) {
    Set<String> candidateCapabilities = Set.copyOf(candidate.capabilities());
    if (!candidateCapabilities.containsAll(predecessor.capabilities())) {
      throw new IllegalArgumentException(
          "baseline " + candidate.id() + " omits a supported predecessor capability");
    }
    Map<String, PlatformApiBaselineEndpoint> candidateEndpoints = candidate.endpointsByIdentity();
    for (PlatformApiBaselineEndpoint endpoint : predecessor.endpoints()) {
      PlatformApiBaselineEndpoint inherited = candidateEndpoints.get(endpoint.identity());
      if (inherited == null) {
        throw new IllegalArgumentException(
            "baseline " + candidate.id() + " omits a supported predecessor endpoint");
      }
      if (!endpoint.equals(inherited)) {
        throw new IllegalArgumentException(
            "baseline "
                + candidate.id()
                + " changes inherited endpoint authorization semantics: "
                + endpoint.identity());
      }
    }
  }

  private static String computeDigest(
      int schemaVersion,
      List<PlatformApiBaselineDefinition> definitions,
      List<PlatformApiBaselineLineage> lineage) {
    StringBuilder canonical = new StringBuilder("platform-api-baseline-registry-v1;");
    canonical.append(schemaVersion).append(';');
    for (PlatformApiBaselineDefinition definition : definitions) {
      PlatformApiBaselineDigest.append(canonical, definition.id().toString());
      PlatformApiBaselineDigest.append(canonical, definition.definitionDigest());
    }
    for (PlatformApiBaselineLineage entry : lineage) {
      PlatformApiBaselineDigest.append(canonical, entry.lineageDigest());
    }
    return PlatformApiBaselineDigest.sha256(canonical.toString());
  }

  private static Map<PlatformApiBaselineStatus, Set<PlatformApiBaselineStatus>> transitionRules() {
    Map<PlatformApiBaselineStatus, Set<PlatformApiBaselineStatus>> rules =
        new java.util.EnumMap<>(PlatformApiBaselineStatus.class);
    rules.put(
        PlatformApiBaselineStatus.PROPOSED,
        EnumSet.of(PlatformApiBaselineStatus.CANDIDATE, PlatformApiBaselineStatus.REJECTED));
    rules.put(
        PlatformApiBaselineStatus.CANDIDATE,
        EnumSet.of(PlatformApiBaselineStatus.REVIEWED, PlatformApiBaselineStatus.REJECTED));
    rules.put(
        PlatformApiBaselineStatus.REVIEWED,
        EnumSet.of(PlatformApiBaselineStatus.DOCUMENTED, PlatformApiBaselineStatus.REJECTED));
    rules.put(
        PlatformApiBaselineStatus.DOCUMENTED,
        EnumSet.of(PlatformApiBaselineStatus.ACTIVE, PlatformApiBaselineStatus.REJECTED));
    rules.put(PlatformApiBaselineStatus.ACTIVE, EnumSet.of(PlatformApiBaselineStatus.DEPRECATED));
    rules.put(
        PlatformApiBaselineStatus.DEPRECATED, EnumSet.of(PlatformApiBaselineStatus.END_OF_SUPPORT));
    rules.put(
        PlatformApiBaselineStatus.END_OF_SUPPORT, EnumSet.noneOf(PlatformApiBaselineStatus.class));
    rules.put(PlatformApiBaselineStatus.REJECTED, EnumSet.noneOf(PlatformApiBaselineStatus.class));
    return Map.copyOf(rules);
  }
}
