package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Defines immutable membership and inherited authorization semantics for one named stable baseline.
 *
 * <p>A definition is the compatibility promise itself: it records the exact capabilities and
 * endpoint semantics present once a baseline candidate is complete. Lifecycle state and release
 * activation are intentionally stored in {@link PlatformApiBaselineLineage}, allowing later
 * evidence to advance a proposal without editing historical membership. Definitions are sorted and
 * self-digested so semantically equivalent input has one deterministic representation.
 *
 * <p>The built-in {@code 1.0} definition is projected from the frozen contract and bound to its
 * retained artifact digest. Later {@code 1.x} definitions must name a predecessor and retain every
 * member required by supported predecessors. Instances are immutable and safe to share between
 * verifier, runtime-admission, CLI, and release-certification code.
 *
 * @param id the canonical baseline identity represented by this definition
 * @param predecessorId the preceding baseline identity, or {@code null} only for {@code 1.0}
 * @param capabilities the exact, deterministically ordered capability membership
 * @param endpoints the exact, deterministically ordered endpoint semantics
 * @param sourceArtifactDigest the digest of the source artifact carrying this definition
 * @param proposalDigest the originating proposal digest, required after {@code 1.0}
 * @param reviewDigest the compatibility and security review digest when available
 * @param documentationDigest the stable-reference documentation digest when available
 * @param firstCompleteContractVersion the first integer contract containing every candidate member
 * @param definitionDigest the canonical self-digest of all preceding definition fields
 */
public record PlatformApiBaselineDefinition(
    PlatformApiBaselineId id,
    PlatformApiBaselineId predecessorId,
    List<String> capabilities,
    List<PlatformApiBaselineEndpoint> endpoints,
    String sourceArtifactDigest,
    String proposalDigest,
    String reviewDigest,
    String documentationDigest,
    int firstCompleteContractVersion,
    String definitionDigest) {

  /**
   * Returns the exact capability membership frozen into this baseline definition.
   *
   * <p>The returned list is a detached immutable copy in canonical lexical order. Callers may use
   * it for deterministic serialization, compatibility comparison, or admission checks, but cannot
   * mutate the definition through the list.
   *
   * @return the canonical immutable list of capability identifiers
   */
  @Override
  public List<String> capabilities() {
    return List.copyOf(capabilities);
  }

  /**
   * Returns the exact endpoint semantics frozen into this baseline definition.
   *
   * <p>The returned list is a detached immutable copy ordered by endpoint identity. Each entry
   * retains the authorization fields used for monotonic compatibility checks; obtaining the list
   * does not authorize an app or perform route matching.
   *
   * @return the canonical immutable list of endpoint-semantic projections
   */
  @Override
  public List<PlatformApiBaselineEndpoint> endpoints() {
    return List.copyOf(endpoints);
  }

  /**
   * Creates and verifies one immutable definition.
   *
   * <p>The canonical constructor is primarily for parsing persisted artifacts because it verifies
   * the supplied self-digest. New producers should use {@link #create}, which normalizes membership
   * and computes that digest. Construction rejects malformed predecessor relationships, duplicate
   * membership, endpoints whose required capabilities are outside the definition, and any digest
   * mismatch. A successfully constructed instance is already normalized and requires no further
   * defensive copying by consumers.
   *
   * @throws NullPointerException if a required identity, membership, or digest is {@code null}
   * @throws IllegalArgumentException if membership, lineage, or digest invariants are violated
   */
  public PlatformApiBaselineDefinition {
    Objects.requireNonNull(id, "id");
    if (id.minor() == 0 && predecessorId != null) {
      throw new IllegalArgumentException("Platform API 1.0 cannot name a predecessor");
    }
    if (id.minor() > 0 && predecessorId == null) {
      throw new IllegalArgumentException(
          "a later Platform API 1.x baseline must name a predecessor");
    }
    if (predecessorId != null && predecessorId.compareTo(id) >= 0) {
      throw new IllegalArgumentException(
          "baseline predecessor must be earlier than the definition");
    }
    capabilities = sortedCapabilities(capabilities);
    endpoints = sortedEndpoints(endpoints, capabilities);
    sourceArtifactDigest =
        PlatformApiBaselineDigest.requireSha256(sourceArtifactDigest, "sourceArtifactDigest");
    proposalDigest = optionalDigest(proposalDigest, "proposalDigest");
    reviewDigest = optionalDigest(reviewDigest, "reviewDigest");
    documentationDigest = optionalDigest(documentationDigest, "documentationDigest");
    if (id.minor() > 0 && proposalDigest == null) {
      throw new IllegalArgumentException(
          "a future 1.x baseline definition requires an originating proposal digest");
    }
    if (firstCompleteContractVersion <= 0) {
      throw new IllegalArgumentException("firstCompleteContractVersion must be positive");
    }
    definitionDigest =
        PlatformApiBaselineDigest.requireSha256(definitionDigest, "definitionDigest");
    String expected =
        computeDigest(
            id,
            predecessorId,
            capabilities,
            endpoints,
            sourceArtifactDigest,
            proposalDigest,
            reviewDigest,
            documentationDigest,
            firstCompleteContractVersion);
    if (!definitionDigest.equals(expected)) {
      throw new IllegalArgumentException("definitionDigest does not match baseline definition");
    }
  }

  /**
   * Creates a definition and computes its canonical self-digest.
   *
   * <p>Capabilities and endpoints are sorted before hashing. Duplicate members, endpoints that
   * require capabilities outside the baseline, and later baselines without proposal evidence are
   * rejected.
   *
   * @param id the canonical identity for the new baseline definition
   * @param predecessorId its earlier baseline, or {@code null} only for {@code 1.0}
   * @param capabilities the exact capability membership to freeze
   * @param endpoints the endpoint identities and authorization semantics to freeze
   * @param sourceArtifactDigest the lowercase SHA-256 digest of the carrying artifact
   * @param proposalDigest the proposal digest, required for a post-{@code 1.0} definition
   * @param reviewDigest an optional compatibility and security review digest
   * @param documentationDigest an optional stable-reference documentation digest
   * @param firstCompleteContractVersion the first positive contract containing the candidate
   * @return a normalized immutable definition with a verified canonical self-digest
   * @throws IllegalArgumentException if any definition invariant is violated
   */
  public static PlatformApiBaselineDefinition create(
      PlatformApiBaselineId id,
      PlatformApiBaselineId predecessorId,
      List<String> capabilities,
      List<PlatformApiBaselineEndpoint> endpoints,
      String sourceArtifactDigest,
      String proposalDigest,
      String reviewDigest,
      String documentationDigest,
      int firstCompleteContractVersion) {
    List<String> normalizedCapabilities = sortedCapabilities(capabilities);
    List<PlatformApiBaselineEndpoint> normalizedEndpoints =
        sortedEndpoints(endpoints, normalizedCapabilities);
    String digest =
        computeDigest(
            id,
            predecessorId,
            normalizedCapabilities,
            normalizedEndpoints,
            sourceArtifactDigest,
            proposalDigest,
            reviewDigest,
            documentationDigest,
            firstCompleteContractVersion);
    return new PlatformApiBaselineDefinition(
        id,
        predecessorId,
        normalizedCapabilities,
        normalizedEndpoints,
        sourceArtifactDigest,
        proposalDigest,
        reviewDigest,
        documentationDigest,
        firstCompleteContractVersion,
        digest);
  }

  /**
   * Imports the exact existing {@code 1.0} projection and binds it to the retained freeze artifact.
   *
   * <p>This method does not regenerate or reinterpret the frozen JSON artifact. It checks the
   * contract's established baseline name and root contract version, then projects the already
   * frozen endpoint semantics for deterministic registry use.
   *
   * @param contract the current contract that must carry the immutable {@code 1.0} projection
   * @param frozenArtifactDigest the retained freeze artifact's lowercase SHA-256 digest
   * @return the immutable imported definition rooted at contract version {@code 19}
   * @throws IllegalArgumentException if the contract no longer matches the frozen baseline
   */
  public static PlatformApiBaselineDefinition importStable10(
      PlatformApiContract contract, String frozenArtifactDigest) {
    PlatformApiContract checked = Objects.requireNonNull(contract, "contract");
    PlatformApiContract.StableBaseline baseline = checked.stableBaseline();
    if (!PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME.equals(baseline.name())
        || baseline.contractVersion()
            != PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION) {
      throw new IllegalArgumentException(
          "contract does not carry the immutable Platform API 1.0 baseline");
    }
    Map<String, PlatformApiEndpointDescriptor> descriptors =
        checked.stableBaselineEndpointsByIdentity();
    List<PlatformApiBaselineEndpoint> endpointSemantics = new ArrayList<>();
    for (String identity : baseline.endpoints()) {
      PlatformApiEndpointDescriptor descriptor = descriptors.get(identity);
      if (descriptor == null) {
        throw new IllegalArgumentException(
            "stable 1.0 endpoint descriptor is missing: " + identity);
      }
      endpointSemantics.add(PlatformApiBaselineEndpoint.fromDescriptor(descriptor));
    }
    PlatformApiBaselineDefinition imported =
        create(
            PlatformApiBaselineId.parse(PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME),
            null,
            baseline.capabilities(),
            endpointSemantics,
            frozenArtifactDigest,
            null,
            null,
            null,
            baseline.contractVersion());
    if (!PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256.equals(
            imported.sourceArtifactDigest())
        || !PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256.equals(
            imported.definitionDigest())) {
      throw new IllegalArgumentException(
          "imported Platform API 1.0 definition must exactly match the frozen authority");
    }
    return imported;
  }

  /**
   * Returns endpoint semantics keyed by exact {@code METHOD /path} identity.
   *
   * <p>The returned map is sorted and immutable. It is intended for exact inherited-semantics
   * comparisons; it does not perform route matching or authorization. Because construction rejects
   * duplicate endpoint identities, every list member has exactly one corresponding map entry. The
   * values remain the immutable endpoint projections stored by this definition.
   *
   * @return all endpoint semantics keyed by their stable descriptor identity
   */
  public Map<String, PlatformApiBaselineEndpoint> endpointsByIdentity() {
    TreeMap<String, PlatformApiBaselineEndpoint> result = new TreeMap<>();
    for (PlatformApiBaselineEndpoint endpoint : endpoints) {
      result.put(endpoint.identity(), endpoint);
    }
    return java.util.Collections.unmodifiableMap(result);
  }

  private static List<String> sortedCapabilities(List<String> values) {
    TreeSet<String> sorted = new TreeSet<>();
    for (String value : Objects.requireNonNull(values, "capabilities")) {
      String capability = requireCapabilityText(value);
      if (!sorted.add(capability)) {
        throw new IllegalArgumentException("duplicate baseline capability: " + capability);
      }
    }
    if (sorted.isEmpty()) {
      throw new IllegalArgumentException("baseline capabilities must not be empty");
    }
    return List.copyOf(sorted);
  }

  private static List<PlatformApiBaselineEndpoint> sortedEndpoints(
      List<PlatformApiBaselineEndpoint> values, List<String> capabilities) {
    TreeSet<String> capabilitySet = new TreeSet<>(capabilities);
    TreeMap<String, PlatformApiBaselineEndpoint> sorted = new TreeMap<>();
    for (PlatformApiBaselineEndpoint endpoint : Objects.requireNonNull(values, "endpoints")) {
      PlatformApiBaselineEndpoint checked = Objects.requireNonNull(endpoint, "endpoint");
      if (!capabilitySet.containsAll(checked.requiredCapabilities())) {
        throw new IllegalArgumentException(
            "baseline endpoint requires a capability outside baseline membership: "
                + checked.identity());
      }
      if (sorted.putIfAbsent(checked.identity(), checked) != null) {
        throw new IllegalArgumentException("duplicate baseline endpoint: " + checked.identity());
      }
    }
    if (sorted.isEmpty()) {
      throw new IllegalArgumentException("baseline endpoints must not be empty");
    }
    return sorted.values().stream()
        .sorted(Comparator.comparing(PlatformApiBaselineEndpoint::identity))
        .toList();
  }

  private static String computeDigest(
      PlatformApiBaselineId id,
      PlatformApiBaselineId predecessorId,
      List<String> capabilities,
      List<PlatformApiBaselineEndpoint> endpoints,
      String sourceArtifactDigest,
      String proposalDigest,
      String reviewDigest,
      String documentationDigest,
      int firstCompleteContractVersion) {
    StringBuilder canonical = new StringBuilder("platform-api-baseline-definition-v1;");
    PlatformApiBaselineDigest.append(canonical, Objects.requireNonNull(id, "id").toString());
    PlatformApiBaselineDigest.append(
        canonical, predecessorId == null ? null : predecessorId.toString());
    canonical.append(firstCompleteContractVersion).append(';');
    PlatformApiBaselineDigest.append(canonical, sourceArtifactDigest);
    PlatformApiBaselineDigest.append(canonical, proposalDigest);
    PlatformApiBaselineDigest.append(canonical, reviewDigest);
    PlatformApiBaselineDigest.append(canonical, documentationDigest);
    for (String capability : capabilities) {
      PlatformApiBaselineDigest.append(canonical, capability);
    }
    for (PlatformApiBaselineEndpoint endpoint : endpoints) {
      PlatformApiBaselineDigest.append(canonical, endpoint.identity());
      PlatformApiBaselineDigest.append(canonical, endpoint.routeFamily());
      PlatformApiBaselineDigest.append(canonical, endpoint.actionLabel());
      canonical
          .append(endpoint.hostOperatorBypassAllowed())
          .append(';')
          .append(endpoint.appProcessAllowed())
          .append(';')
          .append(endpoint.appBrowserAllowed())
          .append(';');
      for (String capability : endpoint.requiredCapabilities()) {
        PlatformApiBaselineDigest.append(canonical, capability);
      }
    }
    return PlatformApiBaselineDigest.sha256(canonical.toString());
  }

  private static String optionalDigest(String value, String fieldName) {
    return value == null ? null : PlatformApiBaselineDigest.requireSha256(value, fieldName);
  }

  private static String requireCapabilityText(String value) {
    String text = Objects.requireNonNull(value, "capability").trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException("capability must not be blank");
    }
    return text;
  }
}
