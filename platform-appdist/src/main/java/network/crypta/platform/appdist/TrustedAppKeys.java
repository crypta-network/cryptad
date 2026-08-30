package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable trusted-key registry used during bundle verification.
 *
 * <p>The registry maps stable signature key ids to explicit public keys. It is passed into {@link
 * AppBundleVerifier} rather than read from global state, which keeps app-host policy construction
 * deterministic and testable. Instances are immutable snapshots; adding a direct key returns a new
 * registry and duplicate key ids or public keys are rejected instead of silently overriding or
 * aliasing trust material.
 *
 * <p>The local file format is intentionally small and line-oriented. Version {@code 1} remains the
 * compatibility format and treats every key as active without a bounded validity interval. Version
 * {@code 2} adds a closed lifecycle state and an explicit verification window. Both versions use
 * contiguous {@code key.N.*} entries and Ed25519 public keys encoded as X.509 base64. Remote
 * catalog trust and key discovery are outside this module.
 */
public final class TrustedAppKeys {
  private static final int COMPATIBILITY_VERSION = 1;
  private static final int LIFECYCLE_VERSION = 2;
  private static final Pattern V1_KEY_PROPERTY_PATTERN =
      Pattern.compile("key\\.(\\d+)\\.(id|algorithm|public\\.key\\.base64)");
  private static final Pattern V2_KEY_PROPERTY_PATTERN =
      Pattern.compile(
          "key\\.(\\d+)\\.(id|algorithm|public\\.key\\.base64|status|valid\\.from|valid\\.until)");
  private static final TrustedAppKeys EMPTY = new TrustedAppKeys(Map.of());

  private final Map<String, TrustedAppKeyPolicy> policiesById;

  private TrustedAppKeys(Map<String, TrustedAppKeyPolicy> policiesById) {
    requireUniquePublicKeys(policiesById.values());
    this.policiesById = Map.copyOf(policiesById);
  }

  /**
   * Creates a trusted-key registry from a collection.
   *
   * <p>The collection is copied immediately, null entries are rejected, and duplicate key ids or
   * canonical public-key fingerprints fail fast. Iteration order is preserved only for
   * deterministic construction; lookup behavior is by key id.
   *
   * @param keys trusted public keys indexed by their stable key ids
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two entries use the same key id or public key, or if a
   *     public key has no canonical encoding
   */
  public static TrustedAppKeys of(Collection<TrustedAppKey> keys) {
    Objects.requireNonNull(keys, "keys");
    List<TrustedAppKeyPolicy> policies = new ArrayList<>(keys.size());
    for (TrustedAppKey key : keys) {
      policies.add(TrustedAppKeyPolicy.activeCompatibilityKey(key));
    }
    return ofPolicies(policies);
  }

  /**
   * Creates a trusted-key registry from individual entries.
   *
   * @param keys trusted public keys indexed by their stable key ids
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two entries use the same key id or public key, or if a
   *     public key has no canonical encoding
   */
  public static TrustedAppKeys of(TrustedAppKey... keys) {
    return of(Arrays.asList(keys));
  }

  /**
   * Creates a trusted-key registry from lifecycle-aware policies.
   *
   * <p>The policies are copied immediately. Duplicate stable key ids and duplicate canonical
   * public-key fingerprints are rejected. This factory is intended for v2 derived registries and
   * deterministic lifecycle tests; existing callers can continue using {@link
   * #of(TrustedAppKey...)}.
   *
   * @param policies lifecycle-aware trusted public-key policies
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two policies use the same key id or public key, or if a
   *     public key has no canonical encoding
   */
  public static TrustedAppKeys ofPolicies(Collection<TrustedAppKeyPolicy> policies) {
    Objects.requireNonNull(policies, "policies");
    Map<String, TrustedAppKeyPolicy> policiesById = new LinkedHashMap<>();
    for (TrustedAppKeyPolicy policy : policies) {
      TrustedAppKeyPolicy checkedPolicy = Objects.requireNonNull(policy, "policy");
      String keyId = checkedPolicy.key().keyId();
      TrustedAppKeyPolicy previous = policiesById.putIfAbsent(keyId, checkedPolicy);
      if (previous != null) {
        throw new IllegalArgumentException("duplicate trusted key id: " + keyId);
      }
    }
    return new TrustedAppKeys(policiesById);
  }

  /**
   * Creates a trusted-key registry from lifecycle-aware policies.
   *
   * @param policies lifecycle-aware trusted public-key policies
   * @return immutable trusted-key registry
   * @throws IllegalArgumentException if two policies use the same key id or public key, or if a
   *     public key has no canonical encoding
   */
  public static TrustedAppKeys ofPolicies(TrustedAppKeyPolicy... policies) {
    return ofPolicies(Arrays.asList(policies));
  }

  /**
   * Returns an empty trusted-key registry.
   *
   * <p>An empty registry is useful for development policies that allow fully unsigned bundles but
   * still need to reject partially signed bundles or bundles signed by unknown keys.
   *
   * @return shared empty trusted-key registry
   */
  public static TrustedAppKeys empty() {
    return EMPTY;
  }

  /**
   * Loads trusted public keys from a local properties-style sidecar.
   *
   * <p>The v1 compatibility format is:
   *
   * <pre>{@code
   * trusted.keys.version=1
   * key.0.id=test-ed25519
   * key.0.algorithm=Ed25519
   * key.0.public.key.base64=<base64-x509-public-key>
   * }</pre>
   *
   * <p>The v2 lifecycle format additionally requires {@code key.N.status}, {@code
   * key.N.valid.from}, and {@code key.N.valid.until}. Status is one of {@code active}, {@code
   * retiring}, {@code retired}, or {@code revoked}; validity timestamps are ISO-8601 instants.
   *
   * <p>A leading UTF-8 byte-order mark is tolerated so operator-edited files saved by common text
   * editors remain usable. Unknown properties, non-contiguous indexes, incomplete entries,
   * unsupported algorithms, duplicate ids, and duplicate public keys are rejected.
   *
   * @param trustedKeysFile local trusted-key sidecar path
   * @return parsed trusted-key registry
   * @throws IOException if the sidecar is missing, malformed, or contains unsupported algorithms
   */
  public static TrustedAppKeys load(Path trustedKeysFile) throws IOException {
    return load(AppDistributionSidecars.readRequiredBytes(trustedKeysFile, "trusted keys file"));
  }

  /**
   * Loads trusted public keys from one already-captured registry byte sequence.
   *
   * <p>The bytes are parsed synchronously and are not retained. This overload lets protected
   * callers compute an authenticated digest and parse the registry from the same immutable file
   * snapshot instead of reopening a mutable path. Path confinement and symbolic-link checks remain
   * the responsibility of the caller that captured the bytes; {@link #load(Path)} provides those
   * checks for ordinary file-backed use.
   *
   * @param trustedKeysBytes exact UTF-8 registry bytes to parse
   * @return parsed trusted-key registry
   * @throws IOException if the sidecar is malformed or contains unsupported algorithms
   */
  public static TrustedAppKeys load(byte[] trustedKeysBytes) throws IOException {
    String content =
        new String(
            Objects.requireNonNull(trustedKeysBytes, "trustedKeysBytes"), StandardCharsets.UTF_8);
    Map<String, String> properties =
        AppDistributionSidecars.parseKeyValueSidecar(content, "trusted keys file");
    int version = validateTrustedKeysVersion(properties.remove("trusted.keys.version"));
    Map<Integer, TrustedKeyBuilder> builders = readTrustedKeyBuilders(properties, version);
    return buildTrustedKeys(builders, version);
  }

  private static int validateTrustedKeysVersion(String versionText)
      throws AppDistributionException {
    if (versionText == null) {
      throw new AppDistributionException("missing trusted.keys.version");
    }
    int version;
    try {
      version = Integer.parseInt(versionText);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid trusted.keys.version: " + versionText, exception);
    }
    if (version != COMPATIBILITY_VERSION && version != LIFECYCLE_VERSION) {
      throw new AppDistributionException("unsupported trusted.keys.version: " + version);
    }
    return version;
  }

  private static Map<Integer, TrustedKeyBuilder> readTrustedKeyBuilders(
      Map<String, String> properties, int version) throws AppDistributionException {
    Map<Integer, TrustedKeyBuilder> builders = new TreeMap<>();
    for (Map.Entry<String, String> property : properties.entrySet()) {
      TrustedKeyProperty trustedKeyProperty = parseTrustedKeyProperty(property.getKey(), version);
      TrustedKeyBuilder builder =
          builders.computeIfAbsent(trustedKeyProperty.index(), ignored -> new TrustedKeyBuilder());
      setTrustedKeyField(builder, trustedKeyProperty.field(), property.getValue());
    }
    return builders;
  }

  private static TrustedKeyProperty parseTrustedKeyProperty(String propertyName, int version)
      throws AppDistributionException {
    Pattern propertyPattern =
        version == COMPATIBILITY_VERSION ? V1_KEY_PROPERTY_PATTERN : V2_KEY_PROPERTY_PATTERN;
    Matcher matcher = propertyPattern.matcher(propertyName);
    if (!matcher.matches()) {
      throw new AppDistributionException("unsupported trusted keys property: " + propertyName);
    }
    return new TrustedKeyProperty(parseIndex(matcher.group(1), propertyName), matcher.group(2));
  }

  private static void setTrustedKeyField(TrustedKeyBuilder builder, String field, String value)
      throws AppDistributionException {
    switch (field) {
      case "id" -> builder.id = value;
      case "algorithm" -> builder.algorithm = value;
      case "public.key.base64" -> builder.publicKeyBase64 = value;
      case "status" -> builder.lifecycle = parseLifecycle(value);
      case "valid.from" -> builder.validFrom = value;
      case "valid.until" -> builder.validUntil = value;
      default -> throw new AppDistributionException("unsupported trusted key field: " + field);
    }
  }

  private static TrustedAppKeyLifecycle parseLifecycle(String value)
      throws AppDistributionException {
    return switch (value) {
      case "active" -> TrustedAppKeyLifecycle.ACTIVE;
      case "retiring" -> TrustedAppKeyLifecycle.RETIRING;
      case "retired" -> TrustedAppKeyLifecycle.RETIRED;
      case "revoked" -> TrustedAppKeyLifecycle.REVOKED;
      default -> throw new AppDistributionException("unsupported trusted app key status: " + value);
    };
  }

  private static TrustedAppKeys buildTrustedKeys(
      Map<Integer, TrustedKeyBuilder> builders, int version) throws IOException {
    if (builders.isEmpty()) {
      return empty();
    }

    List<TrustedAppKeyPolicy> policies = new ArrayList<>(builders.size());
    for (int expectedIndex = 0; expectedIndex < builders.size(); expectedIndex++) {
      TrustedKeyBuilder builder = requireTrustedKeyBuilder(builders, expectedIndex);
      policies.add(buildTrustedKeyPolicy(builder, expectedIndex, version));
    }
    try {
      return ofPolicies(policies);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(
          "trusted keys file is ambiguous: " + exception.getMessage(), exception);
    }
  }

  private static TrustedKeyBuilder requireTrustedKeyBuilder(
      Map<Integer, TrustedKeyBuilder> builders, int expectedIndex) throws AppDistributionException {
    TrustedKeyBuilder builder = builders.get(expectedIndex);
    if (builder == null) {
      throw new AppDistributionException("trusted keys must use contiguous indexes");
    }
    return builder;
  }

  private static TrustedAppKeyPolicy buildTrustedKeyPolicy(
      TrustedKeyBuilder builder, int expectedIndex, int version) throws IOException {
    if (builder.id == null || builder.algorithm == null || builder.publicKeyBase64 == null) {
      throw new AppDistributionException("trusted key " + expectedIndex + " is incomplete");
    }
    if (!AppBundleSignature.SIGNATURE_ALGORITHM.equals(builder.algorithm)) {
      throw new AppDistributionException("unsupported trusted key algorithm: " + builder.algorithm);
    }
    TrustedAppKey key = TrustedAppKey.ed25519(builder.id, builder.publicKeyBase64);
    if (version == COMPATIBILITY_VERSION) {
      return TrustedAppKeyPolicy.activeCompatibilityKey(key);
    }
    if (builder.lifecycle == null || builder.validFrom == null || builder.validUntil == null) {
      throw new AppDistributionException("trusted key " + expectedIndex + " is incomplete");
    }
    try {
      return new TrustedAppKeyPolicy(
          key,
          builder.lifecycle,
          Instant.parse(builder.validFrom),
          Instant.parse(builder.validUntil));
    } catch (DateTimeParseException | IllegalArgumentException exception) {
      throw new AppDistributionException(
          "trusted key " + expectedIndex + " has an invalid validity window", exception);
    }
  }

  /**
   * Looks up a trusted key by id.
   *
   * <p>This compatibility lookup does not apply lifecycle policy. Verification code must use {@link
   * AppBundleVerifier}, which enforces the key's intended new or historical verification purpose.
   *
   * @param keyId stable signature key identifier from a bundle signature sidecar
   * @return matching trusted key, when configured
   */
  public Optional<TrustedAppKey> find(String keyId) {
    return findPolicy(keyId).map(TrustedAppKeyPolicy::key);
  }

  /**
   * Looks up the lifecycle policy for a trusted key id.
   *
   * <p>This method exposes public-key lifecycle metadata only; it does not itself authorize a
   * verification purpose. Bundle verification remains responsible for applying new-versus-
   * historical policy.
   *
   * @param keyId stable signature key identifier from a bundle signature sidecar
   * @return matching trusted-key lifecycle policy, when configured
   */
  public Optional<TrustedAppKeyPolicy> findPolicy(String keyId) {
    return Optional.ofNullable(policiesById.get(keyId));
  }

  /**
   * Returns the closed set of stable key ids present in this registry.
   *
   * <p>The returned set includes every lifecycle state, including staged, retiring, retired, and
   * revoked entries. It exposes no key bytes and cannot be used as an authorization decision;
   * callers must still use the purpose-specific lookup or {@link AppBundleVerifier}. This view is
   * primarily useful for role-separation checks that must reject an otherwise valid registry when
   * it contains identities outside an explicitly approved bounded cohort.
   *
   * @return immutable set of every configured stable key id
   */
  public Set<String> keyIds() {
    return policiesById.keySet();
  }

  /**
   * Looks up a key that is authorized for routine verification at one instant.
   *
   * <p>Version 1 and direct compatibility keys remain active across the full representable time
   * range. Version 2 keys must be explicitly active and inside their declared half-open validity
   * interval. Registry membership without this policy check is not authorization.
   *
   * @param keyId stable signature key identifier
   * @param verifiedAt instant at which authorization is evaluated
   * @return matching public key when it is active and currently valid
   */
  public Optional<TrustedAppKey> findActiveForVerification(String keyId, Instant verifiedAt) {
    Objects.requireNonNull(verifiedAt, "verifiedAt");
    return findPolicy(keyId)
        .filter(policy -> policy.allowsRoutineVerification(verifiedAt))
        .map(TrustedAppKeyPolicy::key);
  }

  /**
   * Looks up a key authorized to verify an exact retained historical subject.
   *
   * <p>Active, retiring, and retired version 2 keys remain eligible only during their declared
   * support interval. Revoked keys always fail. Version 1 compatibility keys remain active across
   * the full representable time range.
   *
   * @param keyId stable signature key identifier
   * @param verifiedAt instant at which historical support is evaluated
   * @return matching public key when historical verification remains authorized
   */
  public Optional<TrustedAppKey> findHistoricalForVerification(String keyId, Instant verifiedAt) {
    Objects.requireNonNull(verifiedAt, "verifiedAt");
    return findPolicy(keyId)
        .filter(policy -> policy.allowsHistoricalVerification(verifiedAt))
        .map(TrustedAppKeyPolicy::key);
  }

  /**
   * Returns a new trusted-key registry with one additional key.
   *
   * <p>This is used by runtime configuration when an operator supplies both a trusted-keys file and
   * one direct key. A duplicate key id or canonical public-key fingerprint is treated as
   * configuration ambiguity and rejected.
   *
   * @param key trusted key to add
   * @return combined trusted-key registry
   * @throws IllegalArgumentException if the key id or public key already exists in this registry,
   *     or if a public key has no canonical encoding
   */
  public TrustedAppKeys plus(TrustedAppKey key) {
    Map<String, TrustedAppKeyPolicy> combined = new LinkedHashMap<>(policiesById);
    TrustedAppKeyPolicy policy = TrustedAppKeyPolicy.activeCompatibilityKey(key);
    TrustedAppKeyPolicy previous = combined.putIfAbsent(policy.key().keyId(), policy);
    if (previous != null) {
      throw new IllegalArgumentException("duplicate trusted key id: " + policy.key().keyId());
    }
    return new TrustedAppKeys(combined);
  }

  /**
   * Returns a registry containing the complete lifecycle policies from both local registries.
   *
   * <p>This is intended for combining independently authenticated publisher registries assigned to
   * the same bundle-signing role. Duplicate key IDs and duplicate public-key fingerprints remain
   * configuration errors; callers must never use this method to combine distinct signing roles.
   *
   * @param other additional registry for the same signing role
   * @return immutable combined registry preserving lifecycle and validity policy
   */
  public TrustedAppKeys plus(TrustedAppKeys other) {
    Objects.requireNonNull(other, "other");
    Map<String, TrustedAppKeyPolicy> combined = new LinkedHashMap<>(policiesById);
    for (Map.Entry<String, TrustedAppKeyPolicy> entry : other.policiesById.entrySet()) {
      if (combined.putIfAbsent(entry.getKey(), entry.getValue()) != null) {
        throw new IllegalArgumentException("duplicate trusted key id: " + entry.getKey());
      }
    }
    return new TrustedAppKeys(combined);
  }

  private static void requireUniquePublicKeys(Collection<TrustedAppKeyPolicy> policies) {
    Map<String, String> keyIdByFingerprint = new LinkedHashMap<>();
    for (TrustedAppKeyPolicy policy : policies) {
      String keyId = policy.key().keyId();
      String fingerprint = PublicKeyFingerprint.sha256(policy.key().publicKey());
      String previousKeyId = keyIdByFingerprint.putIfAbsent(fingerprint, keyId);
      if (previousKeyId != null && !previousKeyId.equals(keyId)) {
        throw new IllegalArgumentException(
            "duplicate trusted public-key fingerprint for key ids: "
                + previousKeyId
                + " and "
                + keyId);
      }
    }
  }

  /**
   * Requires this registry and another role registry to contain disjoint trust material.
   *
   * <p>Role separation applies to every configured key, including retiring, retired, and revoked
   * entries. Reusing either a stable key id or the SHA-256 fingerprint of canonical X.509 public
   * key bytes across roles is configuration ambiguity and fails closed. Callers that deliberately
   * support a legacy shared registry should not invoke this method for that fallback.
   *
   * @param other trusted-key registry assigned to another signing role
   * @throws IllegalArgumentException if a key id or public-key fingerprint occurs in both
   *     registries, or if a public key has no canonical encoding
   */
  public void requireDisjointFrom(TrustedAppKeys other) {
    Objects.requireNonNull(other, "other");
    for (String keyId : policiesById.keySet()) {
      if (other.policiesById.containsKey(keyId)) {
        throw new IllegalArgumentException("trusted key registries overlap on key id: " + keyId);
      }
    }
    Set<String> fingerprints = new HashSet<>();
    for (TrustedAppKeyPolicy policy : policiesById.values()) {
      fingerprints.add(PublicKeyFingerprint.sha256(policy.key().publicKey()));
    }
    for (TrustedAppKeyPolicy policy : other.policiesById.values()) {
      if (fingerprints.contains(PublicKeyFingerprint.sha256(policy.key().publicKey()))) {
        throw new IllegalArgumentException(
            "trusted key registries overlap on public-key fingerprint");
      }
    }
  }

  private static int parseIndex(String rawIndex, String propertyName)
      throws AppDistributionException {
    try {
      return Integer.parseInt(rawIndex);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException(
          "invalid trusted key entry index in " + propertyName, exception);
    }
  }

  private record TrustedKeyProperty(int index, String field) {}

  private static final class TrustedKeyBuilder {
    private String id;
    private String algorithm;
    private String publicKeyBase64;
    private TrustedAppKeyLifecycle lifecycle;
    private String validFrom;
    private String validUntil;
  }
}
