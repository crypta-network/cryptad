package network.crypta.platform.api.appservices;

import java.time.Duration;
import java.util.LinkedHashMap;

/**
 * Manifest-declared dependency metadata attached to an app-service request alias.
 *
 * <p>This record is the signed review metadata for one consumer-to-provider service relationship.
 * It travels with an {@link AppServiceRequestDescriptor}, appears in dependency graph output, and
 * is copied into grant-bundle review surfaces. The metadata explains whether the app considers the
 * dependency required, which feature is affected, which provider service versions are acceptable,
 * and how the app should degrade when the service is missing or no grant authorizes invocation.
 *
 * <p>The descriptor is not an authorization artifact. It cannot create a grant, approve a bundle,
 * or bypass provider compatibility checks. Its constructor normalizes tokens, keeps operator-facing
 * text bounded and path-free, and applies conservative defaults so legacy request manifests remain
 * visible as optional dependencies.
 *
 * @param alias manifest-local request alias used to correlate requests, bundles, and graph edges
 * @param kind required or optional dependency classification declared by the consumer app
 * @param required boolean mirror of {@code kind}; it must match the normalized dependency kind
 * @param versionRange optional provider service version range accepted by this dependency
 * @param reason optional bounded operator-facing explanation for the dependency relationship
 * @param degradeBehavior requested app behavior when the dependency cannot authorize calls
 * @param featureId optional stable feature token affected by this dependency
 * @param featureName optional bounded display name for the affected feature
 * @param grantBundle optional bundle alias used to group related dependency grants
 * @param grantExpiresAfter optional requested grant lifetime before local policy capping
 */
public record AppServiceDependencyDescriptor(
    String alias,
    AppServiceDependencyKind kind,
    boolean required,
    AppServiceVersionRange versionRange,
    String reason,
    AppServiceDegradeBehavior degradeBehavior,
    String featureId,
    String featureName,
    String grantBundle,
    Duration grantExpiresAfter) {
  /**
   * Creates a normalized dependency descriptor.
   *
   * <p>The compact constructor enforces the dependency-kind invariant, applies default degrade
   * behavior, and validates all text before the descriptor can be serialized. The stored duration
   * is only the app's requested lifetime; the coordinator still caps it with local policy when it
   * approves a grant bundle.
   *
   * @throws IllegalArgumentException when required and kind disagree, text is unsafe, or expiry is
   *     not positive
   */
  public AppServiceDependencyDescriptor {
    alias = AppServiceManifestParser.normalizeAlias(alias);
    kind = kind == null ? AppServiceDependencyKind.OPTIONAL : kind;
    if (required != (kind == AppServiceDependencyKind.REQUIRED)) {
      throw new IllegalArgumentException("dependency required flag must match dependency kind");
    }
    reason = AppServiceManifestParser.optionalSafeText(reason, 512);
    degradeBehavior = degradeBehavior == null ? defaultDegradeBehavior(kind) : degradeBehavior;
    featureId =
        featureId == null ? null : AppServiceManifestParser.normalizeToken("featureId", featureId);
    featureName = AppServiceManifestParser.optionalSafeText(featureName, 80);
    grantBundle = grantBundle == null ? null : AppServiceManifestParser.normalizeAlias(grantBundle);
    if (grantExpiresAfter != null
        && (grantExpiresAfter.isZero() || grantExpiresAfter.isNegative())) {
      throw new IllegalArgumentException("grant expiry duration must be positive");
    }
  }

  /**
   * Builds legacy optional dependency metadata for a pre-PR-253 request alias.
   *
   * <p>Older manifests declare service requests without explicit dependency fields. Treating those
   * requests as optional dependency metadata preserves review visibility while avoiding a new
   * default-blocking behavior during upgrade.
   *
   * @param alias manifest-local request alias from the legacy request list
   * @return optional dependency metadata with safe default degrade behavior
   */
  static AppServiceDependencyDescriptor legacyOptional(String alias) {
    return new AppServiceDependencyDescriptor(
        alias,
        AppServiceDependencyKind.OPTIONAL,
        false,
        null,
        null,
        AppServiceDegradeBehavior.DISABLE_FEATURE,
        null,
        null,
        null,
        null);
  }

  /**
   * Returns public deterministic JSON for graph, bundle, and SDK callers.
   *
   * <p>The map contains only normalized identifiers, bounded display text, optional version-range
   * metadata, and the ISO-8601 duration string. It deliberately excludes local installation paths,
   * raw service request bodies, provider runtime state, tokens, and raw Trust Graph data.
   *
   * @return ordered JSON-compatible dependency metadata map
   */
  public java.util.Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put("alias", alias);
    json.put("kind", kind.jsonValue());
    json.put("required", required);
    json.put("versionRange", versionRange == null ? null : versionRange.toJson());
    json.put("reason", reason);
    json.put("degradeBehavior", degradeBehavior.jsonValue());
    json.put("featureId", featureId);
    json.put("featureName", featureName);
    json.put("grantBundle", grantBundle);
    json.put("grantExpiresAfter", grantExpiresAfter == null ? null : grantExpiresAfter.toString());
    return json;
  }

  /**
   * Chooses the conservative fallback behavior for manifests that omit the degrade-behavior field.
   *
   * <p>Legacy and optional dependencies default to disabling only the affected feature. Required
   * dependencies default to app-start blocking so missing dependency metadata cannot make a
   * required local service look harmless during lifecycle review.
   *
   * @param kind normalized dependency requiredness
   * @return default operator-visible fallback behavior for the dependency kind
   */
  private static AppServiceDegradeBehavior defaultDegradeBehavior(AppServiceDependencyKind kind) {
    return kind == AppServiceDependencyKind.REQUIRED
        ? AppServiceDegradeBehavior.BLOCK_APP_START
        : AppServiceDegradeBehavior.DISABLE_FEATURE;
  }
}
