package network.crypta.platform.api.appservices;

/**
 * Requiredness of a manifest-declared local app-service dependency.
 *
 * <p>The kind is signed manifest metadata that tells the platform and operator how strongly the
 * consumer app depends on a local service. It is shown in dependency graph output, bundle review
 * panels, and install or update review summaries. The value does not approve a grant, and it does
 * not make an invocation legal; the coordinator still checks the current provider descriptor and an
 * active non-expired grant on every call.
 *
 * <p>The paired {@code required} boolean in the manifest must agree with this kind. Keeping both
 * forms lets manifests stay easy to review while giving route and SDK JSON a stable field for
 * simple UI decisions.
 */
public enum AppServiceDependencyKind {
  /**
   * The app can start and run with the related feature disabled or degraded.
   *
   * <p>Optional dependencies are appropriate for additive features such as local annotations. When
   * the provider, descriptor, grant, or renewal is unavailable, the app should keep unrelated
   * workflows available and report a neutral unavailable feature state.
   */
  OPTIONAL("optional"),

  /**
   * The app declares that install, update, or launch review may need to block.
   *
   * <p>Required dependencies indicate that missing or incompatible service access can prevent safe
   * app operation. The exact lifecycle consequence is still expressed by the dependency's degrade
   * behavior and enforced by host/operator review code.
   */
  REQUIRED("required");

  /** Stable lower-case token used by manifest metadata, JSON responses, and bundle fingerprints. */
  private final String jsonValue;

  /**
   * Creates an enum value bound to its public dependency-kind token.
   *
   * @param jsonValue lower-case token exposed outside the Java implementation
   */
  AppServiceDependencyKind(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable lower-case token used in manifests and public JSON.
   *
   * <p>Callers should serialize this value rather than the Java enum name. The public token is part
   * of the app-service dependency contract and is also included in bundle dependency fingerprints.
   *
   * @return public dependency-kind token for deterministic JSON and fingerprint output
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses one manifest or API token into a dependency kind.
   *
   * <p>The input is normalized with the app-service token rules before comparison. Unsupported
   * values fail closed so malformed dependency declarations cannot silently downgrade required
   * services to optional review metadata.
   *
   * @param value raw dependency kind token from signed manifest metadata or route input
   * @return dependency kind matching the normalized public token
   * @throws IllegalArgumentException when the token is malformed or unsupported
   */
  public static AppServiceDependencyKind parse(String value) {
    String normalized = AppServiceManifestParser.normalizeToken("dependency.kind", value);
    for (AppServiceDependencyKind kind : values()) {
      if (kind.jsonValue.equals(normalized)) {
        return kind;
      }
    }
    throw new IllegalArgumentException("unsupported app-service dependency kind: " + value);
  }
}
