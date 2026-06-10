package network.crypta.platform.api.appservices;

/**
 * Operator-visible behavior requested when a declared app-service dependency is unavailable.
 *
 * <p>The value is signed manifest metadata used by dependency graph rendering, install or update
 * review, and grant-bundle presentation. It does not authorize service calls by itself. The
 * coordinator still requires an active app-service grant and a compatible provider descriptor
 * before invocation can proceed.
 *
 * <p>The behavior describes the consumer app's intended fallback when the service is missing,
 * expired, revoked, or marked for revalidation. Optional dependencies normally disable only the
 * affected feature, while required dependencies can ask the host to block app start or update
 * application. Operators can use the value to make a single bundle decision without reading raw
 * request bodies, local paths, or provider state.
 */
public enum AppServiceDegradeBehavior {
  /**
   * Disable only the feature named by the dependency metadata.
   *
   * <p>This is the normal fallback for optional features such as Social Inbox trust-score
   * annotations. The app remains usable, but the specific feature reports a neutral unavailable
   * state until a compatible grant becomes active again.
   */
  DISABLE_FEATURE("disable-feature"),

  /**
   * Keep the app available while warning the operator and caller-visible app surface.
   *
   * <p>Use this value for dependencies whose absence should be visible during review, but whose
   * absence does not require disabling a named feature or blocking app lifecycle actions.
   */
  WARN_ONLY("warn-only"),

  /**
   * Treat the missing or stale dependency as an app-start blocker.
   *
   * <p>This value is appropriate only for required local services that the app cannot safely run
   * without. It is still advisory metadata for lifecycle review; the app-service grant boundary
   * remains enforced separately at invocation time.
   */
  BLOCK_APP_START("block-app-start"),

  /**
   * Treat the missing or stale dependency as an app-update blocker.
   *
   * <p>This value lets update review identify a newly introduced required dependency that is
   * missing, incompatible, or waiting for explicit operator approval. It does not grant access and
   * does not override migration or channel policy gates.
   */
  BLOCK_UPDATE("block-update");

  /** Stable lower-case token written to manifests, JSON responses, and review fingerprints. */
  private final String jsonValue;

  /**
   * Creates an enum value bound to its public app-service token.
   *
   * @param jsonValue lower-case token exposed outside the Java implementation
   */
  AppServiceDegradeBehavior(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable lower-case token serialized in manifests, JSON responses, and bundle
   * fingerprints.
   *
   * <p>The token is intentionally independent of the Java enum constant name so public API output
   * can stay stable if internal naming changes. Callers should compare this value rather than
   * relying on {@link #name()}.
   *
   * @return public app-service degrade behavior token for deterministic JSON output
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses one manifest or API token into the corresponding degrading behavior.
   *
   * <p>The parser uses the same token normalization as the rest of app-service manifest handling:
   * leading and trailing whitespace is ignored, the value is lower-cased, and unsupported tokens
   * fail closed with an {@link IllegalArgumentException}. Callers wrap that exception in the
   * appropriate route or manifest error.
   *
   * @param value manifest or API token supplied by a dependency declaration
   * @return enum value matching the normalized public token
   * @throws IllegalArgumentException when the token is malformed or unsupported
   */
  public static AppServiceDegradeBehavior parse(String value) {
    String normalized = AppServiceManifestParser.normalizeToken("degradeBehavior", value);
    for (AppServiceDegradeBehavior behavior : values()) {
      if (behavior.jsonValue.equals(normalized)) {
        return behavior;
      }
    }
    throw new IllegalArgumentException("unsupported app-service degrade behavior: " + value);
  }
}
