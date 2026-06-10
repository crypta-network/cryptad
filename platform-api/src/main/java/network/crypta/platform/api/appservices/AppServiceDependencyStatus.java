package network.crypta.platform.api.appservices;

/**
 * Effective status of one app-service dependency edge in the dependency graph.
 *
 * <p>The coordinator derives this value from the signed consumer request, currently advertised
 * provider descriptors, current grant records, and registered adapters. It is a caller-visible
 * review state, not a durable grant status. The value can change between requests when a provider
 * is installed, removed, updated, revoked, or when a grant expires.
 *
 * <p>The statuses deliberately separate descriptor compatibility from grant lifecycle. That lets
 * the Web Shell show why a dependency is unavailable before the operator approves or renews a
 * bundle, while invocation still fails closed unless an active grant and compatible descriptor are
 * present at call time.
 */
enum AppServiceDependencyStatus {
  /**
   * The provider descriptor satisfies the dependency, but no active grant is required or present.
   *
   * <p>This state is requestable during bundle review. It does not authorize invocation by itself;
   * approval still has to create or reuse an active matching grant.
   */
  AVAILABLE("available"),

  /**
   * The requested provider app is not installed or not visible to the coordinator.
   *
   * <p>Optional dependencies can degrade from this state. Required dependencies use the dependency
   * metadata to decide whether install, update, or start review should block.
   */
  MISSING_PROVIDER("missing-provider"),

  /**
   * The provider app is installed but does not advertise the requested service id.
   *
   * <p>This usually means the provider was updated, removed the service, or never supplied the
   * manifest descriptor expected by the consumer.
   */
  MISSING_SERVICE("missing-service"),

  /**
   * The provider service version falls outside the dependency's declared version range.
   *
   * <p>The graph uses this state instead of throwing for ordinary compatibility failures so
   * operators can review the mismatch and approve only after a compatible descriptor is available.
   */
  VERSION_MISMATCH("version-mismatch"),

  /**
   * The provider descriptor does not include every requested app-service scope.
   *
   * <p>Scopes are part of the grant boundary. A scope mismatch remains non-authorizing even if an
   * older grant record exists for the same consumer and service.
   */
  SCOPE_MISMATCH("scope-mismatch"),

  /**
   * The provider descriptor does not include every requested invocation context.
   *
   * <p>Contexts keep grant approval bounded to the feature surface the operator reviewed. A context
   * mismatch means the dependency cannot be approved until the provider descriptor changes.
   */
  CONTEXT_MISMATCH("context-mismatch"),

  /**
   * A matching grant exists but is still waiting for operator approval.
   *
   * <p>The dependency is visible to the app and operator, but invocation continues to fail closed
   * until the grant becomes active through an explicit host/operator action.
   */
  GRANT_PENDING("grant-pending"),

  /**
   * A matching grant is active and the provider descriptor remains compatible.
   *
   * <p>This is the only dependency graph state that represents currently authorizing grant state.
   * Invocation still rechecks the same boundary for every call.
   */
  GRANT_ACTIVE("grant-active"),

  /**
   * A matching grant exists, but its expiry timestamp is in the past.
   *
   * <p>Expired grants are shown so the operator can renew through the bundle flow. They do not
   * authorize invocation until explicit renewal succeeds.
   */
  GRANT_EXPIRED("grant-expired"),

  /**
   * A matching grant exists, but descriptor drift or manifest drift requires review.
   *
   * <p>This state is used when the previously approved compatibility fingerprint no longer matches
   * the safe provider descriptor or bundle dependency snapshot.
   */
  REVALIDATION_REQUIRED("revalidation-required"),

  /**
   * The provider descriptor exists but cannot be invoked by this coordinator.
   *
   * <p>This covers unsupported service kinds or adapters that are not registered in the current
   * build. The dependency is shown as unavailable rather than requestable.
   */
  UNAVAILABLE("unavailable");

  /** Stable lower-case token serialized in public dependency graph JSON. */
  private final String jsonValue;

  /**
   * Creates a dependency status with its public JSON token.
   *
   * @param jsonValue lower-case token exposed in dependency graph and bundle dependency JSON
   */
  AppServiceDependencyStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the public dependency graph status token.
   *
   * @return stable lower-case status token for deterministic JSON output
   */
  String jsonValue() {
    return jsonValue;
  }
}
