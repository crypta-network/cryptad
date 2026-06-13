package network.crypta.platform.api.operator.recovery;

/**
 * Groups operator RC recovery actions into the operational areas shown by the API and Web Shell.
 *
 * <p>The category is presentation metadata rather than an authorization boundary. Route handlers
 * still perform host/operator checks, and {@code OperatorRecoveryActionId} remains the closed
 * dispatch key for planning and execution. Keeping this enum separate from action identifiers lets
 * clients render stable sections such as app lifecycle, content subscriptions, and support bundles
 * while allowing individual actions in those sections to evolve independently.
 *
 * <p>Each constant has a stable JSON token. Those tokens are intentionally short, lowercase, and
 * path-free so support bundles and release-certification evidence can include them without exposing
 * operator-local implementation details.
 */
public enum OperatorRecoveryActionCategory {
  /**
   * Catalog source and signature repair actions.
   *
   * <p>Actions in this category refresh or reverify catalog metadata while preserving catalog
   * policy, channel, review, and signature gates.
   */
  CATALOG("catalog"),
  /**
   * Installed app lifecycle, update, rollback, reinstall, and uninstall-preparation actions.
   *
   * <p>These actions operate on app identifiers and are expected to preserve app-data, migration,
   * dependency, and security-advisory checks.
   */
  APP("app"),
  /**
   * Content subscription recovery actions scoped by app and subscription identifiers.
   *
   * <p>The category covers metadata-only scheduling repair as well as explicit refresh requests
   * that still consume network-scale fetch budgets.
   */
  SUBSCRIPTION("subscription"),
  /**
   * App-service grant and dependency-bundle recovery actions.
   *
   * <p>Actions here expose provider and grant state in redacted form and keep expired or drifted
   * grants fail-closed until an explicit recovery operation succeeds.
   */
  APP_SERVICE("app-service"),
  /**
   * Local Trust Graph recovery actions.
   *
   * <p>This category is limited to local operator-curated trust metadata. It does not represent
   * global truth, routing policy, moderation, or legacy Web of Trust compatibility.
   */
  TRUST_GRAPH("trust-graph"),
  /**
   * Safe network-budget visibility actions.
   *
   * <p>The category reports counters, limits, leases, and next-availability metadata without raw
   * URIs, content bodies, request bodies, or queue internals.
   */
  NETWORK_BUDGET("network-budget"),
  /**
   * Support-bundle preview and export actions.
   *
   * <p>Actions in this category assemble redacted operator evidence and must not include app-data
   * backup payloads, raw Trust Graph statements, tokens, passwords, or local paths.
   */
  SUPPORT("support");

  private final String jsonValue;

  OperatorRecoveryActionCategory(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON token for this category.
   *
   * <p>The value is suitable for deterministic API responses, support-bundle summaries, and Web
   * Shell grouping. It is not a route segment chosen by clients and must not be treated as a
   * permission check.
   *
   * @return the lowercase, path-free category token emitted in operator recovery JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
