package network.crypta.platform.api.consent;

/**
 * Operator-visible action families that can require an explicit consent decision.
 *
 * <p>The consent layer groups several Platform API mutations behind one preview and decision model.
 * This enum is the stable vocabulary shared by previews, decisions, audit records, and Web Shell
 * rendering. It deliberately names the local management action rather than the transport route, so
 * stale approval checks can compare the operator's decision with the mutation that later consumes
 * it. Adding a new value extends the consent contract and should be paired with route, digest, and
 * audit handling.
 *
 * <p>Each value serializes to a lower-case token that is safe to persist in process-local audit
 * records and to expose through the Platform API JSON surface.
 *
 * @see ConsentSnapshot
 * @see ConsentDecision
 */
public enum ConsentActionType {
  /**
   * Installing an app from a signed catalog entry.
   *
   * <p>The preview summarizes the catalog entry, bundle digest, permissions, API target stability,
   * review receipt state, security policy, service dependencies, and app-data declarations before
   * AppHost receives an installation request.
   */
  INSTALL_APP("install_app"),

  /**
   * Updating an installed app to a catalog or prepared update candidate.
   *
   * <p>The preview compares installed and candidate metadata. It is also used to derive legacy
   * acknowledgement flags for review, security, and app-data migration gates after the approved
   * digest has been verified.
   */
  UPDATE_APP("update_app"),

  /**
   * Reviewing an app-service dependency grant bundle.
   *
   * <p>The preview explains the requesting app, provider app, service id, scopes, contexts, expiry,
   * dependency kind, and audit impact before a host/operator approves, renews, rejects, or defers
   * the bundle.
   */
  APP_SERVICE_GRANT("app_service_grant"),

  /**
   * Reviewing app-data migration and backup requirements before an update.
   *
   * <p>This action is represented separately in JSON so clients can explain migration risk even
   * when the final mutation is an app update. It does not authorize raw backup payload access or
   * expose migration command paths.
   */
  APP_DATA_MIGRATION("app_data_migration");

  private final String jsonValue;

  ConsentActionType(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON token used in consent previews and audit records.
   *
   * <p>The token is intentionally independent of enum names so Java refactors do not alter the
   * Platform API response shape. Callers should compare this value only as a protocol token, not as
   * a localized label for operator-facing text.
   *
   * @return lower-case consent action token for API JSON fields
   */
  public String jsonValue() {
    return jsonValue;
  }
}
