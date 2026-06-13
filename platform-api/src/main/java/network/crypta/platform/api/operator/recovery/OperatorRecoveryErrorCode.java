package network.crypta.platform.api.operator.recovery;

/**
 * Stable safe reason codes for blocked or failed operator recovery work.
 *
 * <p>Recovery results expose these codes instead of raw exception classes, stack traces, paths, or
 * request bodies. The codes are intentionally coarse: they give the Web Shell, support bundles, and
 * release-certification evidence enough structure to explain why an action did not complete without
 * revealing private catalog URIs, app-data values, backup payloads, Trust Graph statements, tokens,
 * or local filesystem details.
 *
 * <p>A code describes the recovery envelope state, not an HTTP status by itself. Route handlers may
 * reject malformed requests before a recovery result exists, while planned actions can return
 * blocked, failed, or partial results with one of these safe reason tokens.
 */
public enum OperatorRecoveryErrorCode {
  /**
   * No error or block reason is present.
   *
   * <p>Completed actions use this code when every planned step finished and no partial-failure
   * summary is required.
   */
  NONE("none"),
  /**
   * The submitted action id is not part of the closed recovery allowlist.
   *
   * <p>This code prevents arbitrary route, method, or command dispatch from being represented as a
   * supported recovery action.
   */
  UNKNOWN_ACTION("unknown_action"),
  /**
   * The submitted target shape is missing, malformed, or incompatible with the action.
   *
   * <p>Target validation is performed before service dispatch. Redacted target summaries may be
   * audited, but raw operator-supplied paths or private URIs must not be stored.
   */
  INVALID_TARGET("invalid_target"),
  /**
   * A required backing service is not configured or cannot safely answer.
   *
   * <p>Examples include unavailable Trust Graph storage, missing app-service coordinators, or
   * absent catalog/update handlers in a test or reduced runtime composition.
   */
  SERVICE_UNAVAILABLE("service_unavailable"),
  /**
   * The current state does not satisfy the planned action preconditions.
   *
   * <p>Precondition failures include running-app guards, unavailable rollback metadata, missing
   * subscriptions, blocked gate state, or unsupported destructive store operations.
   */
  PRECONDITION_FAILED("precondition_failed"),
  /**
   * Execution did not include the required confirmation data.
   *
   * <p>Destructive actions use this code when a caller attempts execution without the boolean
   * confirmation flag, phrase, or previously issued plan token required by the route.
   */
  CONFIRMATION_REQUIRED("confirmation_required"),
  /**
   * Execution confirmation was present but did not match the planned operation.
   *
   * <p>This code is used for phrase mismatches and similar deliberate-action guard failures. It
   * does not disclose the raw target beyond the bounded plan envelope.
   */
  CONFIRMATION_MISMATCH("confirmation_mismatch"),
  /**
   * The action is known but intentionally unavailable in the current RC implementation.
   *
   * <p>Unavailable actions are represented so operators can see the limitation explicitly rather
   * than receiving fake success or being offered an unsafe fallback.
   */
  ACTION_UNAVAILABLE("action_unavailable"),
  /**
   * A planned execution branch failed after dispatch.
   *
   * <p>The result may include redacted details, partial-step summaries, or a sensitive backup
   * payload when that payload is the explicit purpose of the action. It must not include raw
   * exception internals.
   */
  OPERATION_FAILED("operation_failed");

  private final String jsonValue;

  OperatorRecoveryErrorCode(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON token for this error code.
   *
   * <p>The token is lowercase and path-free so it can appear safely in API results, support-bundle
   * recovery context, and deterministic release-certification fixtures.
   *
   * @return the safe reason-code token emitted in recovery JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
