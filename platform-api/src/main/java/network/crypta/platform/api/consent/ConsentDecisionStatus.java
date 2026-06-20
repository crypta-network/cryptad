package network.crypta.platform.api.consent;

/**
 * Stable decision state recorded for one consent request.
 *
 * <p>Decision status is the small state machine behind the process-local approval cache and consent
 * audit log. A request starts as a preview in {@link ConsentService}; an operator can approve,
 * reject, or defer the exact snapshot digest; and pruning can mark stale requests expired. Only an
 * approved decision can be consumed by mutating install, update, or service-grant routes, and that
 * consumption is single-use.
 *
 * <p>The values are persisted as stable lower-case JSON tokens. They are intentionally local
 * operator decisions, not app-authentication state and not a replacement for signed bundle,
 * catalog, review receipt, or security-policy verification.
 *
 * @see ConsentDecision
 * @see ConsentAuditEvent
 */
public enum ConsentDecisionStatus {
  /**
   * The operator approved the exact consent snapshot digest.
   *
   * <p>An approved decision authorizes only the matching request id, digest, action, and app id.
   * The first successful verification consumes it so later mutations cannot replay the same
   * approval.
   */
  APPROVED("approved"),

  /**
   * The operator rejected the proposed action.
   *
   * <p>Rejected decisions are audit evidence and never satisfy a mutating route. A client must
   * create a fresh preview and obtain a separate approval before trying the operation again.
   */
  REJECTED("rejected"),

  /**
   * The operator deferred the decision without approving the mutation.
   *
   * <p>Deferred decisions let Web Shell and API clients record that the operator intentionally left
   * the candidate pending. They do not grant authority and are useful for audit timelines.
   */
  DEFERRED("deferred"),

  /**
   * The request expired before an approval was used.
   *
   * <p>Expiry is derived from cache pruning rather than a direct operator action. It prevents old
   * request ids from remaining valid after the preview lifetime has elapsed.
   */
  EXPIRED("expired");

  private final String jsonValue;

  ConsentDecisionStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable lower-case JSON token.
   *
   * <p>The returned value is the wire-format status stored in audit records and returned from
   * decision endpoints. It should remain stable across Java enum refactors.
   *
   * @return protocol token for this decision status
   */
  public String jsonValue() {
    return jsonValue;
  }
}
