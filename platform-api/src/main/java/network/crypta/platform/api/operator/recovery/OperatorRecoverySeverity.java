package network.crypta.platform.api.operator.recovery;

/**
 * Operator-facing risk level for a recovery action or plan.
 *
 * <p>Severity is presentation metadata used by the Web Shell, support evidence, and deterministic
 * certification fixtures. It helps operators distinguish read-only diagnostics, state-changing
 * repairs, and destructive workflows before they request a plan. It is not an authorization
 * decision, and it does not replace server-side preconditions, plan tokens, or confirmation checks.
 *
 * <p>The enum is intentionally small so new actions must choose a conservative risk cue. When an
 * action can remove, replace, or reset local state, use {@link #DESTRUCTIVE} even if the workflow
 * also preserves app data or returns a backup.
 */
public enum OperatorRecoverySeverity {
  /**
   * Read-only or metadata-only recovery action.
   *
   * <p>Info actions may still return diagnostic artifacts, but they should not mutate durable
   * app-platform state or consume network fetch budget unless the action documentation says so.
   */
  INFO("info"),
  /**
   * Non-destructive action that can still change operational state.
   *
   * <p>Warnings cover operations such as refresh, stage, stop, renew, or revalidate where the
   * action is allowed but operators should understand the visible effect.
   */
  WARNING("warning"),
  /**
   * Action that can remove, replace, revoke, delete, reset, or uninstall local state.
   *
   * <p>Destructive actions require explicit confirmation in the RC recovery workflow and should
   * have preconditions that make the blast radius clear before execution.
   */
  DESTRUCTIVE("destructive");

  private final String jsonValue;

  OperatorRecoverySeverity(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON token for this severity.
   *
   * <p>The token is lowercase and path-free for use in plan envelopes, action descriptors, support
   * context, and Web Shell CSS/state decisions.
   *
   * @return the stable severity token emitted in recovery JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
