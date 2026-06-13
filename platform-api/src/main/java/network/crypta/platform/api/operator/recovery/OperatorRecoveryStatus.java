package network.crypta.platform.api.operator.recovery;

/**
 * Stable status tokens shared by RC recovery plans, preconditions, steps, and results.
 *
 * <p>The recovery workflow uses one compact status enum across several envelope types so clients
 * can render consistent states without translating between plan, precondition, step, and result
 * vocabularies. Some values are specific to plan readiness, some to execution results, and some to
 * individual precondition or step summaries. Callers should interpret the token in the context of
 * the containing record.
 *
 * <p>Status values are intentionally safe and coarse. They describe readiness and outcome without
 * embedding raw exception text, local paths, private URIs, backup payloads, fetched content,
 * tokens, or Trust Graph statement bodies.
 */
public enum OperatorRecoveryStatus {
  /**
   * Plan status meaning all blocking preconditions currently pass.
   *
   * <p>A ready plan can execute once the caller supplies the matching one-use plan token and any
   * required confirmation data.
   */
  READY("ready"),
  /**
   * Plan or result status meaning execution cannot proceed.
   *
   * <p>Blocked envelopes should include safe block reasons or preconditions that explain what the
   * operator must change before retrying.
   */
  BLOCKED("blocked"),
  /**
   * Plan status meaning execution is allowed but has non-blocking risk or context.
   *
   * <p>Warnings commonly describe backup recommendations, degraded dependencies, queue pressure, or
   * limitations in a recovery action.
   */
  WARNING("warning"),
  /**
   * Plan status meaning execution is allowed but destructive confirmation is required.
   *
   * <p>The status is used when the selected action can remove, replace, reset, revoke, delete, or
   * uninstall local state.
   */
  DESTRUCTIVE("destructive"),
  /**
   * Plan status meaning the action is known but unsupported in this runtime state.
   *
   * <p>Unavailable plans are explicit limitation reports. They must not be treated as successful
   * no-op execution.
   */
  UNAVAILABLE("unavailable"),
  /**
   * Result or step status meaning the planned work completed.
   *
   * <p>Completed results should still be inspected for warnings and details because read-only
   * export actions may return useful artifacts.
   */
  COMPLETED("completed"),
  /**
   * Result or step status meaning execution failed.
   *
   * <p>Failed envelopes should include a safe reason code and redacted details rather than raw
   * backing-service exceptions.
   */
  FAILED("failed"),
  /**
   * Result status meaning some work completed before a later step failed.
   *
   * <p>Partial is important for export-before-uninstall flows because the response can still return
   * the generated backup artifact after a later uninstall or cleanup step fails.
   */
  PARTIAL("partial"),
  /**
   * Precondition status meaning one readiness check passed.
   *
   * <p>Pass is scoped to the individual precondition and does not by itself mean the whole plan is
   * executable.
   */
  PASS("pass"),
  /**
   * Precondition status meaning one readiness check failed.
   *
   * <p>A failed precondition usually contributes to a blocked or unavailable plan status.
   */
  FAIL("fail"),
  /**
   * Precondition status meaning one readiness check has non-blocking risk.
   *
   * <p>Warnings are useful for backup recommendations, degraded optional dependencies, or
   * operator-visible limitations that do not stop execution.
   */
  WARN("warn"),
  /**
   * Step status meaning the service intentionally did not run that step.
   *
   * <p>Skipped steps should include a safe summary explaining whether the skip was due to a blocked
   * plan, unavailable backing service, or conditional workflow branch.
   */
  SKIPPED("skipped");

  private final String jsonValue;

  OperatorRecoveryStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON token for this status.
   *
   * <p>The token is lowercase and path-free for direct use in API JSON, support context, Web Shell
   * rendering, and release-certification fixtures.
   *
   * @return the stable status token emitted in recovery JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
