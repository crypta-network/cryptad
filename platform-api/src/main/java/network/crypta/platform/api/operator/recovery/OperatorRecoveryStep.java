package network.crypta.platform.api.operator.recovery;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One planned or completed step within an operator recovery workflow.
 *
 * <p>Steps give operators a bounded view of what the server intends to do or what it already did.
 * Plan steps usually include id, label, kind, and the conservative safe flag. Result steps add a
 * status and summary after execution. The step list is descriptive; the service still dispatches
 * through the closed action id rather than accepting step ids from a client.
 *
 * <p>Step labels and summaries must remain safe for ordinary API responses and support bundles.
 * They should describe durable effects such as "backup created" or "subscription rescheduled"
 * without raw content, private URIs, local paths, app-data values, tokens, form passwords, command
 * lines, or raw Trust Graph statements.
 *
 * @param id stable step identifier within the planned action
 * @param label short operator-facing step label for Web Shell rendering
 * @param kind broad implementation area such as app-update or subscription
 * @param safe whether the step is expected to avoid destructive local-state changes
 * @param status execution status for result steps, or {@code null} for plan-only steps
 * @param summary bounded execution summary, or {@code null} for plan-only steps
 */
public record OperatorRecoveryStep(
    String id,
    String label,
    String kind,
    boolean safe,
    OperatorRecoveryStatus status,
    String summary) {
  /**
   * Creates a plan-only step.
   *
   * <p>Planned steps intentionally omit status and summary because no backing service has run yet.
   * The safe flag should be conservative and reflect whether the step can remove, replace, reset,
   * or otherwise mutate local state if the action is later executed.
   *
   * @param id stable step identifier within the planned action
   * @param label short operator-facing label for the step
   * @param kind broad implementation area represented by the step
   * @param safe whether the planned step is expected to be non-destructive
   * @return a step suitable for inclusion in a recovery plan
   */
  public static OperatorRecoveryStep planned(String id, String label, String kind, boolean safe) {
    return new OperatorRecoveryStep(id, label, kind, safe, null, null);
  }

  /**
   * Creates a completed result step.
   *
   * <p>The factory marks the step safe because it describes a successful completed summary rather
   * than a destructive plan warning. Destructive risk is still carried by the enclosing action and
   * plan metadata.
   *
   * @param id stable step identifier copied from the planned action
   * @param label short operator-facing label for the completed step
   * @param kind broad implementation area represented by the step
   * @param summary redacted summary of the completed work
   * @return a completed step suitable for inclusion in a recovery result
   */
  public static OperatorRecoveryStep completed(
      String id, String label, String kind, String summary) {
    return new OperatorRecoveryStep(
        id, label, kind, true, OperatorRecoveryStatus.COMPLETED, summary);
  }

  /**
   * Creates a failed result step.
   *
   * <p>Failed steps use {@code safe=false} to keep operator risk cues conservative after an error.
   * The summary should name the safe reason code or high-level failure without exposing raw
   * exception internals.
   *
   * @param id stable step identifier copied from the planned action
   * @param label short operator-facing label for the failed step
   * @param kind broad implementation area represented by the step
   * @param summary redacted summary of the failure
   * @return a failed step suitable for inclusion in a recovery result
   */
  public static OperatorRecoveryStep failed(String id, String label, String kind, String summary) {
    return new OperatorRecoveryStep(id, label, kind, false, OperatorRecoveryStatus.FAILED, summary);
  }

  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The projection omits {@code status} and {@code summary} when the step is plan-only. This
   * keeps plan JSON compact while allowing executed results to show per-step outcome details.
   *
   * @return a stable step map safe for plan and result envelopes
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("id", id);
    json.put("label", label);
    json.put("kind", kind);
    json.put("safe", safe);
    if (status != null) {
      json.put("status", status.jsonValue());
    }
    if (summary != null) {
      json.put("summary", summary);
    }
    return json;
  }
}
