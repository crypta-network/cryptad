package network.crypta.platform.api.operator.recovery;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result envelope for one executed, blocked, failed, or partially completed recovery action.
 *
 * <p>Results are returned by the execute route after the server validates the one-use plan token
 * and any required confirmation. A result may describe work that did not dispatch because the plan
 * was blocked, work that completed normally, or work that partially completed after a backing
 * service failed. The envelope keeps those states explicit so the Web Shell does not need to infer
 * success from the HTTP status alone.
 *
 * <p>Ordinary fields must remain safe for dashboards, support bundles, and release evidence. The
 * only place an app-data backup payload may appear is {@code sensitiveBackup}, and only for
 * explicit backup-returning workflows such as export-before-uninstall. Callers must not copy that
 * payload into support context or browser persistent storage.
 *
 * @param resultVersion schema version for the result JSON envelope
 * @param actionId closed recovery action that was executed or blocked
 * @param target normalized target metadata for the executed action
 * @param status final recovery status for this execution attempt
 * @param completedAt deterministic timestamp string for the result event
 * @param steps ordered step summaries with per-step completion state
 * @param warnings bounded warnings produced during planning or execution
 * @param supportReference safe reference metadata for support-bundle correlation
 * @param details redacted action-specific output safe for ordinary UI rendering
 * @param sensitiveBackup explicit sensitive backup artifact, or {@code null} when absent
 * @param reasonCode safe reason code describing blocked, failed, or partial outcomes
 */
public record OperatorRecoveryResult(
    int resultVersion,
    OperatorRecoveryActionId actionId,
    OperatorRecoveryTarget target,
    OperatorRecoveryStatus status,
    String completedAt,
    List<OperatorRecoveryStep> steps,
    List<String> warnings,
    Map<String, Object> supportReference,
    Map<String, Object> details,
    Map<String, Object> sensitiveBackup,
    OperatorRecoveryErrorCode reasonCode) {
  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The projection preserves field order and omits {@code sensitiveBackup} when no sensitive
   * artifact was produced. Nested recovery steps and targets are converted through their own safe
   * JSON views, while action-specific details are expected to have been redacted by the producer.
   *
   * @return a stable recovery-result map suitable for the execute API response
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("resultVersion", resultVersion);
    json.put("actionId", actionId.jsonValue());
    json.put("target", target.toJson());
    json.put("status", status.jsonValue());
    json.put("completedAt", completedAt);
    json.put("steps", steps.stream().map(OperatorRecoveryStep::toJson).toList());
    json.put("warnings", warnings);
    json.put("supportReference", supportReference);
    json.put("details", details);
    if (sensitiveBackup != null) {
      json.put("sensitiveBackup", sensitiveBackup);
    }
    json.put("reasonCode", reasonCode.jsonValue());
    return json;
  }
}
