package network.crypta.platform.api.operator.recovery;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Metadata-only plan returned before an operator recovery action can execute.
 *
 * <p>A plan is the operator-facing contract for one typed recovery request. It names the closed
 * action id, normalized target, current status, confirmation requirements, preconditions, planned
 * steps, warnings, and block reasons before any mutating service is called. The execute route must
 * receive the plan token that was issued for the same action and target, which prevents a caller
 * from editing a form into a different operation after planning.
 *
 * <p>The envelope is deterministic and intentionally free of sensitive payloads. It may recommend
 * or require a backup, but it never contains app-data backup bytes, raw subscription content,
 * private URIs, Trust Graph statement bodies, signatures, tokens, passwords, local paths, or queue
 * HTML.
 *
 * @param planVersion schema version for the plan JSON envelope
 * @param planToken one-use token binding execute to this action and target
 * @param actionId closed recovery action selected by the operator
 * @param category presentation category used for grouping operator actions
 * @param target normalized target metadata for the selected action
 * @param status current execution readiness for the planned action
 * @param destructive whether the action can remove or replace local state
 * @param requiresConfirmation whether execute must include explicit operator confirmation
 * @param confirmationPhrase phrase required when confirmation is needed, otherwise empty
 * @param requiresStoppedApp whether the target app must be stopped first
 * @param backupRecommended whether operators should create a backup before execution
 * @param backupRequired whether execution is blocked until a backup exists
 * @param preconditions current checks that explain readiness or blocking state
 * @param steps ordered metadata-only steps the server expects to run
 * @param warnings bounded operator-facing warnings for non-blocking risks
 * @param blockReasons bounded explanations for blocked or unavailable plans
 * @param reasonCode safe reason code for blocked or unavailable plans
 */
public record OperatorRecoveryPlan(
    int planVersion,
    String planToken,
    OperatorRecoveryActionId actionId,
    OperatorRecoveryActionCategory category,
    OperatorRecoveryTarget target,
    OperatorRecoveryStatus status,
    boolean destructive,
    boolean requiresConfirmation,
    String confirmationPhrase,
    boolean requiresStoppedApp,
    boolean backupRecommended,
    boolean backupRequired,
    List<OperatorRecoveryPrecondition> preconditions,
    List<OperatorRecoveryStep> steps,
    List<String> warnings,
    List<String> blockReasons,
    OperatorRecoveryErrorCode reasonCode) {
  /**
   * Returns whether the plan can be executed after required confirmation is supplied.
   *
   * <p>Only ready, warning, and destructive plans are executable. Blocked and unavailable plans
   * still produce useful evidence for the Web Shell and support bundles, but execute returns a
   * blocked result instead of dispatching a backing service. Confirmation is checked separately so
   * destructive plans can remain executable in this sense while still requiring the phrase.
   *
   * @return {@code true} when the plan status allows execution after confirmation checks
   */
  public boolean executable() {
    return status == OperatorRecoveryStatus.READY
        || status == OperatorRecoveryStatus.WARNING
        || status == OperatorRecoveryStatus.DESTRUCTIVE;
  }

  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The map order is stable for tests, Web Shell rendering, support context, and release
   * evidence. Nested recovery records are converted through their own redacted JSON projections.
   * The returned map is a fresh object and does not expose mutable internal state from the plan
   * record.
   *
   * @return a stable recovery-plan map safe for ordinary operator API responses
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(17);
    json.put("planVersion", planVersion);
    json.put("planToken", planToken);
    json.put("actionId", actionId.jsonValue());
    json.put("category", category.jsonValue());
    json.put("target", target.toJson());
    json.put("status", status.jsonValue());
    json.put("destructive", destructive);
    json.put("requiresConfirmation", requiresConfirmation);
    json.put("confirmationPhrase", confirmationPhrase);
    json.put("requiresStoppedApp", requiresStoppedApp);
    json.put("backupRecommended", backupRecommended);
    json.put("backupRequired", backupRequired);
    json.put(
        "preconditions", preconditions.stream().map(OperatorRecoveryPrecondition::toJson).toList());
    json.put("steps", steps.stream().map(OperatorRecoveryStep::toJson).toList());
    json.put("warnings", warnings);
    json.put("blockReasons", blockReasons);
    json.put("reasonCode", reasonCode.jsonValue());
    return json;
  }
}
