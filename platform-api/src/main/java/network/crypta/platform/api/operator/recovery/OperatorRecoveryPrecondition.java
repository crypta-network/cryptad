package network.crypta.platform.api.operator.recovery;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One bounded precondition shown before an operator recovery action can execute.
 *
 * <p>Preconditions explain the current state that makes a plan ready, risky, blocked, or
 * unavailable. Examples include app stopped/running checks, rollback metadata availability,
 * subscription existence, grant-bundle state, Trust Graph store availability, and network-budget
 * visibility. They are diagnostic metadata only; the execute path still revalidates state before
 * dispatching the backing service.
 *
 * <p>Messages must remain safe for ordinary operator dashboards and support bundles. They should
 * identify the condition and consequence without including raw fetched content, private URIs,
 * app-data values, tokens, local paths, process environments, or raw Trust Graph statements.
 *
 * @param id stable precondition identifier used by clients and tests
 * @param status readiness status for this individual precondition
 * @param message bounded operator-facing explanation of the condition
 */
public record OperatorRecoveryPrecondition(
    String id, OperatorRecoveryStatus status, String message) {
  /**
   * Returns a deterministic JSON-compatible representation.
   *
   * <p>The projection keeps the field order stable and converts the status enum to its safe JSON
   * token. The returned map is suitable for plan envelopes, support context, and release evidence.
   *
   * @return a stable map containing {@code id}, {@code status}, and {@code message}
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("id", id);
    json.put("status", status.jsonValue());
    json.put("message", message);
    return json;
  }
}
