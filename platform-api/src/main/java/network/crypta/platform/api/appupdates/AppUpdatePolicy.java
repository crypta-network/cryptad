package network.crypta.platform.api.appupdates;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Per-app update automation policy for the Platform API update lifecycle.
 *
 * <p>The policy controls what the update service may do after a candidate check. It deliberately
 * separates detection, staging, and apply so third-party apps do not silently update by default.
 * The value is local administrative state; it is not embedded in app manifests or signed catalogs,
 * and app principals cannot change it through the app-facing contract.
 *
 * <p>Instances are immutable and safe to expose as summaries. They contain only the selected mode
 * and derived boolean flags used by Web Shell controls. The service still performs compatibility,
 * review, permission-delta, running-state, and AppHost checks before staging or applying any
 * bundle.
 *
 * @param mode operator-selected automation mode for one installed app
 * @see AppUpdatePolicyMode
 * @see AppUpdateService
 */
public record AppUpdatePolicy(AppUpdatePolicyMode mode) {
  /**
   * Conservative default policy: detect candidates only.
   *
   * <p>This default lets catalog checks surface available updates without staging or applying a
   * bundle until an operator or host-managed policy explicitly requests more automation.
   */
  public static final AppUpdatePolicy DEFAULT = new AppUpdatePolicy(AppUpdatePolicyMode.MANUAL);

  /**
   * Creates a validated update policy.
   *
   * <p>The constructor accepts only a non-null mode. Policy persistence and authorization are owned
   * by the service and router layers, not by this value object.
   *
   * @param mode operator-selected automation mode for one installed app
   */
  public AppUpdatePolicy {
    Objects.requireNonNull(mode, "mode");
  }

  /**
   * Converts the policy to a JSON-compatible summary.
   *
   * <p>The summary includes the stable mode string plus two derived booleans so clients can render
   * concise policy state without duplicating the enum mapping. The booleans are descriptive only;
   * they do not bypass the service's candidate and AppHost gates.
   *
   * @return path-free policy summary suitable for Platform API responses
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("mode", mode.jsonValue());
    json.put("automaticStaging", mode == AppUpdatePolicyMode.STAGE);
    json.put("automaticApply", mode == AppUpdatePolicyMode.APPLY_WHEN_STOPPED);
    return json;
  }
}
