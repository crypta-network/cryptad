package network.crypta.platform.api.operator.recovery;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Typed target identifiers supplied to an operator recovery plan or execution request.
 *
 * <p>The target binds a closed action id to the specific app, catalog, subscription, grant, bundle,
 * or global operator surface that the action operates on. It is deliberately a small record instead
 * of an arbitrary path or route proxy. The service validates which fields are required for each
 * action before planning and execution.
 *
 * <p>Values in this record are normalized request identifiers, not a guarantee that the values are
 * safe to publish. Audit and support-bundle code must still redact the primary id before storing or
 * exporting it because rejected requests can contain operator-supplied private URIs or local paths.
 *
 * @param kind stable target-kind token associated with the action
 * @param appId app identifier for app-scoped or subscription-scoped actions
 * @param catalogId catalog identifier for catalog repair or reinstall actions
 * @param subscriptionId subscription identifier for subscription-scoped actions
 * @param grantId app-service grant identifier for grant revocation actions
 * @param bundleId app-service dependency-bundle identifier for bundle actions
 */
public record OperatorRecoveryTarget(
    String kind,
    String appId,
    String catalogId,
    String subscriptionId,
    String grantId,
    String bundleId) {
  /**
   * Returns the primary target id for audit and support summaries.
   *
   * <p>Subscription targets combine app id and subscription id so cross-app operator recovery
   * events remain distinguishable. Other target kinds prefer their natural single identifier. The
   * returned value can still contain unsafe operator input and must be redacted before support
   * output.
   *
   * @return the best available target identifier for this target kind, or {@code null}
   */
  public String primaryId() {
    if ("subscription".equals(kind) && subscriptionId != null) {
      return appId == null ? subscriptionId : appId + "/" + subscriptionId;
    }
    if ("app-service-grant".equals(kind) && grantId != null) {
      return grantId;
    }
    if ("app-service-bundle".equals(kind) && bundleId != null) {
      return bundleId;
    }
    if ("catalog".equals(kind) && catalogId != null) {
      return catalogId;
    }
    if (appId != null) {
      return appId;
    }
    if (catalogId != null) {
      return catalogId;
    }
    if (subscriptionId != null) {
      return subscriptionId;
    }
    if (grantId != null) {
      return grantId;
    }
    return bundleId;
  }

  /**
   * Returns a deterministic JSON-compatible target object.
   *
   * <p>The projection includes the target kind and only non-blank identifier fields. It is intended
   * for plan and execute response envelopes, where the target has already passed action-specific
   * validation.
   *
   * @return a stable map containing the target kind and present identifier fields
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("kind", kind);
    putIfPresent(json, "appId", appId);
    putIfPresent(json, "catalogId", catalogId);
    putIfPresent(json, "subscriptionId", subscriptionId);
    putIfPresent(json, "grantId", grantId);
    putIfPresent(json, "bundleId", bundleId);
    return json;
  }

  private static void putIfPresent(Map<String, Object> json, String key, String value) {
    if (value != null && !value.isBlank()) {
      json.put(key, value);
    }
  }
}
