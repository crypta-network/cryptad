package network.crypta.platform.api.operator.recovery;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.operator.OperatorSupportRedactor;

/**
 * Typed target identifiers supplied to an operator recovery plan or execution request.
 *
 * <p>The target binds a closed action id to the specific app, catalog, subscription, grant, bundle,
 * or global operator surface that the action operates on. It is deliberately a small record instead
 * of an arbitrary path or route proxy. The service validates which fields are required for each
 * action before planning and execution.
 *
 * <p>Values in this record are normalized request identifiers, not a guarantee that the values are
 * safe to publish. The JSON projection hashes any identifier that the support redactor would change
 * so rejected requests cannot echo operator-supplied private URIs or local paths through ordinary
 * plan/result envelopes. Raw values remain available only to package-local fingerprinting used for
 * plan-token binding and support correlation digests.
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
  private static final int DIGEST_DISPLAY_LENGTH = 16;
  private static final int SAFE_IDENTIFIER_LENGTH = 160;
  private static final HexFormat HEX = HexFormat.of();

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
   * <p>The projection includes the target kind and only non-blank identifier fields. Identifier
   * values are safe display values: if an id contains a private content key, local path,
   * credential, or other pattern that the support redactor would alter, the display value becomes a
   * short {@code sha256:...} digest instead of the original text. This keeps plan and result
   * envelopes useful for correlation without exposing rejected operator input.
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

  String fingerprintSource() {
    StringBuilder fingerprint = new StringBuilder(128);
    appendFingerprintPart(fingerprint, "kind", kind);
    appendFingerprintPart(fingerprint, "appId", appId);
    appendFingerprintPart(fingerprint, "catalogId", catalogId);
    appendFingerprintPart(fingerprint, "subscriptionId", subscriptionId);
    appendFingerprintPart(fingerprint, "grantId", grantId);
    appendFingerprintPart(fingerprint, "bundleId", bundleId);
    return fingerprint.toString();
  }

  private static void putIfPresent(Map<String, Object> json, String key, String value) {
    if (value != null && !value.isBlank()) {
      json.put(key, safeIdentifier(value.trim()));
    }
  }

  private static String safeIdentifier(String value) {
    Object redactedValue = OperatorSupportRedactor.redact(value).value();
    if (!Objects.equals(value, redactedValue)) {
      return "sha256:" + safeDigest(value).substring(0, DIGEST_DISPLAY_LENGTH);
    }
    return value.length() <= SAFE_IDENTIFIER_LENGTH
        ? value
        : value.substring(0, SAFE_IDENTIFIER_LENGTH - 3) + "...";
  }

  private static void appendFingerprintPart(StringBuilder fingerprint, String name, String value) {
    fingerprint.append(name).append('=');
    if (value == null) {
      fingerprint.append("-1:");
    } else {
      fingerprint.append(value.length()).append(':').append(value);
    }
    fingerprint.append('|');
  }

  private static String safeDigest(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HEX.formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is required", exception);
    }
  }
}
