package network.crypta.platform.appvault;

import java.time.Instant;
import java.util.Objects;

/**
 * Token-free and value-free audit event emitted by the vault service.
 *
 * <p>Vault audit events are intended for app details, Web Shell management views, and tests. They
 * identify the app, operation, target type, target id, outcome, and stable reason code without
 * recording plaintext secret values, private key bytes, process tokens, browser-session tokens, or
 * local filesystem paths.
 *
 * <p>The event is process-local in v1. It summarizes recent vault activity for operator visibility
 * and API audit records; durable compliance logging would need a separate persistence policy.
 *
 * @param timestamp event creation timestamp
 * @param appId app id associated with the event, or {@code null} for host-only identity creation
 * @param operation stable operation label such as {@code secret.put} or {@code identity.use}
 * @param targetType coarse target kind used for filtering and display
 * @param targetId target identifier safe for audit display, or {@code null}
 * @param outcome stable result label such as {@code allowed}, {@code denied}, or {@code missing}
 * @param reasonCode stable machine-readable reason or detail code
 */
public record AppVaultAuditEvent(
    Instant timestamp,
    String appId,
    String operation,
    String targetType,
    String targetId,
    String outcome,
    String reasonCode) {
  /**
   * Creates a validated vault audit event.
   *
   * <p>The constructor normalizes app ids when present and trims display fields. It does not redact
   * target ids automatically, so callers must pass only identifiers that are safe for public audit
   * summaries.
   */
  public AppVaultAuditEvent {
    Objects.requireNonNull(timestamp, "timestamp");
    appId = appId == null ? null : AppVaultPaths.normalizeAppId(appId);
    operation = requireText(operation, "operation");
    targetType = requireText(targetType, "targetType");
    targetId = targetId == null ? null : targetId.trim();
    outcome = requireText(outcome, "outcome");
    reasonCode = requireText(reasonCode, "reasonCode");
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
