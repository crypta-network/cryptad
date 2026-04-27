package network.crypta.platform.api;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Token-free audit record for one app-originated Platform API decision.
 *
 * <p>Events deliberately keep only route-family metadata and capability names. Query parameters,
 * request bodies, launch tokens, local filesystem paths, and peer/request identifiers are excluded
 * so the process-local audit trail is useful for operators without becoming a secondary secret
 * store.
 *
 * <p>The record is a snapshot value. Its capability list is copied on construction, and callers
 * receive the record through bounded log snapshots rather than a mutable live view. Keep the fields
 * coarse when adding new audit uses: the event should explain which policy gate fired, not replay
 * enough request detail to reconstruct sensitive operator or app data.
 *
 * @param timestamp UTC timestamp captured when the log accepted the event
 * @param appId normalized app id when known, or {@code null} before identity exists
 * @param method HTTP-style method name after bridge normalization, such as {@code GET}
 * @param endpointFamily top-level Platform API endpoint family used for grouping
 * @param action short deterministic route label selected by the capability matrix
 * @param requiredCapabilities immutable capabilities required for the selected action
 * @param decision authorization outcome recorded for operator-facing audit summaries
 * @param statusCode HTTP-style status returned for the decision or completed request
 * @param reasonCode stable machine-readable reason such as {@code missing_capability}
 */
public record AppAuditEvent(
    Instant timestamp,
    String appId,
    String method,
    String endpointFamily,
    String action,
    List<String> requiredCapabilities,
    AppAuditDecision decision,
    int statusCode,
    String reasonCode) {
  /**
   * Creates a validated token-free audit event.
   *
   * <p>The constructor accepts a {@code null} app id only for authentication-failure cases where no
   * app identity has been established. All other fields are required because Web Shell and Apps API
   * projections depend on them for stable display and filtering. The capability list is copied so a
   * caller cannot mutate retained audit history after recording an event.
   *
   * @throws NullPointerException if timestamp, method, action metadata, decision, or reason is
   *     {@code null}
   */
  public AppAuditEvent {
    Objects.requireNonNull(timestamp, "timestamp");
    Objects.requireNonNull(method, "method");
    Objects.requireNonNull(endpointFamily, "endpointFamily");
    Objects.requireNonNull(action, "action");
    requiredCapabilities =
        List.copyOf(Objects.requireNonNull(requiredCapabilities, "requiredCapabilities"));
    Objects.requireNonNull(decision, "decision");
    Objects.requireNonNull(reasonCode, "reasonCode");
  }
}
