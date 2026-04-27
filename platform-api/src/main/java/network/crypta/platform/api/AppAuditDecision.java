package network.crypta.platform.api;

/**
 * High-level authorization outcome for one app-originated Platform API attempt.
 *
 * <p>The audit log stores this value after the bridge and router have decided whether a process
 * that presented an app launch token may reach an endpoint handler. The enum is intentionally
 * small: it captures the operator-relevant decision without storing request bodies, headers, raw
 * tokens, or other transport details. Downstream JSON projections can therefore show the recent
 * security posture of an app while keeping bearer credentials out of diagnostics and browser
 * surfaces.
 *
 * <p>Most events are produced by the router after it maps a route to a capability. The
 * authentication-failure value is reserved for callers that can detect a token-bearing request
 * before a token-free app principal exists.
 */
public enum AppAuditDecision {
  /**
   * The app principal carried every capability required by the matched Platform API action.
   *
   * <p>An allowed event means the request passed the capability gate and was dispatched to the
   * endpoint family. The final HTTP status may still be a validation or runtime error from the
   * handler; the decision records authorization, not business-operation success.
   */
  ALLOWED,

  /**
   * The app principal authenticated successfully but lacked a required capability.
   *
   * <p>Denied events are recorded before handler dispatch. They are suitable for Web Shell
   * summaries such as recent denied counts because they represent policy enforcement rather than
   * malformed input inside an otherwise authorized endpoint.
   */
  DENIED,

  /**
   * Token authentication failed before the request could be represented as an app principal.
   *
   * <p>This decision is for transport layers that choose to audit failed bearer-token attempts.
   * Events using it must still avoid recording the raw token and may omit the app id when no
   * trusted identity was established.
   */
  AUTH_FAILED
}
