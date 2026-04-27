package network.crypta.platform.api;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of applying the app capability policy to a Platform API request.
 *
 * <p>The capability matrix produces this value before the router dispatches to an endpoint handler.
 * For app principals, the decision carries the matched action so denied and allowed audit events
 * can use the same endpoint family, label, and capability list. Host/operator requests are
 * represented as allowed without an action because they bypass app capability checks under the
 * current local-management model.
 *
 * <p>The reason code is intentionally stable and short. It is suitable for JSON error bodies, audit
 * entries, and focused tests, but it is not a replacement for the operator-facing response message
 * that explains the returned HTTP status.
 *
 * @param allowed whether the request may proceed to endpoint dispatch
 * @param action route/action descriptor when the request matched a capability rule
 * @param reasonCode stable audit/error reason code
 */
record PlatformApiAuthorizationDecision(
    boolean allowed, PlatformApiAction action, String reasonCode) {
  /**
   * Creates a capability decision with a required reason code.
   *
   * <p>The action may be {@code null} only for host/operator allow decisions. Denied app decisions
   * normally carry either a mapped route action or an unmapped fallback action so audit events can
   * still identify the endpoint family that was blocked.
   *
   * @throws NullPointerException if {@code reasonCode} is {@code null}
   */
  PlatformApiAuthorizationDecision {
    Objects.requireNonNull(reasonCode, "reasonCode");
  }

  /**
   * Creates an allowed app-principal decision for a matched action.
   *
   * <p>The caller has already confirmed that the app principal carries every capability listed by
   * the action. The router will dispatch the request and record the eventual handler status as an
   * allowed authorization decision.
   *
   * @param action matched action whose required capabilities were present
   * @return allowed capability decision for app-originated routing
   */
  static PlatformApiAuthorizationDecision allowed(PlatformApiAction action) {
    return new PlatformApiAuthorizationDecision(true, action, "capability_present");
  }

  /**
   * Creates the compatibility allow decision for host/operator requests.
   *
   * <p>Host/operator authorization is enforced by the transport bridge before routing. The
   * capability matrix therefore returns an allowed decision with no app action and a reason code
   * that makes tests and diagnostics explicit about the bypass.
   *
   * @return allowed decision for trusted local host/operator traffic
   */
  static PlatformApiAuthorizationDecision hostAllowed() {
    return new PlatformApiAuthorizationDecision(true, null, "host_operator");
  }

  /**
   * Creates a denied app-principal decision.
   *
   * <p>The action describes either the mapped route whose capabilities were missing or the
   * synthetic unmapped action used by default-deny. The reason code should stay stable because it
   * is written to audit entries and may be used by Web Shell summaries.
   *
   * @param action action that explains which route or fallback policy denied the request
   * @param reasonCode stable machine-readable reason for the denial
   * @return denied capability decision that must not be dispatched to handlers
   */
  static PlatformApiAuthorizationDecision denied(PlatformApiAction action, String reasonCode) {
    return new PlatformApiAuthorizationDecision(false, action, reasonCode);
  }

  /**
   * Returns the matched action when one was part of the decision.
   *
   * <p>Host/operator allow decisions intentionally have no action because they are outside the app
   * capability matrix. Audit code can use this optional form to choose between a mapped action and
   * a fallback label without inspecting the nullable record component directly.
   *
   * @return optional action associated with app-principal decisions
   */
  Optional<PlatformApiAction> optionalAction() {
    return Optional.ofNullable(action);
  }
}
