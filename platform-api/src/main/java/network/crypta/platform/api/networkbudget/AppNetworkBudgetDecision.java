package network.crypta.platform.api.networkbudget;

import java.time.Instant;
import java.util.Objects;

/**
 * Result of evaluating one app-network budget operation.
 *
 * <p>Denied decisions contain only stable status metadata: normalized app id, operation, error
 * code, safe message, and optional next availability. They never include raw request URIs, fetched
 * content, request bodies, queue HTML, tokens, private insert material, signatures, app-data
 * values, or local paths.
 *
 * <p>An allowed decision always carries an active or no-op lease and normalizes the status fields
 * to an internal success shape. A denied decision always carries an HTTP-style failure status,
 * stable error code, stable message, and no-op lease. Callers can therefore use the same
 * try-with-resources pattern for allowed decisions and the same safe error-envelope path for denied
 * decisions without inspecting store exceptions or runtime internals.
 *
 * @param allowed whether the operation may proceed to network work
 * @param statusCode HTTP-style status code callers expose for denied decisions
 * @param appId normalized app id or reserved internal budget scope associated with the decision
 * @param operation budget operation that was evaluated for this decision
 * @param errorCode stable safe error code for denied decisions, or {@code null} when allowed
 * @param message stable safe message for denied decisions, or {@code null} when allowed
 * @param decidedAt instant when the service evaluated rate and concurrency state
 * @param nextAvailableAt optional retry time for rate-limited decisions
 * @param lease concurrency lease held by allowed decisions and no-op lease for denied decisions
 */
public record AppNetworkBudgetDecision(
    boolean allowed,
    int statusCode,
    String appId,
    AppNetworkBudgetOperation operation,
    String errorCode,
    String message,
    Instant decidedAt,
    Instant nextAvailableAt,
    AppNetworkBudgetLease lease) {
  /**
   * Creates a validated immutable decision.
   *
   * <p>The constructor canonicalizes success and failure shapes so downstream route handlers do not
   * need to defend against partially populated decisions. Allowed decisions always report status
   * {@code 200} and clear error fields. Denied decisions require an error status and non-blank safe
   * text; their stored lease is cleared so the constructor does not acquire an owned {@link
   * AutoCloseable}. The public {@link #lease()} accessor still returns a no-op lease for denied
   * decisions so accidental close calls cannot affect process-local concurrency counters.
   */
  public AppNetworkBudgetDecision {
    Objects.requireNonNull(appId, "appId");
    Objects.requireNonNull(operation, "operation");
    Objects.requireNonNull(decidedAt, "decidedAt");
    if (allowed) {
      statusCode = 200;
      errorCode = null;
      message = null;
      nextAvailableAt = null;
      Objects.requireNonNull(lease, "lease");
    } else {
      if (statusCode < 400) {
        throw new IllegalArgumentException("denied decisions require an error status");
      }
      errorCode = requireText(errorCode, "errorCode");
      message = requireText(message, "message");
      lease = null;
    }
  }

  static AppNetworkBudgetDecision allowed(
      String appId,
      AppNetworkBudgetOperation operation,
      Instant decidedAt,
      AppNetworkBudgetLease lease) {
    return new AppNetworkBudgetDecision(
        true, 200, appId, operation, null, null, decidedAt, null, lease);
  }

  static AppNetworkBudgetDecision denied(
      int statusCode,
      String appId,
      AppNetworkBudgetOperation operation,
      String errorCode,
      String message,
      Instant decidedAt,
      Instant nextAvailableAt) {
    return new AppNetworkBudgetDecision(
        false, statusCode, appId, operation, errorCode, message, decidedAt, nextAvailableAt, null);
  }

  /**
   * Returns the lease associated with this decision.
   *
   * <p>Allowed decisions return the real concurrency lease that callers must close after bounded
   * network work finishes. Denied decisions return a shared no-op lease so callers can keep simple
   * cleanup code without mutating any budget counters.
   *
   * @return real lease for allowed decisions or a no-op lease for denied decisions
   */
  @Override
  public AppNetworkBudgetLease lease() {
    return lease == null ? AppNetworkBudgetLease.noop() : lease;
  }

  private static String requireText(String value, String name) {
    String checked = Objects.requireNonNull(value, name).trim();
    if (checked.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return checked;
  }
}
