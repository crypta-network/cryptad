package network.crypta.platform.api.appservices;

/**
 * Lifecycle state for a local app-service grant.
 *
 * <p>Only {@link #ACTIVE} grants authorize invocation. {@link #PENDING} grants need operator
 * approval, {@link #REVOKED} grants remain visible as audit history, and {@link #INACTIVE} is used
 * when the provider or service declaration is no longer available.
 *
 * <p>The enum deliberately separates stored state from effective state. A persisted record can be
 * stored as {@link #ACTIVE} while {@link AppServiceCoordinator#listGrants} reports it as {@link
 * #INACTIVE} because current manifests no longer satisfy the grant. Invocation always uses the
 * current effective checks, not a cached browser/UI view.
 *
 * <p>Status values are part of the public Platform API contract. New values should be introduced
 * only when callers can handle the extra lifecycle state without weakening the default-deny
 * authorization model.
 */
public enum AppServiceGrantStatus {
  /**
   * Grant request is waiting for operator approval.
   *
   * <p>Pending grants are visible for review but do not authorize service invocation. Apps can
   * create this state through the grant request route when their manifest declares {@code
   * app.services.call}.
   */
  PENDING("pending"),

  /**
   * Grant is approved and may authorize matching invocations.
   *
   * <p>Active status is necessary but not sufficient: provider advertisement, consumer permission,
   * service id, scope, context, and adapter availability are rechecked for every call.
   */
  ACTIVE("active"),

  /**
   * Grant was explicitly revoked and must not authorize future invocations.
   *
   * <p>Revoked records are retained so the operator can see the grant history and audit reason
   * without leaving a reusable authorization artifact behind.
   */
  REVOKED("revoked"),

  /**
   * Grant cannot currently be used because its app or service declaration is unavailable.
   *
   * <p>This state is used when AppHost cleanup marks stored records inactive. It can also be an
   * effective status when a provider stops advertising a service, changes supported scopes or
   * contexts, or when the consumer app loses the app-service call permission.
   */
  INACTIVE("inactive"),

  /**
   * Grant is past a future expiry boundary.
   *
   * <p>No expiry scheduler is active in PR-243, but the status value is reserved so future bounded
   * grants can become non-authorizing without changing the public JSON shape.
   */
  EXPIRED("expired"),

  /**
   * Grant was approved against provider metadata that now needs explicit operator review.
   *
   * <p>This is non-authorizing. The coordinator reports it when a provider descriptor drifted from
   * the approval-time compatibility fingerprint or service version and the grant must be renewed or
   * revalidated before invocation can resume.
   */
  REVALIDATION_REQUIRED("revalidation-required");

  private final String jsonValue;

  AppServiceGrantStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the public lower-case JSON value.
   *
   * <p>The string form is stable release evidence and SDK surface. Do not use {@link #name()} for
   * public API output because enum names are upper-case implementation details.
   *
   * @return stable lower-case JSON status token
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses one public status token.
   *
   * <p>The parser trims surrounding whitespace but otherwise requires the exact public token. It is
   * used when loading file-backed grant records, so unsupported values fail closed instead of
   * silently becoming active.
   *
   * @param value serialized lower-case status token
   * @return matching status for the public token
   * @throws IllegalArgumentException if the value is null, blank, or unsupported
   */
  public static AppServiceGrantStatus parse(String value) {
    String normalized = value == null ? "" : value.trim();
    for (AppServiceGrantStatus status : values()) {
      if (status.jsonValue.equals(normalized)) {
        return status;
      }
    }
    throw new IllegalArgumentException("unsupported app-service grant status: " + value);
  }
}
