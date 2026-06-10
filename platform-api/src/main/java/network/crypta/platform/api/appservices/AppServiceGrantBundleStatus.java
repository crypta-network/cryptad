package network.crypta.platform.api.appservices;

/**
 * Lifecycle state for an operator-reviewed app-service grant bundle.
 *
 * <p>Bundle status is the operator-facing state of a grouped dependency review. Some values are
 * persisted directly on the bundle record, while others can also be returned as effective state
 * after the coordinator checks current grants, grant expiry, provider descriptor compatibility, and
 * dependency fingerprints. This separation lets the Web Shell show an approved bundle as expired or
 * requiring revalidation without silently changing durable history.
 *
 * <p>A bundle status never authorizes service calls by itself. Invocation continues to require an
 * active matching grant, the caller's app-service permission, and a provider descriptor that still
 * satisfies the reviewed dependency metadata.
 */
public enum AppServiceGrantBundleStatus {
  /**
   * Bundle proposal exists and is waiting for explicit host/operator review.
   *
   * <p>Pending bundles do not create active grants. A consumer app can request this state, but only
   * the host/operator can approve or reject it.
   */
  PENDING("pending"),

  /**
   * Host/operator approved the reviewed dependency set.
   *
   * <p>The approved state is authorizing only when every referenced grant remains active and the
   * provider descriptors still match the approval-time compatibility data.
   */
  APPROVED("approved"),

  /**
   * Host/operator rejected the pending proposal.
   *
   * <p>Rejected bundles keep a durable review record but do not leave active grant artifacts. A
   * later request must create or reuse a separate pending proposal.
   */
  REJECTED("rejected"),

  /**
   * One or more bundle-approved grants have reached their expiry time.
   *
   * <p>Expired bundles are visible to apps and operators so renewal can be requested and approved.
   * Expiry is fail-closed: service invocation remains denied until renewal succeeds.
   */
  EXPIRED("expired"),

  /**
   * Current manifest or provider descriptor state no longer matches the reviewed bundle.
   *
   * <p>This status is used for descriptor drift, missing bundle grant ids, inactive grants, or
   * dependency fingerprint changes. Operators must renew or revalidate explicitly.
   */
  REVALIDATION_REQUIRED("revalidation-required");

  /** Stable lower-case token used in durable bundle records and Platform API JSON. */
  private final String jsonValue;

  /**
   * Creates an enum value bound to its public bundle-status token.
   *
   * @param jsonValue lower-case token exposed outside the Java implementation
   */
  AppServiceGrantBundleStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable lower-case token serialized in bundle JSON and durable records.
   *
   * <p>The file-backed store writes this token, and the Platform API returns the same value in
   * caller-visible bundle lists. Callers should not derive public output from the Java enum name.
   *
   * @return public grant-bundle status token
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses one stored public status token.
   *
   * <p>The parser accepts only exact public tokens after trimming whitespace. Unknown values fail
   * closed during file-store loading so malformed durable records cannot become approved bundles by
   * default.
   *
   * @param value raw token read from durable storage or API-compatible test fixtures
   * @return grant-bundle status represented by the stored public token
   * @throws IllegalArgumentException when the token is missing or unsupported
   */
  public static AppServiceGrantBundleStatus parse(String value) {
    String normalized = value == null ? "" : value.trim();
    for (AppServiceGrantBundleStatus status : values()) {
      if (status.jsonValue.equals(normalized)) {
        return status;
      }
    }
    throw new IllegalArgumentException("unsupported app-service bundle status: " + value);
  }
}
