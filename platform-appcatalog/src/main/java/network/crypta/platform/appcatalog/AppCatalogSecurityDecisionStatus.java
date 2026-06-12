package network.crypta.platform.appcatalog;

/**
 * Derived security-decision status exposed through Platform API summaries.
 *
 * <p>The status is derived from signed catalog policy and local context. It is not a separate
 * catalog property, and callers must not use it as the only enforcement input. The accompanying
 * gate booleans on {@code AppCatalogSecurityDecision} remain authoritative for install, update,
 * stage, apply, and unattended scheduler policy. Status values give operators and release evidence
 * a compact, stable summary of the strongest outcome after catalog-entry advisories and exact
 * app-version denylists have been evaluated.
 *
 * <p>The JSON tokens are intentionally lower-case and stable because Web Shell rendering, redaction
 * checks, and release-certification fixtures compare them directly.
 */
public enum AppCatalogSecurityDecisionStatus {
  /**
   * No security policy applies to the evaluated app version.
   *
   * <p>This value is used for older catalogs, empty policies, and exact-version checks that find no
   * configured denylist entry.
   */
  OK("ok"),

  /**
   * Informational advisory metadata applies but does not gate actions.
   *
   * <p>Operators can see the advisory id and severity, while manual and automatic distribution
   * paths remain eligible if all other gates pass.
   */
  INFORMATIONAL("informational"),

  /**
   * A warning applies and requires manual acknowledgement for manual actions.
   *
   * <p>Warning decisions also block unattended automation by default so scheduler policy cannot
   * silently stage or apply a candidate that needs operator review.
   */
  WARNING("warning"),

  /**
   * A block action applies.
   *
   * <p>The specific blocked operation is expressed by the decision booleans. A blocked status may
   * represent install-only, update-only, or combined gates.
   */
  BLOCKED("blocked"),

  /**
   * An exact app-version denylist entry applies.
   *
   * <p>This is the hard fail-closed outcome for vulnerable versions. It blocks install, update,
   * stage, apply, and unattended automation without an acknowledgement bypass.
   */
  DENYLISTED("denylisted");

  private final String jsonValue;

  AppCatalogSecurityDecisionStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value.
   *
   * <p>The value is written directly to redacted Platform API summaries and should remain stable
   * across catalog parser, Web Shell, and release-certification consumers.
   *
   * @return lower-case decision status used in JSON output
   */
  public String jsonValue() {
    return jsonValue;
  }
}
