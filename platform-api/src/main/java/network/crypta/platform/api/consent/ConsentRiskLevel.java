package network.crypta.platform.api.consent;

/**
 * Severity assigned to a consent snapshot, section, or finding.
 *
 * <p>Risk levels let the consent service combine many independent findings into one operator
 * outcome. Low-level findings can be displayed without stopping automation, material findings
 * require an explicit approval, and blocking findings describe actions that cannot proceed until
 * catalog, review, security, or migration state changes. The rank is local policy logic; the JSON
 * token is the stable Platform API surface.
 *
 * <p>The enum is intentionally ordered from least severe to most severe so callers can aggregate a
 * section or snapshot with {@link #max(ConsentRiskLevel, ConsentRiskLevel)}. It does not replace
 * lower-level verification. Signed catalog, bundle, review receipt, and AppHost checks still run at
 * the mutation boundary.
 *
 * @see ConsentFinding
 * @see ConsentSection
 * @see ConsentSnapshot
 */
public enum ConsentRiskLevel {
  /**
   * Informational preview with no operator decision required.
   *
   * <p>This level is used when the consent route can return a stable preview but the operation does
   * not introduce reviewable or blocking changes.
   */
  NONE("none", 0),

  /**
   * Reviewable metadata that does not require approval by itself.
   *
   * <p>Low-risk findings are still useful in Web Shell and audit previews. They usually describe
   * unchanged state, removed authority, or informational compatibility details.
   */
  LOW("low", 1),

  /**
   * Material trust, permission, migration, service-grant, or catalog change.
   *
   * <p>Material findings require an approved consent request before the corresponding mutation can
   * proceed. Scheduler automation must surface pending consent instead of silently staging or
   * applying these candidates.
   */
  MATERIAL("material", 2),

  /**
   * Candidate cannot proceed until policy or catalog state changes.
   *
   * <p>Blocking findings cover denylist decisions, non-overridable review or security failures, and
   * incompatible candidates. Operators can review these snapshots, but approval is rejected because
   * the requested action is not authorizable in the current state.
   */
  BLOCKING("blocking", 3);

  private final String jsonValue;
  private final int rank;

  ConsentRiskLevel(String jsonValue, int rank) {
    this.jsonValue = jsonValue;
    this.rank = rank;
  }

  /**
   * Returns the stable lower-case JSON token.
   *
   * <p>The token is used in preview, section, and finding JSON. It should remain stable even if
   * enum names or internal ranks are refactored.
   *
   * @return protocol token for the risk level
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Returns whether this level is material enough to require explicit approval.
   *
   * <p>Both material and blocking findings require operator attention. Blocking findings are not
   * approvable, but they still return {@code true} here so snapshots can report that an unattended
   * mutation is not allowed.
   *
   * @return {@code true} when the level requires approval or blocks the action
   */
  public boolean requiresApproval() {
    return rank >= MATERIAL.rank;
  }

  /**
   * Returns the higher-severity level.
   *
   * <p>This helper is used when rolling up finding risk into section risk and section risk into
   * snapshot risk. Both arguments must be non-null enum values.
   *
   * @param left first risk level to compare
   * @param right second risk level to compare
   * @return the argument with the greater or equal internal severity rank
   */
  public static ConsentRiskLevel max(ConsentRiskLevel left, ConsentRiskLevel right) {
    return left.rank >= right.rank ? left : right;
  }
}
