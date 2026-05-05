package network.crypta.platform.api.appupdates;

/**
 * Stable status vocabulary for app update lifecycle summaries.
 *
 * <p>These values are serialized through {@link #jsonValue()} and form part of the Platform API
 * surface consumed by Web Shell, developer tooling, and release-certification evidence. A status
 * describes the update lifecycle state that the service can prove from signed catalog metadata,
 * AppHost state, and local policy. It is not an authorization decision, and it does not replace the
 * compatibility, review, or permission-delta objects in the same response.
 *
 * <p>Clients should treat unknown future values conservatively. In particular, only {@link
 * #AVAILABLE} is eligible for default staging, and policy-driven apply adds review checks on top of
 * that state. Ambiguous or blocked values are intentionally visible to operators instead of being
 * collapsed into a generic failure.
 *
 * @see AppUpdateCandidate
 * @see AppUpdateService
 */
public enum AppUpdateCandidateStatus {
  /**
   * No actionable version change was found.
   *
   * <p>The installed version is up to date, no matching catalog entry exists, or the only matching
   * entry compares equal to the installed manifest. Operators do not need to act on this state.
   */
  NONE("none"),

  /**
   * A verified catalog entry has a safely comparable newer version.
   *
   * <p>This is the only candidate state that default staging accepts. Automatic apply still
   * requires a reviewed catalog entry and an update policy that permits apply while stopped.
   */
  AVAILABLE("available"),

  /**
   * A candidate has been staged for a later explicit apply.
   *
   * <p>The staged summary is still revalidated before replacement, because catalogs or installed
   * manifests may change after staging.
   */
  STAGED("staged"),

  /**
   * A candidate exists, but policy or review gates prevent automatic apply.
   *
   * <p>The operator can inspect review metadata and permission changes before deciding whether a
   * manual action is appropriate.
   */
  BLOCKED("blocked"),

  /**
   * Platform API compatibility metadata says the catalog entry is incompatible.
   *
   * <p>The service reports this state for actual version-change candidates whose declared API range
   * cannot run on the current node contract.
   */
  INCOMPATIBLE("incompatible"),

  /**
   * The catalog version differs but cannot be safely ordered.
   *
   * <p>Ambiguous versions are displayed for operator review, but they are not staged or applied by
   * conservative default policy.
   */
  AMBIGUOUS("ambiguous"),

  /**
   * The latest compared catalog version is lower than the installed version.
   *
   * <p>This state prevents silent downgrades. Applying such a bundle, if ever supported, requires a
   * separate explicit downgrade flow rather than the normal update lifecycle.
   */
  NOT_NEWER("not_newer"),

  /**
   * The candidate was applied to the installed bundle.
   *
   * <p>Post-apply health failures may still leave this status when replacement committed and no
   * rollback was requested or possible.
   */
  APPLIED("applied"),

  /**
   * AppHost reports that a previous bundle can be restored.
   *
   * <p>The rollback record is path-free metadata for the retained immutable bundle only; mutable
   * app data and cache are not part of the rollback scope.
   */
  ROLLBACK_AVAILABLE("rollback_available"),

  /**
   * A rollback is currently being attempted.
   *
   * <p>The current in-memory service does not persist long-running jobs, but this value is reserved
   * for stable clients and future scheduler reporting.
   */
  ROLLBACK_IN_PROGRESS("rollback_in_progress"),

  /**
   * Candidate detection, staging, apply, or rollback failed.
   *
   * <p>Responses include a stable error code and short message when this status is emitted.
   */
  FAILED("failed");

  private final String jsonValue;

  AppUpdateCandidateStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value for this status.
   *
   * <p>The enum names are Java-facing constants. Platform API responses use this lower-case value
   * so clients can compare strings without depending on Java naming conventions.
   *
   * @return lower-case status value used in Platform API JSON
   */
  public String jsonValue() {
    return jsonValue;
  }
}
