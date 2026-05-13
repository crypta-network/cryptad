package network.crypta.platform.api.appupdates;

/**
 * Public status values for the app-update background scheduler.
 *
 * <p>The enum is intentionally small and display-oriented. Scheduler internals may distinguish
 * individual catalog refresh failures from app-check failures, but API summaries need only the
 * stable state that tells operators whether background discovery is disabled, waiting, active,
 * successful, failed, or waiting for failure backoff. The string values returned by {@link
 * #jsonValue()} are the Platform API values and should remain stable across releases.
 *
 * <p>These statuses describe scheduler work, not the app-update candidate itself. Candidate state,
 * staged plans, apply history, and rollback status remain in the surrounding app-update summary.
 */
public enum AppUpdateSchedulerStatus {
  /**
   * Background scheduling is disabled by local configuration.
   *
   * <p>No catalog refresh or installed-app update check is started by the scheduler while this
   * status is active. Manual app-update API routes remain available.
   */
  DISABLED("disabled"),

  /**
   * Background scheduling is enabled and waiting for the next due time.
   *
   * <p>This is the normal idle state for a target that has no active failure and whose next check
   * timestamp has not arrived yet.
   */
  SCHEDULED("scheduled"),

  /**
   * A scheduler pass is currently checking this app or refreshing catalogs.
   *
   * <p>The state is transient. It records that work has started and prevents summaries from
   * reporting stale idle state while a due target is being processed.
   */
  RUNNING("running"),

  /**
   * The most recent scheduler work for this target completed successfully.
   *
   * <p>Success resets consecutive failure metadata and schedules the next due time from the normal
   * catalog or app-check interval plus configured jitter.
   */
  SUCCESS("success"),

  /**
   * The most recent scheduler work failed and no backoff delay is currently active.
   *
   * <p>The current implementation generally moves failures directly into {@link #BACKOFF}; this
   * value is retained for stable API vocabulary and future precise failure states.
   */
  FAILED("failed"),

  /**
   * A failure backoff delay is active before the next scheduler check.
   *
   * <p>Backoff is used for catalog listing, catalog refresh, installed-app listing, app check, and
   * scheduler-store failures. The summary includes a sanitized error code and message.
   */
  BACKOFF("backoff"),

  /**
   * The scheduler skipped work because nothing was due.
   *
   * <p>This status is used for aggregate pass results and target states where the scheduler made a
   * deliberate no-op decision instead of attempting lifecycle work.
   */
  SKIPPED("skipped"),

  /**
   * The app was no longer installed when the scheduler attempted to check it.
   *
   * <p>Missing-app cleanup clears durable scheduler metadata so a later reinstall with the same app
   * id starts from fresh scheduled state.
   */
  NOT_INSTALLED("not_installed");

  private final String jsonValue;

  AppUpdateSchedulerStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value for this status.
   *
   * <p>The value is lower-case ASCII and belongs to the Platform API contract. Callers should use
   * this method rather than enum names when serializing scheduler summaries.
   *
   * @return lower-case scheduler status used in Platform API summaries
   */
  public String jsonValue() {
    return jsonValue;
  }
}
