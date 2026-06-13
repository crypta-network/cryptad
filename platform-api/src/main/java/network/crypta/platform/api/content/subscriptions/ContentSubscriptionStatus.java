package network.crypta.platform.api.content.subscriptions;

/**
 * Safe public status values for app-owned content subscriptions.
 *
 * <p>The values describe scheduler posture only. They deliberately avoid daemon exception text,
 * queue HTML, filesystem paths, request bodies, or fetched content. API handlers serialize the
 * stable lowercase value returned by {@link #jsonValue()}, and the file-backed store persists that
 * same value so scheduler restarts do not depend on Java enum names.
 *
 * <p>Statuses are coarse by design. Apps can use them to decide whether to show a subscription as
 * active, paused, waiting, or temporarily blocked, but they should not infer queue internals or
 * daemon failure causes from the enum. More detail, when safe, is carried separately as a bounded
 * error code and single-line message.
 */
public enum ContentSubscriptionStatus {
  /**
   * The subscription is enabled and waiting for its next due poll.
   *
   * <p>This is the normal idle state after creation, resume, or a scheduler decision that schedules
   * future work without starting a detached fetch immediately.
   */
  SCHEDULED("scheduled"),

  /**
   * A scheduler pass is currently handling the subscription.
   *
   * <p>The state is transient and may be replaced by success, backoff, or a pressure status when
   * the same deterministic tick completes.
   */
  RUNNING("running"),

  /**
   * The most recent detached fetch completed successfully.
   *
   * <p>A success does not necessarily mean the content changed. Apps should inspect update count,
   * digest, resolved URI, and edition metadata to decide whether to refetch and render content.
   */
  SUCCESS("success"),

  /**
   * The most recent detached fetch failed and the subscription is in bounded backoff.
   *
   * <p>The durable record stores a stable error code instead of daemon exception text. The
   * scheduler uses the failure count and configured maximum backoff to choose the next due time.
   */
  BACKOFF("backoff"),

  /**
   * The app paused the subscription.
   *
   * <p>Paused records remain durable and visible to the owning app, but deterministic scheduler
   * ticks skip them until the app resumes the subscription.
   */
  PAUSED("paused"),

  /**
   * Polling was skipped because queue or persistence state is clearly unavailable.
   *
   * <p>This status comes from stable pressure-gate signals only. The scheduler never parses queue
   * HTML and never exposes queue contents in the subscription summary.
   */
  QUEUE_PRESSURE("queue_pressure"),

  /**
   * Polling was skipped because a required runtime or app installation dependency is unavailable.
   *
   * <p>Typical causes include a disabled queue backend or an app that is no longer installed or no
   * longer declares the capabilities required for background content fetches.
   */
  RUNTIME_UNAVAILABLE("runtime_unavailable"),

  /**
   * Polling was skipped because the app-network budget was exhausted.
   *
   * <p>No detached content fetch is started for this status. The durable record carries a stable
   * budget error code and next retry time, but never contains raw URI, queue, or runtime exception
   * details.
   */
  BUDGET_EXHAUSTED("budget_exhausted"),

  /**
   * The scheduler is locally disabled.
   *
   * <p>The status is used for scheduler-level tick summaries. Individual subscription records are
   * not polled while the scheduler is disabled.
   */
  DISABLED("disabled"),

  /**
   * A delete response for a subscription that has just been removed.
   *
   * <p>Deletion is not a durable active state for normal scheduler work; it gives the API a safe
   * summary shape for the request that removed the record.
   */
  DELETED("deleted");

  private final String jsonValue;

  ContentSubscriptionStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value for API responses and persisted metadata.
   *
   * <p>The returned string is the compatibility surface for apps and durable metadata. Do not
   * change an existing value unless the platform contract and file migration story change with it.
   *
   * @return lower-case status label used in JSON and store files
   */
  public String jsonValue() {
    return jsonValue;
  }

  static ContentSubscriptionStatus fromJsonValue(String value) {
    if (value == null || value.isBlank()) {
      return SCHEDULED;
    }
    String normalized = value.trim();
    for (ContentSubscriptionStatus status : values()) {
      if (status.jsonValue.equals(normalized)) {
        return status;
      }
    }
    return SCHEDULED;
  }
}
