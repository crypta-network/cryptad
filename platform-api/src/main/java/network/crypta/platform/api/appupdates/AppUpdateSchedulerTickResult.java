package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.Objects;

/**
 * Deterministic result from one scheduler tick.
 *
 * <p>Tests call {@link AppUpdateScheduler#tick(Instant)} directly and assert on this value instead
 * of waiting for wall-clock executor behavior. Runtime code can ignore the result because durable
 * scheduler state is written through {@link AppUpdateSchedulerStore}. The result is still
 * path-free: it reports counts, status, timestamps, and a short reason, not catalog source paths,
 * staging directories, rollback directories, tokens, or raw exception text.
 *
 * <p>The counters describe attempted scheduler work, not app-update lifecycle outcomes. For
 * example, an app check can complete successfully while discovering no candidate, staging a
 * candidate under the explicit {@code stage} policy, or applying a stopped app under the explicit
 * {@code apply_when_stopped} policy. Those details remain in the update service summary and
 * history.
 *
 * @param ranAt time supplied to the tick
 * @param status aggregate scheduler status for the tick
 * @param result aggregate result label such as {@code success}, {@code failed}, or {@code skipped}
 * @param catalogsAttempted number of configured catalog refreshes attempted during this tick
 * @param catalogFailures number of catalog listing or refresh failures observed
 * @param appsChecked number of installed apps whose update checks were attempted
 * @param appFailures number of attempted app checks that failed or entered store-failure backoff
 * @param skippedApps number of installed apps skipped because their next check was not due
 * @param nextRunAt earliest known next scheduler due time after this pass
 * @param message short path-free tick summary for logs, tests, or evidence
 */
public record AppUpdateSchedulerTickResult(
    Instant ranAt,
    AppUpdateSchedulerStatus status,
    String result,
    int catalogsAttempted,
    int catalogFailures,
    int appsChecked,
    int appFailures,
    int skippedApps,
    Instant nextRunAt,
    String message) {
  /**
   * Creates a validated tick result.
   *
   * <p>The constructor validates only the structural guarantees needed by callers: required labels
   * must be present, counters must be non-negative, and a blank message is normalized to {@code
   * null}. The scheduler owns message sanitization before constructing this record.
   *
   * @param ranAt time supplied to the tick
   * @param status aggregate scheduler status for the completed or skipped pass
   * @param result aggregate result label such as {@code success}, {@code failed}, or {@code
   *     skipped}
   * @param catalogsAttempted number of configured catalog refreshes attempted during this tick
   * @param catalogFailures number of catalog listing or refresh failures observed
   * @param appsChecked number of installed apps whose update checks were attempted
   * @param appFailures number of attempted app checks that failed or entered store-failure backoff
   * @param skippedApps number of installed apps skipped because their next check was not due
   * @param nextRunAt earliest known next scheduler due time after this pass
   * @param message short path-free summary for logs, tests, or evidence
   * @throws NullPointerException if {@code ranAt}, {@code status}, or {@code result} is {@code
   *     null}
   * @throws IllegalArgumentException if any scheduler counter is negative
   */
  public AppUpdateSchedulerTickResult {
    Objects.requireNonNull(ranAt, "ranAt");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(result, "result");
    if (catalogsAttempted < 0
        || catalogFailures < 0
        || appsChecked < 0
        || appFailures < 0
        || skippedApps < 0) {
      throw new IllegalArgumentException("scheduler counts must be >= 0");
    }
    message = message == null || message.isBlank() ? null : message.trim();
  }

  static AppUpdateSchedulerTickResult disabled(Instant now) {
    return new AppUpdateSchedulerTickResult(
        now,
        AppUpdateSchedulerStatus.DISABLED,
        AppUpdateSchedulerState.RESULT_SKIPPED,
        0,
        0,
        0,
        0,
        0,
        null,
        "Background scheduler is disabled.");
  }

  static AppUpdateSchedulerTickResult alreadyRunning(Instant now) {
    return new AppUpdateSchedulerTickResult(
        now,
        AppUpdateSchedulerStatus.RUNNING,
        AppUpdateSchedulerState.RESULT_SKIPPED,
        0,
        0,
        0,
        0,
        0,
        null,
        "Previous scheduler pass is still running.");
  }
}
