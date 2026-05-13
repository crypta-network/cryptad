package network.crypta.platform.api.appupdates;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Durable, path-free scheduler state for one app-update scheduling target.
 *
 * <p>Most instances describe a single installed app. The file-backed store also uses the same value
 * type for the scheduler's catalog-refresh target so refresh failures and backoff can survive a
 * node restart. Public API summaries expose only app states and keep the catalog target internal.
 *
 * <p>The value accepts only bounded single-line labels and messages. It is not a general-purpose
 * exception container; callers should pass stable error codes and short operator-facing messages
 * that have already been reduced to safe text. This keeps filesystem paths, catalog scratch
 * directories, staged bundle path details, app tokens, browser sessions, and raw exception details
 * out of persisted state and Platform API JSON.
 *
 * <p>Status and result are intentionally separate. {@link #status} describes the current scheduling
 * posture, such as scheduled, running, backoff, or disabled. {@link #lastResult} describes the most
 * recent completed pass. That split lets the Web Shell show a target that last succeeded but is now
 * scheduled for a later check, or a target whose latest failure has moved it into backoff.
 *
 * @param appId app id or internal scheduler target id
 * @param enabled whether the scheduler is enabled for the target
 * @param status current scheduler posture for the target
 * @param lastCheckAt time the target was last checked, or {@code null}
 * @param nextCheckAt next due check time, or {@code null}
 * @param lastResult stable result label such as {@code success}, {@code failed}, {@code skipped},
 *     or {@code none}
 * @param lastFailureAt time of the most recent failure, or {@code null}
 * @param failureCount consecutive failure count used to calculate bounded backoff
 * @param lastErrorCode stable error code for the most recent failure, or {@code null}
 * @param message short path-free scheduler message, or {@code null}
 */
public record AppUpdateSchedulerState(
    String appId,
    boolean enabled,
    AppUpdateSchedulerStatus status,
    Instant lastCheckAt,
    Instant nextCheckAt,
    String lastResult,
    Instant lastFailureAt,
    int failureCount,
    String lastErrorCode,
    String message) {
  /**
   * Result value used before the scheduler has checked a target.
   *
   * <p>Initial scheduled and disabled states use this value so callers can distinguish an untouched
   * target from one that completed, failed, or was intentionally skipped.
   */
  public static final String RESULT_NONE = "none";

  /**
   * Result value used for successful scheduler checks.
   *
   * <p>A successful catalog refresh or app update check resets failure metadata and schedules the
   * next due time using the normal success interval plus configured jitter.
   */
  public static final String RESULT_SUCCESS = "success";

  /**
   * Result value used for failed scheduler checks.
   *
   * <p>Failure results preserve a sanitized error code and move the target into backoff. The
   * original exception, path, URI, token, or request body is not stored here.
   */
  public static final String RESULT_FAILED = "failed";

  /**
   * Result value used when a scheduler pass skipped work.
   *
   * <p>Skipped results are used for due-work passes that intentionally do no lifecycle mutation,
   * such as missing-app cleanup or a pass where no target is ready.
   */
  public static final String RESULT_SKIPPED = "skipped";

  private static final Pattern SAFE_LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final int MAX_OPTIONAL_TEXT_LENGTH = 160;

  /**
   * Creates validated scheduler state.
   *
   * <p>The constructor normalizes required and optional labels but does not redact arbitrary
   * strings. Scheduler code passes fixed safe messages and stable error codes so persisted state
   * remains suitable for API summaries and release evidence. Labels are lower-cased and limited to
   * path-safe characters; messages must be single-line and are bounded before storage.
   *
   * @param appId app id or internal scheduler target id
   * @param enabled whether scheduling is enabled for the target
   * @param status scheduler posture for the target
   * @param lastCheckAt last scheduler check time, or {@code null}
   * @param nextCheckAt next scheduler check time, or {@code null}
   * @param lastResult result label, or {@code null} for {@code none}
   * @param lastFailureAt last scheduler failure time, or {@code null}
   * @param failureCount consecutive failure count used to calculate bounded backoff
   * @param lastErrorCode stable error code, or {@code null}
   * @param message path-free operator message, or {@code null}
   * @throws NullPointerException if {@code appId} or {@code status} is {@code null}
   * @throws IllegalArgumentException if labels, messages, or failure counts are invalid
   */
  public AppUpdateSchedulerState {
    appId = requireSafeLabel(appId, "appId");
    Objects.requireNonNull(status, "status");
    String normalizedLastResult = optionalSafeLabel(lastResult);
    lastResult = normalizedLastResult == null ? RESULT_NONE : normalizedLastResult;
    if (failureCount < 0) {
      throw new IllegalArgumentException("failureCount must be >= 0");
    }
    lastErrorCode = optionalSafeLabel(lastErrorCode);
    message = optionalSingleLine(message);
  }

  /**
   * Creates disabled state for an app or scheduler target.
   *
   * <p>Disabled state is synthetic and does not require durable storage. It is used when local
   * configuration turns the background scheduler off while keeping the app-update summary shape
   * stable for API clients and the Web Shell.
   *
   * @param appId app id or internal scheduler target id to include in the summary
   * @return disabled state with no timestamps or failure metadata
   */
  public static AppUpdateSchedulerState disabled(String appId) {
    return new AppUpdateSchedulerState(
        appId,
        false,
        AppUpdateSchedulerStatus.DISABLED,
        null,
        null,
        RESULT_NONE,
        null,
        0,
        null,
        "Background scheduler is disabled.");
  }

  /**
   * Creates initial scheduled state for an enabled target.
   *
   * <p>The returned state has no previous result, no failure metadata, and a next due timestamp.
   * Stores use this when no durable file exists yet, and summaries use it before a scheduler pass
   * has touched a newly installed app.
   *
   * @param appId app id or internal scheduler target id to schedule
   * @param nextCheckAt next due scheduler check time for the target
   * @return scheduled state with no previous result or failure metadata
   */
  public static AppUpdateSchedulerState scheduled(String appId, Instant nextCheckAt) {
    return new AppUpdateSchedulerState(
        appId,
        true,
        AppUpdateSchedulerStatus.SCHEDULED,
        null,
        Objects.requireNonNull(nextCheckAt, "nextCheckAt"),
        RESULT_NONE,
        null,
        0,
        null,
        "Waiting for the next scheduled update check.");
  }

  /**
   * Converts this state to the Platform API scheduler summary shape.
   *
   * <p>The response deliberately contains no scheduler store path, catalog source URI, staged
   * bundle path, rollback path, app token, browser session, or stack trace. It is suitable for
   * direct inclusion in {@code GET /api/v1/apps/{appId}/updates}.
   *
   * <p>Timestamp values are rendered as ISO-8601 strings so callers do not need access to Java time
   * types. The map preserves insertion order to keep Web Shell rendering, tests, and release
   * evidence stable.
   *
   * @return JSON-compatible path-free scheduler summary with stable field ordering
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("appId", appId);
    json.put("enabled", enabled);
    json.put("status", status.jsonValue());
    json.put("lastCheckAt", lastCheckAt == null ? null : lastCheckAt.toString());
    json.put("nextCheckAt", nextCheckAt == null ? null : nextCheckAt.toString());
    json.put("lastResult", lastResult);
    json.put("lastFailureAt", lastFailureAt == null ? null : lastFailureAt.toString());
    json.put("failureCount", failureCount);
    json.put("lastErrorCode", lastErrorCode);
    json.put("message", message);
    json.put("concurrency", "per-app-serialized");
    return json;
  }

  AppUpdateSchedulerState withRunning(Instant now) {
    return new AppUpdateSchedulerState(
        appId,
        enabled,
        AppUpdateSchedulerStatus.RUNNING,
        now,
        nextCheckAt,
        lastResult,
        lastFailureAt,
        failureCount,
        lastErrorCode,
        "Scheduler check is running.");
  }

  AppUpdateSchedulerState withSuccess(Instant now, Instant nextCheckAt, String message) {
    return new AppUpdateSchedulerState(
        appId,
        enabled,
        AppUpdateSchedulerStatus.SUCCESS,
        now,
        nextCheckAt,
        RESULT_SUCCESS,
        null,
        0,
        null,
        message);
  }

  @SuppressWarnings("unused")
  AppUpdateSchedulerState withSkipped(Instant nextCheckAt, String message) {
    return new AppUpdateSchedulerState(
        appId,
        enabled,
        AppUpdateSchedulerStatus.SKIPPED,
        lastCheckAt,
        nextCheckAt,
        RESULT_SKIPPED,
        lastFailureAt,
        failureCount,
        lastErrorCode,
        message);
  }

  AppUpdateSchedulerState withFailure(
      Instant now, Instant nextCheckAt, String errorCode, String message) {
    return new AppUpdateSchedulerState(
        appId,
        enabled,
        AppUpdateSchedulerStatus.BACKOFF,
        now,
        nextCheckAt,
        RESULT_FAILED,
        now,
        failureCount + 1,
        errorCode,
        message);
  }

  AppUpdateSchedulerState withNotInstalled(Instant now) {
    return new AppUpdateSchedulerState(
        appId,
        enabled,
        AppUpdateSchedulerStatus.NOT_INSTALLED,
        now,
        null,
        RESULT_SKIPPED,
        lastFailureAt,
        failureCount,
        null,
        "Scheduler skipped update check because the app is not installed.");
  }

  boolean isScheduledAfter(Instant now) {
    return nextCheckAt != null && nextCheckAt.isAfter(now);
  }

  private static String requireSafeLabel(String value, String fieldName) {
    String text =
        Objects.requireNonNull(value, fieldName).trim().toLowerCase(java.util.Locale.ROOT);
    if (!SAFE_LABEL.matcher(text).matches()) {
      throw new IllegalArgumentException(fieldName + " must be a path-safe label");
    }
    return text;
  }

  private static String optionalSafeLabel(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return requireSafeLabel(value, "optional label");
  }

  private static String optionalSingleLine(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    String text = value.trim();
    if (text.length() > MAX_OPTIONAL_TEXT_LENGTH) {
      text = text.substring(0, MAX_OPTIONAL_TEXT_LENGTH);
    }
    if (text.chars().anyMatch(character -> character == '\n' || character == '\r')) {
      throw new IllegalArgumentException("message must be single-line");
    }
    return text;
  }
}
