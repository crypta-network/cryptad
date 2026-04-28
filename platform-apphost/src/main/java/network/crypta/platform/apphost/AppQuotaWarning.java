package network.crypta.platform.apphost;

import java.util.Objects;

/**
 * Token-free warning emitted while measuring or enforcing AppHost resource quotas.
 *
 * <p>Quota warnings are designed for Platform API and Web Shell responses. They identify a stable
 * condition with a short code and a display-safe message, but they never include launch tokens,
 * command lines, environment values, or host filesystem paths. AppHost runtime code should prefer
 * these warnings over raw exception messages whenever a quota check needs to surface degraded
 * measurement, bounded log maintenance, or restart-guard behavior to an operator.
 *
 * <p>The {@code code} component is the durable machine-readable value. UI code may render the
 * {@code message} directly as escaped text, but should not parse it for behavior. The message is
 * intentionally general because quota checks may encounter sensitive local paths, app-owned file
 * names, or process details while producing the warning.
 *
 * @param code stable machine-readable warning code for API clients and tests
 * @param message concise operator-facing warning text safe for escaped display
 */
public record AppQuotaWarning(String code, String message) {
  /**
   * Creates a validated warning.
   *
   * <p>Both values are trimmed and must remain non-blank. The constructor does not impose a fixed
   * code registry so AppHost can add new warning families without changing this value type, but
   * callers should still use lowercase snake-case codes for consistency.
   *
   * @param code stable machine-readable warning code for API clients and tests
   * @param message concise operator-facing warning text safe for escaped display
   */
  public AppQuotaWarning {
    code = requireNonBlank(code, "code");
    message = requireNonBlank(message, "message");
  }

  /**
   * Reports that usage measurement skipped one or more symlink entries.
   *
   * <p>Symlinks are skipped rather than followed so a quota scan stays inside the AppHost-managed
   * data/cache tree. The warning tells operators that usage may not include linked content without
   * naming the symlink or its target.
   *
   * @param area quota area whose scan skipped a symlink; accepted values are {@code data} and
   *     {@code cache}, case-insensitively
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning symlinkSkipped(String area) {
    String normalizedArea = quotaArea(area);
    return new AppQuotaWarning(
        normalizedArea + "_symlink_skipped",
        capitalize(normalizedArea) + " usage ignores symlink entries.");
  }

  /**
   * Reports that usage measurement could not inspect all entries.
   *
   * <p>Incomplete scans are informational for status views but launch-blocking when the affected
   * area has a positive enforced quota. The warning deliberately omits exception text and path
   * details because unreadable entries may disclose host layout or app-owned file names.
   *
   * @param area quota area whose scan was incomplete; accepted values are {@code data} and {@code
   *     cache}, case-insensitively
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning scanIncomplete(String area) {
    String normalizedArea = quotaArea(area);
    return new AppQuotaWarning(
        normalizedArea + "_scan_incomplete",
        capitalize(normalizedArea)
            + " usage may be incomplete because some entries could not be "
            + "inspected.");
  }

  /**
   * Reports that an app's data directory exceeds its positive quota.
   *
   * <p>This warning is emitted only after policy normalization determines that the manifest's data
   * quota is positive. A manifest value of {@code 0} remains unlimited and does not produce this
   * warning regardless of measured usage.
   *
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning dataQuotaExceeded() {
    return new AppQuotaWarning(
        "data_quota_exceeded", "Data usage exceeds the configured app quota.");
  }

  /**
   * Reports that an app's cache directory exceeds its positive quota.
   *
   * <p>This warning is emitted only after policy normalization determines that the manifest's cache
   * quota is positive. A manifest value of {@code 0} remains unlimited and does not produce this
   * warning regardless of measured usage.
   *
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning cacheQuotaExceeded() {
    return new AppQuotaWarning(
        "cache_quota_exceeded", "Cache usage exceeds the configured app quota.");
  }

  /**
   * Reports that the host truncated the process log to keep it within the configured maximum.
   *
   * <p>The process log is bounded by retaining its tail plus any redaction overlap needed by
   * AppHost log-tail reads. This warning reports that maintenance occurred; it does not expose the
   * log path or any removed content.
   *
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning processLogTruncated() {
    return new AppQuotaWarning(
        "process_log_truncated",
        "Process log exceeded the host limit and was truncated to its tail.");
  }

  /**
   * Reports that the automatic restart storm guard suppressed another restart.
   *
   * <p>The values are included so operators can understand the active guard without inspecting host
   * configuration. They are policy numbers, not app-provided data, and the message remains free of
   * tokens, paths, and process command lines.
   *
   * @param maxRestarts maximum automatic restarts allowed within the rolling window
   * @param windowMillis rolling restart window length in milliseconds
   * @return warning safe for public status responses
   */
  public static AppQuotaWarning restartStormBlocked(int maxRestarts, long windowMillis) {
    return new AppQuotaWarning(
        "restart_storm_blocked",
        "Automatic restart suppressed after "
            + maxRestarts
            + " attempts within "
            + windowMillis
            + " ms.");
  }

  private static String requireNonBlank(String value, String fieldName) {
    String normalized = Objects.requireNonNull(value, fieldName).trim();
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return normalized;
  }

  private static String quotaArea(String area) {
    String normalized = requireNonBlank(area, "area").toLowerCase(java.util.Locale.ROOT);
    if (!normalized.equals("data") && !normalized.equals("cache")) {
      throw new IllegalArgumentException("area must be data or cache");
    }
    return normalized;
  }

  private static String capitalize(String value) {
    return value.substring(0, 1).toUpperCase(java.util.Locale.ROOT) + value.substring(1);
  }
}
