package network.crypta.platform.apphost;

/**
 * Measured byte usage for AppHost-managed app resources.
 *
 * <p>This record contains counts only. It does not retain the data directory, cache directory, run
 * directory, process-log path, or any file names observed while scanning. AppHost may therefore
 * attach it to public runtime status responses without exposing host filesystem layout.
 *
 * <p>The data and cache values are byte counts from the most recent scanner pass. They may be
 * partial when the accompanying quota status includes a scan-incomplete warning. The process-log
 * value comes from AppHost's managed {@code process.log} checkpoint and can be {@code null} when no
 * safe regular log file is available.
 *
 * @param dataUsageBytes non-negative bytes counted under the app-owned data directory
 * @param cacheUsageBytes non-negative bytes counted under the app-owned cache directory
 * @param processLogSizeBytes current managed process-log size in bytes, including any retained
 *     redaction overlap, or {@code null} when no regular process log is available
 */
public record AppQuotaUsage(long dataUsageBytes, long cacheUsageBytes, Long processLogSizeBytes) {
  /**
   * Creates a validated usage snapshot.
   *
   * <p>All present byte counts must be non-negative. The constructor does not compare usage against
   * quota policy, because a {@code 0} manifest quota is unlimited and only {@link AppQuotaStatus}
   * has the policy context needed to derive over-limit flags.
   *
   * @param dataUsageBytes non-negative bytes counted under the app-owned data directory
   * @param cacheUsageBytes non-negative bytes counted under the app-owned cache directory
   * @param processLogSizeBytes current managed process-log size in bytes, including any retained
   *     redaction overlap, or {@code null} when unavailable
   */
  public AppQuotaUsage {
    if (dataUsageBytes < 0L) {
      throw new IllegalArgumentException("dataUsageBytes must be non-negative");
    }
    if (cacheUsageBytes < 0L) {
      throw new IllegalArgumentException("cacheUsageBytes must be non-negative");
    }
    if (processLogSizeBytes != null && processLogSizeBytes < 0L) {
      throw new IllegalArgumentException("processLogSizeBytes must be non-negative when present");
    }
  }

  /**
   * Returns an empty usage snapshot with no process log.
   *
   * <p>The empty snapshot is appropriate for default status objects and tests. It should not be
   * used to hide a failed measurement for an installed app; scanner failures should be represented
   * with the best available byte count plus an {@link AppQuotaWarning}.
   *
   * @return zero-byte mutable directory usage with no process-log size
   */
  public static AppQuotaUsage empty() {
    return new AppQuotaUsage(0L, 0L, null);
  }
}
