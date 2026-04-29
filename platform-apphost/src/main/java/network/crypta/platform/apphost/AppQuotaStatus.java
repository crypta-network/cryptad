package network.crypta.platform.apphost;

import java.util.List;
import java.util.Objects;

/**
 * Token-free quota status for one installed app.
 *
 * <p>The status combines manifest-derived policy, measured usage, and display-safe warnings. It is
 * intentionally path-free: callers can see byte counts, effective limits, over-limit booleans, and
 * process-log metadata without learning where AppHost stores app data, cache, or runtime files.
 *
 * <p>Data and cache limits are enforced only when the effective quota is positive. Raw manifest
 * values are still available through the policy, so API serializers can preserve existing {@code
 * dataBytes}/{@code cacheBytes} fields while also reporting whether those values actually cause
 * enforcement.
 *
 * <p>Instances are immutable point-in-time snapshots. A warning may describe an incomplete
 * measurement, an over-limit condition, a process-log truncation, or a bounded runtime guard. The
 * warning set is advisory for display except where {@link AppQuotaEnforcer} explicitly uses it to
 * fail closed before launch.
 *
 * @param policy effective runtime policy derived from manifest metadata and host defaults
 * @param usage current measured usage for managed app resources at the status checkpoint
 * @param warnings display-safe quota and measurement warnings associated with this snapshot
 */
public record AppQuotaStatus(
    AppQuotaPolicy policy, AppQuotaUsage usage, List<AppQuotaWarning> warnings) {
  /**
   * Creates a validated quota status snapshot.
   *
   * <p>The warning list is defensively copied. Callers can safely retain or serialize the snapshot
   * without being affected by later warning collection changes during another runtime poll.
   *
   * @param policy effective runtime policy derived from manifest metadata and host defaults
   * @param usage current measured usage for managed app resources at the status checkpoint
   * @param warnings display-safe quota and measurement warnings associated with this snapshot
   */
  public AppQuotaStatus {
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(usage, "usage");
    warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
  }

  /**
   * Returns a status for an app with no explicit data/cache quotas and no measured usage.
   *
   * <p>This helper is intended for default or inactive snapshots where the host needs a complete
   * status object before a manifest-specific measurement is available. The returned status still
   * carries the default process-log policy through {@link AppQuotaPolicy#unlimited()}.
   *
   * @return empty unlimited quota status with no warnings
   */
  public static AppQuotaStatus unlimited() {
    return new AppQuotaStatus(AppQuotaPolicy.unlimited(), AppQuotaUsage.empty(), List.of());
  }

  /**
   * Returns whether data usage has a positive enforced quota.
   *
   * <p>This value is derived from the effective policy, not from whether current usage is over the
   * limit. It remains {@code false} for both absent and zero manifest quotas.
   *
   * @return {@code true} when data quota enforcement is active
   */
  public boolean dataQuotaEnforced() {
    return policy.dataQuotaEnforced();
  }

  /**
   * Returns whether cache usage has a positive enforced quota.
   *
   * <p>This value is derived from the effective policy, not from whether current usage is over the
   * limit. It remains {@code false} for both absent and zero manifest quotas.
   *
   * @return {@code true} when cache quota enforcement is active
   */
  public boolean cacheQuotaEnforced() {
    return policy.cacheQuotaEnforced();
  }

  /**
   * Returns whether measured data usage exceeds the positive enforced data quota.
   *
   * <p>When no positive data quota is active, this method returns {@code false} regardless of the
   * measured byte count. Incomplete scans are represented separately through warnings because the
   * byte count may be partial.
   *
   * @return {@code true} when data usage is over an active positive limit
   */
  public boolean dataOverLimit() {
    Long quotaBytes = policy.effectiveDataQuotaBytes();
    return quotaBytes != null && usage.dataUsageBytes() > quotaBytes;
  }

  /**
   * Returns whether measured cache usage exceeds the positive enforced cache quota.
   *
   * <p>When no positive cache quota is active, this method returns {@code false} regardless of the
   * measured byte count. Incomplete scans are represented separately through warnings because the
   * byte count may be partial.
   *
   * @return {@code true} when cache usage is over an active positive limit
   */
  public boolean cacheOverLimit() {
    Long quotaBytes = policy.effectiveCacheQuotaBytes();
    return quotaBytes != null && usage.cacheUsageBytes() > quotaBytes;
  }

  /**
   * Returns display-safe warning messages.
   *
   * <p>The returned text is suitable for Platform API responses and Web Shell display. Callers that
   * need stable machine-readable identifiers should inspect {@link #warnings()} and serialize the
   * warning codes instead of parsing the human-readable messages.
   *
   * @return immutable warning text list safe for Platform API responses
   */
  public List<String> warningMessages() {
    return warnings.stream().map(AppQuotaWarning::message).toList();
  }
}
