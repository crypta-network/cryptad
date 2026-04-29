package network.crypta.platform.apphost;

import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Effective AppHost quota policy derived from an installed app manifest and host defaults.
 *
 * <p>The manifest keeps the original {@code quota.data.bytes} and {@code quota.cache.bytes} values
 * because those fields are part of signed bundle metadata. This policy interprets them for runtime
 * enforcement: {@code null} and {@code 0} both mean no explicit app quota, while positive values
 * are enforced at AppHost lifecycle checkpoints. Negative values are rejected by manifest parsing
 * and remain invalid here as a defensive check.
 *
 * <p>The process-log limit is host policy rather than signed app metadata. AppHost uses it as the
 * display/log-tail bound for the managed {@code process.log} file without exposing the run
 * directory path through public DTOs. The on-disk file may retain a small additional redaction
 * overlap so later tail reads can still redact tokens and known paths split by the display
 * boundary.
 *
 * <p>Instances are immutable value objects. They preserve the manifest-facing quota values for API
 * compatibility while exposing effective quota helpers for enforcement code. Serializers should use
 * the raw values when they need to preserve legacy JSON fields and the effective/enforced helpers
 * when they need to explain current runtime behavior.
 *
 * @param dataQuotaBytes raw manifest data quota in bytes, {@code 0} for no explicit quota, or
 *     {@code null} when absent
 * @param cacheQuotaBytes raw manifest cache quota in bytes, {@code 0} for no explicit quota, or
 *     {@code null} when absent
 * @param processLogMaxBytes positive host process-log display limit in bytes
 */
public record AppQuotaPolicy(Long dataQuotaBytes, Long cacheQuotaBytes, long processLogMaxBytes) {
  /**
   * Creates a validated quota policy.
   *
   * <p>The constructor intentionally accepts {@code null} and {@code 0} for data/cache quotas
   * because both represent unlimited mutable storage in PR-207 compatibility semantics. Positive
   * values are retained as enforceable byte limits. Negative values and non-positive process-log
   * limits fail immediately so callers cannot construct an ambiguous policy.
   *
   * @param dataQuotaBytes raw manifest data quota in bytes, {@code 0} for no explicit quota, or
   *     {@code null} when absent
   * @param cacheQuotaBytes raw manifest cache quota in bytes, {@code 0} for no explicit quota, or
   *     {@code null} when absent
   * @param processLogMaxBytes positive host process-log display limit in bytes
   */
  public AppQuotaPolicy {
    validateManifestQuota(dataQuotaBytes, "dataQuotaBytes");
    validateManifestQuota(cacheQuotaBytes, "cacheQuotaBytes");
    if (processLogMaxBytes <= 0L) {
      throw new IllegalArgumentException("processLogMaxBytes must be positive");
    }
  }

  /**
   * Builds a policy from manifest quota fields and the default host process-log limit.
   *
   * <p>This is the normal AppHost conversion point from signed manifest metadata into runtime
   * enforcement policy. The manifest's quota values are not normalized away; callers can still
   * report that a manifest declared {@code 0} while also showing that no positive quota is
   * enforced.
   *
   * @param manifest installed app manifest that supplies raw data and cache quota values
   * @return runtime quota policy for the manifest and default host log limit
   */
  public static AppQuotaPolicy fromManifest(AppManifest manifest) {
    Objects.requireNonNull(manifest, "manifest");
    return new AppQuotaPolicy(
        manifest.dataQuotaBytes(),
        manifest.cacheQuotaBytes(),
        AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES);
  }

  /**
   * Returns a policy with no explicit data or cache quotas.
   *
   * <p>The returned policy still includes the default process-log limit. It is useful for inactive
   * or placeholder status snapshots where no manifest-specific mutable-directory quota is available
   * but the status object should keep the same host log-bounding semantics.
   *
   * @return unlimited mutable-directory policy with the default process-log limit
   */
  public static AppQuotaPolicy unlimited() {
    return new AppQuotaPolicy(null, null, AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES);
  }

  /**
   * Returns the enforced data quota, or {@code null} when data usage is unlimited.
   *
   * <p>A {@code null} return value includes both absent manifest metadata and an explicit manifest
   * value of {@code 0}. Enforcement code should use this method instead of inspecting the raw
   * record component directly.
   *
   * @return positive data quota in bytes, otherwise {@code null} for unlimited data usage
   */
  public Long effectiveDataQuotaBytes() {
    return effectiveQuota(dataQuotaBytes);
  }

  /**
   * Returns the enforced cache quota, or {@code null} when cache usage is unlimited.
   *
   * <p>A {@code null} return value includes both absent manifest metadata and an explicit manifest
   * value of {@code 0}. Enforcement code should use this method instead of inspecting the raw
   * record component directly.
   *
   * @return positive cache quota in bytes, otherwise {@code null} for unlimited cache usage
   */
  public Long effectiveCacheQuotaBytes() {
    return effectiveQuota(cacheQuotaBytes);
  }

  /**
   * Returns whether data usage has a positive enforced quota.
   *
   * <p>This helper mirrors {@link #effectiveDataQuotaBytes()} for callers that only need the
   * boolean enforcement state in API responses or status snapshots.
   *
   * @return {@code true} when data usage is enforced by a positive manifest quota
   */
  public boolean dataQuotaEnforced() {
    return effectiveDataQuotaBytes() != null;
  }

  /**
   * Returns whether cache usage has a positive enforced quota.
   *
   * <p>This helper mirrors {@link #effectiveCacheQuotaBytes()} for callers that only need the
   * boolean enforcement state in API responses or status snapshots.
   *
   * @return {@code true} when cache usage is enforced by a positive manifest quota
   */
  public boolean cacheQuotaEnforced() {
    return effectiveCacheQuotaBytes() != null;
  }

  private static Long effectiveQuota(Long quotaBytes) {
    return quotaBytes != null && quotaBytes > 0L ? quotaBytes : null;
  }

  private static void validateManifestQuota(Long quotaBytes, String fieldName) {
    if (quotaBytes != null && quotaBytes < 0L) {
      throw new IllegalArgumentException(fieldName + " must be non-negative when present");
    }
  }
}
