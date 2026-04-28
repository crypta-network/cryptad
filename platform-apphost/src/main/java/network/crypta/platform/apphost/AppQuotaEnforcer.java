package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Measures and enforces AppHost quotas at local-process lifecycle checkpoints.
 *
 * <p>The enforcer is intentionally scoped to resources that the current local AppHost can manage
 * portably: mutable data and cache directory sizes, the AppHost-owned process log, and status
 * warnings. It does not inspect arbitrary descendant processes, and it does not provide CPU,
 * memory, or network isolation.
 *
 * <p>Positive data and cache quotas block app launch when current usage is above the configured
 * limit or when usage measurement for the enforced area is incomplete. Missing and zero quotas
 * remain unlimited for backward compatibility with first-party app manifests that already declare
 * {@code quota.data.bytes=0} and {@code quota.cache.bytes=0}. Process-log bounding is the best
 * effort: failures are reported as warnings rather than leaking raw filesystem errors through
 * public status objects.
 *
 * <p>Callers normally use this type from {@code LocalProcessAppHost} before launch, before
 * automatic restart, while reading runtime status, and before serving process-log tails. The status
 * objects returned from those calls are safe for Platform API serialization: they contain byte
 * counts, effective limits, booleans, and stable warning text, but never host paths, launch tokens,
 * command lines, or raw exception messages.
 */
public final class AppQuotaEnforcer {
  private static final String DATA_SCAN_INCOMPLETE_CODE = "data_scan_incomplete";
  private static final String CACHE_SCAN_INCOMPLETE_CODE = "cache_scan_incomplete";
  private static final String DATA_SYMLINK_SKIPPED_CODE = "data_symlink_skipped";
  private static final String CACHE_SYMLINK_SKIPPED_CODE = "cache_symlink_skipped";

  private final AppDiskUsageScanner diskUsageScanner;

  /**
   * Creates an enforcer backed by the default disk-usage scanner.
   *
   * <p>This constructor is the production path for local-process AppHost implementations. The
   * created enforcer performs fresh data/cache scans on each status or launch check and applies the
   * host process-log limit before returning status.
   */
  public AppQuotaEnforcer() {
    this(new AppDiskUsageScanner());
  }

  /**
   * Creates an enforcer backed by an explicit scanner.
   *
   * <p>The explicit scanner constructor keeps quota behavior testable without replacing the
   * enforcer's policy decisions. The scanner is still expected to return path-free warnings and
   * non-negative byte counts.
   *
   * @param diskUsageScanner scanner used for data and cache byte measurement
   */
  public AppQuotaEnforcer(AppDiskUsageScanner diskUsageScanner) {
    this.diskUsageScanner = Objects.requireNonNull(diskUsageScanner, "diskUsageScanner");
  }

  /**
   * Returns current quota status after applying best-effort process-log bounding.
   *
   * <p>This method is suitable for app summaries and runtime polling. It first enforces the
   * process-log storage bound, then measures data/cache usage, then derives over-limit flags and
   * warnings from the effective policy. It never throws for ordinary scan incompleteness; that
   * condition is represented as a warning so UI and API callers can display the degraded
   * measurement. Launch enforcement uses {@link #enforceLaunch(AppManifest, InstalledAppPaths)} to
   * turn the same warning into a fail-closed block when a positive quota is active.
   *
   * @param manifest installed app manifest that supplies data and cache quota metadata
   * @param paths AppHost-managed paths for the app being measured
   * @return token-free, path-free quota status for API and UI display
   */
  public AppQuotaStatus status(AppManifest manifest, InstalledAppPaths paths) {
    AppQuotaPolicy policy = AppQuotaPolicy.fromManifest(manifest);
    ProcessLogLimitResult processLog = enforceProcessLogLimit(paths, policy);
    AppDiskUsageScanner.ScanResult scanResult =
        diskUsageScanner.scan(paths, processLog.sizeBytes());
    return buildStatus(
        policy, scanResult.usage(), merge(scanResult.warnings(), processLog.warnings()));
  }

  /**
   * Enforces positive data/cache quotas before app launch.
   *
   * <p>The check is intentionally conservative. A positive quota must be measured completely before
   * launch is allowed. If the scanner reports that it skipped or could not inspect part of the
   * enforced data/cache area, launch fails with an {@link AppHostException} even when the partial
   * byte count is below the limit. That prevents apps from hiding state below unreadable entries.
   * Unset and zero quotas stay unlimited and therefore do not convert scan warnings into launch
   * failures.
   *
   * @param manifest installed app manifest that supplies data and cache quota metadata
   * @param paths AppHost-managed paths for the app being launched
   * @return measured quota status when launch may proceed
   * @throws AppHostException if a positive data or cache quota is exceeded or cannot be measured
   *     completely
   */
  public AppQuotaStatus enforceLaunch(AppManifest manifest, InstalledAppPaths paths)
      throws AppHostException {
    AppQuotaStatus status = status(manifest, paths);
    if (status.dataQuotaEnforced()
        && hasAnyWarning(status, DATA_SCAN_INCOMPLETE_CODE, DATA_SYMLINK_SKIPPED_CODE)) {
      throw new AppHostException("app data quota scan incomplete: " + manifest.appId());
    }
    if (status.cacheQuotaEnforced()
        && hasAnyWarning(status, CACHE_SCAN_INCOMPLETE_CODE, CACHE_SYMLINK_SKIPPED_CODE)) {
      throw new AppHostException("app cache quota scan incomplete: " + manifest.appId());
    }
    if (status.dataOverLimit()) {
      throw new AppHostException("app data quota exceeded: " + manifest.appId());
    }
    if (status.cacheOverLimit()) {
      throw new AppHostException("app cache quota exceeded: " + manifest.appId());
    }
    return status;
  }

  private static boolean hasAnyWarning(AppQuotaStatus status, String... codes) {
    for (AppQuotaWarning warning : status.warnings()) {
      for (String code : codes) {
        if (warning.code().equals(code)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Applies the process-log size limit without scanning data/cache usage.
   *
   * <p>The retained file may be slightly larger than the display limit in {@code policy}. AppHost
   * log tailing reads a redaction overlap before the requested suffix so tokens and known paths
   * split by a byte boundary can still be recognized before the final display bound is applied.
   * Truncation keeps that overlap on disk instead of cutting directly at the display limit.
   *
   * <p>If the log is missing, unreadable, a symlink, or not a regular file, the method reports no
   * size and no warning because the caller cannot safely mutate it as the AppHost-owned process
   * log. If truncation fails after a regular log was observed, the original size is returned with a
   * display-safe warning. The method does not expose the log path or the underlying exception text.
   *
   * @param paths AppHost-managed paths for the app whose process log may be bounded
   * @param policy quota policy containing the host process-log limit in bytes
   * @return resulting process-log size and display-safe warnings from the bounding attempt
   */
  public ProcessLogLimitResult enforceProcessLogLimit(
      InstalledAppPaths paths, AppQuotaPolicy policy) {
    Objects.requireNonNull(paths, "paths");
    Objects.requireNonNull(policy, "policy");
    Path logFile = paths.processLogFile();
    BasicFileAttributes attributes = processLogAttributes(logFile);
    if (attributes == null) {
      return new ProcessLogLimitResult(null, List.of());
    }
    long sizeBytes = attributes.size();
    long retainedMaxBytes = retainedProcessLogMaxBytes(paths, policy.processLogMaxBytes());
    if (sizeBytes <= retainedMaxBytes) {
      return new ProcessLogLimitResult(sizeBytes, List.of());
    }
    try {
      truncateProcessLogTail(logFile, sizeBytes, retainedMaxBytes);
      BasicFileAttributes updatedAttributes = processLogAttributes(logFile);
      Long updatedSizeBytes = updatedAttributes == null ? null : updatedAttributes.size();
      return new ProcessLogLimitResult(
          updatedSizeBytes, List.of(AppQuotaWarning.processLogTruncated()));
    } catch (IOException | RuntimeException _) {
      return new ProcessLogLimitResult(
          sizeBytes,
          List.of(
              new AppQuotaWarning(
                  "process_log_limit_failed", "Process log limit could not be applied.")));
    }
  }

  private static AppQuotaStatus buildStatus(
      AppQuotaPolicy policy, AppQuotaUsage usage, List<AppQuotaWarning> warnings) {
    List<AppQuotaWarning> statusWarnings = new ArrayList<>(warnings);
    if (policy.effectiveDataQuotaBytes() != null
        && usage.dataUsageBytes() > policy.effectiveDataQuotaBytes()) {
      statusWarnings.add(AppQuotaWarning.dataQuotaExceeded());
    }
    if (policy.effectiveCacheQuotaBytes() != null
        && usage.cacheUsageBytes() > policy.effectiveCacheQuotaBytes()) {
      statusWarnings.add(AppQuotaWarning.cacheQuotaExceeded());
    }
    return new AppQuotaStatus(policy, usage, deduplicated(statusWarnings));
  }

  private static List<AppQuotaWarning> merge(
      List<AppQuotaWarning> first, List<AppQuotaWarning> second) {
    List<AppQuotaWarning> merged = new ArrayList<>(first.size() + second.size());
    merged.addAll(first);
    merged.addAll(second);
    return deduplicated(merged);
  }

  private static List<AppQuotaWarning> deduplicated(List<AppQuotaWarning> warnings) {
    List<AppQuotaWarning> deduplicated = new ArrayList<>();
    for (AppQuotaWarning warning : warnings) {
      if (deduplicated.stream().noneMatch(existing -> existing.code().equals(warning.code()))) {
        deduplicated.add(warning);
      }
    }
    return List.copyOf(deduplicated);
  }

  private static long retainedProcessLogMaxBytes(InstalledAppPaths paths, long processLogMaxBytes) {
    int overlapBytes = AppHostTokenRedactor.redactionOverlapBytes(null, paths);
    if (Long.MAX_VALUE - processLogMaxBytes < overlapBytes) {
      return Long.MAX_VALUE;
    }
    return processLogMaxBytes + overlapBytes;
  }

  private static BasicFileAttributes processLogAttributes(Path logFile) {
    try {
      if (!Files.exists(logFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(logFile)) {
        return null;
      }
      BasicFileAttributes attributes =
          Files.readAttributes(logFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      return attributes.isRegularFile() ? attributes : null;
    } catch (IOException | RuntimeException _) {
      return null;
    }
  }

  private static void truncateProcessLogTail(Path logFile, long sizeBytes, long retainedMaxBytes)
      throws IOException {
    int bytesToKeep = Math.toIntExact(Math.min(sizeBytes, retainedMaxBytes));
    ByteBuffer buffer = ByteBuffer.allocate(bytesToKeep);
    try (SeekableByteChannel readChannel =
        Files.newByteChannel(logFile, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      readChannel.position(sizeBytes - bytesToKeep);
      while (buffer.hasRemaining()) {
        if (readChannel.read(buffer) < 0) {
          break;
        }
      }
    }
    buffer.flip();
    try (SeekableByteChannel writeChannel =
        Files.newByteChannel(
            logFile,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING,
            LinkOption.NOFOLLOW_LINKS)) {
      while (buffer.hasRemaining()) {
        writeChannel.write(buffer);
      }
    }
    OwnerOnlyFilePermissions.hardenSensitiveFile(logFile);
  }

  /**
   * Result of applying the host process-log limit.
   *
   * <p>The size is the regular-file size after a successful bounding attempt, the observed size
   * when truncation failed, or {@code null} when no safe regular process log was available. Warning
   * values are stable API-facing descriptions and must not contain host filesystem paths or process
   * launch details.
   *
   * @param sizeBytes current log size after best-effort bounding, or {@code null} when unavailable
   * @param warnings display-safe log-limit warnings from the bounding attempt
   */
  public record ProcessLogLimitResult(Long sizeBytes, List<AppQuotaWarning> warnings) {
    /**
     * Creates a validated process-log limit result.
     *
     * <p>The warning list is defensively copied so a runtime status snapshot preserves the warnings
     * observed at the checkpoint even if the caller's input list is later modified.
     *
     * @param sizeBytes current log size after best-effort bounding, or {@code null} when
     *     unavailable
     * @param warnings display-safe log-limit warnings from the bounding attempt
     */
    public ProcessLogLimitResult {
      if (sizeBytes != null && sizeBytes < 0L) {
        throw new IllegalArgumentException("sizeBytes must be non-negative when present");
      }
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    }
  }
}
