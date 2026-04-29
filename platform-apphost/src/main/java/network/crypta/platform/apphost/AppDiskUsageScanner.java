package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Measures AppHost-managed app data and cache usage without following links.
 *
 * <p>The scanner walks only the installed app's mutable data and cache directories. It counts
 * regular-file byte sizes and deliberately uses the JVM's default no-follow link behavior for tree
 * traversal. A symlink encountered in an app-owned tree is skipped instead of resolved.
 * Inaccessible entries, unexpected root shapes, and arithmetic overflow are reported as incomplete
 * scans so the caller can distinguish a precise measurement from best-effort usage.
 *
 * <p>Warnings are deliberately path-free and token-free. They can be returned through app
 * summaries, runtime status, and Web Shell views without disclosing host layout. This type also
 * keeps scanning separate from policy: it does not decide whether a measured value is over quota,
 * whether an incomplete scan should block launch, or whether process-log state should be repaired.
 * {@link AppQuotaEnforcer} combines scanner output with {@link AppQuotaPolicy} at lifecycle
 * checkpoints.
 */
public final class AppDiskUsageScanner {
  /**
   * Creates a disk-usage scanner with no cached filesystem state.
   *
   * <p>Instances are stateless and can be reused by an AppHost implementation for multiple apps or
   * status requests. Each call to {@link #scan(InstalledAppPaths, Long)} performs a fresh
   * filesystem walk against the supplied app paths.
   */
  public AppDiskUsageScanner() {
    // Stateless scanner; each call receives all paths and process-log metadata it needs.
  }

  /**
   * Scans data and cache usage for one installed app.
   *
   * <p>Missing data or cache directories are treated as empty because an app may not have created
   * mutable state yet. A non-directory root, symlink root, unreadable subtree, failed file visit,
   * or size overflow produces a warning and returns the bytes that could be counted. Callers
   * enforcing a positive quota should treat scan-incomplete warnings for that quota area as an
   * enforcement failure; callers that only display status can still show the partial byte count.
   *
   * @param paths AppHost-managed filesystem paths for the installed app being measured
   * @param processLogSizeBytes current bounded process-log size, or {@code null} when unavailable
   * @return usage counts and display-safe measurement warnings from the current scan
   */
  public ScanResult scan(InstalledAppPaths paths, Long processLogSizeBytes) {
    Objects.requireNonNull(paths, "paths");
    DirectoryUsage dataUsage = scanDirectory(paths.dataDir(), "data");
    DirectoryUsage cacheUsage = scanDirectory(paths.cacheDir(), "cache");
    List<AppQuotaWarning> warnings = new ArrayList<>();
    warnings.addAll(dataUsage.warnings());
    warnings.addAll(cacheUsage.warnings());
    return new ScanResult(
        new AppQuotaUsage(dataUsage.bytes(), cacheUsage.bytes(), processLogSizeBytes), warnings);
  }

  private static DirectoryUsage scanDirectory(Path root, String area) {
    Objects.requireNonNull(root, "root");
    DirectoryAccumulator accumulator = new DirectoryAccumulator(area);
    try {
      if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
        return accumulator.toUsage();
      }
      if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
        accumulator.addWarning(AppQuotaWarning.scanIncomplete(area));
        return accumulator.toUsage();
      }
      Files.walkFileTree(root, accumulator);
    } catch (IOException | RuntimeException _) {
      accumulator.addWarning(AppQuotaWarning.scanIncomplete(area));
    }
    return accumulator.toUsage();
  }

  private record DirectoryUsage(long bytes, List<AppQuotaWarning> warnings) {
    private DirectoryUsage {
      if (bytes < 0L) {
        throw new IllegalArgumentException("bytes must be non-negative");
      }
      warnings = List.copyOf(warnings);
    }
  }

  /**
   * Result of one data/cache usage scan.
   *
   * <p>The result keeps byte counts separate from warnings so callers can continue to report the
   * best available usage even when part of a directory could not be inspected. Warning objects
   * carry stable codes and user-safe messages, but they do not include app-owned paths, host paths,
   * or process launch details.
   *
   * @param usage measured data, cache, and process-log sizes from the same scan pass
   * @param warnings display-safe measurement warnings produced while scanning data or cache trees
   */
  public record ScanResult(AppQuotaUsage usage, List<AppQuotaWarning> warnings) {
    /**
     * Creates a validated scan result.
     *
     * <p>The warning list is defensively copied so status snapshots cannot be changed after
     * construction. The contained {@link AppQuotaWarning} values are already safe for public API
     * serialization.
     *
     * @param usage measured data, cache, and process-log sizes from the same scan pass
     * @param warnings display-safe measurement warnings produced while scanning data or cache trees
     */
    public ScanResult {
      Objects.requireNonNull(usage, "usage");
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    }
  }

  private static final class DirectoryAccumulator extends SimpleFileVisitor<Path> {
    private final String area;
    private final List<AppQuotaWarning> warnings = new ArrayList<>();
    private long bytes;
    private boolean symlinkWarningAdded;
    private boolean scanWarningAdded;

    private DirectoryAccumulator(String area) {
      this.area = area;
    }

    @Override
    public @NotNull FileVisitResult visitFile(@NotNull Path file, BasicFileAttributes attributes) {
      if (attributes.isSymbolicLink() || Files.isSymbolicLink(file)) {
        addSymlinkWarning();
        return FileVisitResult.CONTINUE;
      }
      if (attributes.isRegularFile()) {
        addBytes(attributes.size());
      }
      return FileVisitResult.CONTINUE;
    }

    @Override
    public @NotNull FileVisitResult visitFileFailed(
        @NotNull Path file, @NotNull IOException exception) {
      addWarning(AppQuotaWarning.scanIncomplete(area));
      return FileVisitResult.CONTINUE;
    }

    private void addBytes(long size) {
      if (size < 0L) {
        addWarning(AppQuotaWarning.scanIncomplete(area));
        return;
      }
      long updated = bytes + size;
      if (updated < bytes) {
        bytes = Long.MAX_VALUE;
        addWarning(AppQuotaWarning.scanIncomplete(area));
      } else {
        bytes = updated;
      }
    }

    private void addSymlinkWarning() {
      if (!symlinkWarningAdded) {
        warnings.add(AppQuotaWarning.symlinkSkipped(area));
        symlinkWarningAdded = true;
      }
    }

    private void addWarning(AppQuotaWarning warning) {
      if (warning.code().endsWith("_scan_incomplete")) {
        if (scanWarningAdded) {
          return;
        }
        scanWarningAdded = true;
      }
      warnings.add(warning);
    }

    private DirectoryUsage toUsage() {
      return new DirectoryUsage(bytes, warnings);
    }
  }
}
