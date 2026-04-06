package network.crypta.platform.apphost;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Stable filesystem layout for host-owned app state.
 *
 * <p>{@code AppHostLayout} is the single source of truth for where an AppHost implementation keeps
 * immutable bundles and mutable per-app state on disk. Callers provide the three top-level base
 * directories, and the layout derives the installation, data, cache, and runtime trees from those
 * roots deterministically. This keeps shell layers, tests, and future API adapters aligned on the
 * same placement rules.
 *
 * <p>The design deliberately separates long-lived bundle contents from mutable data and
 * session-scoped run files. That split makes it easier to validate installed bundles, clean up the
 * runtime state, and apply tighter ownership checks to the directories that the host controls on
 * behalf of each application.
 *
 * @param dataDir base directory for installed bundles and persistent app data
 * @param cacheDir base directory for app cache data
 * @param runDir base directory for session-scoped app run data
 */
public record AppHostLayout(Path dataDir, Path cacheDir, Path runDir) {
  /**
   * Creates a validated host layout.
   *
   * @param dataDir base directory for installed bundles and persistent app data
   * @param cacheDir base directory for app cache data
   * @param runDir base directory for session-scoped app run data
   */
  public AppHostLayout {
    dataDir = normalizeBaseDir(dataDir, "dataDir");
    cacheDir = normalizeBaseDir(cacheDir, "cacheDir");
    runDir = normalizeBaseDir(runDir, "runDir");
  }

  /**
   * Returns the root directory that holds installed bundles.
   *
   * <p>This tree holds the immutable copied bundle for each installed application. Callers should
   * treat entries beneath it as host-managed installation state rather than writable application
   * data.
   *
   * @return install root under {@code dataDir}
   */
  public Path installedAppsDir() {
    return dataDir.resolve("apps").resolve("installed");
  }

  /**
   * Returns the root directory that holds persistent app data.
   *
   * <p>This tree is the long-lived writable area that survives restarts and reinstalls unless the
   * app is explicitly uninstalled.
   *
   * @return data root under {@code dataDir}
   */
  public Path appDataRoot() {
    return dataDir.resolve("apps").resolve("data");
  }

  /**
   * Returns the root directory that holds app cache data.
   *
   * <p>Cache contents are mutable and host-managed, but unlike the data tree, they are intended for
   * disposable or rebuildable state.
   *
   * @return cache root under {@code cacheDir}
   */
  public Path appCacheRoot() {
    return cacheDir.resolve("apps");
  }

  /**
   * Returns the root directory that holds per-session app run data.
   *
   * <p>This tree is intended for transient launch artifacts such as process logs, sockets, or
   * pid-adjacent runtime files that should not survive indefinitely.
   *
   * @return run root under {@code runDir}
   */
  public Path appRunRoot() {
    return runDir.resolve("apps");
  }

  /**
   * Returns the derived filesystem paths for one app id.
   *
   * <p>The returned value normalizes the identifier and derives the immutable and mutable paths
   * that the host uses for one application. Callers can use the result as the canonical mapping
   * between manifest identity and on-disk placement.
   *
   * @param appId stable application identifier
   * @return path bundle for the supplied app
   */
  public InstalledAppPaths pathsFor(String appId) {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    return new InstalledAppPaths(
        normalizedAppId,
        installedAppsDir().resolve(normalizedAppId),
        appDataRoot().resolve(normalizedAppId),
        appCacheRoot().resolve(normalizedAppId),
        appRunRoot().resolve(normalizedAppId));
  }

  private static Path normalizeBaseDir(Path path, String label) {
    Objects.requireNonNull(path, label);
    return path.toAbsolutePath().normalize();
  }
}
