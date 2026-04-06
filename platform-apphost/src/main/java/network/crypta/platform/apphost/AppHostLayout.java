package network.crypta.platform.apphost;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Stable filesystem layout for host-owned app state.
 *
 * <p>The layout uses caller-supplied base directories and derives all host-managed paths from them.
 * The host keeps the installed bundle, persistent app data, cache, and per-session run data in
 * separate trees so future shell and API layers can reuse the same placement rules.
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
   * @return install root under {@code dataDir}
   */
  public Path installedAppsDir() {
    return dataDir.resolve("apps").resolve("installed");
  }

  /**
   * Returns the root directory that holds persistent app data.
   *
   * @return data root under {@code dataDir}
   */
  public Path appDataRoot() {
    return dataDir.resolve("apps").resolve("data");
  }

  /**
   * Returns the root directory that holds app cache data.
   *
   * @return cache root under {@code cacheDir}
   */
  public Path appCacheRoot() {
    return cacheDir.resolve("apps");
  }

  /**
   * Returns the root directory that holds per-session app run data.
   *
   * @return run root under {@code runDir}
   */
  public Path appRunRoot() {
    return runDir.resolve("apps");
  }

  /**
   * Returns the derived filesystem paths for one app id.
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
