package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;

/**
 * Derived filesystem paths for one installed application.
 *
 * @param appId stable application identifier
 * @param installedRoot immutable bundle copy root
 * @param dataDir persistent mutable data directory
 * @param cacheDir mutable cache directory
 * @param runDir current-session runtime directory
 */
public record InstalledAppPaths(
    String appId, Path installedRoot, Path dataDir, Path cacheDir, Path runDir) {
  private static final Pattern APP_ID_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final String PROCESS_LOG_FILE = "process.log";

  /**
   * Creates a normalized path bundle.
   *
   * @param appId stable application identifier
   * @param installedRoot immutable bundle copy root
   * @param dataDir persistent mutable data directory
   * @param cacheDir mutable cache directory
   * @param runDir current-session runtime directory
   */
  public InstalledAppPaths {
    appId = normalizeAppId(appId);
    installedRoot = normalizePath(installedRoot, "installedRoot");
    dataDir = normalizePath(dataDir, "dataDir");
    cacheDir = normalizePath(cacheDir, "cacheDir");
    runDir = normalizePath(runDir, "runDir");
  }

  /**
   * Returns the installed manifest file path.
   *
   * @return installed manifest path
   */
  public Path manifestFile() {
    return installedRoot.resolve(AppManifestParser.MANIFEST_FILE_NAME);
  }

  /**
   * Returns the combined child-process log path.
   *
   * @return runtime log file path
   */
  public Path processLogFile() {
    return runDir.resolve(PROCESS_LOG_FILE);
  }

  /**
   * Resolves a relative bundle path beneath the installed root.
   *
   * @param relativePath relative path inside the installed bundle
   * @return absolute installed-bundle path
   */
  public Path resolveInstalledPath(Path relativePath) {
    Objects.requireNonNull(relativePath, "relativePath");
    Path resolved = installedRoot.resolve(relativePath).normalize();
    if (!resolved.startsWith(installedRoot)) {
      throw new IllegalArgumentException(
          "resolved path must stay under installedRoot: " + relativePath);
    }
    return resolved;
  }

  /**
   * Resolves the manifest-declared executable beneath the installed root.
   *
   * @param manifest application manifest
   * @return absolute executable path inside the installed bundle
   */
  public Path executablePath(AppManifest manifest) {
    Objects.requireNonNull(manifest, "manifest");
    return resolveInstalledPath(manifest.execPath());
  }

  /**
   * Creates the persistent and runtime directories managed by the host.
   *
   * @throws IOException if any directory cannot be created
   */
  public void ensureMutableDirectories() throws IOException {
    ensureMutableDirectory(dataDir, "dataDir");
    ensureMutableDirectory(cacheDir, "cacheDir");
    ensureMutableDirectory(runDir, "runDir");
  }

  /**
   * Creates the installation parent directory.
   *
   * @throws IOException if the installation parent cannot be created
   */
  public void ensureInstallParentDirectory() throws IOException {
    Files.createDirectories(installedRoot.getParent());
  }

  /**
   * Validates and normalizes an application identifier.
   *
   * @param appId application identifier
   * @return normalized application identifier
   */
  public static String normalizeAppId(String appId) {
    Objects.requireNonNull(appId, "appId");
    String normalized = appId.trim().toLowerCase(Locale.ROOT);
    if (!APP_ID_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException("invalid app id: " + appId);
    }
    return normalized;
  }

  private static Path normalizePath(Path path, String label) {
    Objects.requireNonNull(path, label);
    return path.toAbsolutePath().normalize();
  }

  private static void ensureMutableDirectory(Path directory, String label) throws IOException {
    Path normalized = normalizePath(directory, label);
    Deque<Path> missingSegments = new ArrayDeque<>();
    Path current = normalized;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      Path fileName = current.getFileName();
      if (fileName != null) {
        missingSegments.push(fileName);
      }
      current = current.getParent();
    }
    if (current != null) {
      validateDirectoryEntry(current, label);
      while (!missingSegments.isEmpty()) {
        current = current.resolve(missingSegments.pop());
        Files.createDirectory(current);
      }
    } else {
      Files.createDirectories(normalized);
    }
    validateDirectoryEntry(normalized, label);
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(label + " must be a directory: " + normalized);
    }
  }

  private static void validateDirectoryEntry(Path entry, String label) throws IOException {
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(entry) || isAliasedPathEntry(entry))) {
      throw new AppHostException(
          label + " must not be a symlink, reparse point, or alias: " + entry);
    }
  }

  private static boolean isAliasedPathEntry(Path entry) throws IOException {
    if (Files.isSymbolicLink(entry)) {
      return true;
    }
    Path parent = entry.getParent();
    if (parent == null) {
      return false;
    }
    Path expectedRealPath = parent.toRealPath().resolve(entry.getFileName()).normalize();
    Path actualRealPath = entry.toRealPath();
    return !actualRealPath.equals(expectedRealPath);
  }
}
