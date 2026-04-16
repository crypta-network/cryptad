package network.crypta.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.FileBucket;

/**
 * Builds and releases the nested manifest trees used by package-local directory insert paths.
 *
 * <p>{@link ClientPutDir} still stores directory contents in the long-lived legacy shape used by
 * the FCP insert stack: a mutable {@code Map<String, Object>} whose values are either nested
 * directory maps or {@link ManifestElement} leaves. This helper keeps that structural logic out of
 * the request shell. Callers use it in two places only: once when the node scans a local filesystem
 * tree into manifest entries, and later when the request is done with the staged buckets and needs
 * to release them without reintroducing runtime-owned metadata helpers.
 *
 * <p>The utility is intentionally package-private and stateless. It does not cache filesystem
 * state, sort entries, or attempt to normalize away the legacy manifest representation. Its job is
 * narrower: preserve the current on-node directory upload behavior while isolating the tree-build
 * and tree-teardown mechanics behind one adapter-owned surface.
 *
 * <ul>
 *   <li>Builds the in-memory manifest tree for disk-backed directory inserts.
 *   <li>Preserves the legacy nested-map representation expected by surrounding FCP code.
 *   <li>Recursively frees {@link ManifestElement} buckets once the request no longer needs them.
 * </ul>
 */
final class ClientPutDirManifestSupport {

  /** Utility class; callers use the static helpers only. */
  private ClientPutDirManifestSupport() {}

  /**
   * Scans a local directory and returns the manifest tree used by {@link ClientPutDir}.
   *
   * <p>The scan is recursive and preserves the relative path structure by nesting child maps under
   * their directory names. Regular files become {@link ManifestElement} instances backed by {@link
   * FileBucket}. Hidden entries are included only when requested, unreadable or unsupported entries
   * either fail fast or are skipped according to {@code allowUnreadableFiles}, and missing or
   * non-directory roots fail deterministically through the underlying filesystem checks.
   *
   * @param dir root directory to enumerate into the legacy manifest-tree shape
   * @param allowUnreadableFiles whether unreadable or unsupported entries should be skipped instead
   *     of aborting the scan
   * @param includeHiddenFiles whether hidden files and directories should be kept in the manifest
   * @return mutable manifest tree keyed by child name and containing nested maps or manifest leaves
   * @throws FileNotFoundException if the scan encounters an unreadable or unsupported entry and the
   *     caller requested fail-fast behavior
   */
  static Map<String, Object> buildDiskManifest(
      File dir, boolean allowUnreadableFiles, boolean includeHiddenFiles)
      throws FileNotFoundException {
    return buildDiskManifest(dir, "", allowUnreadableFiles, includeHiddenFiles);
  }

  /**
   * Recursively frees the bucket data held by every {@link ManifestElement} in a manifest tree.
   *
   * <p>The method walks the same nested map structure returned by {@link #buildDiskManifest(File,
   * boolean, boolean)} and delegates to {@link ManifestElement#freeData()} at the leaves. It does
   * not clear the enclosing maps or null out references; callers remain responsible for dropping
   * the now-released manifest tree once they no longer need its structure.
   *
   * @param manifestElements manifest tree whose file-entry buckets should be released
   */
  static void freeManifest(Map<String, Object> manifestElements) {
    for (Object value : manifestElements.values()) {
      if (value instanceof Map) {
        freeManifest(ManifestTreeMaps.forceMap(value));
      } else {
        ((ManifestElement) value).freeData();
      }
    }
  }

  /**
   * Recursively scans one directory node while preserving the current relative-path prefix.
   *
   * @param dir directory whose immediate children should be converted into manifest entries
   * @param prefix relative path prefix to prepend to child file names in nested directories
   * @param allowUnreadableFiles whether unreadable or unsupported entries should be skipped
   * @param includeHiddenFiles whether hidden entries should remain visible to the scan
   * @return mutable manifest node for the supplied directory
   * @throws FileNotFoundException if fail-fast mode is enabled and an entry cannot be represented
   */
  private static Map<String, Object> buildDiskManifest(
      File dir, String prefix, boolean allowUnreadableFiles, boolean includeHiddenFiles)
      throws FileNotFoundException {
    Map<String, Object> map = new HashMap<>();
    File[] files = dir.listFiles();

    if (files == null) {
      throw new IllegalArgumentException("No such directory");
    }

    for (File file : files) {
      if (file.isHidden() && !includeHiddenFiles) {
        continue;
      }

      if (!file.exists() || !file.canRead()) {
        handleUnreadableFile(file, allowUnreadableFiles);
      } else if (file.isFile()) {
        addFileEntry(map, file, prefix);
      } else if (file.isDirectory()) {
        addDirectoryEntry(map, file, prefix, allowUnreadableFiles, includeHiddenFiles);
      } else {
        handleUnsupportedEntry(file, allowUnreadableFiles);
      }
    }

    return map;
  }

  /**
   * Throws when an unreadable entry should abort the scan.
   *
   * @param file unreadable or missing entry encountered during scanning
   * @param allowUnreadableFiles whether the caller requested skip-on-error behavior
   * @throws FileNotFoundException if unreadable entries are not allowed
   */
  private static void handleUnreadableFile(File file, boolean allowUnreadableFiles)
      throws FileNotFoundException {
    if (!allowUnreadableFiles) {
      throw new FileNotFoundException("The file does not exist or is unreadable : " + file);
    }
  }

  /**
   * Throws when a filesystem entry is neither a regular file nor a directory and cannot be kept.
   *
   * @param file unsupported filesystem entry encountered during scanning
   * @param allowUnreadableFiles whether the caller requested skip-on-error behavior
   * @throws FileNotFoundException if unsupported entries are not allowed
   */
  private static void handleUnsupportedEntry(File file, boolean allowUnreadableFiles)
      throws FileNotFoundException {
    if (!allowUnreadableFiles) {
      throw new FileNotFoundException("Not a file and not a directory : " + file);
    }
  }

  /**
   * Creates one disk-backed manifest leaf for a regular file.
   *
   * @param map manifest node receiving the new leaf entry
   * @param file regular file discovered during the scan
   * @param prefix relative path prefix used to preserve the nested directory structure
   */
  private static void addFileEntry(Map<String, Object> map, File file, String prefix) {
    FileBucket bucket = new FileBucket(file, true, false, false, false);
    map.put(
        file.getName(),
        new ManifestElement(
            file.getName(),
            prefix + file.getName(),
            bucket,
            DefaultMIMETypes.guessMIMEType(file.getName(), true),
            file.length()));
  }

  /**
   * Recursively creates one nested manifest node for a child directory.
   *
   * @param map manifest node receiving the child directory entry
   * @param directory child directory discovered during the scan
   * @param prefix relative path prefix used for descendants
   * @param allowUnreadableFiles whether unreadable or unsupported descendants should be skipped
   * @param includeHiddenFiles whether hidden descendants should remain visible to the scan
   * @throws FileNotFoundException if fail-fast mode is enabled and a descendant cannot be
   *     represented
   */
  private static void addDirectoryEntry(
      Map<String, Object> map,
      File directory,
      String prefix,
      boolean allowUnreadableFiles,
      boolean includeHiddenFiles)
      throws FileNotFoundException {
    map.put(
        directory.getName(),
        buildDiskManifest(
            directory,
            prefix + directory.getName() + "/",
            allowUnreadableFiles,
            includeHiddenFiles));
  }
}
