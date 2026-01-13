package network.crypta.node;

import java.io.File;
import java.util.Arrays;
import network.crypta.config.Option;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks configured transfer allowlists for {@link NodeClientCore} and evaluates file path
 * permissions.
 *
 * <p>This helper owns the mutable download and upload allowlists derived from node configuration.
 * It registers configuration callbacks, normalizes special tokens such as {@code "all"} and {@code
 * "downloads"}, and answers permission checks against candidate paths. Typical usage is to
 * construct the policy during client-core initialization, call the registration methods to wire it
 * into {@link NodeClientCoreInit}, and then consult {@link #allowDownloadTo(File)} or {@link
 * #allowUploadFrom(File)} before initiating file I/O.
 *
 * <p>The policy is stateful and thread-safe for its own fields: mutations and reads of allowlist
 * arrays are synchronized on {@code this}. Permission checks never create directories or touch the
 * filesystem beyond parent-path comparisons, but download checks also honor the current physical
 * threat level from {@link SecurityLevels}. Changes take effect immediately for subsequent calls.
 *
 * <ul>
 *   <li>Maintains normalized download and upload allowlists.
 *   <li>Registers configuration callbacks to update policy state.
 *   <li>Answers permission checks for transfer source and destination paths.
 * </ul>
 *
 * @see NodeClientCore
 * @see NodeClientCoreInit
 * @see SecurityLevels
 */
final class NodeClientCoreTransferPolicy {
  /** Logger used for unexpected allowlist state; avoids throwing on anomalies. */
  private static final Logger LOG = LoggerFactory.getLogger(NodeClientCoreTransferPolicy.class);

  /** Token used in configuration to include the configured downloads directory. */
  private static final String DOWNLOADS_DIR_NAME = "downloads";

  /** Node providing security levels that gate download permissions. */
  private final Node node;

  /** Downloads directory used when the {@code "downloads"} token is present. */
  private final File downloadsDir;

  /** Normalized list of explicit directories allowed as download destinations. */
  private File[] downloadAllowedDirs = new File[0];

  /** Whether the {@code "downloads"} token is currently enabled. */
  private boolean includeDownloadDir;

  /** Whether downloads are allowed to any destination regardless of path. */
  private boolean downloadAllowedEverywhere;

  /** Whether configuration supplied no download entries and thus disabled downloads. */
  private boolean downloadDisabled;

  /** Normalized list of explicit directories allowed as upload sources. */
  private File[] uploadAllowedDirs = new File[0];

  /** Whether uploads are allowed from any source regardless of path. */
  private boolean uploadAllowedEverywhere;

  /**
   * Creates a transfer policy bound to a node and downloads directory.
   *
   * <p>The instance starts with empty allowlists and no implied permissions until either the
   * registration helpers or the setter methods are invoked. The provided downloads directory is
   * used only for parent-path checks; it is not created or validated here. Callers typically
   * construct this policy once during client-core initialization and reuse it for subsequent
   * permission checks.
   *
   * @param node owning node used to read security levels; must be non-null.
   * @param downloadsDir downloads directory used for {@code "downloads"} resolution.
   */
  NodeClientCoreTransferPolicy(Node node, File downloadsDir) {
    this.node = node;
    this.downloadsDir = downloadsDir;
  }

  /**
   * Reports whether downloads are disabled by the last configuration update.
   *
   * <p>The flag is set when {@link #setDownloadAllowedDirs(String[])} is called with an empty
   * array. It reflects configuration intent and does not consult the filesystem. Other checks, such
   * as {@link #allowDownloadTo(File)}, still apply their own logic independently.
   *
   * @return {@code true} when the most recent download allowlist was empty.
   */
  boolean isDownloadDisabled() {
    return downloadDisabled;
  }

  /**
   * Registers the download allowlist option and binds its update callback.
   *
   * <p>This method wires a {@code String[]} option into the node configuration so that changes
   * immediately update this policy. After registration, it applies the current stored value, so
   * subsequent permission checks reflect persisted settings. Callers typically chain the returned
   * sort order when registering additional options. Re-registering the same option would attempt to
   * add a duplicate and is not supported.
   *
   * @param init initialization bundle providing the node configuration to register.
   * @param sortOrder sort order used for UI display; incremented for return.
   * @return next sort order value to chain for further registrations.
   * @throws NullPointerException if {@code init} or its nodeConfig is null.
   */
  int registerDownloadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "downloadAllowedDirs",
            new String[] {"all"},
            new Option.Meta(
                sortOrder,
                true,
                true,
                "NodeClientCore.downloadAllowedDirs",
                "NodeClientCore.downloadAllowedDirsLong"),
            new StringArrCallback() {

              @Override
              public String[] get() {
                synchronized (NodeClientCoreTransferPolicy.this) {
                  if (downloadAllowedEverywhere) return new String[] {"all"};
                  String[] dirs =
                      new String[downloadAllowedDirs.length + (includeDownloadDir ? 1 : 0)];
                  for (int i = 0; i < downloadAllowedDirs.length; i++)
                    dirs[i] = downloadAllowedDirs[i].getPath();
                  if (includeDownloadDir) dirs[downloadAllowedDirs.length] = DOWNLOADS_DIR_NAME;
                  return dirs;
                }
              }

              @Override
              public void set(String[] val) {
                setDownloadAllowedDirs(val);
              }
            });
    setDownloadAllowedDirs(init.nodeConfig().getStringArr("downloadAllowedDirs"));
    return sortOrder + 1;
  }

  /**
   * Registers the upload allowlist option and binds its update callback.
   *
   * <p>This method wires a {@code String[]} option into the node configuration so that changes
   * immediately update this policy. After registration, it applies the current stored value, so
   * subsequent permission checks reflect persisted settings. Callers typically chain the returned
   * sort order when registering additional options. Re-registering the same option would attempt to
   * add a duplicate and is not supported.
   *
   * @param init initialization bundle providing the node configuration to register.
   * @param sortOrder sort order used for UI display; incremented for return.
   * @return next sort order value to chain for further registrations.
   * @throws NullPointerException if {@code init} or its nodeConfig is null.
   */
  int registerUploadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "uploadAllowedDirs",
            new String[] {"all"},
            new Option.Meta(
                sortOrder,
                true,
                true,
                "NodeClientCore.uploadAllowedDirs",
                "NodeClientCore.uploadAllowedDirsLong"),
            new StringArrCallback() {

              @Override
              public String[] get() {
                synchronized (NodeClientCoreTransferPolicy.this) {
                  if (uploadAllowedEverywhere) return new String[] {"all"};
                  String[] dirs = new String[uploadAllowedDirs.length];
                  for (int i = 0; i < uploadAllowedDirs.length; i++)
                    dirs[i] = uploadAllowedDirs[i].getPath();
                  return dirs;
                }
              }

              @Override
              public void set(String[] val) {
                setUploadAllowedDirs(val);
              }
            });
    setUploadAllowedDirs(init.nodeConfig().getStringArr("uploadAllowedDirs"));
    return sortOrder + 1;
  }

  /**
   * Configures directories where downloads may be written.
   *
   * <p>Recognized entries include {@code "all"} to allow any destination and {@code "downloads"} to
   * allow the configured downloads directory. Any other string is treated as a filesystem path and
   * stored as a {@link File}. Passing an empty array disables downloads entirely. The update is
   * applied immediately and affects subsequent permission checks.
   *
   * @param val array of directory entries; may include {@code "all"} or {@code "downloads"} tokens.
   * @throws NullPointerException if {@code val} contains a null entry.
   */
  synchronized void setDownloadAllowedDirs(String[] val) {
    int x = 0;
    downloadAllowedEverywhere = false;
    includeDownloadDir = false;
    downloadDisabled = false;
    int i;
    downloadAllowedDirs = new File[val.length];
    for (i = 0; i < downloadAllowedDirs.length; i++) {
      String s = val[i];
      if (s.equals(DOWNLOADS_DIR_NAME)) includeDownloadDir = true;
      else if (s.equals("all")) downloadAllowedEverywhere = true;
      else downloadAllowedDirs[x++] = new File(val[i]);
    }
    if (x != i) {
      downloadAllowedDirs = Arrays.copyOf(downloadAllowedDirs, x);
    }
    if (i == 0) {
      downloadDisabled = true;
    }
  }

  /**
   * Configures directories from which uploads may read.
   *
   * <p>Recognized entries include {@code "all"} to allow any source. Any other string is treated as
   * a filesystem path and stored as a {@link File}. The configuration is applied immediately and
   * affects subsequent permission checks for upload sources.
   *
   * @param val array of directory entries; may include {@code "all"} token.
   * @throws NullPointerException if {@code val} contains a null entry.
   */
  synchronized void setUploadAllowedDirs(String[] val) {
    int x = 0;
    int i;
    uploadAllowedEverywhere = false;
    uploadAllowedDirs = new File[val.length];
    for (i = 0; i < uploadAllowedDirs.length; i++) {
      String s = val[i];
      if (s.equals("all")) uploadAllowedEverywhere = true;
      else uploadAllowedDirs[x++] = new File(val[i]);
    }
    if (x != i) {
      uploadAllowedDirs = Arrays.copyOf(uploadAllowedDirs, x);
    }
  }

  /**
   * Determines whether a target file path is permitted for downloads.
   *
   * <p>The check first consults the node's physical threat level and denies all downloads at {@link
   * PHYSICAL_THREAT_LEVEL#MAXIMUM}. It then compares the candidate path against the current
   * allowlist, including the configured downloads directory when enabled. Matches are evaluated by
   * parent-directory containment and do not create files or directories. Supplying an empty
   * allowlist disables downloads by making every path fail this check.
   *
   * @param filename candidate path to evaluate; must be non-null.
   * @return {@code true} when the path is within an allowed parent directory.
   */
  boolean allowDownloadTo(File filename) {
    PHYSICAL_THREAT_LEVEL physicalThreatLevel =
        node.services().securityLevels().getPhysicalThreatLevel();
    if (physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) return false;
    synchronized (this) {
      if (downloadAllowedEverywhere) return true;
      if (includeDownloadDir && FileUtil.isParent(downloadsDir, filename)) return true;
      for (File dir : downloadAllowedDirs) {
        if (dir == null) {
          // Debug mysterious NPE...
          LOG.error("Null in upload allowed dirs???");
          continue;
        }
        if (FileUtil.isParent(dir, filename)) return true;
      }
      return false;
    }
  }

  /**
   * Determines whether a source file path is permitted for uploads.
   *
   * <p>The check compares the candidate path against the current upload allowlist and does not
   * verify file existence. The result is a snapshot of configuration at call time and is used to
   * gate upload requests before any I/O occurs. Paths are matched by parent-directory containment;
   * when {@code "all"} is configured, any path is accepted.
   *
   * @param filename candidate source path to evaluate; must be non-null.
   * @return {@code true} when the path is within an allowed parent directory.
   */
  synchronized boolean allowUploadFrom(File filename) {
    if (uploadAllowedEverywhere) return true;
    for (File dir : uploadAllowedDirs) {
      if (dir == null) {
        // Debug mysterious NPE...
        LOG.error("Null in upload allowed dirs???");
        continue;
      }
      if (FileUtil.isParent(dir, filename)) return true;
    }
    return false;
  }

  /**
   * Returns the current allowlist for download destinations.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to internal state, so callers should not modify the array or its elements. The
   * contents may be empty when no explicit directories are configured. Callers should treat the
   * array and its entries as read-only snapshots.
   *
   * @return current allowlist array reference; entries are not defensive copies.
   */
  synchronized File[] getAllowedDownloadDirs() {
    return downloadAllowedDirs;
  }

  /**
   * Returns the current allowlist for upload sources.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to internal state, so callers should not modify the array or its elements. The
   * contents may be empty when no explicit directories are configured. Callers should treat the
   * array and its entries as read-only snapshots.
   *
   * @return current allowlist array reference; entries are not defensive copies.
   */
  synchronized File[] getAllowedUploadDirs() {
    return uploadAllowedDirs;
  }
}
