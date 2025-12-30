package network.crypta.node;

import java.io.File;
import java.util.Arrays;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles download/upload allowlists and file permission checks for {@link NodeClientCore}.
 *
 * <p>This helper owns mutable allowlist state and encapsulates the configuration callbacks that
 * update it. It keeps policy logic cohesive and reduces the core's direct dependencies.
 */
final class NodeClientCoreTransferPolicy {
  private static final Logger LOG = LoggerFactory.getLogger(NodeClientCoreTransferPolicy.class);
  private static final String DOWNLOADS_DIR_NAME = "downloads";

  private final Node node;
  private final File downloadsDir;

  private File[] downloadAllowedDirs = new File[0];
  private boolean includeDownloadDir;
  private boolean downloadAllowedEverywhere;
  private boolean downloadDisabled;
  private File[] uploadAllowedDirs = new File[0];
  private boolean uploadAllowedEverywhere;

  NodeClientCoreTransferPolicy(Node node, File downloadsDir) {
    this.node = node;
    this.downloadsDir = downloadsDir;
  }

  boolean isDownloadDisabled() {
    return downloadDisabled;
  }

  int registerDownloadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "downloadAllowedDirs",
            new String[] {"all"},
            sortOrder,
            true,
            true,
            "NodeClientCore.downloadAllowedDirs",
            "NodeClientCore.downloadAllowedDirsLong",
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

  int registerUploadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "uploadAllowedDirs",
            new String[] {"all"},
            sortOrder,
            true,
            true,
            "NodeClientCore.uploadAllowedDirs",
            "NodeClientCore.uploadAllowedDirsLong",
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
   * stored as a {@link File}. Passing an empty array disables downloads entirely.
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
   * Returns whether a file path is permitted as a download target.
   *
   * <p>This check enforces the current physical threat level and the configured download allowlist,
   * including the downloads directory when enabled. If downloads are disabled by configuration, no
   * target is accepted. The check uses parent-path matching and does not create directories or
   * touch the filesystem beyond path comparisons.
   *
   * @param filename target file path to validate against download allowlist.
   * @return {@code true} if the path is allowed under current policy.
   */
  boolean allowDownloadTo(File filename) {
    PHYSICAL_THREAT_LEVEL physicalThreatLevel = node.getSecurityLevels().getPhysicalThreatLevel();
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
   * Returns whether a file path is permitted as an upload source.
   *
   * <p>This check uses the configured upload allowlist and does not verify file existence. The
   * result is a snapshot of current configuration and is used to gate upload requests before any
   * I/O occurs. Paths are matched by parent-directory containment.
   *
   * @param filename source file path to validate against upload allowlist.
   * @return {@code true} if the path is allowed as an upload source.
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
   * direct reference to internal state, so callers should not modify the array or its elements.
   *
   * @return current allowlist array; entries are internal references, not copies.
   */
  synchronized File[] getAllowedDownloadDirs() {
    return downloadAllowedDirs;
  }

  /**
   * Returns the current allowlist for upload sources.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to internal state, so callers should not modify the array or its elements.
   *
   * @return current allowlist array; entries are internal references, not copies.
   */
  synchronized File[] getAllowedUploadDirs() {
    return uploadAllowedDirs;
  }
}
