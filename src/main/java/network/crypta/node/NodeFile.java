package network.crypta.node;

import java.io.File;

/**
 * Lists well-known files used by the node and the base directory where each resides.
 *
 * <p>This enum centralizes the mapping between logical files (for example, the seed node list) and
 * their location relative to a {@link ProgramDirectory} for a specific {@link Node} instance.
 * Helper methods resolve the absolute {@link File} or return the short filename.
 *
 * <p>Thread-safety: the enum is immutable and thread-safe. Resolution methods are pure and allocate
 * no resources.
 */
public enum NodeFile {
  /**
   * Seed server references list stored under the node directory.
   *
   * <p>File name: {@code seednodes.fref}. Used by opennet bootstrap and tools that need the
   * canonical seed reference set.
   */
  SEEDNODES(InstallDirectory.NODE, "seednodes.fref"),

  /**
   * Cached Windows installer binary under the runtime directory.
   *
   * <p>File name: {@code freenet-latest-installer-windows.exe}. Populated by the updater and
   * exposed by the HTTP UI for convenience.
   */
  INSTALLER_WINDOWS(InstallDirectory.RUN, "freenet-latest-installer-windows.exe"),

  /**
   * Cached cross-platform installer JAR under the runtime directory.
   *
   * <p>File name: {@code freenet-latest-installer-nonwindows.jar}. Populated by the updater and
   * exposed by the HTTP UI for convenience.
   */
  INSTALLER_NON_WINDOWS(InstallDirectory.RUN, "freenet-latest-installer-nonwindows.jar"),

  /**
   * IPv4 geo-IP mapping database under the runtime directory.
   *
   * <p>File name: {@code IpToCountry.dat}. Consumed by {@code IPConverter} to render country flags
   * and metadata for peer addresses.
   */
  IPV4_TO_COUNTRY(InstallDirectory.RUN, "IpToCountry.dat");

  private final InstallDirectory dir;
  private final String filename;

  /**
   * Resolves the absolute path for this logical file within the given node's directories.
   *
   * @param node node whose directory layout determines the base path; must not be {@code null}
   * @return absolute {@link File} under the mapped {@link ProgramDirectory}; the file may not exist
   *     yet
   */
  public File getFile(Node node) {
    return dir.getDir(node).file(filename);
  }

  /**
   * Returns the short file name without any directory components.
   *
   * @return base name such as {@code seednodes.fref}
   */
  public String getFilename() {
    return filename;
  }

  /**
   * Returns the base directory that contains this file for the given node.
   *
   * @param node node whose directory layout determines the base path; must not be {@code null}
   * @return {@link ProgramDirectory} where the file resides
   */
  public ProgramDirectory getProgramDirectory(Node node) {
    return dir.getDir(node);
  }

  NodeFile(InstallDirectory dir, String filename) {
    this.dir = dir;
    this.filename = filename;
  }

  private enum InstallDirectory {
    /* Maps to Node.nodeDir() (the persistent node directory). */
    NODE() {
      @Override
      ProgramDirectory getDir(Node node) {
        return node.nodeDir();
      }
    },
    /* Maps to Node.cfgDir() (configuration files). */
    CFG() {
      @Override
      ProgramDirectory getDir(Node node) {
        return node.cfgDir();
      }
    },
    /* Maps to Node.userDir() (user-specific data outside the node dir). */
    USER() {
      @Override
      ProgramDirectory getDir(Node node) {
        return node.userDir();
      }
    },
    /* Maps to Node.runDir() (ephemeral runtime files and caches). */
    RUN() {
      @Override
      ProgramDirectory getDir(Node node) {
        return node.runDir();
      }
    },

    /* Maps to Node.storeDir() (content store and indexes). */
    STORE() {
      @Override
      ProgramDirectory getDir(Node node) {
        return node.storeDir();
      }
    };

    abstract ProgramDirectory getDir(Node node);
  }
}
