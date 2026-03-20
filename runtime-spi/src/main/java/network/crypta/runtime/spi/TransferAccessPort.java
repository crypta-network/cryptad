package network.crypta.runtime.spi;

import java.io.File;

/**
 * Exposes file-transfer policy checks and directories using only JDK file types.
 *
 * <p>This port gives infrastructure code a narrow way to consult the daemon's existing
 * disk-transfer policy without depending on {@code NodeClientCore} or other root-module classes.
 * Callers can ask whether a particular upload or download path is currently permitted and can read
 * the configured directories that shape those decisions. The SPI intentionally returns {@link File}
 * values rather than richer internal wrappers so the module stays below the daemon in the
 * dependency graph.
 *
 * <p>Implementations should preserve current policy semantics. The methods in this interface report
 * what the runtime presently allows; they do not create directories, normalize paths beyond
 * existing behavior, or change configuration on the caller's behalf.
 *
 * @see RuntimePorts
 */
public interface TransferAccessPort {
  /**
   * Checks whether the runtime currently permits an upload from the supplied file path.
   *
   * <p>The runtime evaluates {@code file} using its existing upload-policy rules, including any
   * configured allowlists or directory restrictions. This method performs policy consultation only;
   * it does not open the file or guarantee that later file system access will still succeed.
   * Callers should therefore treat a {@code true} result as permission under current policy, not as
   * a full liveness or existence check.
   *
   * @param file upload source path to validate against the current runtime policy
   * @return {@code true} when uploads from the supplied path are currently allowed
   */
  boolean allowUploadFrom(File file);

  /**
   * Checks whether the runtime currently permits a download to the supplied file path.
   *
   * <p>The runtime evaluates {@code file} using its current destination-policy rules. A positive
   * result means the configured policy accepts the path at the time of the call. It does not create
   * parent directories, reserve the destination, or guarantee that later writes will succeed if the
   * file system state changes.
   *
   * @param file download destination path to validate against the current runtime policy
   * @return {@code true} when downloads to the supplied path are currently allowed
   */
  boolean allowDownloadTo(File file);

  /**
   * Returns the runtime's configured "downloads" directory.
   *
   * <p>This is the path the daemon currently exposes as its downloads location. The returned {@link
   * File} reflects configuration state only; callers should still perform their own existence,
   * writability, or creation checks when they need stronger guarantees for a specific operation.
   *
   * @return configured "downloads" directory path as exposed by the runtime
   */
  File downloadsDir();

  /**
   * Returns the runtime's configured persistent temporary directory.
   *
   * <p>This directory is intended for temporary files that survive longer than a single immediate
   * operation, according to the daemon's existing behavior. The method reports configuration rather
   * than provisioning state, so callers should not assume the directory already exists or is ready
   * for use without additional checks.
   *
   * @return configured persistent temporary directory path as exposed by the runtime
   */
  @SuppressWarnings("unused")
  File persistentTempDir();

  /**
   * Returns the directories that the runtime currently allows as upload roots.
   *
   * <p>The returned array reflects the daemon's current upload policy using plain {@link File}
   * paths. Implementations may return an empty array when no explicit upload roots are configured.
   * Callers should treat the array as a snapshot of the current policy and avoid mutating it unless
   * the implementation explicitly documents such mutation as safe.
   *
   * @return current upload-allowed directory roots represented as {@link File} paths
   */
  @SuppressWarnings("unused")
  File[] allowedUploadDirs();

  /**
   * Computes the legacy default starting directory for upload-oriented file browsers.
   *
   * <p>The helper preserves the longstanding behavior used by the HTTP local-file browsers: when
   * uploads are effectively unrestricted (represented by a single {@code "all"} entry) or when no
   * explicit upload roots are configured, it falls back to the current JVM user's home directory.
   * Otherwise, it returns the first configured upload directory unchanged except for converting it
   * to an absolute-path string.
   *
   * @return legacy default upload browser directory
   */
  default String defaultUploadDir() {
    File[] allowedUploadDirs = allowedUploadDirs();
    if ((allowedUploadDirs.length == 1 && allowedUploadDirs[0].toString().equals("all"))
        || allowedUploadDirs.length == 0) {
      return System.getProperty("user.home");
    }
    return allowedUploadDirs[0].getAbsolutePath();
  }

  /**
   * Returns the directories that the runtime currently allows as download roots.
   *
   * <p>The returned array reflects the daemon's current download policy using plain {@link File}
   * paths. Implementations may return an empty array when no explicit download roots are
   * configured. As with other policy views in this SPI, the result describes current configuration
   * and should be treated as an advisory state rather than a permanent reservation.
   *
   * @return current download-allowed directory roots represented as {@link File} paths
   */
  @SuppressWarnings("unused")
  File[] allowedDownloadDirs();

  /**
   * Computes the legacy default starting directory for download-oriented file browsers.
   *
   * <p>The helper preserves the existing local-browser behavior: when downloads are effectively
   * unrestricted (represented by a single {@code "all"} entry) or when no explicit download roots
   * are configured, it prefers the configured "downloads" directory. Otherwise, it returns the
   * first configured download directory unchanged except for converting it to an absolute-path
   * string.
   *
   * @return legacy default download browser directory
   */
  default String defaultDownloadDir() {
    File[] allowedDownloadDirs = allowedDownloadDirs();
    if ((allowedDownloadDirs.length == 1 && allowedDownloadDirs[0].toString().equals("all"))
        || allowedDownloadDirs.length == 0) {
      return downloadsDir().getAbsolutePath();
    }
    return allowedDownloadDirs[0].getAbsolutePath();
  }
}
