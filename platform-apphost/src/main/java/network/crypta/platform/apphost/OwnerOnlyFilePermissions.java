package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/**
 * Best-effort owner-only permission hardening for AppHost-owned runtime state.
 *
 * <p>POSIX filesystems receive explicit owner-only modes. Platforms or filesystems without a POSIX
 * attribute view are treated as a supported fallback and do not fail solely because those
 * permissions are unavailable.
 *
 * <p>This helper is part of AppHost runtime hygiene, not an operating-system sandbox. It reduces
 * accidental exposure of app data directories, cache directories, run directories, tokens, and log
 * files on filesystems where Java can set POSIX permissions. It does not isolate processes, prevent
 * network access, or override platform account policy.
 *
 * <p>When possible, permissions are applied through a parent {@link SecureDirectoryStream} with
 * {@link LinkOption#NOFOLLOW_LINKS} so the checked entry and the modified entry are the same
 * directory entry. On providers without secure directory streams, the fallback still asks for a
 * no-follow POSIX view and refuses symbolic links before applying permissions.
 */
public final class OwnerOnlyFilePermissions {
  private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);
  private static final Set<PosixFilePermission> SENSITIVE_FILE_PERMISSIONS =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private enum PermissionAttemptResult {
    APPLIED,
    UNSUPPORTED,
    UNAVAILABLE
  }

  private OwnerOnlyFilePermissions() {}

  /**
   * Applies {@code rwx------} to a directory when POSIX permissions are supported.
   *
   * <p>The mode gives the owning user read, write, and execute access and removes group and other
   * access bits. AppHost uses this for mutable app-owned directories such as data, cache, and run
   * roots. A {@code false} return means the filesystem does not expose POSIX permissions through
   * Java; callers should continue with the platform fallback behavior already documented for the
   * runtime.
   *
   * @param directory directory path to harden without following symbolic links
   * @return {@code true} when POSIX permissions were applied, {@code false} on non-POSIX fallback
   * @throws IOException if POSIX permissions are supported but cannot be applied safely
   */
  public static boolean hardenDirectory(Path directory) throws IOException {
    return setPermissionsIfSupported(directory, DIRECTORY_PERMISSIONS);
  }

  /**
   * Applies {@code rw-------} to a sensitive file when POSIX permissions are supported.
   *
   * <p>The mode gives the owning user read/write access and removes all group and other access
   * bits. AppHost uses this for files that may contain runtime-sensitive content, including process
   * logs after creation. The method is intentionally best-effort across platforms, but it does fail
   * on POSIX providers when permissions cannot be applied to the requested non-link entry.
   *
   * @param file sensitive file path to harden without following symbolic links
   * @return {@code true} when POSIX permissions were applied, {@code false} on non-POSIX fallback
   * @throws IOException if POSIX permissions are supported but cannot be applied safely
   */
  public static boolean hardenSensitiveFile(Path file) throws IOException {
    return setPermissionsIfSupported(file, SENSITIVE_FILE_PERMISSIONS);
  }

  private static boolean setPermissionsIfSupported(Path path, Set<PosixFilePermission> permissions)
      throws IOException {
    PermissionAttemptResult secureResult =
        setPermissionsWithSecureParentIfAvailable(path, permissions);
    if (secureResult != PermissionAttemptResult.UNAVAILABLE) {
      return secureResult == PermissionAttemptResult.APPLIED;
    }
    return setPermissionsWithPathView(path, permissions);
  }

  private static PermissionAttemptResult setPermissionsWithSecureParentIfAvailable(
      Path path, Set<PosixFilePermission> permissions) throws IOException {
    Path normalized = path.toAbsolutePath().normalize();
    Path parent = normalized.getParent();
    Path fileName = normalized.getFileName();
    if (parent == null || fileName == null) {
      return PermissionAttemptResult.UNAVAILABLE;
    }
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(parent)) {
      if (!(stream instanceof SecureDirectoryStream<?>)) {
        return PermissionAttemptResult.UNAVAILABLE;
      }
      SecureDirectoryStream<Path> secureStream = (SecureDirectoryStream<Path>) stream;
      PosixFileAttributeView view =
          secureStream.getFileAttributeView(
              fileName, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
      if (view == null) {
        return PermissionAttemptResult.UNSUPPORTED;
      }
      view.setPermissions(permissions);
      return PermissionAttemptResult.APPLIED;
    }
  }

  private static boolean setPermissionsWithPathView(Path path, Set<PosixFilePermission> permissions)
      throws IOException {
    if (Files.isSymbolicLink(path)) {
      throw new IOException("refusing to harden symbolic link: " + path);
    }
    PosixFileAttributeView view =
        Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
    if (view == null) {
      return false;
    }
    view.setPermissions(permissions);
    return true;
  }
}
