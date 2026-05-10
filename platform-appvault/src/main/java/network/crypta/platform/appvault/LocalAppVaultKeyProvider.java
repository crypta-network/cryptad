package network.crypta.platform.appvault;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

/**
 * File-backed local vault key provider with best-effort owner-only permissions.
 *
 * <p>This provider is the v1 default for nodes that do not have a stronger master-password or
 * hardware-backed key source wired into the app vault. It creates one 256-bit random AES key,
 * stores it as Base64 in the local vault directory, and reuses it for envelopes under that vault
 * root.
 *
 * <p>The protection level is local at-rest protection. The provider refuses symlink key files,
 * validates existing key length and Base64 encoding, and applies owner-only POSIX permissions when
 * the filesystem supports them. It does not claim to protect against a local user who can read the
 * key file or against compromise of the running process.
 */
public final class LocalAppVaultKeyProvider implements AppVaultKeyProvider {
  /**
   * Stable key id used by the v1 local vault key.
   *
   * <p>The id is serialized into every envelope and must remain stable while this provider can
   * decrypt existing vault material.
   */
  public static final String KEY_ID = "local-vault-key-v1";

  private static final int AES_256_BYTES = 32;
  private static final Set<PosixFilePermission> OWNER_READ_WRITE =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
  private static final Set<PosixFilePermission> OWNER_DIRECTORY =
      Set.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);

  private final Path keyFile;
  private final SecureRandom secureRandom;

  /**
   * Creates a provider backed by the supplied key file.
   *
   * <p>The key file path is normalized immediately. The file is not read or created until {@link
   * #currentKey()} is called, which lets runtime composition construct an optional provider without
   * touching storage first.
   *
   * @param keyFile local key file path under the vault root
   * @param secureRandom secure random source for first-time key creation
   */
  public LocalAppVaultKeyProvider(Path keyFile, SecureRandom secureRandom) {
    this.keyFile = keyFile.toAbsolutePath().normalize();
    this.secureRandom = java.util.Objects.requireNonNull(secureRandom, "secureRandom");
  }

  /**
   * Returns the current local vault key, creating it when absent.
   *
   * <p>Existing non-symlink key files are permission-hardened before use. Malformed key files are
   * reported as {@link IOException} so optional vault initialization can disable vault routes
   * without aborting the rest of HTTP startup.
   *
   * @return current local vault key with raw bytes redacted from diagnostics
   * @throws IOException if the key file is unsafe, malformed, unreadable, or cannot be created
   */
  @Override
  public synchronized VaultKey currentKey() throws IOException {
    if (Files.exists(keyFile, LinkOption.NOFOLLOW_LINKS)) {
      return new VaultKey(KEY_ID, readExistingKey());
    }
    return new VaultKey(KEY_ID, createKey());
  }

  private byte[] readExistingKey() throws IOException {
    if (Files.isSymbolicLink(keyFile)) {
      throw new IOException("local vault key must not be a symbolic link");
    }
    if (!Files.isRegularFile(keyFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("local vault key must be a regular file");
    }
    hardenDirectoryIfSupported(keyFile.getParent());
    hardenSensitiveFileIfSupported(keyFile);
    byte[] key;
    try {
      key = Base64.getDecoder().decode(Files.readString(keyFile).trim());
    } catch (IllegalArgumentException exception) {
      throw new IOException("local vault key is not valid Base64", exception);
    }
    if (key.length != AES_256_BYTES) {
      throw new IOException("local vault key has unexpected length");
    }
    return key;
  }

  private byte[] createKey() throws IOException {
    byte[] key = new byte[AES_256_BYTES];
    secureRandom.nextBytes(key);
    Files.createDirectories(keyFile.getParent());
    hardenDirectoryIfSupported(keyFile.getParent());
    Path temp = Files.createTempFile(keyFile.getParent(), keyFile.getFileName().toString(), ".tmp");
    Files.writeString(
        temp,
        Base64.getEncoder().encodeToString(key) + "\n",
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE);
    hardenSensitiveFileIfSupported(temp);
    try {
      Files.move(temp, keyFile, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(temp, keyFile);
    }
    hardenSensitiveFileIfSupported(keyFile);
    return key;
  }

  private static void hardenSensitiveFileIfSupported(Path file) throws IOException {
    PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class);
    if (view != null) {
      view.setPermissions(OWNER_READ_WRITE);
    }
  }

  private static void hardenDirectoryIfSupported(Path directory) throws IOException {
    PosixFileAttributeView view =
        Files.getFileAttributeView(directory, PosixFileAttributeView.class);
    if (view != null) {
      view.setPermissions(OWNER_DIRECTORY);
    }
  }
}
