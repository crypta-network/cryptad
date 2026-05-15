package network.crypta.platform.devtools;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Set;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Generates local Ed25519 key material for developer signing workflows.
 *
 * <p>This class backs {@code crypta-app keys generate}. It creates key pairs using the same Ed25519
 * algorithm expected by bundle and catalog signatures, then writes encoded key files and optional
 * trusted-app-key property files that the existing signing and verification commands can consume.
 *
 * <p>The private key path receives stricter handling than public material. The generator checks for
 * duplicate output paths before writing anything, refuses symlink outputs, creates new private-key
 * files with owner-only permissions where the filesystem supports POSIX attributes, and fails if a
 * portable fallback cannot restrict access. It never formats or returns private key bytes for
 * terminal output.
 */
final class DeveloperKeyGenerator {
  /** POSIX permissions used for private key files: owner read/write only. */
  private static final Set<PosixFilePermission> OWNER_ONLY =
      Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private static final String PRIVATE_KEY_FILE_LABEL = "private key file";
  private static final String PUBLIC_KEY_FILE_LABEL = "public key file";
  private static final String TRUSTED_KEYS_FILE_LABEL = "trusted keys file";

  /** Prevents construction of this stateless key-generation helper. */
  private DeveloperKeyGenerator() {}

  /**
   * Generates one key pair and writes the requested output files.
   *
   * <p>All output paths are validated and checked for collisions before key material is generated.
   * Public keys and trust files are normal files; private keys are written through the owner-only
   * path. When {@code trustedKeysFile} is supplied, it is written in the trusted app-key format
   * consumed by bundle verification.
   *
   * @param keyId stable key id written into generated trust-store entries
   * @param privateKeyFile output path for encoded private key bytes
   * @param publicKeyFile output path for encoded public key bytes
   * @param trustedKeysFile optional trust-store properties file to write alongside the key pair
   * @param overwrite whether existing regular output files may be replaced
   * @return normalized paths for the files written by this invocation
   * @throws IOException if generation succeeds but an output file cannot be written safely
   */
  static GeneratedKeys generate(
      String keyId,
      Path privateKeyFile,
      Path publicKeyFile,
      Path trustedKeysFile,
      boolean overwrite)
      throws IOException {
    validateKeyId(keyId);
    Path privateOut = normalizeOutput(privateKeyFile, PRIVATE_KEY_FILE_LABEL);
    Path publicOut = normalizeOutput(publicKeyFile, PUBLIC_KEY_FILE_LABEL);
    Path trustedOut =
        trustedKeysFile == null ? null : normalizeOutput(trustedKeysFile, TRUSTED_KEYS_FILE_LABEL);
    requireDistinctOutputPaths(privateOut, publicOut, trustedOut);
    requireWritable(privateOut, overwrite);
    requireWritable(publicOut, overwrite);
    if (trustedOut != null) {
      requireWritable(trustedOut, overwrite);
    }
    KeyPair keyPair = generatePair();
    writePrivateKey(privateOut, keyPair.getPrivate().getEncoded(), overwrite);
    writeBytes(publicOut, keyPair.getPublic().getEncoded(), overwrite);
    if (trustedOut != null) {
      writeString(trustedOut, trustedAppKeys(keyId, keyPair.getPublic().getEncoded()), overwrite);
    }
    return new GeneratedKeys(privateOut, publicOut, trustedOut);
  }

  /**
   * Builds a warning when a key output appears to live in a repository or artifact directory.
   *
   * <p>The warning is advisory rather than fatal because tests and controlled local workflows may
   * intentionally write into temporary repository paths. The CLI prints this text separately from
   * generated key material.
   *
   * @param path requested output path for a key or trust-store file
   * @return warning text, or an empty string when no repository-like path is detected
   */
  static String repoPathWarning(Path path) {
    Path root = Path.of("").toAbsolutePath().normalize();
    Path normalized = path.toAbsolutePath().normalize();
    if (normalized.startsWith(root)) {
      return "Warning: key output is inside the repository: " + root.relativize(normalized);
    }
    String text = normalized.toString().replace('\\', '/');
    if (text.contains("/build/") || text.contains("/dist/")) {
      return "Warning: key output appears to be under a generated artifact directory.";
    }
    return "";
  }

  /**
   * Validates the single-line key id stored in trust files and signatures.
   *
   * @param keyId key id supplied by the developer
   * @throws AppDistributionException if the id is blank or contains a line break
   */
  private static void validateKeyId(String keyId) throws AppDistributionException {
    if (keyId == null || keyId.isBlank() || keyId.contains("\n") || keyId.contains("\r")) {
      throw new AppDistributionException("key id must be a non-blank single line");
    }
  }

  /**
   * Generates an Ed25519 key pair using the JCA provider available to the runtime.
   *
   * @return generated key pair using the app bundle signature algorithm
   * @throws AppDistributionException if the configured signature algorithm is unavailable
   */
  private static KeyPair generatePair() throws AppDistributionException {
    try {
      return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    } catch (GeneralSecurityException exception) {
      throw new AppDistributionException("failed to generate Ed25519 key pair", exception);
    }
  }

  /**
   * Normalizes and validates one output file path.
   *
   * @param path user-supplied output path
   * @param label human-readable label used in CLI diagnostics
   * @return absolute normalized output path
   * @throws AppDistributionException if the path is missing or does not name a file
   */
  private static Path normalizeOutput(Path path, String label) throws AppDistributionException {
    if (path == null) {
      throw new AppDistributionException(label + " is required");
    }
    Path normalized = path.toAbsolutePath().normalize();
    if (normalized.getFileName() == null) {
      throw new AppDistributionException(label + " must name a file");
    }
    return normalized;
  }

  /**
   * Ensures no generated output path can overwrite another generated output.
   *
   * @param privateOut normalized private key path
   * @param publicOut normalized public key path
   * @param trustedOut optional normalized trust-store path
   * @throws AppDistributionException if any two paths are identical
   */
  private static void requireDistinctOutputPaths(Path privateOut, Path publicOut, Path trustedOut)
      throws AppDistributionException {
    requireDistinctOutputPath(privateOut, PRIVATE_KEY_FILE_LABEL, publicOut, PUBLIC_KEY_FILE_LABEL);
    if (trustedOut != null) {
      requireDistinctOutputPath(
          privateOut, PRIVATE_KEY_FILE_LABEL, trustedOut, TRUSTED_KEYS_FILE_LABEL);
      requireDistinctOutputPath(
          publicOut, PUBLIC_KEY_FILE_LABEL, trustedOut, TRUSTED_KEYS_FILE_LABEL);
    }
  }

  /**
   * Checks one pair of output paths for equality.
   *
   * @param left first normalized path
   * @param leftLabel CLI label for the first path
   * @param right second normalized path
   * @param rightLabel CLI label for the second path
   * @throws AppDistributionException if both paths are equal
   */
  private static void requireDistinctOutputPath(
      Path left, String leftLabel, Path right, String rightLabel) throws AppDistributionException {
    if (left.equals(right)) {
      throw new AppDistributionException(
          "key output paths must be distinct: " + leftLabel + " and " + rightLabel);
    }
  }

  /**
   * Checks whether an output path can be written under the requested overwrite policy.
   *
   * @param file normalized output path
   * @param overwrite whether an existing regular file may be replaced
   * @throws AppDistributionException if the path is a symlink, non-regular file, or protected
   *     existing file
   */
  private static void requireWritable(Path file, boolean overwrite)
      throws AppDistributionException {
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (Files.isSymbolicLink(file)) {
      throw new AppDistributionException("key output must not be a symbolic link: " + file);
    }
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("key output must be a regular file: " + file);
    }
    if (!overwrite) {
      throw new AppDistributionException("key output already exists: " + file);
    }
  }

  /**
   * Writes non-private binary output such as the public key file.
   *
   * @param file normalized output path
   * @param bytes encoded bytes to write
   * @param overwrite whether an existing regular file may be truncated
   * @throws IOException if the file cannot be created or written
   */
  private static void writeBytes(Path file, byte[] bytes, boolean overwrite) throws IOException {
    createParent(file);
    if (overwrite) {
      Files.write(
          file,
          bytes,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE,
          LinkOption.NOFOLLOW_LINKS);
      return;
    }
    Files.write(
        file,
        bytes,
        StandardOpenOption.CREATE_NEW,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Writes private key bytes after enforcing owner-only permissions.
   *
   * <p>New files are created before any key bytes are written, and failure during permission
   * enforcement removes a newly created placeholder. Existing files are rechecked by the shared
   * writability guard and restricted before and after truncation.
   *
   * @param file normalized private key output path
   * @param bytes encoded private key bytes
   * @param overwrite whether an existing regular private key file may be replaced
   * @throws IOException if permissions cannot be enforced or bytes cannot be written
   */
  private static void writePrivateKey(Path file, byte[] bytes, boolean overwrite)
      throws IOException {
    createParent(file);
    boolean created = false;
    if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      requireWritable(file, overwrite);
      restrictOwnerOnly(file);
    } else {
      createEmptyOwnerOnlyFile(file);
      created = true;
    }
    try {
      restrictOwnerOnly(file);
      try (OutputStream output =
          Files.newOutputStream(
              file,
              StandardOpenOption.WRITE,
              StandardOpenOption.TRUNCATE_EXISTING,
              LinkOption.NOFOLLOW_LINKS)) {
        output.write(bytes);
      }
      restrictOwnerOnly(file);
    } catch (IOException | RuntimeException exception) {
      if (created) {
        Files.deleteIfExists(file);
      }
      throw exception;
    }
  }

  /**
   * Creates an empty private-key file with owner-only access before writing material.
   *
   * @param file normalized private key output path that does not already exist
   * @throws IOException if the file cannot be created or access cannot be restricted
   */
  private static void createEmptyOwnerOnlyFile(Path file) throws IOException {
    try {
      FileAttribute<Set<PosixFilePermission>> permissions =
          PosixFilePermissions.asFileAttribute(OWNER_ONLY);
      Files.createFile(file, permissions);
    } catch (UnsupportedOperationException _) {
      Files.createFile(file);
      try {
        restrictPortableOwnerOnly(file);
      } catch (IOException | RuntimeException exception) {
        Files.deleteIfExists(file);
        throw exception;
      }
    }
  }

  /**
   * Writes non-private UTF-8 properties output such as generated trust stores.
   *
   * @param file normalized output path
   * @param text properties text to write
   * @param overwrite whether an existing regular file may be truncated
   * @throws IOException if the file cannot be created or written
   */
  private static void writeString(Path file, String text, boolean overwrite) throws IOException {
    createParent(file);
    if (overwrite) {
      Files.writeString(
          file,
          text,
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE,
          LinkOption.NOFOLLOW_LINKS);
      return;
    }
    Files.writeString(
        file,
        text,
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE_NEW,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Creates the parent directory for an output file when it has one.
   *
   * @param file normalized output file path
   * @throws IOException if the parent directory cannot be created
   */
  private static void createParent(Path file) throws IOException {
    Path parent = file.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }

  /**
   * Restricts a private key file to owner read/write access.
   *
   * @param file private key file whose permissions should be tightened
   * @throws IOException if POSIX or portable permission enforcement fails
   */
  private static void restrictOwnerOnly(Path file) throws IOException {
    try {
      Files.setPosixFilePermissions(file, OWNER_ONLY);
    } catch (UnsupportedOperationException _) {
      restrictPortableOwnerOnly(file);
    }
  }

  /**
   * Applies best-effort owner-only permissions through {@link java.io.File} APIs.
   *
   * @param file private key file on a filesystem without POSIX permission support
   * @throws IOException if the runtime reports that any permission change failed
   */
  private static void restrictPortableOwnerOnly(Path file) throws IOException {
    java.io.File javaFile = file.toFile();
    if (!javaFile.setReadable(false, false)
        || !javaFile.setWritable(false, false)
        || !javaFile.setExecutable(false, false)
        || !javaFile.setReadable(true, true)
        || !javaFile.setWritable(true, true)) {
      throw new IOException("failed to restrict private key file permissions: " + file);
    }
  }

  /**
   * Renders a trusted app-key properties file.
   *
   * @param keyId trusted app signing key id
   * @param publicKeyBytes encoded public key bytes
   * @return properties text accepted by bundle verification commands
   */
  private static String trustedAppKeys(String keyId, byte[] publicKeyBytes) {
    return "trusted.keys.version=1\n"
        + "key.0.id="
        + keyId
        + "\n"
        + "key.0.algorithm="
        + AppBundleSignature.SIGNATURE_ALGORITHM
        + "\n"
        + "key.0.public.key.base64="
        + Base64.getEncoder().encodeToString(publicKeyBytes)
        + "\n";
  }

  /**
   * Paths written by a successful key-generation command.
   *
   * @param privateKeyFile normalized private key output path
   * @param publicKeyFile normalized public key output path
   * @param trustedKeysFile optional normalized generated trust-store path
   */
  record GeneratedKeys(Path privateKeyFile, Path publicKeyFile, Path trustedKeysFile) {}
}
