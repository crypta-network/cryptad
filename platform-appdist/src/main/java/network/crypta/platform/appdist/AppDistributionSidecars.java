package network.crypta.platform.appdist;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared parsing, path-safety, and encoding helpers for app distribution sidecars.
 *
 * <p>This package-private utility keeps the digest, signature, trusted-key, and command-line
 * tooling classes aligned on the same local bundle rules. It centralizes UTF-8 text handling,
 * bundle-root validation, sidecar path names, base64 key material decoding, and checks that reject
 * symlinks or filesystem aliases before distribution metadata is trusted.
 */
final class AppDistributionSidecars {
  private static final String BUNDLE_ROOT_PARAMETER = "bundleRoot";
  private static final String CATALOG_FILE_NAME = "cryptad-app.catalog";
  private static final String CATALOG_SIGNATURE_FILE_NAME = "cryptad-app.catalog.signature";
  private static final Set<String> DISTRIBUTION_SIDECAR_NAMES =
      Set.of(
          AppBundleDigest.DIGEST_FILE_NAME,
          AppBundleSignature.SIGNATURE_FILE_NAME,
          CATALOG_FILE_NAME,
          CATALOG_SIGNATURE_FILE_NAME);

  /** UTF-8 byte-order mark accepted at the beginning of operator-authored text sidecars. */
  private static final char UTF_8_BOM = '\uFEFF';

  /** Prevents construction of this stateless utility class. */
  private AppDistributionSidecars() {}

  /**
   * Validates and normalizes a local bundle root directory.
   *
   * @param bundleRoot caller-supplied bundle root path
   * @return absolute normalized bundle root path
   * @throws AppDistributionException if the root is missing, not a directory, or aliased
   */
  static Path requireBundleRoot(Path bundleRoot) throws AppDistributionException {
    Objects.requireNonNull(bundleRoot, BUNDLE_ROOT_PARAMETER);
    Path normalized = bundleRoot.toAbsolutePath().normalize();
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("bundle root must be an existing directory");
    }
    try {
      if (Files.isSymbolicLink(normalized) || isAliasedPathEntry(normalized)) {
        throw new AppDistributionException(
            "bundle root must not be a symlink, reparse point, or alias: " + normalized);
      }
    } catch (IOException exception) {
      throw new AppDistributionException("failed to inspect bundle root", exception);
    }
    return normalized;
  }

  /**
   * Requires a sidecar field value to be present on one text line.
   *
   * @param value raw field value
   * @param fieldName field name used in error messages
   * @return original value when it is non-blank and single-line
   */
  static String requireNonBlankSingleLine(String value, String fieldName) {
    Objects.requireNonNull(value, fieldName);
    if (value.isBlank()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new IllegalArgumentException(fieldName + " must be a single line");
    }
    return value;
  }

  /**
   * Converts a bundle file path into normalized sidecar path text.
   *
   * @param bundleRoot normalized bundle root path
   * @param file file path under the bundle root
   * @return bundle-relative path using {@code /} separators
   */
  static String normalizeBundleRelativePath(Path bundleRoot, Path file) {
    return normalizeBundleRelativePath(
        toNormalizedRelativePath(Objects.requireNonNull(bundleRoot, BUNDLE_ROOT_PARAMETER), file),
        "bundle path");
  }

  /**
   * Validates normalized bundle-relative sidecar path text.
   *
   * @param path path text from a sidecar or manifest
   * @param fieldName field name used in error messages
   * @return validated path text using {@code /} separators
   */
  static String normalizeBundleRelativePath(String path, String fieldName) {
    String normalized = requireNonBlankSingleLine(path, fieldName);
    if (normalized.contains("\\")) {
      throw new IllegalArgumentException(fieldName + " must use '/' separators");
    }
    if (normalized.startsWith("/")) {
      throw new IllegalArgumentException(fieldName + " must be relative");
    }
    if (normalized.length() >= 2
        && Character.isLetter(normalized.charAt(0))
        && normalized.charAt(1) == ':') {
      throw new IllegalArgumentException(fieldName + " must not use a drive prefix");
    }
    validateRelativePathSegments(normalized, fieldName);
    return normalized;
  }

  /**
   * Returns whether a normalized path is reserved for distribution metadata.
   *
   * @param path normalized bundle-relative path
   * @return {@code true} when the path names a digest, signature, or catalog sidecar
   */
  static boolean isDistributionSidecar(String path) {
    return DISTRIBUTION_SIDECAR_NAMES.contains(
        Objects.requireNonNull(path, "path").toLowerCase(Locale.ROOT));
  }

  /**
   * Returns whether the bundle root contains no reserved distribution sidecar name.
   *
   * <p>The comparison is intentionally case-insensitive even on case-sensitive filesystems. That
   * mirrors the reserved-name checks used while digesting bundle contents and prevents development
   * unsigned policy from treating case variants such as {@code CRYPTAD-APP.DIGESTS} as ordinary app
   * payload files.
   *
   * @param bundleRoot bundle root directory to inspect
   * @return {@code true} when no direct root entry uses a reserved sidecar name
   * @throws IOException if the bundle root is unsafe or cannot be listed
   */
  static boolean isDistributionSidecarFree(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = requireBundleRoot(bundleRoot);
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(normalizedBundleRoot)) {
      for (Path entry : entries) {
        Path fileName = entry.getFileName();
        if (fileName != null && isDistributionSidecar(fileName.toString())) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Creates an SHA-256 message digest from the current JDK provider set.
   *
   * @return new SHA-256 digest instance
   * @throws AppDistributionException if SHA-256 is unavailable in the running JDK
   */
  static MessageDigest newSha256Digest() throws AppDistributionException {
    try {
      return MessageDigest.getInstance(AppBundleDigest.DIGEST_ALGORITHM);
    } catch (NoSuchAlgorithmException exception) {
      throw new AppDistributionException("SHA-256 is not supported by the current JDK", exception);
    }
  }

  /**
   * Encodes bytes as lowercase hexadecimal text.
   *
   * @param bytes bytes to encode
   * @return lowercase hexadecimal text with two characters per byte
   */
  static String lowercaseHex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte value : bytes) {
      builder.append(Character.forDigit((value >>> 4) & 0x0F, 16));
      builder.append(Character.forDigit(value & 0x0F, 16));
    }
    return builder.toString();
  }

  /**
   * Reads a required sidecar as UTF-8 text.
   *
   * @param file expected file path
   * @param description human-readable sidecar description for errors
   * @return decoded UTF-8 content
   * @throws IOException if the file is missing, unsafe, or unreadable
   */
  static String readRequiredUtf8File(Path file, String description) throws IOException {
    return new String(readRequiredBytes(file, description), StandardCharsets.UTF_8);
  }

  /**
   * Reads a required non-symlink file as bytes.
   *
   * @param file expected file path
   * @param description human-readable file description for errors
   * @return file bytes
   * @throws IOException if the file is missing, unsafe, or unreadable
   */
  static byte[] readRequiredBytes(Path file, String description) throws IOException {
    Path normalized = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
    if (Files.isSymbolicLink(normalized)) {
      throw new AppDistributionException(description + " must not be a symbolic link");
    }
    if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("missing " + description);
    }
    return Files.readAllBytes(normalized);
  }

  /**
   * Writes UTF-8 text to a sidecar path after rejecting symbolic-link replacement.
   *
   * @param file destination sidecar path
   * @param content UTF-8 text content to write
   * @throws IOException if the destination is unsafe or cannot be written
   */
  static void writeUtf8File(Path file, String content) throws IOException {
    Path normalized = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
    if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(normalized)) {
      throw new AppDistributionException("sidecar path must not be a symbolic link");
    }
    Files.writeString(normalized, content, StandardCharsets.UTF_8);
  }

  /**
   * Parses a strict {@code key=value} sidecar format.
   *
   * @param content complete text sidecar content
   * @param description human-readable sidecar description for errors
   * @return insertion-ordered key/value properties
   * @throws AppDistributionException if a line is malformed or a key is duplicated
   */
  static Map<String, String> parseKeyValueSidecar(String content, String description)
      throws AppDistributionException {
    Objects.requireNonNull(content, "content");
    Map<String, String> properties = new LinkedHashMap<>();
    String[] lines = stripLeadingBom(content).split("\\R", -1);
    for (String line : lines) {
      if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
        continue;
      }
      int separatorIndex = line.indexOf('=');
      if (separatorIndex < 0) {
        throw new AppDistributionException("invalid " + description + " line: " + line);
      }
      String key = line.substring(0, separatorIndex).trim();
      if (key.isEmpty()) {
        throw new AppDistributionException("invalid " + description + " line: " + line);
      }
      String value = line.substring(separatorIndex + 1);
      String previous = properties.putIfAbsent(key, value);
      if (previous != null) {
        throw new AppDistributionException("duplicate " + description + " property: " + key);
      }
    }
    return properties;
  }

  /**
   * Removes one leading UTF-8 byte-order mark if present.
   *
   * @param content text content read from a sidecar
   * @return content without a leading BOM
   */
  private static String stripLeadingBom(String content) {
    if (!content.isEmpty() && content.charAt(0) == UTF_8_BOM) {
      return content.substring(1);
    }
    return content;
  }

  /**
   * Decodes strict base64 text for one sidecar field.
   *
   * @param value base64-encoded field value
   * @param fieldName field name used in error messages
   * @return decoded bytes
   */
  static byte[] decodeBase64(String value, String fieldName) {
    try {
      return java.util.Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException("invalid " + fieldName, exception);
    }
  }

  /**
   * Decodes base64 key material, accepting PEM wrapper lines.
   *
   * @param value base64 or PEM-encoded key material
   * @param fieldName field name used in error messages
   * @return decoded key bytes
   */
  static byte[] decodeBase64KeyMaterial(String value, String fieldName) {
    Objects.requireNonNull(value, fieldName);
    String normalized =
        value
            .lines()
            .map(String::trim)
            .filter(line -> !line.isEmpty())
            .filter(line -> !line.startsWith("-----BEGIN"))
            .filter(line -> !line.startsWith("-----END"))
            .collect(Collectors.joining());
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return decodeBase64(normalized, fieldName);
  }

  /**
   * Reads key material as PEM/base64 text with raw-byte fallback.
   *
   * @param file key material file path
   * @return decoded key bytes or raw file bytes when text decoding is not applicable
   * @throws IOException if the file is missing, unsafe, or unreadable
   */
  static byte[] readKeyMaterial(Path file) throws IOException {
    byte[] rawBytes = readRequiredBytes(file, "key material");
    String text = new String(rawBytes, StandardCharsets.UTF_8);
    try {
      return decodeBase64KeyMaterial(text, "key material");
    } catch (IllegalArgumentException _) {
      return rawBytes;
    }
  }

  /**
   * Validates that a bundle entry resolves exactly under the real bundle root.
   *
   * @param bundleRoot normalized bundle root path
   * @param bundleRealRoot real bundle root path
   * @param entry path being walked or resolved
   * @return real path for the entry
   * @throws IOException if the entry is a symlink, alias, reparse-point escape, or unreadable
   */
  static Path validateBundleEntry(Path bundleRoot, Path bundleRealRoot, Path entry)
      throws IOException {
    Objects.requireNonNull(bundleRoot, BUNDLE_ROOT_PARAMETER);
    Objects.requireNonNull(bundleRealRoot, "bundleRealRoot");
    Objects.requireNonNull(entry, "entry");
    if (entry.equals(bundleRoot)) {
      return bundleRealRoot;
    }
    if (Files.isSymbolicLink(entry)) {
      throw new AppDistributionException("bundle must not contain symlinks: " + entry);
    }
    Path expectedRealPath = bundleRealRoot.resolve(bundleRoot.relativize(entry)).normalize();
    Path actualRealPath = entry.toRealPath();
    if (!actualRealPath.equals(expectedRealPath)) {
      throw new AppDistributionException(
          "bundle must not contain links or reparse points: " + entry);
    }
    return actualRealPath;
  }

  /**
   * Returns whether an entry resolves somewhere other than its lexical parent would imply.
   *
   * @param entry filesystem entry to inspect
   * @return {@code true} when the path is a symlink or other alias
   * @throws IOException if the entry or its parent cannot be resolved
   */
  static boolean isAliasedPathEntry(Path entry) throws IOException {
    Objects.requireNonNull(entry, "entry");
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

  /**
   * Converts a file under a bundle root to slash-separated relative text.
   *
   * @param bundleRoot normalized bundle root path
   * @param file file path under the bundle root
   * @return relative path text before sidecar path validation
   */
  private static String toNormalizedRelativePath(Path bundleRoot, Path file) {
    Path relative = bundleRoot.relativize(file);
    StringBuilder builder = new StringBuilder();
    for (Path name : relative) {
      if (!builder.isEmpty()) {
        builder.append('/');
      }
      builder.append(name.toString());
    }
    return builder.toString();
  }

  /**
   * Rejects empty, current-directory, and parent-directory path segments.
   *
   * @param normalized slash-separated path text
   * @param fieldName field name used in error messages
   */
  private static void validateRelativePathSegments(String normalized, String fieldName) {
    int start = 0;
    while (start <= normalized.length()) {
      int separatorIndex = normalized.indexOf('/', start);
      String segment =
          separatorIndex >= 0
              ? normalized.substring(start, separatorIndex)
              : normalized.substring(start);
      if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)) {
        throw new IllegalArgumentException(fieldName + " must not escape the bundle root");
      }
      if (separatorIndex < 0) {
        return;
      }
      start = separatorIndex + 1;
    }
  }
}
