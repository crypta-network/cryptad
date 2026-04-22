package network.crypta.platform.appcatalog;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleDigest;

/**
 * Shared sidecar parsing, URI policy, digest, and error-code helpers for app catalogs.
 *
 * <p>This class keeps the low-level catalog format rules in one package-private place so parser,
 * fetcher, verifier, downloader, and source-store code report the same stable error codes. It is
 * not a generic properties or URI utility. The helpers are tuned for signed catalog sidecars and
 * catalog artifacts: exact UTF-8 bytes, duplicate-key rejection, bounded reads, local-file
 * restrictions, HTTPS by default, loopback-only HTTP, and lowercase SHA-256 artifact digests.
 */
final class AppCatalogSidecars {
  /** Error code used when an operator-configured catalog source cannot be used safely. */
  static final String INVALID_CATALOG_SOURCE = "invalid_catalog_source";

  /** Error code used when catalog signature metadata or verification fails. */
  static final String INVALID_CATALOG_SIGNATURE = "invalid_catalog_signature";

  /** Error code used when authenticated catalog entry metadata is malformed. */
  static final String INVALID_CATALOG_ENTRY = "invalid_catalog_entry";

  /** Error code used when a catalog artifact cannot be retrieved or read. */
  static final String ARTIFACT_DOWNLOAD_FAILED = "artifact_download_failed";

  /** Error code used when artifact size or SHA-256 does not match catalog metadata. */
  static final String ARTIFACT_DIGEST_MISMATCH = "artifact_digest_mismatch";

  /** Error code used when an extracted artifact is not a valid signed app bundle. */
  static final String INVALID_APP_BUNDLE = "invalid_app_bundle";

  /** Error code used when a configured catalog id is not present in the source store. */
  static final String CATALOG_NOT_FOUND = "catalog_not_found";

  /** Error code used when adding a catalog whose authenticated id is already configured. */
  static final String CATALOG_CONFLICT = "catalog_conflict";

  /** Error code used when a verified catalog does not contain the requested app id. */
  static final String APP_NOT_FOUND = "app_not_found";

  /** Maximum accepted catalog properties sidecar size, in bytes. */
  static final long MAX_CATALOG_BYTES = 1024L * 1024L;

  /** Maximum accepted catalog signature sidecar size, in bytes. */
  static final long MAX_SIGNATURE_BYTES = 64L * 1024L;

  /** Maximum accepted ZIP artifact and extracted payload size, in bytes. */
  static final long MAX_ARTIFACT_BYTES = 512L * 1024L * 1024L;

  /** Optional UTF-8 byte-order mark accepted only at the start of text sidecars. */
  private static final char UTF_8_BOM = '\uFEFF';

  /** Strict lowercase hexadecimal SHA-256 digest grammar for catalog artifact metadata. */
  private static final Pattern LOWERCASE_SHA256_PATTERN = Pattern.compile("[0-9a-f]{64}");

  /** Prevents construction; all helpers are stateless and package-private. */
  private AppCatalogSidecars() {}

  /**
   * Parses a strict key/value sidecar into insertion-ordered properties.
   *
   * <p>Blank lines and comment lines beginning with {@code #} or {@code !} are ignored. Every other
   * line must contain a non-empty key before the first {@code =}. Duplicate keys are rejected so
   * signature and catalog parsers cannot silently accept ambiguous metadata.
   *
   * @param content UTF-8 decoded sidecar content, optionally starting with a BOM
   * @param description short sidecar name used in error messages
   * @return insertion-ordered key/value map without duplicate keys
   * @throws AppCatalogException if the sidecar line grammar is invalid
   */
  static Map<String, String> parseKeyValueSidecar(String content, String description)
      throws AppCatalogException {
    Objects.requireNonNull(content, "content");
    Map<String, String> properties = new LinkedHashMap<>();
    String[] lines = stripLeadingBom(content).split("\\R", -1);
    for (String line : lines) {
      if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
        continue;
      }
      int separatorIndex = line.indexOf('=');
      if (separatorIndex < 0) {
        throw invalidEntry("invalid " + description + " line: " + line);
      }
      String key = line.substring(0, separatorIndex).trim();
      if (key.isEmpty()) {
        throw invalidEntry("invalid " + description + " line: " + line);
      }
      String value = line.substring(separatorIndex + 1);
      String previous = properties.putIfAbsent(key, value);
      if (previous != null) {
        throw invalidEntry("duplicate " + description + " property: " + key);
      }
    }
    return properties;
  }

  /**
   * Reads a required local sidecar file after symlink, regular-file, and size checks.
   *
   * <p>The path is normalized before inspection, symbolic links are rejected, and the file must fit
   * within the caller-provided byte limit. This protects catalog metadata reads from unexpectedly
   * following host-owned links or consuming unbounded memory.
   *
   * @param file sidecar file path supplied by the fetcher or source store
   * @param maxBytes maximum accepted byte length
   * @param description short file description used in error messages
   * @param errorCode catalog error code to attach to validation failures
   * @return complete file contents
   * @throws IOException if the file cannot be read after validation
   */
  static byte[] readRequiredBytes(Path file, long maxBytes, String description, String errorCode)
      throws IOException {
    Path normalized = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
    if (Files.isSymbolicLink(normalized)) {
      throw new AppCatalogException(errorCode, description + " must not be a symbolic link");
    }
    if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(errorCode, "missing " + description);
    }
    long size = Files.size(normalized);
    if (size > maxBytes) {
      throw new AppCatalogException(errorCode, description + " exceeds the allowed size");
    }
    return Files.readAllBytes(normalized);
  }

  /**
   * Reads bounded sidecar bytes from a remote response stream.
   *
   * <p>The method consumes the stream incrementally and fails as soon as the configured byte cap is
   * exceeded. It is used for catalog properties and signature sidecars, not for large ZIP
   * artifacts.
   *
   * @param input response stream to consume
   * @param maxBytes maximum accepted byte length
   * @param description short payload description used in error messages
   * @return bytes read from the stream
   * @throws IOException if the stream cannot be read
   */
  static byte[] readLimitedCatalogSource(InputStream input, long maxBytes, String description)
      throws IOException {
    Objects.requireNonNull(input, "input");
    byte[] buffer = new byte[64 * 1024];
    try (var output = new ByteArrayOutputStream()) {
      long totalBytes = 0L;
      int bytesRead;
      while ((bytesRead = input.read(buffer)) >= 0) {
        if (bytesRead == 0) {
          continue;
        }
        totalBytes += bytesRead;
        if (totalBytes > maxBytes) {
          throw new AppCatalogException(
              INVALID_CATALOG_SOURCE, description + " exceeds the allowed size");
        }
        output.write(buffer, 0, bytesRead);
      }
      return output.toByteArray();
    }
  }

  /**
   * Decodes sidecar bytes as UTF-8 text.
   *
   * @param bytes exact sidecar bytes read from disk or network
   * @return decoded UTF-8 string
   */
  static String utf8(byte[] bytes) {
    return new String(Objects.requireNonNull(bytes, "bytes"), StandardCharsets.UTF_8);
  }

  /**
   * Requires a non-blank single-line metadata value.
   *
   * <p>The returned value is trimmed, but embedded line breaks are rejected so sidecar fields
   * cannot smuggle additional properties or multi-line display text into deterministic catalog
   * files.
   *
   * @param value raw metadata value
   * @param fieldName field name used in diagnostics
   * @param errorCode catalog error code to attach to validation failures
   * @return trimmed single-line value
   * @throws AppCatalogException if the value is blank or multi-line
   */
  static String requireNonBlankSingleLine(String value, String fieldName, String errorCode)
      throws AppCatalogException {
    Objects.requireNonNull(value, fieldName);
    if (value.isBlank()) {
      throw new AppCatalogException(errorCode, fieldName + " must not be blank");
    }
    if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
      throw new AppCatalogException(errorCode, fieldName + " must be a single line");
    }
    return value.trim();
  }

  /**
   * Requires a lowercase SHA-256 digest string.
   *
   * @param value raw digest text from catalog metadata
   * @param fieldName field name used in diagnostics
   * @return validated lowercase 64-character hexadecimal digest
   * @throws AppCatalogException if the digest is missing or malformed
   */
  static String requireLowercaseSha256(String value, String fieldName) throws AppCatalogException {
    String normalized = requireNonBlankSingleLine(value, fieldName, INVALID_CATALOG_ENTRY);
    if (!LOWERCASE_SHA256_PATTERN.matcher(normalized).matches()) {
      throw invalidEntry(fieldName + " must be lowercase SHA-256 hex");
    }
    return normalized;
  }

  /**
   * Validates and normalizes a catalog source URI.
   *
   * @param uri source URI for {@code cryptad-app-catalog.properties}
   * @return normalized source URI accepted by catalog fetch policy
   * @throws AppCatalogException if the URI is not absolute or uses an unsupported scheme
   */
  static URI requireSafeCatalogSourceUri(URI uri) throws AppCatalogException {
    URI normalized = normalizeUri(uri, INVALID_CATALOG_SOURCE, "catalog source URI");
    requireSupportedScheme(normalized, INVALID_CATALOG_SOURCE, "catalog source URI");
    return normalized;
  }

  /**
   * Validates and normalizes an artifact URI from authenticated catalog metadata.
   *
   * @param uri bundle artifact URI from a catalog entry
   * @return normalized artifact URI accepted by artifact download policy
   * @throws AppCatalogException if the URI is not absolute or uses an unsupported scheme
   */
  static URI requireSafeArtifactUri(URI uri) throws AppCatalogException {
    URI normalized = normalizeUri(uri, INVALID_CATALOG_ENTRY, "artifact URI");
    requireSupportedScheme(normalized, INVALID_CATALOG_ENTRY, "artifact URI");
    return normalized;
  }

  /**
   * Creates an SHA-256 digest using the appdist digest algorithm constant.
   *
   * @return initialized digest for artifact streaming
   * @throws AppCatalogException if the current JDK cannot provide SHA-256
   */
  static MessageDigest newArtifactSha256Digest() throws AppCatalogException {
    try {
      return MessageDigest.getInstance(AppBundleDigest.DIGEST_ALGORITHM);
    } catch (NoSuchAlgorithmException exception) {
      throw new AppCatalogException(
          ARTIFACT_DIGEST_MISMATCH, "SHA-256 is not supported by the current JDK", exception);
    }
  }

  /**
   * Encodes bytes as lowercase hexadecimal text.
   *
   * @param bytes bytes to encode
   * @return lowercase hexadecimal representation with two characters per byte
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
   * Creates an invalid-entry exception.
   *
   * @param message diagnostic message for the rejected catalog entry state
   * @return catalog exception tagged with {@link #INVALID_CATALOG_ENTRY}
   */
  static AppCatalogException invalidEntry(String message) {
    return new AppCatalogException(INVALID_CATALOG_ENTRY, message);
  }

  /**
   * Creates an invalid-signature exception.
   *
   * @param message diagnostic message for the rejected signature state
   * @return catalog exception tagged with {@link #INVALID_CATALOG_SIGNATURE}
   */
  static AppCatalogException invalidSignature(String message) {
    return new AppCatalogException(INVALID_CATALOG_SIGNATURE, message);
  }

  /**
   * Normalizes and checks URI invariants shared by source and artifact URIs.
   *
   * @param uri URI to normalize
   * @param errorCode catalog error code for validation failures
   * @param fieldName field name used in diagnostics
   * @return normalized absolute URI without fragments or user info
   * @throws AppCatalogException if the URI is not safe to store or fetch
   */
  private static URI normalizeUri(URI uri, String errorCode, String fieldName)
      throws AppCatalogException {
    Objects.requireNonNull(uri, fieldName);
    if (!uri.isAbsolute()) {
      throw new AppCatalogException(errorCode, fieldName + " must be absolute");
    }
    if (uri.getFragment() != null) {
      throw new AppCatalogException(errorCode, fieldName + " must not include a fragment");
    }
    if (uri.getUserInfo() != null) {
      throw new AppCatalogException(errorCode, fieldName + " must not include user info");
    }
    return uri.normalize();
  }

  /**
   * Applies catalog transport scheme policy to a normalized URI.
   *
   * @param uri absolute URI to validate
   * @param errorCode catalog error code for validation failures
   * @param fieldName field name used in diagnostics
   * @throws AppCatalogException if the URI scheme is unsupported or unsafe
   */
  private static void requireSupportedScheme(URI uri, String errorCode, String fieldName)
      throws AppCatalogException {
    String scheme = uri.getScheme();
    if (scheme == null) {
      throw new AppCatalogException(errorCode, fieldName + " must include a URI scheme");
    }
    String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
    switch (normalizedScheme) {
      case "https" -> {
        requireRemoteHttpUri(uri, errorCode, fieldName);
        return;
      }
      case "file" -> {
        requireLocalFileUri(uri, errorCode, fieldName);
        return;
      }
      case "http" -> {
        requireRemoteHttpUri(uri, errorCode, fieldName);
        if (isLocalhost(uri.getHost())) {
          return;
        }
      }
      default -> throw new IllegalStateException("Unexpected value: " + normalizedScheme);
    }
    throw new AppCatalogException(errorCode, "unsupported " + fieldName + " scheme: " + scheme);
  }

  /**
   * Requires an HTTP(S) URI with a concrete authority host.
   *
   * @param uri URI whose scheme is {@code http} or {@code https}
   * @param errorCode catalog error code for validation failures
   * @param fieldName field name used in diagnostics
   */
  private static void requireRemoteHttpUri(URI uri, String errorCode, String fieldName) {
    if (uri.isOpaque() || uri.getHost() == null || uri.getHost().isBlank()) {
      throw new AppCatalogException(errorCode, fieldName + " must include a host");
    }
  }

  /**
   * Requires a hierarchical local {@code file:} URI that can be converted to a path.
   *
   * @param uri URI whose scheme is {@code file}
   * @param errorCode catalog error code for validation failures
   * @param fieldName field name used in diagnostics
   * @throws AppCatalogException if the URI is opaque, remote, query-bearing, or path-invalid
   */
  private static void requireLocalFileUri(URI uri, String errorCode, String fieldName)
      throws AppCatalogException {
    if (uri.isOpaque()
        || uri.getPath() == null
        || uri.getPath().isBlank()
        || uri.getAuthority() != null
        || uri.getQuery() != null) {
      throw new AppCatalogException(errorCode, fieldName + " must be a local file URI");
    }
    try {
      Path localPath = Path.of(uri);
      if (!localPath.isAbsolute()) {
        throw new IllegalArgumentException("file URI path must be absolute");
      }
    } catch (IllegalArgumentException | FileSystemNotFoundException exception) {
      throw new AppCatalogException(errorCode, fieldName + " must be a local file URI", exception);
    }
  }

  /**
   * Returns whether a host name is explicitly local enough for plaintext HTTP.
   *
   * @param host host component from a URI
   * @return {@code true} for {@code localhost}, numeric IPv4 127/8, or IPv6 loopback literals
   */
  private static boolean isLocalhost(String host) {
    if (host == null) {
      return false;
    }
    String normalized = stripIpv6Brackets(host.toLowerCase(Locale.ROOT));
    return "localhost".equals(normalized)
        || isIpv4LoopbackLiteral(normalized)
        || "::1".equals(normalized)
        || "0:0:0:0:0:0:0:1".equals(normalized);
  }

  /**
   * Removes square brackets from an IPv6 host literal when present.
   *
   * @param host lower-case host text
   * @return host text without surrounding IPv6 brackets
   */
  private static String stripIpv6Brackets(String host) {
    if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  /**
   * Checks for a dotted-decimal IPv4 loopback literal in 127/8.
   *
   * @param host lower-case host text without URI brackets
   * @return {@code true} when all four octets are decimal and the first octet is {@code 127}
   */
  private static boolean isIpv4LoopbackLiteral(String host) {
    String[] octets = host.split("\\.", -1);
    if (octets.length != 4 || !"127".equals(octets[0])) {
      return false;
    }
    for (String octet : octets) {
      if (!isDecimalIpv4Octet(octet)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Validates one decimal IPv4 octet.
   *
   * @param octet octet text from a dotted IPv4 literal
   * @return {@code true} when the octet is decimal and within {@code 0..255}
   */
  private static boolean isDecimalIpv4Octet(String octet) {
    if (octet.isEmpty()) {
      return false;
    }
    int value = 0;
    for (int i = 0; i < octet.length(); i++) {
      char digit = octet.charAt(i);
      if (digit < '0' || digit > '9') {
        return false;
      }
      value = value * 10 + digit - '0';
      if (value > 255) {
        return false;
      }
    }
    return true;
  }

  /**
   * Removes one leading UTF-8 BOM character from decoded sidecar text.
   *
   * @param content decoded sidecar content
   * @return content without a leading BOM, if one was present
   */
  private static String stripLeadingBom(String content) {
    if (!content.isEmpty() && content.charAt(0) == UTF_8_BOM) {
      return content.substring(1);
    }
    return content;
  }
}
