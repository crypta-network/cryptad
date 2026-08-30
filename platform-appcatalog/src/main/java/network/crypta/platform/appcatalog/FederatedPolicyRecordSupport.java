package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Shared closed-record primitives for host-owned federation policy stores.
 *
 * <p>The helpers enforce bounded UTF-8 records, closed property sets, stable identifiers, canonical
 * digests, confined paths, and atomic replacement. Catalog-scoped routing deliberately treats a
 * record's clear-text catalog identifier as an indexing hint only; each owning store must still
 * parse and authenticate the complete record before using it for authorization.
 */
final class FederatedPolicyRecordSupport {
  /** Maximum accepted serialized policy-record size. */
  static final long MAX_RECORD_BYTES = 64 * 1024L;

  /** Closed grammar for stable local policy identifiers. */
  static final Pattern LOCAL_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}");

  /** Closed grammar for signing-key identifiers. */
  static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

  /** Canonical lowercase hexadecimal SHA-256 grammar. */
  static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Prevents construction of this stateless persistence utility. */
  private FederatedPolicyRecordSupport() {}

  /**
   * Requires a bounded identifier matching a closed grammar.
   *
   * @param value identifier value
   * @param name field name used in failures
   * @param pattern accepted identifier grammar
   * @return validated identifier
   */
  static String requireId(String value, String name, Pattern pattern) {
    String checked = requireText(value, name, 128);
    if (!pattern.matcher(checked).matches()) {
      throw invalid("invalid " + name);
    }
    return checked;
  }

  /**
   * Requires a canonical lowercase SHA-256 digest.
   *
   * @param value digest value
   * @param name field name used in failures
   * @return validated digest
   */
  static String requireDigest(String value, String name) {
    if (value == null || !SHA256.matcher(value).matches()) {
      throw invalid(name + " must be lowercase SHA-256");
    }
    return value;
  }

  /**
   * Requires bounded, nonblank, delimiter-free single-line policy text.
   *
   * @param value text value
   * @param name field name used in failures
   * @param maxLength maximum permitted character count
   * @return validated text
   */
  static String requireText(String value, String name, int maxLength) {
    if (value == null
        || value.isBlank()
        || value.length() > maxLength
        || value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0
        || value.indexOf('=') >= 0
        || value.indexOf(',') >= 0) {
      throw invalid(name + " must be bounded single-line policy text");
    }
    return value;
  }

  /**
   * Computes lowercase SHA-256 over canonical UTF-8 policy text.
   *
   * @param canonicalText canonical digest subject
   * @return lowercase hexadecimal SHA-256 digest
   */
  static String digest(String canonicalText) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256")
                  .digest(canonicalText.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 is unavailable", impossible);
    }
  }

  /**
   * Parses one confined, bounded, closed-record candidate into unique properties.
   *
   * @param path policy-record path
   * @return insertion-ordered mutable properties for model parsing
   * @throws IOException if the record cannot be inspected or read
   */
  static Map<String, String> parse(Path path) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)
        || Files.size(path) > MAX_RECORD_BYTES) {
      throw invalid("federation policy record is not a bounded regular file");
    }
    LinkedHashMap<String, String> fields = new LinkedHashMap<>();
    for (String line : Files.readString(path, StandardCharsets.UTF_8).split("\\n", -1)) {
      if (line.isEmpty()) {
        continue;
      }
      int separator = line.indexOf('=');
      if (separator <= 0 || line.indexOf('=', separator + 1) >= 0) {
        throw invalid("invalid federation policy record line");
      }
      if (fields.put(line.substring(0, separator), line.substring(separator + 1)) != null) {
        throw invalid("duplicate federation policy property");
      }
    }
    return fields;
  }

  /**
   * Selects records that advertise one catalog ID without making the advertisement authoritative.
   *
   * <p>Record-local damage is isolated here so a malformed policy for another catalog cannot
   * prevent routine work. Callers must still fully parse every returned path and verify that the
   * authenticated model retains the requested catalog ID. Root confinement and enumeration failures
   * remain store-wide failures.
   *
   * @param root confined policy-store root
   * @param suffix record filename suffix
   * @param catalogId normalized catalog identity to select
   * @return immutable sorted list of records advertising the catalog identity
   * @throws IOException if the store root cannot be enumerated
   */
  static List<Path> catalogScopedRecordPaths(Path root, String suffix, String catalogId)
      throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    requireSafeRoot(root);
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    List<Path> selected = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path path :
          stream.filter(item -> item.getFileName().toString().endsWith(suffix)).sorted().toList()) {
        if (catalogIdRoutingHint(path).filter(normalizedCatalogId::equals).isPresent()) {
          selected.add(path);
        }
      }
    }
    return List.copyOf(selected);
  }

  /**
   * Reads the non-authoritative catalog routing hint from one record candidate.
   *
   * @param path candidate policy record
   * @return normalized advertised catalog ID, or empty when damaged or ambiguous
   */
  private static Optional<String> catalogIdRoutingHint(Path path) {
    try {
      if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
          || Files.isSymbolicLink(path)
          || Files.size(path) > MAX_RECORD_BYTES) {
        return Optional.empty();
      }
      String catalogId = null;
      for (String line : Files.readString(path, StandardCharsets.UTF_8).split("\\n", -1)) {
        int separator = line.indexOf('=');
        if (separator <= 0 || !"catalogId".equals(line.substring(0, separator))) {
          continue;
        }
        if (line.indexOf('=', separator + 1) >= 0 || catalogId != null) {
          return Optional.empty();
        }
        catalogId = AppCatalog.normalizeCatalogId(line.substring(separator + 1));
      }
      return Optional.ofNullable(catalogId);
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  /**
   * Removes one required property from a mutable parsed record.
   *
   * @param fields remaining parsed properties
   * @param key required property name
   * @return removed property value
   */
  static String remove(Map<String, String> fields, String key) {
    String value = fields.remove(key);
    if (value == null) {
      throw invalid("missing federation policy property: " + key);
    }
    return value;
  }

  /**
   * Removes and parses the required closed schema version.
   *
   * @param fields remaining parsed properties
   * @return parsed integer schema version
   */
  static int parseVersion(Map<String, String> fields) {
    try {
      return Integer.parseInt(remove(fields, "schemaVersion"));
    } catch (NumberFormatException exception) {
      throw invalid("invalid federation policy schema version", exception);
    }
  }

  /**
   * Removes and parses one required timestamp.
   *
   * @param fields remaining parsed properties
   * @param key timestamp property name
   * @return parsed instant
   */
  static Instant parseInstant(Map<String, String> fields, String key) {
    try {
      return Instant.parse(remove(fields, key));
    } catch (RuntimeException exception) {
      throw invalid("invalid " + key, exception);
    }
  }

  /**
   * Splits a canonical comma-delimited field while preserving closed empty semantics.
   *
   * @param value serialized list value
   * @return immutable list of serialized members
   */
  static List<String> split(String value) {
    return value.isBlank() ? List.of() : List.of(value.split(",", -1));
  }

  /**
   * Rejects properties not consumed by the owning closed model parser.
   *
   * @param fields remaining parsed properties
   */
  static void requireClosed(Map<String, String> fields) {
    if (!fields.isEmpty()) {
      throw invalid("unsupported federation policy property: " + fields.keySet().iterator().next());
    }
  }

  /**
   * Requires a non-symbolic-link directory or an absent path suitable for creation.
   *
   * @param root policy-store root
   */
  static void requireSafeRoot(Path root) {
    if (Files.isSymbolicLink(root)
        || (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
            && !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
      throw invalid("federation policy store root is not a directory");
    }
  }

  /**
   * Writes one UTF-8 policy record through a confined temporary file and replacement move.
   *
   * @param root confined policy-store root
   * @param target final record path
   * @param text canonical serialized record
   * @param temporaryPrefix bounded temporary-file prefix
   * @throws IOException if creation, writing, replacement, or cleanup fails
   */
  static void atomicWrite(Path root, Path target, String text, String temporaryPrefix)
      throws IOException {
    Files.createDirectories(root);
    requireSafeRoot(root);
    Path temporary = Files.createTempFile(root, temporaryPrefix, ".tmp");
    try {
      Files.writeString(temporary, text, StandardCharsets.UTF_8);
      try {
        Files.move(
            temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      } catch (AtomicMoveNotSupportedException _) {
        Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  /**
   * Creates a stable federation-policy validation failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception carrying the stable policy error code
   */
  static AppCatalogException invalid(String message) {
    return new AppCatalogException("invalid_federation_policy", message);
  }

  /**
   * Creates a stable federation-policy validation failure with its cause.
   *
   * @param message bounded validation explanation
   * @param cause underlying parse or persistence failure
   * @return catalog exception carrying the stable policy error code
   */
  static AppCatalogException invalid(String message, Exception cause) {
    return new AppCatalogException("invalid_federation_policy", message, cause);
  }
}
