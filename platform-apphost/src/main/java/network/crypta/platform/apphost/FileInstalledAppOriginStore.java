package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Atomic, path-confined persistence for current and rollback app-origin provenance.
 *
 * <p>Each application has one current record and at most one rollback record below a host-private
 * root. Writes use a same-directory temporary file and an atomic move when the file system supports
 * it. Reads reject links, non-regular files, oversized records, unknown fields, and app identifiers
 * that do not match the confined file name. The store contains no source URI, token, private path,
 * or raw app content, and it is intended to remain inaccessible to app processes.
 *
 * <p>Public operations synchronize on the store instance so current and rollback slots cannot be
 * interleaved by callers sharing that instance. Higher-level AppHost transaction coordination is
 * still responsible for keeping these provenance records aligned with the corresponding bundle
 * directories across installation, update, rollback, and recovery.
 */
public final class FileInstalledAppOriginStore {
  /** Maximum accepted serialized origin-record size. */
  private static final long MAX_BYTES = 64 * 1024L;

  /** File suffix used for each confined serialized provenance record. */
  private static final String RECORD_SUFFIX = ".properties";

  /** Absolute normalized private root for current provenance records. */
  private final Path root;

  /** Confined child directory holding provenance for retained rollback bundles. */
  private final Path rollbackRoot;

  /**
   * Creates a store below the supplied host-private root.
   *
   * @param root dedicated host-private directory for installed-origin records
   */
  public FileInstalledAppOriginStore(Path root) {
    this.root = root.toAbsolutePath().normalize();
    this.rollbackRoot = this.root.resolve("rollback");
  }

  /**
   * Records a new current origin and retains the previous exact origin for rollback.
   *
   * <p>If a current record exists, the method first copies its validated text to the rollback slot
   * and then atomically replaces the current record. Callers coordinate this operation with the
   * corresponding bundle installation.
   *
   * @param origin validated provenance for the newly installed application revision
   * @throws IOException if the confined store cannot be validated or written atomically
   */
  public synchronized void put(InstalledAppOrigin origin) throws IOException {
    InstalledAppOrigin checked = java.util.Objects.requireNonNull(origin, "origin");
    Files.createDirectories(root);
    Files.createDirectories(rollbackRoot);
    requireSafeRoots();
    Path current = path(root, checked.appId());
    if (Files.isRegularFile(current, LinkOption.NOFOLLOW_LINKS)) {
      atomicWrite(path(rollbackRoot, checked.appId()), Files.readString(current));
    } else {
      Files.deleteIfExists(path(rollbackRoot, checked.appId()));
    }
    atomicWrite(current, checked.canonicalText());
  }

  /**
   * Reads current provenance for one app.
   *
   * @param appId normalized application identifier to look up
   * @return current validated provenance, or an empty result when none exists
   * @throws IOException if a present record is unsafe, malformed, substituted, or unreadable
   */
  public synchronized Optional<InstalledAppOrigin> find(String appId) throws IOException {
    return readIfPresent(path(root, appId));
  }

  /**
   * Returns whether exact rollback provenance exists for an app.
   *
   * @param appId normalized application identifier to inspect
   * @return {@code true} only when a valid rollback provenance record is present
   * @throws IOException if a present rollback record is unsafe, malformed, or unreadable
   */
  public synchronized boolean hasRollback(String appId) throws IOException {
    return readIfPresent(path(rollbackRoot, appId)).isPresent();
  }

  /**
   * Captures the exact current and rollback records before a coordinated bundle mutation.
   *
   * @param appId normalized application identifier whose slots are read
   * @return immutable snapshot that preserves present and explicitly absent provenance slots
   * @throws IOException if a present record or the confined store root is invalid
   */
  public synchronized State snapshot(String appId) throws IOException {
    return new State(find(appId), readIfPresent(path(rollbackRoot, appId)));
  }

  /**
   * Captures every current and rollback provenance record in deterministic app-id order.
   *
   * @return immutable map from normalized app id to its exact provenance slots
   * @throws IOException if a present record or either confined store root is invalid
   */
  public synchronized Map<String, State> snapshotAll() throws IOException {
    requireSafeRoots();
    Set<String> appIds = new LinkedHashSet<>();
    collectAppIds(root, appIds);
    collectAppIds(rollbackRoot, appIds);
    LinkedHashMap<String, State> states = new LinkedHashMap<>();
    for (String appId : appIds.stream().sorted().toList()) {
      states.put(appId, snapshot(appId));
    }
    return Collections.unmodifiableMap(states);
  }

  /**
   * Restores an exact snapshot after a coordinated bundle mutation fails.
   *
   * @param appId normalized application identifier whose slots are restored
   * @param state exact snapshot captured before the failed mutation began
   * @throws IOException if either confined slot cannot be restored or removed
   */
  public synchronized void restore(String appId, State state) throws IOException {
    java.util.Objects.requireNonNull(state, "state");
    Files.createDirectories(root);
    Files.createDirectories(rollbackRoot);
    requireSafeRoots();
    restoreRecord(path(root, appId), state.current().orElse(null));
    restoreRecord(path(rollbackRoot, appId), state.rollback().orElse(null));
  }

  /**
   * Swaps current and rollback provenance after AppHost swaps the same bundles.
   *
   * <p>Both slots are parsed before either replacement is attempted. One slot may be absent to
   * represent an explicitly retained legacy bundle that predates origin persistence; swapping to
   * that bundle removes current provenance rather than fabricating an origin.
   *
   * @param appId normalized application identifier whose origins are exchanged
   * @throws IOException if both slots are absent, a present record is invalid or unsafe, or either
   *     slot cannot be replaced
   */
  public synchronized void swapRollback(String appId) throws IOException {
    State state = snapshot(appId);
    if (state.current().isEmpty() && state.rollback().isEmpty()) {
      throw new AppHostException("rollback origin is not available: " + appId);
    }
    try {
      restoreRecord(path(root, appId), state.rollback().orElse(null));
      restoreRecord(path(rollbackRoot, appId), state.current().orElse(null));
    } catch (IOException exception) {
      try {
        restore(appId, state);
      } catch (IOException restoreFailure) {
        exception.addSuppressed(restoreFailure);
      }
      throw exception;
    }
  }

  /**
   * Deletes current and rollback provenance during uninstall.
   *
   * @param appId normalized application identifier whose provenance is removed
   * @throws IOException if either confined record cannot be deleted
   */
  public synchronized void remove(String appId) throws IOException {
    requireSafeRoots();
    Path current = path(root, appId);
    Path rollback = path(rollbackRoot, appId);
    Files.deleteIfExists(current);
    Files.deleteIfExists(rollback);
  }

  /**
   * Replaces or removes one exact provenance slot during compensation.
   *
   * @param path confined slot path
   * @param origin exact provenance to restore, or {@code null} for an absent slot
   * @throws IOException if the slot cannot be replaced or removed
   */
  private static void restoreRecord(Path path, InstalledAppOrigin origin) throws IOException {
    if (origin != null) {
      atomicWrite(path, origin.canonicalText());
    } else {
      Files.deleteIfExists(path);
    }
  }

  /**
   * Exact path-free provenance slots used only for local transaction compensation.
   *
   * @param current current installed-bundle provenance, or empty for a legacy bundle
   * @param rollback retained rollback-bundle provenance, or empty when none was recorded
   */
  public record State(Optional<InstalledAppOrigin> current, Optional<InstalledAppOrigin> rollback) {
    /** Validates that both exact provenance slots have explicit presence semantics. */
    public State {
      java.util.Objects.requireNonNull(current, "current");
      java.util.Objects.requireNonNull(rollback, "rollback");
    }
  }

  /**
   * Reads one slot when its confined record exists.
   *
   * @param path confined origin-record path
   * @return validated origin, or empty when the slot is absent
   * @throws IOException if a present record cannot be read
   */
  private Optional<InstalledAppOrigin> readIfPresent(Path path) throws IOException {
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path));
  }

  /**
   * Adds the normalized app identifiers represented by safe records in one provenance directory.
   *
   * @param directory current or rollback provenance directory to inspect
   * @param appIds destination set that receives each validated application identifier
   * @throws IOException if the directory cannot be listed or contains an invalid record name
   */
  private static void collectAppIds(Path directory, Set<String> appIds) throws IOException {
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try (var records = Files.list(directory)) {
      for (Path originRecord : records.toList()) {
        Path recordFileName = originRecord.getFileName();
        if (recordFileName == null) {
          throw new AppHostException("installed-origin record has no file name");
        }
        String fileName = recordFileName.toString();
        if (!fileName.endsWith(RECORD_SUFFIX)
            || !Files.isRegularFile(originRecord, LinkOption.NOFOLLOW_LINKS)
            || Files.isSymbolicLink(originRecord)) {
          continue;
        }
        String appId = fileName.substring(0, fileName.length() - RECORD_SUFFIX.length());
        if (!InstalledAppPaths.normalizeAppId(appId).equals(appId)) {
          throw new AppHostException("installed-origin record has an invalid app id");
        }
        appIds.add(appId);
      }
    }
  }

  /**
   * Parses and validates one closed installed-origin record.
   *
   * @param path confined origin-record path
   * @return validated installed provenance
   * @throws IOException if the record is unsafe, malformed, or unreadable
   */
  private InstalledAppOrigin read(Path path) throws IOException {
    requireSafeRoots();
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)
        || Files.size(path) > MAX_BYTES) {
      throw new AppHostException("installed-origin record is not a bounded regular file");
    }
    Map<String, String> fields = parse(Files.readString(path, StandardCharsets.UTF_8));
    try {
      int schemaVersion = Integer.parseInt(remove(fields, "schemaVersion"));
      InstalledAppOrigin origin =
          new InstalledAppOrigin(
              schemaVersion,
              remove(fields, "appId"),
              remove(fields, "appVersion"),
              remove(fields, "bundleSha256"),
              remove(fields, "catalogId"),
              remove(fields, "catalogSignerKeyId"),
              remove(fields, "catalogSignerFingerprintSha256"),
              remove(fields, "catalogRevisionDigestSha256"),
              remove(fields, "publisherKeyId"),
              remove(fields, "publisherKeyFingerprintSha256"),
              schemaVersion >= InstalledAppOrigin.CURRENT_SCHEMA_VERSION
                  ? remove(fields, "signedContentDigestSha256")
                  : "",
              remove(fields, "reviewReceiptFingerprintSha256"),
              remove(fields, "reviewStatus"),
              remove(fields, "catalogTrustBindingId"),
              remove(fields, "catalogTrustBindingDigestSha256"),
              remove(fields, "publisherPolicyDigestSha256"),
              remove(fields, "reviewerPolicyDigestSha256"),
              Instant.parse(remove(fields, "installedAt")),
              optional(remove(fields, "previousOriginDigestSha256")),
              remove(fields, "selfDigestSha256"));
      if (!fields.isEmpty()) {
        throw new AppHostException(
            "unsupported installed-origin property: " + fields.keySet().iterator().next());
      }
      Path fileName = path.getFileName();
      if (fileName == null || !fileName.toString().equals(origin.appId() + RECORD_SUFFIX)) {
        throw new AppHostException("installed-origin app id does not match file name");
      }
      return origin;
    } catch (IllegalArgumentException | DateTimeParseException exception) {
      throw new AppHostException("invalid installed-origin record", exception);
    }
  }

  /**
   * Requires both configured roots to be absent or non-symbolic-link directories.
   *
   * @throws IOException if either root is unsafe
   */
  private void requireSafeRoots() throws IOException {
    for (Path directory : java.util.List.of(root, rollbackRoot)) {
      if (Files.isSymbolicLink(directory)
          || (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)
              && !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))) {
        throw new AppHostException("installed-origin store root is unsafe");
      }
    }
  }

  /**
   * Resolves one normalized application identity below a provenance directory.
   *
   * @param directory confined current or rollback directory
   * @param appId application identity
   * @return confined normalized record path
   * @throws AppHostException if the app identity or resolved path is invalid
   */
  private static Path path(Path directory, String appId) throws AppHostException {
    String normalized = InstalledAppPaths.normalizeAppId(appId);
    Path path = directory.resolve(normalized + RECORD_SUFFIX).normalize();
    if (!directory.equals(path.getParent())) {
      throw new AppHostException("installed-origin path escapes store root");
    }
    return path;
  }

  /**
   * Writes canonical provenance through a same-directory temporary replacement.
   *
   * @param target confined final record path
   * @param content canonical serialized provenance
   * @throws IOException if creation, writing, replacement, or cleanup fails
   */
  private static void atomicWrite(Path target, String content) throws IOException {
    Path parent = target.getParent();
    if (parent == null) {
      throw new AppHostException("installed-origin target has no confined parent");
    }
    Files.createDirectories(parent);
    Path temporary = Files.createTempFile(parent, ".origin-", ".tmp");
    try {
      Files.writeString(temporary, content, StandardCharsets.UTF_8);
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
   * Parses unique properties from one serialized provenance record.
   *
   * @param text serialized UTF-8 record text
   * @return insertion-ordered mutable properties
   * @throws AppHostException if a line or property is invalid
   */
  private static Map<String, String> parse(String text) throws AppHostException {
    LinkedHashMap<String, String> result = new LinkedHashMap<>();
    for (String line : text.split("\\n", -1)) {
      if (line.isEmpty()) {
        continue;
      }
      int separator = line.indexOf('=');
      if (separator <= 0) {
        throw new AppHostException("invalid installed-origin line");
      }
      if (result.putIfAbsent(line.substring(0, separator), line.substring(separator + 1)) != null) {
        throw new AppHostException("duplicate installed-origin property");
      }
    }
    return result;
  }

  /**
   * Removes one required property from a parsed record.
   *
   * @param fields remaining parsed properties
   * @param name required property name
   * @return removed property value
   * @throws AppHostException if the property is absent
   */
  private static String remove(Map<String, String> fields, String name) throws AppHostException {
    String value = fields.remove(name);
    if (value == null) {
      throw new AppHostException("missing installed-origin property: " + name);
    }
    return value;
  }

  /**
   * Interprets the canonical empty-string representation of an optional value.
   *
   * @param value serialized property value
   * @return optional nonempty value
   */
  private static Optional<String> optional(String value) {
    return value.isEmpty() ? Optional.empty() : Optional.of(value);
  }
}
