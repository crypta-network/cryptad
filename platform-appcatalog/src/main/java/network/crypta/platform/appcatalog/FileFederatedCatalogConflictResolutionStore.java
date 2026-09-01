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
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Atomic host-owned persistence for digest-bound local catalog conflict resolutions.
 *
 * <p>Each record is routed by a hash of its app ID and contains both the exact conflict-set digest
 * and the resolution's own digest. Lookups distinguish missing, applicable, and stale decisions.
 * Read leases retain that result across a host mutation, while writes use a shared fair lock and
 * confined replacement files so another store instance cannot race a commit.
 */
public final class FileFederatedCatalogConflictResolutionStore {
  /** Closed on-disk envelope schema version. */
  private static final int SCHEMA_VERSION = 1;

  /** Filename suffix for serialized resolutions. */
  private static final String SUFFIX = ".properties";

  /** Maximum accepted serialized resolution size. */
  private static final long MAX_RECORD_BYTES = 16 * 1024L;

  /** Fair mutation fences shared by stores addressing the same normalized root. */
  private static final ConcurrentMap<Path, CatalogMutationFence> MUTATION_FENCES =
      new ConcurrentHashMap<>();

  /** Absolute normalized private resolution-store root. */
  private final Path root;

  /** Store-wide fence coordinating decisions with retained lookups. */
  private final CatalogMutationFence mutationFence;

  /** Single-use lease fencing conflict-resolution replacement through a host mutation. */
  @FunctionalInterface
  public interface AuthorizationLease extends AutoCloseable {
    /** Releases the retained local conflict policy. */
    @Override
    void close();
  }

  /** Describes whether a stored decision is absent, exact, or stale for a current conflict set. */
  public enum LookupStatus {
    /** No local resolution exists for the application. */
    MISSING,
    /** The stored decision binds the exact current conflict subjects. */
    APPLICABLE,
    /** A stored decision exists but its bound subjects have changed. */
    STALE
  }

  /**
   * One fail-closed lookup result, optionally carrying the stored decision for local display.
   *
   * @param status relationship between the stored decision and current conflict subjects
   * @param resolution stored local decision, absent only when the lookup status is missing
   */
  public record Lookup(
      LookupStatus status, Optional<FederatedCatalogConflictEngine.Resolution> resolution) {
    /** Validates the closed relationship between lookup status and optional decision. */
    public Lookup {
      Objects.requireNonNull(status, "status");
      Objects.requireNonNull(resolution, "resolution");
      if ((status == LookupStatus.MISSING) != resolution.isEmpty()) {
        throw new IllegalArgumentException("missing lookups must not carry a resolution");
      }
    }

    /**
     * Returns whether the stored decision binds the exact current conflict subjects.
     *
     * @return {@code true} only for an exact applicable lookup
     */
    public boolean applicable() {
      return status == LookupStatus.APPLICABLE;
    }
  }

  /**
   * Exact lookup result retained against concurrent local resolution replacement.
   *
   * @param lookup fail-closed relationship to the current conflict subjects
   * @param authorization lease retaining that relationship until closed
   */
  public record RetainedLookup(Lookup lookup, AuthorizationLease authorization)
      implements AutoCloseable {
    /** Validates the retained lookup and its required authorization lease. */
    public RetainedLookup {
      Objects.requireNonNull(lookup, "lookup");
      Objects.requireNonNull(authorization, "authorization");
    }

    /** Releases the resolution-store read lease. */
    @Override
    public void close() {
      authorization.close();
    }
  }

  /**
   * Creates a store rooted in a host-private directory.
   *
   * @param root private directory containing conflict-resolution records
   */
  public FileFederatedCatalogConflictResolutionStore(Path root) {
    this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
    mutationFence = MUTATION_FENCES.computeIfAbsent(this.root, _ -> new CatalogMutationFence());
  }

  /**
   * Looks up and retains the exact current resolution through one host mutation.
   *
   * <p>The lookup occurs after acquiring the shared read lease, so the returned result and its
   * absence are both stable until {@link RetainedLookup#close()} is called. Resolution writes
   * through any store instance rooted at the same path wait for that close.
   *
   * @param current exact current conflict set
   * @return lookup result with a retained read authorization
   * @throws IOException if the stored decision cannot be read
   */
  public synchronized RetainedLookup retainLookup(
      FederatedCatalogConflictEngine.ConflictSet current) throws IOException {
    CatalogMutationFence.Authorized<Lookup> authorized =
        mutationFence.authorizeRead(() -> lookup(Objects.requireNonNull(current, "current")));
    try (var leaseTransfer = new AuthorizationLeaseTransfer(authorized.authorization())) {
      return new RetainedLookup(authorized.value(), leaseTransfer.transfer());
    }
  }

  /** Closes a retained fence authorization unless ownership transfers to a returned lookup. */
  private static final class AuthorizationLeaseTransfer implements AutoCloseable {
    /** Authorization still owned by this guard, or {@code null} after transfer. */
    private AppCatalogManager.CatalogTrustAuthorization authorization;

    /** Creates a guard that initially owns the supplied fence authorization. */
    private AuthorizationLeaseTransfer(AppCatalogManager.CatalogTrustAuthorization authorization) {
      this.authorization = Objects.requireNonNull(authorization, "authorization");
    }

    /** Transfers authorization ownership to the returned retained lookup. */
    private AuthorizationLease transfer() {
      AppCatalogManager.CatalogTrustAuthorization transferred = authorization;
      authorization = null;
      return transferred::close;
    }

    @Override
    public void close() {
      if (authorization != null) {
        authorization.close();
      }
    }
  }

  /**
   * Atomically records a decision only when it binds the exact supplied conflict set.
   *
   * <p>The app ID is stored in the host-owned envelope so a later conflict-set change can be
   * reported as stale even though the deterministic conflict ID also changes.
   *
   * @param conflictSet exact current conflict subjects being resolved
   * @param resolution exact digest-bound local decision
   * @throws IOException if the record cannot be written atomically
   */
  public synchronized void put(
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FederatedCatalogConflictEngine.Resolution resolution)
      throws IOException {
    mutationFence.withWriteLock(() -> putUnderFence(conflictSet, resolution));
  }

  /** Validates and persists one resolution while the mutation fence is exclusive. */
  private void putUnderFence(
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FederatedCatalogConflictEngine.Resolution resolution)
      throws IOException {
    FederatedCatalogConflictEngine.ConflictSet checkedConflict =
        Objects.requireNonNull(conflictSet, "conflictSet");
    FederatedCatalogConflictEngine.Resolution checkedResolution =
        Objects.requireNonNull(resolution, "resolution");
    if (!checkedResolution.appliesTo(checkedConflict)) {
      throw invalid("conflict resolution does not bind the exact conflict set");
    }
    requireRecordText(checkedResolution.conflictId(), "conflictId");
    requireRecordText(checkedResolution.reason(), "reason");
    validateSelectedSubject(checkedConflict, checkedResolution);
    Files.createDirectories(root);
    requireSafeRoot();
    Path target = recordPath(checkedConflict.appId());
    String text = canonicalText(checkedConflict.appId(), checkedResolution);
    Path temporary = Files.createTempFile(root, ".catalog-conflict-resolution-", ".tmp");
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
   * Reads the stored decision for an app, rejecting malformed or substituted records.
   *
   * @param appId exact application identity
   * @return validated stored decision, or empty when absent
   * @throws IOException if an existing record cannot be read
   */
  public synchronized Optional<FederatedCatalogConflictEngine.Resolution> find(String appId)
      throws IOException {
    String normalized = AppCatalogEntry.normalizeAppId(appId);
    Path path = recordPath(normalized);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path, normalized));
  }

  /**
   * Compares the stored decision with the current conflict set without accepting stale consent.
   *
   * <p>A stale result includes the historical decision for bounded operator display, but callers
   * must use {@link Lookup#applicable()} before applying it.
   *
   * @param current exact current conflict subjects
   * @return fail-closed relationship between the stored and current subjects
   * @throws IOException if an existing record cannot be read
   */
  public synchronized Lookup lookup(FederatedCatalogConflictEngine.ConflictSet current)
      throws IOException {
    FederatedCatalogConflictEngine.ConflictSet checked = Objects.requireNonNull(current, "current");
    Optional<FederatedCatalogConflictEngine.Resolution> stored = find(checked.appId());
    if (stored.isEmpty()) {
      return new Lookup(LookupStatus.MISSING, Optional.empty());
    }
    LookupStatus status =
        stored.orElseThrow().appliesTo(checked) ? LookupStatus.APPLICABLE : LookupStatus.STALE;
    return new Lookup(status, stored);
  }

  /**
   * Parses and validates one resolution envelope and its canonical digest.
   *
   * @param path confined record path
   * @param expectedAppId normalized app identity derived by the caller
   * @return validated local conflict resolution
   * @throws IOException if the record cannot be read
   */
  private FederatedCatalogConflictEngine.Resolution read(Path path, String expectedAppId)
      throws IOException {
    requireSafeRoot();
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
      throw invalid("catalog conflict resolution is not a regular file");
    }
    byte[] bytes = Files.readAllBytes(path);
    if (bytes.length > MAX_RECORD_BYTES) {
      throw invalid("catalog conflict resolution exceeds the size limit");
    }
    String text = new String(bytes, StandardCharsets.UTF_8);
    Map<String, String> fields = parse(text);
    int schemaVersion = parseSchemaVersion(remove(fields, "schemaVersion"));
    if (schemaVersion != SCHEMA_VERSION) {
      throw invalid("unsupported catalog conflict resolution schema version");
    }
    String appId = AppCatalogEntry.normalizeAppId(remove(fields, "appId"));
    if (!appId.equals(expectedAppId) || !path.equals(recordPath(appId))) {
      throw invalid("catalog conflict resolution app id does not match its record path");
    }
    String conflictId = remove(fields, "conflictId");
    String subjectSetDigest = remove(fields, "subjectSetDigest");
    FederatedCatalogConflictEngine.ResolutionKind kind = parseKind(remove(fields, "kind"));
    Optional<String> catalogId = optional(remove(fields, "catalogId"));
    Optional<String> publisherFingerprint = optional(remove(fields, "publisherFingerprint"));
    Instant decidedAt = parseDecidedAt(remove(fields, "decidedAt"));
    String reason = remove(fields, "reason");
    String resolutionSelfDigest = remove(fields, "resolutionSelfDigest");
    String recordSelfDigest = remove(fields, "recordSelfDigest");
    if (!fields.isEmpty()) {
      throw invalid(
          "unsupported catalog conflict resolution property: " + fields.keySet().iterator().next());
    }
    FederatedCatalogConflictEngine.Resolution resolution =
        new FederatedCatalogConflictEngine.Resolution(
            conflictId,
            subjectSetDigest,
            kind,
            catalogId,
            publisherFingerprint,
            decidedAt,
            reason,
            resolutionSelfDigest);
    String expectedRecordDigest = sha256(canonicalBody(appId, resolution));
    if (!expectedRecordDigest.equals(requireRecordSelfDigest(recordSelfDigest))) {
      throw invalid("catalog conflict resolution record digest does not match");
    }
    if (!text.equals(canonicalText(appId, resolution))) {
      throw invalid("catalog conflict resolution is not canonical");
    }
    return resolution;
  }

  /**
   * Resolves a hashed app identity below the store root.
   *
   * @param appId exact application identity
   * @return confined normalized record path
   */
  private Path recordPath(String appId) {
    String normalized = AppCatalogEntry.normalizeAppId(appId);
    Path path = root.resolve(sha256(normalized) + SUFFIX).normalize();
    if (!root.equals(path.getParent())) {
      throw invalid("catalog conflict resolution path escapes store root");
    }
    return path;
  }

  /** Requires the configured root to be absent or a non-symbolic-link directory. */
  private void requireSafeRoot() {
    if (Files.isSymbolicLink(root)
        || (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
            && !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
      throw invalid("catalog conflict resolution store root is not a directory");
    }
  }

  /**
   * Requires any catalog or publisher selection to name an exact conflict subject.
   *
   * @param conflictSet exact current conflict subjects
   * @param resolution proposed local decision
   */
  private static void validateSelectedSubject(
      FederatedCatalogConflictEngine.ConflictSet conflictSet,
      FederatedCatalogConflictEngine.Resolution resolution) {
    if (resolution.catalogId().isPresent()
        && conflictSet.subjects().stream()
            .noneMatch(
                subject -> subject.catalogId().equals(resolution.catalogId().orElseThrow()))) {
      throw invalid("catalog resolution does not select a conflict subject");
    }
    if (resolution.publisherFingerprint().isPresent()
        && conflictSet.subjects().stream()
            .noneMatch(
                subject ->
                    subject
                        .publisherFingerprint()
                        .equals(resolution.publisherFingerprint().orElseThrow()))) {
      throw invalid("publisher resolution does not select a conflict subject");
    }
  }

  /**
   * Builds the complete canonical record including its envelope digest.
   *
   * @param appId exact application identity
   * @param resolution validated local decision
   * @return deterministic newline-terminated record text
   */
  private static String canonicalText(
      String appId, FederatedCatalogConflictEngine.Resolution resolution) {
    String body = canonicalBody(appId, resolution);
    return body + "recordSelfDigest=" + sha256(body) + "\n";
  }

  /**
   * Builds the canonical record body covered by the envelope digest.
   *
   * @param appId exact application identity
   * @param resolution validated local decision
   * @return deterministic newline-terminated digest subject
   */
  private static String canonicalBody(
      String appId, FederatedCatalogConflictEngine.Resolution resolution) {
    return String.join(
            "\n",
            "schemaVersion=" + SCHEMA_VERSION,
            "appId=" + appId,
            "conflictId=" + resolution.conflictId(),
            "subjectSetDigest=" + resolution.subjectSetDigest(),
            "kind=" + resolution.kind().name(),
            "catalogId=" + resolution.catalogId().orElse(""),
            "publisherFingerprint=" + resolution.publisherFingerprint().orElse(""),
            "decidedAt=" + resolution.decidedAt(),
            "reason=" + resolution.reason(),
            "resolutionSelfDigest=" + resolution.selfDigest())
        + "\n";
  }

  /**
   * Parses unique properties from one serialized record.
   *
   * @param text serialized UTF-8 record text
   * @return insertion-ordered mutable properties
   */
  private static Map<String, String> parse(String text) {
    LinkedHashMap<String, String> fields = new LinkedHashMap<>();
    for (String line : text.split("\\n", -1)) {
      if (line.isEmpty()) {
        continue;
      }
      int separator = line.indexOf('=');
      if (separator <= 0 || line.indexOf('\r') >= 0) {
        throw invalid("invalid catalog conflict resolution line");
      }
      String previous = fields.put(line.substring(0, separator), line.substring(separator + 1));
      if (previous != null) {
        throw invalid("duplicate catalog conflict resolution property");
      }
    }
    return fields;
  }

  /**
   * Removes one required property from a parsed record.
   *
   * @param fields remaining parsed properties
   * @param key required property name
   * @return removed property value
   */
  private static String remove(Map<String, String> fields, String key) {
    String value = fields.remove(key);
    if (value == null) {
      throw invalid("missing catalog conflict resolution property: " + key);
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

  /**
   * Parses the closed record schema version.
   *
   * @param value serialized integer
   * @return parsed schema version
   */
  private static int parseSchemaVersion(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException exception) {
      throw invalid("invalid schemaVersion", exception);
    }
  }

  /**
   * Parses the required decision timestamp.
   *
   * @param value serialized instant
   * @return parsed decision timestamp
   */
  private static Instant parseDecidedAt(String value) {
    try {
      return Instant.parse(value);
    } catch (RuntimeException exception) {
      throw invalid("invalid decidedAt", exception);
    }
  }

  /**
   * Parses the closed local resolution kind.
   *
   * @param value serialized enum name
   * @return parsed resolution kind
   */
  private static FederatedCatalogConflictEngine.ResolutionKind parseKind(String value) {
    try {
      return FederatedCatalogConflictEngine.ResolutionKind.valueOf(value);
    } catch (RuntimeException exception) {
      throw invalid("invalid conflict resolution kind", exception);
    }
  }

  /**
   * Requires the canonical resolution-envelope digest grammar.
   *
   * @param value serialized digest
   * @return validated lowercase SHA-256 digest
   */
  private static String requireRecordSelfDigest(String value) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw invalid("recordSelfDigest must be SHA-256");
    }
    return value;
  }

  /**
   * Rejects control characters in persisted operator-visible text.
   *
   * @param value record value to inspect
   * @param field field name used in failures
   */
  private static void requireRecordText(String value, String field) {
    if (value.chars().anyMatch(Character::isISOControl)) {
      throw invalid(field + " contains unsupported control text");
    }
  }

  /**
   * Computes lowercase SHA-256 over UTF-8 text.
   *
   * @param value digest subject
   * @return lowercase hexadecimal digest
   */
  private static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /**
   * Creates the stable invalid-store failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception with the stable store error code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException("invalid_catalog_conflict_resolution_store", message);
  }

  /**
   * Creates the stable invalid-store failure with its cause.
   *
   * @param message bounded validation explanation
   * @param cause underlying parse failure
   * @return catalog exception with the stable store error code
   */
  private static AppCatalogException invalid(String message, Exception cause) {
    return new AppCatalogException("invalid_catalog_conflict_resolution_store", message, cause);
  }
}
