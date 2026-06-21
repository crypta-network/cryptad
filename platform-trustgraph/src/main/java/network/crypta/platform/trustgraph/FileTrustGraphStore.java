package network.crypta.platform.trustgraph;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;
import org.jetbrains.annotations.Nullable;

/**
 * File-backed local store for Trust Graph RC anchors, statements, lifecycle, and audit events.
 *
 * <p>The store is rooted below a platform-owned app-service data directory such as {@code
 * <app-host-data-dir>/apps/trust-graph}. It stores only local anchors, normalized public trust
 * statement documents, sanitized source metadata, and redacted audit summaries. It never stores raw
 * request bodies, raw fetched content outside the normalized public statement document, private
 * insert URIs, private identity material, tokens, form passwords, or local filesystem paths in
 * returned errors.
 *
 * <p>Each record is written through a temporary file in the target directory, fsynced where the
 * filesystem allows it, and then moved into place with atomic replace when supported. Read paths
 * skip corrupt, incomplete, over-limit, or mismatched records so one bad persisted entry does not
 * prevent other local trust graph state from loading.
 *
 * <p>The implementation is synchronized at the public method boundary. Callers can share one
 * instance across Platform API requests without adding external locking, and every returned list is
 * an immutable snapshot. This class is intentionally a local RC service store, not a network
 * crawler or a node-wide policy source. Scores produced from its contents stay local to the app
 * platform trust graph API.
 *
 * <p>Important persistence behaviors:
 *
 * <ul>
 *   <li>Statement import is idempotent by document fingerprint and refreshes source metadata for an
 *       existing document.
 *   <li>Anchor replacement preserves the configured anchor cap and does not evict unrelated
 *       anchors.
 *   <li>Retention cleanup is best-effort during cap eviction but explicit anchor removal fails if
 *       the durable backing file cannot be deleted.
 *   <li>Directory creation rejects symlinked managed path segments so records cannot escape the
 *       app-platform data tree.
 * </ul>
 */
public final class FileTrustGraphStore implements TrustGraphStore {
  private static final String ANCHORS_DIRECTORY = "anchors";
  private static final String STATEMENTS_DIRECTORY = "statements";
  private static final String AUDIT_DIRECTORY = "audit";
  private static final String LIFECYCLE_DIRECTORY = "lifecycle";
  private static final String FILE_SUFFIX = ".properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_ISSUER_FINGERPRINT = "issuerFingerprint";
  private static final String KEY_LABEL = "label";
  private static final String KEY_SOURCE = "source";
  private static final String KEY_CREATED_AT = "createdAt";
  private static final String KEY_DOCUMENT_FINGERPRINT = "documentFingerprint";
  private static final String KEY_PAYLOAD_HASH = "payloadHash";
  private static final String KEY_SIGNATURE_VERIFIED = "signatureVerified";
  private static final String KEY_SOURCE_URI = "sourceUri";
  private static final String KEY_SOURCE_LABEL = "sourceLabel";
  private static final String KEY_IMPORTED_AT = "importedAt";
  private static final String KEY_UPDATED_AT = "updatedAt";
  private static final String KEY_DOCUMENT_BYTES = "documentBytes";
  private static final String KEY_DOCUMENT_JSON = "documentJson";
  private static final String KEY_EVENT_TYPE = "eventType";
  private static final String KEY_TIMESTAMP = "timestamp";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_SUBJECT_KIND = "subjectKind";
  private static final String KEY_SUBJECT_URI_HASH = "subjectUriHash";
  private static final String KEY_SUBJECT_URI_SUMMARY = "subjectUriSummary";
  private static final String KEY_SOURCE_URI_HASH = "sourceUriHash";
  private static final String KEY_SOURCE_URI_KIND = "sourceUriKind";
  private static final String KEY_SUBSCRIPTION_ID = "subscriptionId";
  private static final String KEY_SOURCE_SUMMARY = "sourceSummary";
  private static final String KEY_STATUS_CODE = "statusCode";
  private static final String KEY_LIFECYCLE_STATUS = "lifecycleStatus";
  private static final String KEY_REASON_CODE = "reasonCode";
  private static final String KEY_NOTE = "note";
  private static final String KEY_REPLACEMENT_URI = "replacementUri";
  private static final String KEY_ACTOR_APP_ID = "actorAppId";
  private static final int MAX_PROPERTIES_FILE_BYTES = 1024 * 1024;

  private final Path rootDirectory;
  private final Path managedBoundaryDirectory;
  private final TrustGraphStoreConfig config;
  private final Clock clock;
  private final Map<String, TrustAnchor> anchors = new LinkedHashMap<>();
  private final Map<String, StoredTrustStatement> statements = new LinkedHashMap<>();
  private final Map<String, TrustStatementLifecycleRecord> lifecycleRecords = new LinkedHashMap<>();
  private final List<TrustGraphAuditEvent> auditEvents = new ArrayList<>();

  /**
   * Opens a file-backed store with default local RC limits and the system UTC clock.
   *
   * <p>This constructor is useful for production composition when the runtime has already chosen a
   * platform-owned Trust Graph RC state directory. The managed boundary defaults to the parent of
   * {@code rootDirectory}; use {@link #FileTrustGraphStore(Path, Path)} when the caller can provide
   * the app-host data root explicitly.
   *
   * @param rootDirectory platform-owned trust graph state root containing managed record
   *     directories
   * @throws TrustGraphException when the directory tree cannot be created or safely opened
   */
  @SuppressWarnings("unused")
  public FileTrustGraphStore(Path rootDirectory) {
    this(rootDirectory, TrustGraphStoreConfig.defaults(), Clock.systemUTC());
  }

  /**
   * Opens a file-backed store with explicit limits and clock.
   *
   * <p>Tests and reduced embeddings use this constructor to make timestamp-sensitive import and
   * audit behavior deterministic. The provided configuration is applied immediately during load, so
   * over-limit persisted records are trimmed before the instance is returned.
   *
   * @param rootDirectory platform-owned trust graph state root containing managed record
   *     directories
   * @param config positive retention caps and maximum canonical document byte limit
   * @param clock clock used for import, update, and caller-supplied audit metadata comparisons
   * @throws TrustGraphException when persisted state cannot be opened through the managed path
   */
  public FileTrustGraphStore(Path rootDirectory, TrustGraphStoreConfig config, Clock clock) {
    this.rootDirectory =
        java.util.Objects.requireNonNull(rootDirectory, "rootDirectory")
            .toAbsolutePath()
            .normalize();
    this.managedBoundaryDirectory = defaultManagedBoundary(this.rootDirectory);
    this.config = java.util.Objects.requireNonNull(config, "config");
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
    loadPersistedState();
  }

  /**
   * Opens a file-backed store below a platform-owned managed boundary.
   *
   * <p>The boundary should be the trusted app-platform data root. Directory creation then validates
   * and creates every trust-graph path segment beneath that root without following symlinks, so an
   * {@code apps} or {@code trust-graph} symlink cannot redirect durable local trust state outside
   * the managed tree.
   *
   * @param rootDirectory platform-owned trust graph state root containing managed record
   *     directories
   * @param managedBoundaryDirectory trusted app-platform data root containing {@code rootDirectory}
   * @throws TrustGraphException when the boundary or child path cannot be verified safely
   */
  public FileTrustGraphStore(Path rootDirectory, Path managedBoundaryDirectory) {
    this(
        rootDirectory,
        managedBoundaryDirectory,
        TrustGraphStoreConfig.defaults(),
        Clock.systemUTC());
  }

  /**
   * Opens a file-backed store below a platform-owned managed boundary with explicit limits.
   *
   * <p>This is the most explicit constructor and is preferred for runtime wiring. It keeps the
   * storage root, trusted boundary, retention policy, and clock visible at the composition site.
   * Construction loads existing records, skips invalid entries, and may apply cap eviction before
   * the store is used by any route handler.
   *
   * @param rootDirectory platform-owned trust graph state root containing managed record
   *     directories
   * @param managedBoundaryDirectory trusted app-platform data root containing {@code rootDirectory}
   * @param config positive retention caps and maximum canonical document byte limit
   * @param clock clock used for import, update, and caller-supplied audit metadata comparisons
   * @throws TrustGraphException when persisted state cannot be opened through the managed path
   */
  public FileTrustGraphStore(
      Path rootDirectory,
      Path managedBoundaryDirectory,
      TrustGraphStoreConfig config,
      Clock clock) {
    this.rootDirectory =
        java.util.Objects.requireNonNull(rootDirectory, "rootDirectory")
            .toAbsolutePath()
            .normalize();
    this.managedBoundaryDirectory =
        java.util.Objects.requireNonNull(managedBoundaryDirectory, "managedBoundaryDirectory")
            .toAbsolutePath()
            .normalize();
    this.config = java.util.Objects.requireNonNull(config, "config");
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
    loadPersistedState();
  }

  /**
   * Imports a parsed trust statement into durable local RC state.
   *
   * <p>The stored document is the canonical public statement representation derived from {@code
   * document}, not the caller's raw request or fetched response body. The import key is the
   * document fingerprint, so repeated imports of the same statement update source metadata and
   * {@code updatedAt} while preserving the original {@code importedAt}. Distinct statements are
   * retained until the configured statement cap is exceeded, at which point the oldest retained
   * entries are evicted.
   *
   * @param document parsed trust statement document to canonicalize and retain
   * @param source bounded source type such as {@code manual}, {@code content-fetch}, or {@code
   *     local-publish}
   * @param sourceUri optional Crypta content URI; only a redacted summary and hash are retained
   * @param sourceLabel optional caller-facing label for the import source
   * @return redacted import summary with document hashes, timestamps, and verification status
   * @throws TrustGraphException when the canonical document exceeds the byte cap or storage fails
   */
  @Override
  public synchronized TrustGraphImportResult importStatement(
      TrustStatementDocument document, String source, String sourceUri, String sourceLabel) {
    return importStatement(document, source, sourceUri, sourceLabel, null);
  }

  @Override
  public synchronized TrustGraphImportResult importStatement(
      TrustStatementDocument document,
      String source,
      String sourceUri,
      String sourceLabel,
      String subscriptionId) {
    String canonicalDocumentJson = TrustGraphStoreSanitizer.canonicalDocumentJson(document);
    int documentBytes = canonicalDocumentJson.getBytes(StandardCharsets.UTF_8).length;
    if (documentBytes > config.maxStoredDocumentBytes()) {
      throw new TrustGraphException(
          "trust_statement_too_large", "Trust statement document is too large.");
    }
    String documentFingerprint = TrustStatementFingerprint.documentFingerprint(document);
    String payloadHash = TrustStatementFingerprint.payloadHash(document);
    boolean signatureVerified = TrustStatementVerifier.isSignatureVerified(document);
    String normalizedSource = TrustGraphStoreSanitizer.normalizeSource(source);
    String normalizedSourceUri = TrustGraphStoreSanitizer.redactedUriSummary(sourceUri);
    String sourceUriHash = TrustGraphStoreSanitizer.sourceUriHash(sourceUri);
    String normalizedSourceLabel = TrustGraphStoreSanitizer.normalizeSourceLabel(sourceLabel);
    String sourceUriKind = TrustGraphStoreSanitizer.sourceUriKind(sourceUri);
    String normalizedSubscriptionId =
        TrustGraphStoreSanitizer.normalizeSubscriptionId(subscriptionId);
    StoredTrustStatement existing = statements.get(documentFingerprint);
    boolean imported = existing == null;
    Instant now = clock.instant();
    Instant importedAt = imported ? now : existing.importedAt();
    StoredTrustStatement stored =
        new StoredTrustStatement(
            document,
            documentFingerprint,
            payloadHash,
            signatureVerified,
            normalizedSource,
            normalizedSourceUri,
            sourceUriHash,
            normalizedSourceLabel,
            sourceUriKind,
            normalizedSubscriptionId,
            importedAt,
            now);
    writeStatement(stored, canonicalDocumentJson, documentBytes);
    statements.put(documentFingerprint, stored);
    evictEldestStatementsIfNeeded();
    return new TrustGraphImportResult(
        documentFingerprint,
        payloadHash,
        imported,
        signatureVerified,
        normalizedSource,
        normalizedSourceUri,
        sourceUriHash,
        normalizedSourceLabel,
        sourceUriKind,
        normalizedSubscriptionId,
        importedAt,
        now,
        document);
  }

  /**
   * Adds or replaces a durable local trust anchor.
   *
   * <p>Anchors are local operator/app RC inputs. Replacing an existing issuer fingerprint writes
   * the new record before the in-memory view changes, so a write failure leaves the previous state
   * intact. Adding a new issuer may evict the oldest anchor after the replacement has been
   * persisted.
   *
   * @param anchor validated local anchor metadata to persist under its issuer fingerprint
   * @return the anchor that is now visible from this store
   * @throws TrustGraphException when the anchor cannot be written durably
   */
  @Override
  public synchronized TrustAnchor addAnchor(TrustAnchor anchor) {
    boolean replacing = anchors.containsKey(anchor.issuerFingerprint());
    writeAnchor(anchor);
    anchors.put(anchor.issuerFingerprint(), anchor);
    if (!replacing) {
      evictEldestAnchorsIfNeeded();
    }
    return anchor;
  }

  /**
   * Removes a durable local trust anchor by issuer fingerprint.
   *
   * <p>The backing record is deleted before the in-memory map is updated. If the file cannot be
   * removed or the anchor directory is no longer a safe managed directory, the method throws and
   * the current in-memory anchor remains visible. This prevents a removed anchor from silently
   * reappearing after restart.
   *
   * @param issuerFingerprint public issuer fingerprint to remove from local anchor state
   * @return {@code true} when an anchor existed and was deleted from durable and memory state
   * @throws TrustGraphException when the fingerprint is invalid or the backing record cannot be
   *     deleted
   */
  @Override
  public synchronized boolean removeAnchor(String issuerFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_ISSUER_FINGERPRINT, issuerFingerprint, 128);
    if (!anchors.containsKey(normalized)) {
      return false;
    }
    deletePersistedRecord(anchorFile(normalized));
    anchors.remove(normalized);
    return true;
  }

  @Override
  public synchronized TrustAnchor updateAnchorLifecycle(
      String issuerFingerprint,
      TrustStatementLifecycleStatus status,
      String reasonCode,
      String actorAppId,
      String source) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_ISSUER_FINGERPRINT, issuerFingerprint, 128);
    TrustAnchor existing = anchors.get(normalized);
    if (existing == null) {
      throw new TrustGraphException("trust_anchor_not_found", "Trust anchor was not found.");
    }
    TrustAnchor updated =
        new TrustAnchor(
            existing.issuerFingerprint(),
            existing.label(),
            source == null ? existing.source() : source,
            existing.createdAt(),
            java.util.Objects.requireNonNull(status, "status"),
            clock.instant(),
            reasonCode);
    writeAnchor(updated);
    anchors.put(normalized, updated);
    return updated;
  }

  /**
   * Returns local anchors in deterministic issuer-fingerprint order.
   *
   * <p>The returned list is a snapshot. Subsequent imports, removals, or cap evictions do not
   * mutate it, which makes route serialization and tests independent of concurrent app requests.
   *
   * @return immutable snapshot of retained local anchors
   */
  @Override
  public synchronized List<TrustAnchor> anchors() {
    ArrayList<TrustAnchor> ordered = new ArrayList<>(anchors.values());
    ordered.sort(Comparator.comparing(TrustAnchor::issuerFingerprint));
    return List.copyOf(ordered);
  }

  /**
   * Returns retained trust statements in stable import order.
   *
   * <p>Records are loaded oldest-first on startup and retained in insertion order thereafter.
   * Re-importing an existing document refreshes metadata without moving it to the end of the list,
   * which keeps listing and cap behavior deterministic across restart.
   *
   * @return immutable snapshot of retained statement metadata and parsed documents
   */
  @Override
  public synchronized List<StoredTrustStatement> statements() {
    return List.copyOf(statements.values());
  }

  /**
   * Returns one retained statement by canonical document fingerprint.
   *
   * @param documentFingerprint statement document fingerprint to look up
   * @return retained statement metadata, or {@code null} when absent
   */
  @Override
  public synchronized StoredTrustStatement statement(String documentFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_DOCUMENT_FINGERPRINT, documentFingerprint, 128);
    return statements.get(normalized);
  }

  /**
   * Returns distinct subjects present in retained statements.
   *
   * <p>Subjects are de-duplicated by subject kind and URI, then returned in deterministic sorted
   * order. The method does not imply that every subject is trusted; scoring still requires a local
   * anchor, a verified signature, and a currently valid statement.
   *
   * @return immutable subject list suitable for app-facing discovery responses
   */
  @Override
  public synchronized List<TrustSubject> subjects() {
    java.util.TreeMap<String, TrustSubject> subjects = new java.util.TreeMap<>();
    for (StoredTrustStatement statement : statements.values()) {
      TrustSubject subject = statement.document().payload().subject();
      subjects.put(subject.kind().jsonValue() + "\n" + subject.uri(), subject);
    }
    return List.copyOf(subjects.values());
  }

  /**
   * Returns whether an issuer fingerprint is anchored locally.
   *
   * <p>The check consults the current in-memory snapshot loaded from disk and updated by local
   * mutations. It does not perform normalization beyond the exact key lookup used by scoring.
   *
   * @param issuerFingerprint issuer fingerprint from a retained statement payload
   * @return {@code true} when the fingerprint is currently anchored by this local store
   */
  @Override
  public synchronized boolean isAnchor(String issuerFingerprint) {
    TrustAnchor anchor = anchors.get(issuerFingerprint);
    return anchor != null && anchor.lifecycleStatus() == TrustStatementLifecycleStatus.ACTIVE;
  }

  /**
   * Returns local lifecycle policy for one statement fingerprint.
   *
   * <p>When no explicit record exists, the method returns an active default tied to the statement's
   * import timestamp. That default is not persisted unless a caller explicitly reactivates the
   * statement through the lifecycle mutation route.
   *
   * @param documentFingerprint canonical statement document fingerprint
   * @return local lifecycle record or active default
   */
  @Override
  public synchronized TrustStatementLifecycleRecord lifecycle(String documentFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_DOCUMENT_FINGERPRINT, documentFingerprint, 128);
    TrustStatementLifecycleRecord lifecycleRecord = lifecycleRecords.get(normalized);
    if (lifecycleRecord != null) {
      return lifecycleRecord;
    }
    StoredTrustStatement statement = statements.get(normalized);
    Instant timestamp =
        statement == null || statement.importedAt() == null
            ? clock.instant()
            : statement.importedAt();
    return TrustStatementLifecycleRecord.active(normalized, timestamp);
  }

  /**
   * Writes a durable local lifecycle policy record for one imported statement.
   *
   * <p>The method requires the statement to be currently retained. It preserves the first lifecycle
   * timestamp across later changes, writes the durable record before exposing it in memory, and
   * then reapplies the lifecycle retention cap.
   *
   * @param documentFingerprint canonical statement document fingerprint
   * @param status lifecycle state to store locally
   * @param reasonCode optional stable reason code
   * @param note optional bounded local note
   * @param replacementUri optional replacement statement URI; only a redacted summary is stored
   * @param actorAppId optional app id that requested the change
   * @param source local source label for the mutation workflow
   * @return stored lifecycle record
   * @throws TrustGraphException when the statement is absent or the lifecycle record cannot be
   *     written durably
   */
  @Override
  public synchronized TrustStatementLifecycleRecord updateLifecycle(
      String documentFingerprint,
      TrustStatementLifecycleStatus status,
      String reasonCode,
      String note,
      String replacementUri,
      String actorAppId,
      String source) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_DOCUMENT_FINGERPRINT, documentFingerprint, 128);
    if (!statements.containsKey(normalized)) {
      throw new TrustGraphException("trust_statement_not_found", "Trust statement was not found.");
    }
    Instant now = clock.instant();
    TrustStatementLifecycleRecord previous = lifecycleRecords.get(normalized);
    Instant createdAt = previous == null ? now : previous.createdAt();
    TrustStatementLifecycleRecord lifecycleRecord =
        TrustStatementLifecycleRecord.updated(
            normalized,
            status,
            reasonCode,
            note,
            replacementUri,
            createdAt,
            now,
            actorAppId,
            source);
    writeLifecycleRecord(lifecycleRecord);
    lifecycleRecords.put(normalized, lifecycleRecord);
    evictEldestLifecycleRecordsIfNeeded();
    return lifecycleRecord;
  }

  /**
   * Returns the number of retained imported statements.
   *
   * <p>The count reflects idempotent import replacement and cap eviction. It is suitable for status
   * responses but should not be treated as a global network trust count.
   *
   * @return retained statement count after import idempotency and retention cleanup
   */
  @Override
  public synchronized int statementCount() {
    return statements.size();
  }

  /**
   * Reports that this implementation persists Trust Graph RC state.
   *
   * @return {@code true} because anchors, statements, and audit events are backed by files
   */
  @Override
  public boolean durable() {
    return true;
  }

  /**
   * Returns the public store type label used by status responses.
   *
   * @return {@code file}, indicating durable file-backed local RC storage
   */
  @Override
  public String storeType() {
    return "file";
  }

  /**
   * Returns the retention and byte limits used by this store instance.
   *
   * <p>The configuration is immutable and is applied both when loading existing records and when
   * accepting new mutations.
   *
   * @return immutable store configuration supplied at construction time
   */
  @Override
  public TrustGraphStoreConfig config() {
    return config;
  }

  /**
   * Appends a redacted audit event to durable local history.
   *
   * <p>Events are written before the in-memory history changes. The configured audit cap is then
   * enforced by evicting the oldest retained entries. The caller is responsible for constructing an
   * event without raw bodies, signatures, private insert URIs, tokens, passwords, or local paths;
   * the event record type performs the same bounded-field validation used when records are loaded.
   *
   * @param event redacted local mutation or exchange event to persist
   * @throws TrustGraphException when the audit record cannot be written durably
   */
  @Override
  public synchronized void appendAuditEvent(TrustGraphAuditEvent event) {
    TrustGraphAuditEvent checked = java.util.Objects.requireNonNull(event, "event");
    writeAuditEvent(checked);
    auditEvents.add(checked);
    evictEldestAuditEventsIfNeeded();
  }

  /**
   * Returns recent redacted audit events in newest-first order.
   *
   * <p>The requested limit is clamped to the configured audit cap and to at least one event. The
   * returned snapshot is intended for app-facing audit and release-certification evidence; it never
   * includes raw trust statement JSON or raw fetched content because those values are not persisted
   * in audit records.
   *
   * @param limit requested maximum number of recent audit events to return
   * @return immutable, newest-first audit event snapshot
   */
  @Override
  public synchronized List<TrustGraphAuditEvent> auditEvents(int limit) {
    int boundedLimit = Math.clamp(limit, 1, config.maxAuditEntries());
    ArrayList<TrustGraphAuditEvent> ordered = new ArrayList<>(auditEvents);
    ordered.sort(
        Comparator.comparing(TrustGraphAuditEvent::timestamp)
            .reversed()
            .thenComparing(TrustGraphAuditEvent::eventType)
            .thenComparing(event -> java.util.Objects.toString(event.documentFingerprint(), "")));
    if (ordered.size() > boundedLimit) {
      return List.copyOf(ordered.subList(0, boundedLimit));
    }
    return List.copyOf(ordered);
  }

  private void loadPersistedState() {
    try {
      ensureManagedDirectories();
      loadAnchors();
      loadStatements();
      loadLifecycleRecords();
      loadAuditEvents();
      evictEldestAnchorsIfNeeded();
      evictEldestStatementsIfNeeded();
      evictEldestLifecycleRecordsIfNeeded();
      evictEldestAuditEventsIfNeeded();
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void loadAnchors() throws IOException {
    Path directory = anchorsDirectory();
    if (!isExistingDirectory(directory)) {
      return;
    }
    ArrayList<TrustAnchor> loaded = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path file : sortedPropertyFiles(stream)) {
        readAnchor(file).ifPresent(loaded::add);
      }
    }
    loaded.sort(
        Comparator.comparing(TrustAnchor::createdAt).thenComparing(TrustAnchor::issuerFingerprint));
    for (TrustAnchor anchor : loaded) {
      anchors.put(anchor.issuerFingerprint(), anchor);
    }
  }

  private void loadStatements() throws IOException {
    Path directory = statementsDirectory();
    if (!isExistingDirectory(directory)) {
      return;
    }
    ArrayList<StoredTrustStatement> loaded = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path file : sortedPropertyFiles(stream)) {
        readStatement(file).ifPresent(loaded::add);
      }
    }
    loaded.sort(
        Comparator.comparing(StoredTrustStatement::importedAt)
            .thenComparing(StoredTrustStatement::documentFingerprint));
    for (StoredTrustStatement statement : loaded) {
      statements.put(statement.documentFingerprint(), statement);
    }
  }

  private void loadLifecycleRecords() throws IOException {
    Path directory = lifecycleDirectory();
    if (!isExistingDirectory(directory)) {
      return;
    }
    ArrayList<TrustStatementLifecycleRecord> loaded = new ArrayList<>();
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path file : sortedPropertyFiles(stream)) {
        readLifecycleRecord(file).ifPresent(loaded::add);
      }
    }
    loaded.sort(
        Comparator.comparing(TrustStatementLifecycleRecord::createdAt)
            .thenComparing(TrustStatementLifecycleRecord::statementFingerprint));
    for (TrustStatementLifecycleRecord lifecycleRecord : loaded) {
      lifecycleRecords.put(lifecycleRecord.statementFingerprint(), lifecycleRecord);
    }
  }

  private void loadAuditEvents() throws IOException {
    Path directory = auditDirectory();
    if (!isExistingDirectory(directory)) {
      return;
    }
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path file : sortedPropertyFiles(stream)) {
        readAuditEvent(file).ifPresent(auditEvents::add);
      }
    }
    auditEvents.sort(
        Comparator.comparing(TrustGraphAuditEvent::timestamp)
            .thenComparing(TrustGraphAuditEvent::eventType));
  }

  private Optional<TrustAnchor> readAnchor(Path file) {
    try {
      Properties properties = readProperties(file).orElse(null);
      if (properties == null || !"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      return Optional.of(
          new TrustAnchor(
              properties.getProperty(KEY_ISSUER_FINGERPRINT),
              properties.getProperty(KEY_LABEL),
              properties.getProperty(KEY_SOURCE),
              instant(properties.getProperty(KEY_CREATED_AT)),
              TrustStatementLifecycleStatus.parse(
                  properties.getProperty(KEY_LIFECYCLE_STATUS, "active")),
              instant(
                  properties.getProperty(KEY_UPDATED_AT, properties.getProperty(KEY_CREATED_AT))),
              properties.getProperty(KEY_REASON_CODE)));
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  private Optional<StoredTrustStatement> readStatement(Path file) {
    try {
      Properties properties = readProperties(file).orElse(null);
      if (properties == null || !"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      String documentJson = properties.getProperty(KEY_DOCUMENT_JSON);
      if (documentJson == null) {
        return Optional.empty();
      }
      int documentBytes = documentJson.getBytes(StandardCharsets.UTF_8).length;
      if (documentBytes > config.maxStoredDocumentBytes()
          || documentBytes != positiveInt(properties.getProperty(KEY_DOCUMENT_BYTES))) {
        return Optional.empty();
      }
      TrustStatementDocument document = TrustStatementParser.parse(documentJson);
      String documentFingerprint = TrustStatementFingerprint.documentFingerprint(document);
      if (!documentFingerprint.equals(properties.getProperty(KEY_DOCUMENT_FINGERPRINT))) {
        return Optional.empty();
      }
      String payloadHash = TrustStatementFingerprint.payloadHash(document);
      if (!payloadHash.equals(properties.getProperty(KEY_PAYLOAD_HASH))) {
        return Optional.empty();
      }
      boolean signatureVerified = TrustStatementVerifier.isSignatureVerified(document);
      if (signatureVerified
          != Boolean.parseBoolean(properties.getProperty(KEY_SIGNATURE_VERIFIED))) {
        return Optional.empty();
      }
      return Optional.of(
          new StoredTrustStatement(
              document,
              documentFingerprint,
              payloadHash,
              signatureVerified,
              TrustGraphStoreSanitizer.normalizeSource(properties.getProperty(KEY_SOURCE)),
              TrustGraphStoreSanitizer.normalizeSourceUriSummary(
                  properties.getProperty(KEY_SOURCE_URI)),
              TrustGraphStoreSanitizer.normalizeSourceUriHash(
                  properties.getProperty(KEY_SOURCE_URI_HASH)),
              TrustGraphStoreSanitizer.normalizeSourceLabel(
                  properties.getProperty(KEY_SOURCE_LABEL)),
              TrustGraphStoreSanitizer.optionalAuditText(
                  KEY_SOURCE_URI_KIND, properties.getProperty(KEY_SOURCE_URI_KIND), 32),
              TrustGraphStoreSanitizer.normalizeSubscriptionId(
                  properties.getProperty(KEY_SUBSCRIPTION_ID)),
              instant(properties.getProperty(KEY_IMPORTED_AT)),
              instant(properties.getProperty(KEY_UPDATED_AT))));
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  private Optional<TrustStatementLifecycleRecord> readLifecycleRecord(Path file) {
    try {
      Properties properties = readProperties(file).orElse(null);
      if (properties == null || !"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      String fingerprint = properties.getProperty(KEY_DOCUMENT_FINGERPRINT);
      if (fingerprint == null || !hashFileName(fingerprint).equals(file.getFileName().toString())) {
        return Optional.empty();
      }
      return Optional.of(
          new TrustStatementLifecycleRecord(
              fingerprint,
              TrustStatementLifecycleStatus.parse(properties.getProperty(KEY_LIFECYCLE_STATUS)),
              properties.getProperty(KEY_REASON_CODE),
              properties.getProperty(KEY_NOTE),
              properties.getProperty(KEY_REPLACEMENT_URI),
              instant(properties.getProperty(KEY_CREATED_AT)),
              instant(properties.getProperty(KEY_UPDATED_AT)),
              properties.getProperty(KEY_ACTOR_APP_ID),
              properties.getProperty(KEY_SOURCE)));
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  private Optional<TrustGraphAuditEvent> readAuditEvent(Path file) {
    try {
      Properties properties = readProperties(file).orElse(null);
      if (properties == null || !"1".equals(properties.getProperty(KEY_VERSION))) {
        return Optional.empty();
      }
      return Optional.of(
          new TrustGraphAuditEvent(
              properties.getProperty(KEY_EVENT_TYPE),
              instant(properties.getProperty(KEY_TIMESTAMP)),
              properties.getProperty(KEY_APP_ID),
              properties.getProperty(KEY_DOCUMENT_FINGERPRINT),
              properties.getProperty(KEY_PAYLOAD_HASH),
              properties.getProperty(KEY_ISSUER_FINGERPRINT),
              properties.getProperty(KEY_SUBJECT_KIND),
              properties.getProperty(KEY_SUBJECT_URI_HASH),
              properties.getProperty(KEY_SUBJECT_URI_SUMMARY),
              properties.getProperty(KEY_SOURCE),
              properties.getProperty(KEY_SOURCE_URI_HASH),
              properties.getProperty(KEY_SOURCE_SUMMARY),
              nullableBoolean(properties.getProperty(KEY_SIGNATURE_VERIFIED)),
              properties.getProperty(KEY_STATUS_CODE)));
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  private void writeAnchor(TrustAnchor anchor) {
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_ISSUER_FINGERPRINT, anchor.issuerFingerprint());
    setOptional(properties, KEY_LABEL, anchor.label());
    properties.setProperty(KEY_SOURCE, anchor.source());
    properties.setProperty(KEY_CREATED_AT, anchor.createdAt().toString());
    properties.setProperty(KEY_LIFECYCLE_STATUS, anchor.lifecycleStatus().jsonValue());
    properties.setProperty(KEY_UPDATED_AT, anchor.updatedAt().toString());
    properties.setProperty(KEY_REASON_CODE, anchor.reasonCode());
    writeProperties(anchorFile(anchor.issuerFingerprint()), properties, "Cryptad trust anchor");
  }

  private void writeStatement(
      StoredTrustStatement statement, String canonicalDocumentJson, int documentBytes) {
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_DOCUMENT_FINGERPRINT, statement.documentFingerprint());
    properties.setProperty(KEY_PAYLOAD_HASH, statement.payloadHash());
    properties.setProperty(KEY_SIGNATURE_VERIFIED, Boolean.toString(statement.signatureVerified()));
    properties.setProperty(KEY_SOURCE, statement.source());
    setOptional(properties, KEY_SOURCE_URI, statement.sourceUri());
    setOptional(properties, KEY_SOURCE_URI_HASH, statement.sourceUriHash());
    setOptional(properties, KEY_SOURCE_LABEL, statement.sourceLabel());
    setOptional(properties, KEY_SOURCE_URI_KIND, statement.sourceUriKind());
    setOptional(properties, KEY_SUBSCRIPTION_ID, statement.subscriptionId());
    properties.setProperty(KEY_IMPORTED_AT, statement.importedAt().toString());
    properties.setProperty(KEY_UPDATED_AT, statement.updatedAt().toString());
    properties.setProperty(KEY_DOCUMENT_BYTES, Integer.toString(documentBytes));
    properties.setProperty(KEY_DOCUMENT_JSON, canonicalDocumentJson);
    writeProperties(
        statementFile(statement.documentFingerprint()), properties, "Cryptad trust statement");
  }

  private void writeLifecycleRecord(TrustStatementLifecycleRecord lifecycleRecord) {
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_DOCUMENT_FINGERPRINT, lifecycleRecord.statementFingerprint());
    properties.setProperty(KEY_LIFECYCLE_STATUS, lifecycleRecord.status().jsonValue());
    properties.setProperty(KEY_REASON_CODE, lifecycleRecord.reasonCode());
    setOptional(properties, KEY_NOTE, lifecycleRecord.note());
    setOptional(properties, KEY_REPLACEMENT_URI, lifecycleRecord.replacementUri());
    properties.setProperty(KEY_CREATED_AT, lifecycleRecord.createdAt().toString());
    properties.setProperty(KEY_UPDATED_AT, lifecycleRecord.updatedAt().toString());
    setOptional(properties, KEY_ACTOR_APP_ID, lifecycleRecord.actorAppId());
    properties.setProperty(KEY_SOURCE, lifecycleRecord.source());
    writeProperties(
        lifecycleFile(lifecycleRecord.statementFingerprint()),
        properties,
        "Cryptad trust statement lifecycle");
  }

  private void writeAuditEvent(TrustGraphAuditEvent event) {
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_EVENT_TYPE, event.eventType());
    properties.setProperty(KEY_TIMESTAMP, event.timestamp().toString());
    setOptional(properties, KEY_APP_ID, event.appId());
    setOptional(properties, KEY_DOCUMENT_FINGERPRINT, event.documentFingerprint());
    setOptional(properties, KEY_PAYLOAD_HASH, event.payloadHash());
    setOptional(properties, KEY_ISSUER_FINGERPRINT, event.issuerFingerprint());
    setOptional(properties, KEY_SUBJECT_KIND, event.subjectKind());
    setOptional(properties, KEY_SUBJECT_URI_HASH, event.subjectUriHash());
    setOptional(properties, KEY_SUBJECT_URI_SUMMARY, event.subjectUriSummary());
    setOptional(properties, KEY_SOURCE, event.source());
    setOptional(properties, KEY_SOURCE_URI_HASH, event.sourceUriHash());
    setOptional(properties, KEY_SOURCE_SUMMARY, event.sourceSummary());
    if (event.signatureVerified() != null) {
      properties.setProperty(KEY_SIGNATURE_VERIFIED, Boolean.toString(event.signatureVerified()));
    }
    setOptional(properties, KEY_STATUS_CODE, event.statusCode());
    writeProperties(
        auditDirectory()
            .resolve(TrustGraphStoreSanitizer.eventFileId(event.timestamp(), event) + FILE_SUFFIX),
        properties,
        "Cryptad trust graph audit event");
  }

  private void evictEldestStatementsIfNeeded() {
    while (statements.size() > config.maxStatements()) {
      String key = statements.keySet().iterator().next();
      statements.remove(key);
      deleteQuietly(statementFile(key));
    }
  }

  private void evictEldestAnchorsIfNeeded() {
    while (anchors.size() > config.maxAnchors()) {
      TrustAnchor eldest =
          anchors.values().stream()
              .min(
                  Comparator.comparing(TrustAnchor::createdAt)
                      .thenComparing(TrustAnchor::issuerFingerprint))
              .orElse(null);
      if (eldest == null) {
        return;
      }
      anchors.remove(eldest.issuerFingerprint());
      deleteQuietly(anchorFile(eldest.issuerFingerprint()));
    }
  }

  private void evictEldestLifecycleRecordsIfNeeded() {
    while (lifecycleRecords.size() > config.maxLifecycleRecords()) {
      TrustStatementLifecycleRecord eldest =
          lifecycleRecords.values().stream()
              .min(
                  Comparator.comparing(TrustStatementLifecycleRecord::createdAt)
                      .thenComparing(TrustStatementLifecycleRecord::statementFingerprint))
              .orElse(null);
      if (eldest == null) {
        return;
      }
      lifecycleRecords.remove(eldest.statementFingerprint());
      deleteQuietly(lifecycleFile(eldest.statementFingerprint()));
    }
  }

  private void evictEldestAuditEventsIfNeeded() {
    while (auditEvents.size() > config.maxAuditEntries()) {
      TrustGraphAuditEvent eldest =
          auditEvents.stream()
              .min(
                  Comparator.comparing(TrustGraphAuditEvent::timestamp)
                      .thenComparing(TrustGraphAuditEvent::eventType)
                      .thenComparing(
                          event -> java.util.Objects.toString(event.documentFingerprint(), "")))
              .orElse(null);
      if (eldest == null) {
        return;
      }
      auditEvents.remove(eldest);
      deleteAuditEventFilesFor(eldest);
    }
  }

  private List<Path> sortedPropertyFiles(Stream<Path> stream) {
    return stream
        .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        .filter(path -> path.getFileName().toString().endsWith(FILE_SUFFIX))
        .sorted(Comparator.comparing(path -> path.getFileName().toString()))
        .toList();
  }

  private Optional<Properties> readProperties(Path file) throws IOException {
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    long size = Files.size(file);
    if (size < 1 || size > MAX_PROPERTIES_FILE_BYTES) {
      return Optional.empty();
    }
    Properties properties = new Properties();
    try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(reader);
      return Optional.of(properties);
    } catch (IllegalArgumentException _) {
      return Optional.empty();
    }
  }

  private void writeProperties(Path file, Properties properties, String comment) {
    try {
      ensureDirectory(file.getParent());
      Path tempFile = Files.createTempFile(file.getParent(), ".trust-graph-", ".tmp");
      boolean moved = false;
      try {
        try (Writer writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
          properties.store(writer, comment);
        }
        forceFile(tempFile);
        moveReplacing(tempFile, file);
        forceDirectory(file.getParent());
        moved = true;
      } finally {
        if (!moved) {
          Files.deleteIfExists(tempFile);
        }
      }
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void ensureDirectory(Path directory) throws IOException {
    Path relative = managedRelativePath(directory);
    Path current = ensureManagedBoundaryDirectory();
    for (Path segment : relative) {
      current = current.resolve(segment);
      ensureSingleDirectory(current);
    }
    if (!isExistingDirectory(current)) {
      throw new IOException("trust graph directory is unavailable");
    }
  }

  private void ensureManagedDirectories() throws IOException {
    ensureDirectory(rootDirectory);
    ensureDirectory(anchorsDirectory());
    ensureDirectory(statementsDirectory());
    ensureDirectory(lifecycleDirectory());
    ensureDirectory(auditDirectory());
  }

  private Path managedRelativePath(Path directory) throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    if (!normalized.startsWith(rootDirectory) || !normalized.startsWith(managedBoundaryDirectory)) {
      throw new IOException("trust graph directory is outside managed storage");
    }
    return managedBoundaryDirectory.relativize(normalized);
  }

  private Path ensureManagedBoundaryDirectory() throws IOException {
    if (isExistingDirectory(managedBoundaryDirectory)) {
      return managedBoundaryDirectory;
    }
    Path parent = managedBoundaryDirectory.getParent();
    if (parent == null || !isExistingDirectory(parent)) {
      throw new IOException("trust graph directory is unavailable");
    }
    ensureSingleDirectory(managedBoundaryDirectory);
    return managedBoundaryDirectory;
  }

  private static void ensureSingleDirectory(Path directory) throws IOException {
    if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      if (!isExistingDirectory(directory)) {
        throw new IOException("trust graph directory is unavailable");
      }
      return;
    }
    try {
      Files.createDirectory(directory);
    } catch (FileAlreadyExistsException _) {
      if (!isExistingDirectory(directory)) {
        throw new IOException("trust graph directory is unavailable");
      }
    }
  }

  private static boolean isExistingDirectory(Path directory) {
    return Files.exists(directory, LinkOption.NOFOLLOW_LINKS)
        && !Files.isSymbolicLink(directory)
        && Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS);
  }

  private static Path defaultManagedBoundary(Path rootDirectory) {
    Path parent = rootDirectory.getParent();
    return parent == null ? rootDirectory : parent;
  }

  private static void forceFile(Path file) throws IOException {
    try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
      channel.force(true);
    }
  }

  private static void forceDirectory(Path directory) {
    try (FileChannel channel =
        FileChannel.open(directory, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
      channel.force(true);
    } catch (IOException _) {
      // Directory fsync is not supported by every provider. The record file itself was fsynced.
    }
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private void deleteQuietly(Path file) {
    try {
      ensureDirectory(file.getParent());
      Files.deleteIfExists(file);
    } catch (IOException _) {
      // Best-effort cleanup. Retention is re-applied on the next store open.
    }
  }

  private void deletePersistedRecord(Path file) {
    try {
      ensureDirectory(file.getParent());
      Files.deleteIfExists(file);
      forceDirectory(file.getParent());
    } catch (IOException _) {
      throw storeUnavailable();
    }
  }

  private void deleteAuditEventFilesFor(TrustGraphAuditEvent event) {
    Path directory = auditDirectory();
    if (!isExistingDirectory(directory)) {
      return;
    }
    try (Stream<Path> stream = Files.list(directory)) {
      for (Path file : sortedPropertyFiles(stream)) {
        Optional<TrustGraphAuditEvent> maybeEvent = readAuditEvent(file);
        if (maybeEvent.isPresent() && maybeEvent.get().equals(event)) {
          deleteQuietly(file);
          return;
        }
      }
    } catch (IOException _) {
      // Best-effort cleanup. Retention is re-applied on the next store open.
    }
  }

  private Path anchorsDirectory() {
    return rootDirectory.resolve(ANCHORS_DIRECTORY);
  }

  private Path statementsDirectory() {
    return rootDirectory.resolve(STATEMENTS_DIRECTORY);
  }

  private Path auditDirectory() {
    return rootDirectory.resolve(AUDIT_DIRECTORY);
  }

  private Path lifecycleDirectory() {
    return rootDirectory.resolve(LIFECYCLE_DIRECTORY);
  }

  private Path anchorFile(String issuerFingerprint) {
    return anchorsDirectory().resolve(hashFileName(issuerFingerprint));
  }

  private Path statementFile(String documentFingerprint) {
    return statementsDirectory().resolve(hashFileName(documentFingerprint));
  }

  private Path lifecycleFile(String documentFingerprint) {
    return lifecycleDirectory().resolve(hashFileName(documentFingerprint));
  }

  private static String hashFileName(String value) {
    return TrustGraphStoreSanitizer.hashText(value).substring(0, 48) + FILE_SUFFIX;
  }

  private static void setOptional(Properties properties, String key, String value) {
    if (value != null) {
      properties.setProperty(key, value);
    }
  }

  private static Instant instant(String value) {
    if (value == null || value.isBlank()) {
      throw new TrustGraphException("invalid_trust_store_record", "Invalid trust graph record.");
    }
    return Instant.parse(value.trim());
  }

  private static int positiveInt(String value) {
    if (value == null || value.isBlank()) {
      return -1;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException _) {
      return -1;
    }
  }

  private static @Nullable Boolean nullableBoolean(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return Boolean.parseBoolean(value.trim());
  }

  private static TrustGraphException storeUnavailable() {
    return new TrustGraphException(
        "trust_graph_store_unavailable", "Trust graph store is unavailable.");
  }
}
