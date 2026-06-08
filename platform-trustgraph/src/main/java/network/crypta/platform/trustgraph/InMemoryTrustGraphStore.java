package network.crypta.platform.trustgraph;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Process-local Trust Graph RC store used by the minimal service surface.
 *
 * <p>The store keeps imported statements and local anchors in memory with explicit retention caps.
 * It is suitable for reference apps, offline developer tools, and tests that need deterministic
 * behavior without introducing daemon-core storage or background crawler state. The implementation
 * is synchronized because callers may import, anchor, and score from different app-originated
 * Platform API requests.
 *
 * <p>Stored records are redacted summaries around parsed trust documents. Source URI metadata is
 * limited to Crypta content-key forms, signatures are verified when issuer public keys are present,
 * and insertion-order eviction bounds heap growth from granted apps.
 */
public final class InMemoryTrustGraphStore implements TrustGraphStore {
  /**
   * Default maximum number of imported trust statements retained in memory.
   *
   * <p>When the cap is reached, adding a distinct statement evicts the oldest retained statement.
   * Re-importing the same document refreshes its metadata without increasing the retained count.
   */
  public static final int DEFAULT_MAX_STATEMENTS = 512;

  /**
   * Default maximum number of local trust anchors retained in memory.
   *
   * <p>Anchors are local process policy inputs. The cap prevents a granted app from growing the
   * local response set or scorer lookup table without bound.
   */
  public static final int DEFAULT_MAX_ANCHORS = 256;

  private static final String KEY_DOCUMENT_FINGERPRINT = "documentFingerprint";

  private final Clock clock;
  private final int maxStatements;
  private final int maxAnchors;
  private final int maxAuditEntries;
  private final int maxLifecycleRecords;
  private final Map<String, TrustAnchor> anchors = new LinkedHashMap<>();
  private final Map<String, StoredTrustStatement> statements = new LinkedHashMap<>();
  private final Map<String, TrustStatementLifecycleRecord> lifecycleRecords = new LinkedHashMap<>();
  private final List<TrustGraphAuditEvent> auditEvents = new ArrayList<>();

  /**
   * Creates an in-memory store using the system UTC clock.
   *
   * <p>This constructor is used by default Platform API composition. Tests that assert timestamp or
   * expiry behavior should use a fixed-clock constructor.
   */
  public InMemoryTrustGraphStore() {
    this(Clock.systemUTC());
  }

  /**
   * Creates an in-memory store using an explicit clock.
   *
   * @param clock clock used for helper-created anchor timestamps
   */
  public InMemoryTrustGraphStore(Clock clock) {
    this(clock, DEFAULT_MAX_STATEMENTS);
  }

  /**
   * Creates an in-memory store using an explicit clock and statement retention limit.
   *
   * @param clock clock used for helper-created anchor timestamps
   * @param maxStatements positive maximum number of retained statement records
   */
  public InMemoryTrustGraphStore(Clock clock, int maxStatements) {
    this(clock, maxStatements, DEFAULT_MAX_ANCHORS);
  }

  /**
   * Creates an in-memory store using an explicit clock plus statement and anchor retention limits.
   *
   * @param clock clock used for helper-created anchor timestamps
   * @param maxStatements positive maximum number of retained statement records
   * @param maxAnchors positive maximum number of retained anchor records
   * @throws IllegalArgumentException when either retention limit is less than one
   */
  public InMemoryTrustGraphStore(Clock clock, int maxStatements, int maxAnchors) {
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
    if (maxStatements < 1) {
      throw new IllegalArgumentException("maxStatements must be positive.");
    }
    if (maxAnchors < 1) {
      throw new IllegalArgumentException("maxAnchors must be positive.");
    }
    this.maxStatements = maxStatements;
    this.maxAnchors = maxAnchors;
    TrustGraphStoreConfig defaults = TrustGraphStoreConfig.defaults();
    this.maxAuditEntries = defaults.maxAuditEntries();
    this.maxLifecycleRecords = defaults.maxLifecycleRecords();
  }

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
    if (imported) {
      evictEldestStatementIfFull();
    }
    statements.put(
        documentFingerprint,
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
            now));
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

  @Override
  public synchronized TrustAnchor addAnchor(TrustAnchor anchor) {
    if (!anchors.containsKey(anchor.issuerFingerprint())) {
      evictEldestAnchorIfFull();
    }
    anchors.put(anchor.issuerFingerprint(), anchor);
    return anchor;
  }

  /**
   * Adds an anchor using the store clock.
   *
   * <p>This convenience method is used by tests and local callers that do not already have a {@link
   * TrustAnchor} instance. It applies the same validation, replacement, and eviction policy as
   * {@link #addAnchor(TrustAnchor)}.
   *
   * @param fingerprint public issuer fingerprint to mark as locally anchored
   * @param label optional bounded display label for local UI summaries
   * @param source optional bounded local source label such as {@code manual}
   * @return stored anchor after validation and defaulting
   */
  public synchronized TrustAnchor addAnchor(String fingerprint, String label, String source) {
    return addAnchor(new TrustAnchor(fingerprint, label, source, clock.instant()));
  }

  @Override
  public synchronized boolean removeAnchor(String issuerFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText("issuerFingerprint", issuerFingerprint, 128);
    return anchors.remove(normalized) != null;
  }

  @Override
  public synchronized List<TrustAnchor> anchors() {
    ArrayList<TrustAnchor> ordered = new ArrayList<>(anchors.values());
    ordered.sort(Comparator.comparing(TrustAnchor::issuerFingerprint));
    return List.copyOf(ordered);
  }

  @Override
  public synchronized List<StoredTrustStatement> statements() {
    return List.copyOf(statements.values());
  }

  @Override
  public synchronized StoredTrustStatement statement(String documentFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText(KEY_DOCUMENT_FINGERPRINT, documentFingerprint, 128);
    return statements.get(normalized);
  }

  @Override
  public synchronized List<TrustSubject> subjects() {
    TreeMap<String, TrustSubject> subjects = new TreeMap<>();
    for (StoredTrustStatement statement : statements.values()) {
      TrustSubject subject = statement.document().payload().subject();
      subjects.put(subject.kind().jsonValue() + "\n" + subject.uri(), subject);
    }
    ArrayList<TrustSubject> ordered = new ArrayList<>(subjects.values());
    ordered.sort(
        Comparator.comparing((TrustSubject subject) -> subject.kind().jsonValue())
            .thenComparing(TrustSubject::uri));
    return List.copyOf(ordered);
  }

  @Override
  public synchronized boolean isAnchor(String issuerFingerprint) {
    return anchors.containsKey(issuerFingerprint);
  }

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
    if (!lifecycleRecords.containsKey(normalized)) {
      evictEldestLifecycleIfFull();
    }
    lifecycleRecords.put(normalized, lifecycleRecord);
    return lifecycleRecord;
  }

  @Override
  public synchronized int statementCount() {
    return statements.size();
  }

  @Override
  public TrustGraphStoreConfig config() {
    return new TrustGraphStoreConfig(
        maxStatements,
        maxAnchors,
        maxAuditEntries,
        TrustStatementValidator.MAX_DOCUMENT_BYTES,
        maxLifecycleRecords);
  }

  @Override
  public synchronized void appendAuditEvent(TrustGraphAuditEvent event) {
    auditEvents.add(java.util.Objects.requireNonNull(event, "event"));
    while (auditEvents.size() > maxAuditEntries) {
      auditEvents.removeFirst();
    }
  }

  @Override
  public synchronized List<TrustGraphAuditEvent> auditEvents(int limit) {
    int boundedLimit = Math.clamp(limit, 1, maxAuditEntries);
    ArrayList<TrustGraphAuditEvent> ordered = new ArrayList<>(auditEvents);
    ordered.sort(
        Comparator.comparing(TrustGraphAuditEvent::timestamp)
            .reversed()
            .thenComparing(TrustGraphAuditEvent::eventType));
    if (ordered.size() > boundedLimit) {
      return List.copyOf(ordered.subList(0, boundedLimit));
    }
    return List.copyOf(ordered);
  }

  private void evictEldestStatementIfFull() {
    while (statements.size() >= maxStatements) {
      Iterator<String> iterator = statements.keySet().iterator();
      if (!iterator.hasNext()) {
        return;
      }
      iterator.next();
      iterator.remove();
    }
  }

  private void evictEldestAnchorIfFull() {
    while (anchors.size() >= maxAnchors) {
      Iterator<String> iterator = anchors.keySet().iterator();
      if (!iterator.hasNext()) {
        return;
      }
      iterator.next();
      iterator.remove();
    }
  }

  private void evictEldestLifecycleIfFull() {
    while (lifecycleRecords.size() >= maxLifecycleRecords) {
      Iterator<String> iterator = lifecycleRecords.keySet().iterator();
      if (!iterator.hasNext()) {
        return;
      }
      iterator.next();
      iterator.remove();
    }
  }
}
