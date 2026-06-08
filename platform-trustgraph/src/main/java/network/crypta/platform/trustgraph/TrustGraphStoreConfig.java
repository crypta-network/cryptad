package network.crypta.platform.trustgraph;

/**
 * Retention and byte limits for local Trust Graph RC storage.
 *
 * <p>The local RC store is intentionally bounded even when file-backed. These limits apply only to
 * local platform trust graph state: they are not daemon routing, moderation, peer-selection, or
 * network crawler policy.
 *
 * <p>Instances are immutable and validated at construction time. Store implementations use the same
 * values during startup and mutation: startup can trim excess persisted records, while later
 * imports and audit appends apply the cap immediately after the new record is accepted. This keeps
 * memory use, on-disk record counts, and API response sizes predictable for granted local apps.
 *
 * <p>The byte limit applies to the normalized public trust statement document that the store writes
 * after parsing and canonicalization. It is not a limit for raw fetched content or raw request
 * bodies; those inputs are bounded by the API workflow before a document reaches the store.
 *
 * @param maxStatements maximum retained trust statement records after idempotent replacement and
 *     cap eviction
 * @param maxAnchors maximum retained local anchor records after replacement and cap eviction
 * @param maxAuditEntries maximum retained redacted audit entries available to app-facing routes
 * @param maxStoredDocumentBytes maximum UTF-8 bytes accepted for a normalized public statement
 *     document
 * @param maxLifecycleRecords maximum retained local lifecycle records keyed by statement
 *     fingerprint
 */
public record TrustGraphStoreConfig(
    int maxStatements,
    int maxAnchors,
    int maxAuditEntries,
    int maxStoredDocumentBytes,
    int maxLifecycleRecords) {
  private static final int DEFAULT_MAX_AUDIT_ENTRIES = 512;
  private static final int DEFAULT_MAX_LIFECYCLE_RECORDS = 512;

  /**
   * Creates a configuration using the historical four Trust Graph storage limits.
   *
   * <p>The lifecycle cap defaults to the same conservative value used by the release-candidate
   * store defaults. This overload preserves existing tests and embeddings that construct store
   * limits before local lifecycle records were introduced.
   *
   * @param maxStatements maximum retained statement records
   * @param maxAnchors maximum retained local anchor records
   * @param maxAuditEntries maximum retained redacted audit records
   * @param maxStoredDocumentBytes maximum stored canonical statement bytes
   */
  public TrustGraphStoreConfig(
      int maxStatements, int maxAnchors, int maxAuditEntries, int maxStoredDocumentBytes) {
    this(
        maxStatements,
        maxAnchors,
        maxAuditEntries,
        maxStoredDocumentBytes,
        DEFAULT_MAX_LIFECYCLE_RECORDS);
  }

  /**
   * Creates a validated configuration.
   *
   * <p>All limits must be positive. Very small values are valid and useful in tests because they
   * exercise eviction without requiring large fixtures. Production composition should normally use
   * {@link #defaults()} unless a deployment has a specific reason to tighten local RC storage.
   *
   * @throws IllegalArgumentException when any limit is less than one
   */
  public TrustGraphStoreConfig {
    if (maxStatements < 1) {
      throw new IllegalArgumentException("maxStatements must be positive.");
    }
    if (maxAnchors < 1) {
      throw new IllegalArgumentException("maxAnchors must be positive.");
    }
    if (maxAuditEntries < 1) {
      throw new IllegalArgumentException("maxAuditEntries must be positive.");
    }
    if (maxStoredDocumentBytes < 1) {
      throw new IllegalArgumentException("maxStoredDocumentBytes must be positive.");
    }
    if (maxLifecycleRecords < 1) {
      throw new IllegalArgumentException("maxLifecycleRecords must be positive.");
    }
  }

  /**
   * Returns the default bounded local-RC store configuration.
   *
   * <p>The defaults preserve the existing in-memory statement and anchor caps, add a bounded audit
   * history, and reuse the Trust Statement parser's maximum normalized document size. They are
   * intentionally conservative for a local RC service: enough to exercise exchange workflows and
   * scoring, but not enough to become a global trust database.
   *
   * @return default limits matching the current Trust Graph RC storage policy
   */
  public static TrustGraphStoreConfig defaults() {
    return new TrustGraphStoreConfig(
        InMemoryTrustGraphStore.DEFAULT_MAX_STATEMENTS,
        InMemoryTrustGraphStore.DEFAULT_MAX_ANCHORS,
        DEFAULT_MAX_AUDIT_ENTRIES,
        TrustStatementValidator.MAX_DOCUMENT_BYTES,
        DEFAULT_MAX_LIFECYCLE_RECORDS);
  }
}
