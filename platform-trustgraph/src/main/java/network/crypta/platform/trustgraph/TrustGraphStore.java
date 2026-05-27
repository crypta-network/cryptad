package network.crypta.platform.trustgraph;

import java.util.List;
import java.util.Map;

/**
 * Local store abstraction for Trust Graph Preview statements and anchors.
 *
 * <p>The interface separates the preview model and scorer from a specific retention mechanism.
 * Implementations own import idempotency, source metadata normalization, signature verification
 * bookkeeping, anchor storage, and deterministic listing order. They must not expose raw request
 * bodies, raw signature values, tokens, local filesystem paths, or private identity material
 * through summaries.
 */
public interface TrustGraphStore {
  /**
   * Imports or replaces one statement record and returns a redacted summary.
   *
   * @param document parsed and validated trust statement document
   * @param source bounded local source label, or {@code null} for an implementation default
   * @param sourceUri optional Crypta content URI associated with the imported document. Stores may
   *     retain only a redacted summary and hash for this value.
   * @param sourceLabel optional short display label supplied by the importing app
   * @return redacted import summary including hashes and signature verification status
   */
  TrustGraphImportResult importStatement(
      TrustStatementDocument document, String source, String sourceUri, String sourceLabel);

  /**
   * Adds or replaces a local trust anchor.
   *
   * @param anchor validated local anchor metadata
   * @return stored anchor after replacement or retention policy is applied
   */
  TrustAnchor addAnchor(TrustAnchor anchor);

  /**
   * Removes a local trust anchor by issuer fingerprint.
   *
   * @param issuerFingerprint public issuer fingerprint to remove from local anchor state
   * @return {@code true} when an anchor existed and was removed
   */
  boolean removeAnchor(String issuerFingerprint);

  /**
   * Returns all local trust anchors in deterministic order.
   *
   * @return immutable snapshot of local anchors
   */
  List<TrustAnchor> anchors();

  /**
   * Returns all imported statements in deterministic order.
   *
   * @return immutable snapshot of retained statement metadata
   */
  List<StoredTrustStatement> statements();

  /**
   * Returns all distinct subjects currently present in imported statements.
   *
   * @return immutable subject list suitable for app-facing discovery responses
   */
  List<TrustSubject> subjects();

  /**
   * Returns whether the supplied issuer fingerprint is a local anchor.
   *
   * @param issuerFingerprint issuer fingerprint from a retained statement payload
   * @return {@code true} when the fingerprint is currently anchored locally
   */
  boolean isAnchor(String issuerFingerprint);

  /**
   * Returns the number of imported statements.
   *
   * @return retained statement count after import idempotency and eviction
   */
  int statementCount();

  /**
   * Returns whether this store is backed by durable platform-owned storage.
   *
   * @return {@code true} when anchors, statements, and audit records survive process restart
   */
  default boolean durable() {
    return false;
  }

  /**
   * Returns a short implementation label for status responses.
   *
   * @return bounded store type label
   */
  default String storeType() {
    return "in-memory";
  }

  /**
   * Returns the retention and byte limits currently applied by this store.
   *
   * @return immutable store configuration
   */
  default TrustGraphStoreConfig config() {
    return TrustGraphStoreConfig.defaults();
  }

  /**
   * Appends a redacted local audit event.
   *
   * <p>Implementations may persist this event or keep it process-local. The default implementation
   * intentionally ignores events for reduced embeddings that do not expose audit history.
   *
   * @param event redacted audit event that does not contain raw trust bodies, signatures, tokens,
   *     private keys, private insert URIs, or local paths
   */
  default void appendAuditEvent(TrustGraphAuditEvent event) {
    // Reduced embeddings may omit audit storage.
  }

  /**
   * Returns recent redacted audit events in deterministic newest-first order.
   *
   * @param limit positive maximum number of events to return
   * @return immutable audit event snapshot
   */
  default List<TrustGraphAuditEvent> auditEvents(int limit) {
    return List.of();
  }

  /**
   * Stored trust statement metadata.
   *
   * <p>The record wraps the parsed document with hashes, verification status, and sanitized source
   * metadata. It is the unit consumed by the scorer and statement-summary route.
   *
   * @param document parsed trust statement document retained in memory
   * @param documentFingerprint hash over the normalized public document representation
   * @param payloadHash hash over the domain-separated canonical payload bytes
   * @param signatureVerified whether the statement signature verified during import
   * @param source sanitized local source label
   * @param sourceUri optional redacted Crypta content URI summary
   * @param sourceUriHash optional SHA-256 hash of the normalized source URI
   * @param sourceLabel optional caller-provided display label
   */
  record StoredTrustStatement(
      TrustStatementDocument document,
      String documentFingerprint,
      String payloadHash,
      boolean signatureVerified,
      String source,
      String sourceUri,
      String sourceUriHash,
      String sourceLabel,
      java.time.Instant importedAt,
      java.time.Instant updatedAt) {
    /**
     * Returns a redacted statement summary.
     *
     * @return public metadata without raw document text or signature value
     */
    public Map<String, Object> toSummaryJson() {
      Map<String, Object> summary =
          document.toSummaryJson(signatureVerified, source, sourceUri, sourceLabel);
      if (sourceUriHash != null) {
        summary.put("sourceUriHash", sourceUriHash);
      }
      if (importedAt != null) {
        summary.put("importedAt", importedAt.toString());
      }
      if (updatedAt != null) {
        summary.put("updatedAt", updatedAt.toString());
      }
      return summary;
    }
  }
}
