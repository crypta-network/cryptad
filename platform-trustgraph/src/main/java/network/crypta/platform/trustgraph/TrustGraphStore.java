package network.crypta.platform.trustgraph;

import java.util.List;

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
   * @param sourceUri optional Crypta content URI associated with the imported document
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
   * @param sourceUri optional normalized Crypta content URI
   * @param sourceLabel optional caller-provided display label
   */
  record StoredTrustStatement(
      TrustStatementDocument document,
      String documentFingerprint,
      String payloadHash,
      boolean signatureVerified,
      String source,
      String sourceUri,
      String sourceLabel) {
    /**
     * Returns a redacted statement summary.
     *
     * @return public metadata without raw document text or signature value
     */
    public java.util.Map<String, Object> toSummaryJson() {
      return document.toSummaryJson(signatureVerified, source, sourceUri, sourceLabel);
    }
  }
}
