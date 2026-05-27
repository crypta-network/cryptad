package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Summary returned after importing a trust statement.
 *
 * <p>The import result gives apps enough metadata to display and later query the retained statement
 * without echoing raw user-provided JSON. The document and payload hashes are stable identifiers
 * for local summaries; {@code signatureVerified} tells the scorer whether the statement may
 * contribute once its issuer fingerprint is anchored.
 *
 * @param documentFingerprint hash over the normalized public document representation
 * @param payloadHash hash over the domain-separated canonical payload bytes
 * @param imported {@code true} when this call added a new retained document fingerprint
 * @param signatureVerified whether the statement signature verified against issuer key metadata
 * @param source sanitized local source label
 * @param sourceUri optional redacted Crypta content URI summary associated with the import
 * @param sourceUriHash optional SHA-256 hash of the normalized source URI
 * @param sourceLabel optional short caller-supplied label for display
 * @param importedAt first time this statement fingerprint was retained
 * @param updatedAt latest time this statement fingerprint metadata was updated
 * @param document parsed trust statement model retained by the store
 */
public record TrustGraphImportResult(
    String documentFingerprint,
    String payloadHash,
    boolean imported,
    boolean signatureVerified,
    String source,
    String sourceUri,
    String sourceUriHash,
    String sourceLabel,
    java.time.Instant importedAt,
    java.time.Instant updatedAt,
    TrustStatementDocument document) {
  /**
   * Returns a redacted import summary without the raw document or signature value.
   *
   * @return insertion-ordered JSON-compatible import metadata for app responses
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("documentFingerprint", documentFingerprint);
    json.put("payloadHash", payloadHash);
    json.put("imported", imported);
    json.put("signatureVerified", signatureVerified);
    json.put("type", TrustDocumentTypes.TRUST_STATEMENT_V1);
    json.put("issuerFingerprint", document.payload().issuer().publicKeyFingerprint());
    json.put("subject", document.payload().subject().toJson());
    json.put("context", document.payload().context());
    json.put("source", source);
    if (sourceUri != null) {
      json.put("sourceUri", sourceUri);
    }
    if (sourceUriHash != null) {
      json.put("sourceUriHash", sourceUriHash);
    }
    if (sourceLabel != null) {
      json.put("sourceLabel", sourceLabel);
    }
    if (importedAt != null) {
      json.put("importedAt", importedAt.toString());
    }
    if (updatedAt != null) {
      json.put("updatedAt", updatedAt.toString());
    }
    return json;
  }
}
