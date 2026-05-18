package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jetbrains.annotations.NotNull;

/**
 * Public root trust statement document.
 *
 * <p>The document wrapper binds the fixed type, canonical signed payload, and signature envelope.
 * Import and publication APIs exchange this shape as JSON with content type {@code
 * application/vnd.crypta.trust+json}. Normal summaries expose hashes, public metadata, and
 * verification status rather than the raw document body or signature value.
 *
 * @param type fixed document type {@code crypta.trust.statement.v1}
 * @param payload signed payload
 * @param signature public signature envelope
 */
public record TrustStatementDocument(
    String type, TrustStatementPayload payload, TrustSignatureEnvelope signature) {
  /**
   * Creates a validated trust statement root.
   *
   * <p>The constructor checks only wrapper invariants. Payload and signature field bounds are
   * enforced by their own model types, and cryptographic verification happens at import time.
   */
  public TrustStatementDocument {
    if (!TrustDocumentTypes.TRUST_STATEMENT_V1.equals(type)) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field 'type' must be " + TrustDocumentTypes.TRUST_STATEMENT_V1 + ".");
    }
    java.util.Objects.requireNonNull(payload, "payload");
    java.util.Objects.requireNonNull(signature, "signature");
  }

  /**
   * Returns this statement as an insertion-ordered JSON object.
   *
   * @return public trust statement document suitable for publication
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("type", type);
    json.put("payload", payload.toJson());
    json.put("signature", signature.toJson());
    return json;
  }

  /**
   * Returns a token-free, signature-free summary of this statement.
   *
   * @param signatureVerified whether the document signature verified during import
   * @param source sanitized local source label
   * @param sourceUri optional normalized Crypta content URI
   * @param sourceLabel optional caller-provided short display label
   * @return redacted public statement metadata for app-facing lists
   */
  public Map<String, Object> toSummaryJson(
      boolean signatureVerified, String source, String sourceUri, String sourceLabel) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put("documentFingerprint", TrustStatementFingerprint.documentFingerprint(this));
    json.put("payloadHash", TrustStatementFingerprint.payloadHash(this));
    json.put("type", type);
    json.put("issuerFingerprint", payload.issuer().publicKeyFingerprint());
    json.put("subject", payload.subject().toJson());
    json.put("context", payload.context());
    json.put("score", payload.score());
    json.put("confidence", payload.confidence());
    json.put("issuedAt", payload.issuedAt().toString());
    json.put("expiresAt", payload.expiresAt() == null ? null : payload.expiresAt().toString());
    json.put("signatureAlgorithm", signature.algorithm());
    json.put("signaturePresent", true);
    json.put("signatureVerified", signatureVerified);
    json.put("source", source);
    if (sourceUri != null) {
      json.put("sourceUri", sourceUri);
    }
    if (sourceLabel != null) {
      json.put("sourceLabel", sourceLabel);
    }
    return json;
  }

  @Override
  @NotNull
  public String toString() {
    return "TrustStatementDocument[type="
        + type
        + ", payload="
        + payload
        + ", signature=<redacted>]";
  }
}
