package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;

/**
 * Deterministic canonicalization for signed trust statement payloads.
 *
 * <p>The Trust Graph Preview signs only the payload, not the surrounding document wrapper. This
 * class defines the exact byte sequence used by the AppVault signing route and by local signature
 * verification. It relies on the bounded payload model for field order and rejects unknown fields
 * before the payload reaches this layer.
 */
public final class TrustStatementCanonicalizer {
  private TrustStatementCanonicalizer() {}

  /**
   * Serializes a payload to canonical JSON with stable field order and no insignificant whitespace.
   *
   * @param payload validated trust statement payload to serialize
   * @return compact canonical payload JSON in the model-defined field order
   */
  public static String canonicalPayloadJson(TrustStatementPayload payload) {
    return TrustJson.write(payload.toJson());
  }

  /**
   * Returns the domain-separated UTF-8 byte sequence that is signed by the preview route.
   *
   * <p>The byte sequence is:
   *
   * <pre>{@code
   * crypta.trust.statement.v1\n<canonical-payload-json>
   * }</pre>
   *
   * @param payload validated payload
   * @return UTF-8 bytes signed and verified for trust statement documents
   */
  public static byte[] canonicalPayloadBytes(TrustStatementPayload payload) {
    return (TrustDocumentTypes.TRUST_STATEMENT_V1 + "\n" + canonicalPayloadJson(payload))
        .getBytes(StandardCharsets.UTF_8);
  }
}
