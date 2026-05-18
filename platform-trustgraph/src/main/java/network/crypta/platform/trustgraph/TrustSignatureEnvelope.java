package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jetbrains.annotations.NotNull;

/**
 * Public signature envelope attached to a trust statement.
 *
 * <p>The envelope identifies the bounded AppVault preview signature attached to a trust statement.
 * It fixes both the algorithm label and the signing domain so callers cannot smuggle generic
 * signing outputs into the trust statement format. The signature value is public document data, but
 * normal diagnostics and summaries still redact it.
 *
 * @param algorithm public algorithm label
 * @param domain fixed trust statement signing domain
 * @param value base64 signature or deterministic preview signature
 */
public record TrustSignatureEnvelope(String algorithm, String domain, String value) {
  /**
   * Creates a bounded signature envelope.
   *
   * <p>The constructor validates the preview algorithm and domain labels. It does not verify the
   * signature bytes; import-time verification belongs to {@link TrustStatementVerifier}.
   */
  public TrustSignatureEnvelope {
    algorithm = TrustStatementValidator.requiredText("signature.algorithm", algorithm, 96);
    domain = TrustStatementValidator.requiredText("signature.domain", domain, 96);
    value = TrustStatementValidator.requiredText("signature.value", value, 4096);
    if (!TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM.equals(algorithm)) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field 'signature.algorithm' must be "
              + TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM
              + ".");
    }
    if (!TrustDocumentTypes.TRUST_STATEMENT_V1.equals(domain)) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field 'signature.domain' must be " + TrustDocumentTypes.TRUST_STATEMENT_V1 + ".");
    }
  }

  /**
   * Returns this envelope as an insertion-ordered JSON object.
   *
   * @return public signature envelope for trust statement serialization
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("algorithm", algorithm);
    json.put("domain", domain);
    json.put("value", value);
    return json;
  }

  @Override
  @NotNull
  public String toString() {
    return "TrustSignatureEnvelope[algorithm="
        + algorithm
        + ", domain="
        + domain
        + ", value=<redacted>]";
  }
}
