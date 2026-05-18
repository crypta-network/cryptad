package network.crypta.platform.trustgraph;

import java.util.LinkedHashMap;
import java.util.Map;
import org.jetbrains.annotations.NotNull;

/**
 * Public issuer metadata included in a trust statement payload.
 *
 * <p>The issuer identifies the app-visible or public identity that authored a statement. The
 * fingerprint is the local anchor key used by the preview scorer. The optional public key lets
 * importers verify AppVault preview signatures before evidence can contribute to a score; older or
 * externally constructed statements without the key remain non-contributing evidence.
 *
 * <p>The record deliberately carries public metadata only. It does not reference vault storage,
 * private keys, seeds, process tokens, browser session tokens, or local filesystem paths.
 *
 * @param identityId app-visible or public identity id
 * @param publicKeyFingerprint public signing key fingerprint
 * @param publicKeyBase64 optional X.509-encoded public signing key for preview verification
 * @param profileUri optional issuer profile URI
 */
public record TrustIssuer(
    String identityId, String publicKeyFingerprint, String publicKeyBase64, String profileUri) {
  /** Creates issuer metadata after applying public field bounds. */
  public TrustIssuer {
    identityId = TrustStatementValidator.requiredText("issuer.identityId", identityId, 192);
    publicKeyFingerprint =
        TrustStatementValidator.requiredText(
            "issuer.publicKeyFingerprint", publicKeyFingerprint, 128);
    publicKeyBase64 =
        TrustStatementValidator.optionalText("issuer.publicKeyBase64", publicKeyBase64, 4096);
    profileUri = TrustStatementValidator.optionalText("issuer.profileUri", profileUri, 1024);
  }

  /**
   * Creates issuer metadata without an inline public key.
   *
   * <p>This overload keeps compatibility with fixtures and externally supplied statements that only
   * carry a fingerprint. Such statements can be imported and displayed, but they cannot verify
   * locally or contribute to scores until a future source supplies key material.
   *
   * @param identityId app-visible or public identity id
   * @param publicKeyFingerprint public signing key fingerprint
   * @param profileUri optional issuer profile URI
   */
  public TrustIssuer(String identityId, String publicKeyFingerprint, String profileUri) {
    this(identityId, publicKeyFingerprint, null, profileUri);
  }

  /**
   * Returns this issuer as an insertion-ordered JSON object.
   *
   * @return public issuer metadata in canonical payload field order
   */
  public Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("identityId", identityId);
    json.put("publicKeyFingerprint", publicKeyFingerprint);
    if (publicKeyBase64 != null) {
      json.put("publicKeyBase64", publicKeyBase64);
    }
    if (profileUri != null) {
      json.put("profileUri", profileUri);
    }
    return json;
  }

  @Override
  @NotNull
  public String toString() {
    return "TrustIssuer[identityId="
        + identityId
        + ", publicKeyFingerprint="
        + publicKeyFingerprint
        + ", publicKeyBase64=<redacted>, profileUri="
        + profileUri
        + "]";
  }
}
