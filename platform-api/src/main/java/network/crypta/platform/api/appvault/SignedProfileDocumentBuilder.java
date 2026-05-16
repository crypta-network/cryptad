package network.crypta.platform.api.appvault;

import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageResult;

/**
 * Builds the public signed profile document returned by the profile-document route.
 *
 * <p>The document contains the canonical profile payload plus public verification material only. It
 * deliberately omits private key bytes, encrypted envelopes, local vault paths, request bodies, and
 * app process or browser-session credentials.
 *
 * <p>This builder is the final serialization boundary for the browser-safe profile-publishing
 * route. It combines three already-authorized inputs: the normalized unsigned profile request, the
 * public identity metadata visible to the app, and the public result of a vault signing operation.
 * The output shape is intentionally stable and shallow so static apps, SDK helpers, and future
 * profile readers can treat it as the signed profile document root:
 *
 * <ul>
 *   <li>{@code schema} identifies the profile document format.
 *   <li>{@code profile} carries the exact app and identity-bound payload that was signed.
 *   <li>{@code identity} carries public verification material only.
 *   <li>{@code signature} carries the fixed purpose, payload hash, and signature bytes.
 * </ul>
 *
 * <p>The class is stateless and thread-safe. It performs no authorization, signing, or redaction
 * decisions itself; those decisions must happen before the builder is called.
 */
final class SignedProfileDocumentBuilder {
  /** Prevents construction because this class only groups pure document-building helpers. */
  private SignedProfileDocumentBuilder() {}

  /**
   * Builds the signed profile document map returned to the Platform API caller.
   *
   * <p>The method preserves deterministic top-level field order and delegates each nested section
   * to a helper with the same insertion-order discipline. The returned map contains mutable map
   * instances because the Platform API JSON writer consumes map values directly, but callers should
   * treat the result as a response value and avoid mutating it after construction.
   *
   * @param request normalized unsigned profile request whose payload was signed
   * @param identity public identity metadata for the resolved target identity
   * @param usageResult public result returned by the approved vault signing operation
   * @return insertion-ordered signed profile document response value
   */
  static Map<String, Object> build(
      ProfileDocumentRequest request,
      AppIdentityRecord identity,
      AppIdentityUsageResult usageResult) {
    LinkedHashMap<String, Object> document = LinkedHashMap.newLinkedHashMap(4);
    document.put("schema", ProfileDocumentRequest.SCHEMA);
    document.put("profile", request.payload());
    document.put("identity", identity(identity, usageResult));
    document.put("signature", signature(usageResult));
    return document;
  }

  /**
   * Creates the public identity verification section.
   *
   * <p>The identity id and fingerprint come from the vault identity record selected by the route.
   * The algorithm and public key come from the actual signing result so the response reflects the
   * operation that produced the signature, not only the stored metadata. Private key material and
   * encrypted envelopes are not available through either source.
   *
   * @param identity public metadata for the identity that signed the profile payload
   * @param usageResult public signing result containing algorithm and public key material
   * @return insertion-ordered identity verification section for the signed document
   */
  private static Map<String, Object> identity(
      AppIdentityRecord identity, AppIdentityUsageResult usageResult) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("identityId", identity.identityId());
    json.put("fingerprint", identity.fingerprint());
    json.put("algorithm", usageResult.algorithm());
    json.put("publicKeyBase64", usageResult.publicKeyBase64());
    return json;
  }

  /**
   * Creates the public signature metadata section.
   *
   * <p>The purpose is fixed to {@link ProfileDocumentRequest#SIGNING_PURPOSE}; browser callers do
   * not choose arbitrary signing purposes through this route. The domain-separated payload is
   * public verification material for v1 local signing. It is included exactly as returned by the
   * vault service so verifiers can reconstruct or compare the signed domain string.
   *
   * @param usageResult public signing result returned by the vault identity operation
   * @return insertion-ordered signature section for the signed document
   */
  private static Map<String, Object> signature(AppIdentityUsageResult usageResult) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("scope", usageResult.scope().jsonValue());
    json.put("purpose", ProfileDocumentRequest.SIGNING_PURPOSE);
    json.put("payloadSha256", usageResult.payloadSha256());
    json.put("domainSeparatedPayload", usageResult.domainSeparatedPayload());
    json.put("signatureBase64", usageResult.signatureBase64());
    return json;
  }
}
