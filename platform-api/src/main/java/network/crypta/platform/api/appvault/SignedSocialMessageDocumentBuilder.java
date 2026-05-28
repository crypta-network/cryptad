package network.crypta.platform.api.appvault;

import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageResult;

/**
 * Builds the public signed social-message document returned by the Social Inbox Preview route.
 *
 * <p>The output contains only the canonical public message payload and public verification
 * metadata. It deliberately omits private key bytes, encrypted vault envelopes, local vault paths,
 * browser-session tokens, app process tokens, raw request bodies, and the internal canonical bytes
 * that AppVault signed.
 *
 * <p>This builder is the final serialization boundary for the bounded {@code
 * crypta.social.message.v1} signing route. The route has already authenticated the app principal,
 * resolved an AppVault identity visible to that app, validated the message shape, and received a
 * domain-separated signing result. This class only combines those public inputs into the document
 * that static apps can put into an outbox snapshot or hand to a verifier.
 *
 * <p>The returned document uses a shallow, deterministic shape:
 *
 * <ul>
 *   <li>{@code type} names the signed social-message document format.
 *   <li>{@code message} carries the exact app-bound payload that was signed.
 *   <li>{@code signature} carries public verification metadata for the fixed signing domain.
 * </ul>
 *
 * <p>The class is stateless and thread-safe. It performs no authorization, signing, redaction, or
 * trust scoring decisions; those decisions belong to the route handler, AppVault service, and the
 * importing Social Inbox app.
 */
final class SignedSocialMessageDocumentBuilder {
  /** Prevents construction because this class only groups pure document-building helpers. */
  private SignedSocialMessageDocumentBuilder() {}

  /**
   * Builds the signed social-message document map returned to the Platform API caller.
   *
   * <p>The method preserves deterministic top-level field order and delegates the public signature
   * section to a helper with the same insertion-order discipline. The returned map contains mutable
   * map instances because the Platform API JSON writer consumes map values directly, but callers
   * should treat it as a response value and avoid mutating it after construction.
   *
   * <p>The {@code request} must be the same normalized request whose canonical bytes were passed to
   * AppVault. The builder does not recompute the payload hash and does not verify the signature; it
   * records the hash and signature material returned by the vault operation.
   *
   * @param request normalized social-message request whose canonical bytes were signed
   * @param identity public metadata for the identity selected by the route
   * @param usageResult public result returned by the approved vault signing operation
   * @return insertion-ordered signed social-message document response value
   */
  static Map<String, Object> build(
      SocialMessageRequest request,
      AppIdentityRecord identity,
      AppIdentityUsageResult usageResult) {
    LinkedHashMap<String, Object> document = LinkedHashMap.newLinkedHashMap(3);
    document.put("type", SocialMessageRequest.TYPE);
    document.put("message", request.message());
    document.put("signature", signature(identity, usageResult));
    return document;
  }

  /**
   * Creates the public signature metadata section.
   *
   * <p>The domain is fixed to {@link SocialMessageRequest#SIGNING_PURPOSE}; browser callers do not
   * choose arbitrary signing domains through this route. The public key fingerprint comes from the
   * resolved identity metadata, while the algorithm, public key bytes, payload hash, and signature
   * bytes come from the AppVault signing result. Private key material and encrypted envelopes are
   * not available through either source.
   *
   * @param identity public metadata for the identity that signed the social message
   * @param usageResult public signing result returned by the vault identity operation
   * @return insertion-ordered signature section for the signed social-message document
   */
  private static Map<String, Object> signature(
      AppIdentityRecord identity, AppIdentityUsageResult usageResult) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("algorithm", usageResult.algorithm());
    json.put("domain", SocialMessageRequest.SIGNING_PURPOSE);
    json.put("payloadHash", usageResult.payloadSha256());
    json.put("publicKeyFingerprint", identity.fingerprint());
    json.put("publicKeyBase64", usageResult.publicKeyBase64());
    json.put("signatureBase64", usageResult.signatureBase64());
    return json;
  }
}
