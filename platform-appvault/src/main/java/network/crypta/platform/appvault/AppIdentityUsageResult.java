package network.crypta.platform.appvault;

import java.util.Objects;

/**
 * Public result returned after a vault identity performs an approved operation.
 *
 * <p>For the v1 local Ed25519 implementation, the result contains public key metadata, the payload
 * hash, the exact domain-separated string that was signed, and the signature. It does not contain
 * the private key, encrypted private envelope, local store path, wrapping key id, or raw payload
 * bytes.
 *
 * <p>The signature is returned to the API caller, but {@link #toString()} still redacts it. That
 * keeps diagnostic output compact and prevents large signatures from being copied into logs while
 * leaving explicit response serialization to the Platform API handler.
 *
 * @param identityId identity that performed the operation
 * @param scope grant scope used for the operation
 * @param algorithm public algorithm label for the operation result
 * @param fingerprint public fingerprint of the identity key or reference
 * @param publicKeyBase64 Base64-encoded public key bytes for verification
 * @param payloadSha256 SHA-256 hash of the original payload
 * @param domainSeparatedPayload exact domain-separated string signed by the vault
 * @param signatureBase64 Base64-encoded operation signature returned to the caller
 */
public record AppIdentityUsageResult(
    String identityId,
    AppIdentityGrantScope scope,
    String algorithm,
    String fingerprint,
    String publicKeyBase64,
    String payloadSha256,
    String domainSeparatedPayload,
    String signatureBase64) {
  /**
   * Creates a validated identity usage result.
   *
   * <p>All public string fields are required and trimmed so malformed service output fails before
   * it reaches API serialization. The constructor validates identifiers but does not verify the
   * signature; verification belongs to callers that consume the public key and signature.
   */
  public AppIdentityUsageResult {
    identityId = AppVaultPaths.normalizeIdentityId(identityId);
    Objects.requireNonNull(scope, "scope");
    algorithm = requireText(algorithm, "algorithm");
    fingerprint = requireText(fingerprint, "fingerprint");
    publicKeyBase64 = requireText(publicKeyBase64, "publicKeyBase64");
    payloadSha256 = requireText(payloadSha256, "payloadSha256");
    domainSeparatedPayload = requireText(domainSeparatedPayload, "domainSeparatedPayload");
    signatureBase64 = requireText(signatureBase64, "signatureBase64");
  }

  @Override
  public String toString() {
    return "AppIdentityUsageResult[identityId="
        + identityId
        + ", scope="
        + scope.jsonValue()
        + ", algorithm="
        + algorithm
        + ", fingerprint="
        + fingerprint
        + ", payloadSha256="
        + payloadSha256
        + ", signature=<redacted>]";
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }
}
