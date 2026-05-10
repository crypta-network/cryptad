package network.crypta.platform.appvault;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable request to use a granted identity for one bounded operation.
 *
 * <p>The service builds authorization decisions from this value: app id, identity id, requested
 * scope, purpose, and payload. The payload is defensive-copied on input and output because callers
 * may hold mutable byte arrays. {@link #toString()} redacts the payload so failed requests and test
 * diagnostics cannot leak message content.
 *
 * <p>The purpose becomes part of the domain-separated signing string for local Ed25519 identities.
 * It is restricted to a small path-safe vocabulary so apps can create stable purpose labels without
 * embedding control characters, whitespace, or user content in the signed domain.
 *
 * @param appId authenticated app id requesting identity use
 * @param identityId identity id to use for the requested operation
 * @param scope grant scope required by the operation
 * @param purpose app-defined domain-separation purpose label
 * @param payload raw request payload whose hash is used by the live signing operation
 */
public record AppIdentityUsageRequest(
    String appId, String identityId, AppIdentityGrantScope scope, String purpose, byte[] payload) {
  /**
   * Creates a validated usage request.
   *
   * <p>App and identity ids are normalized to vault-safe identifiers, the purpose is trimmed and
   * checked, and the payload is copied immediately. Payload size limits are enforced by the service
   * so the same record type can be used by tests and future operations with different limits.
   */
  public AppIdentityUsageRequest {
    appId = AppVaultPaths.normalizeAppId(appId);
    identityId = AppVaultPaths.normalizeIdentityId(identityId);
    Objects.requireNonNull(scope, "scope");
    purpose = normalizePurpose(purpose);
    payload = Objects.requireNonNull(payload, "payload").clone();
  }

  /**
   * Returns a defensive copy of the request payload.
   *
   * @return copied payload bytes supplied by the caller
   */
  @Override
  public byte[] payload() {
    return payload.clone();
  }

  @Override
  public boolean equals(Object other) {
    if (!(other
        instanceof
        AppIdentityUsageRequest(
            var thatAppId,
            var thatIdentityId,
            var thatScope,
            var thatPurpose,
            var thatPayload))) {
      return false;
    }
    return appId.equals(thatAppId)
        && identityId.equals(thatIdentityId)
        && scope == thatScope
        && purpose.equals(thatPurpose)
        && Arrays.equals(payload, thatPayload);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(appId, identityId, scope, purpose);
    return 31 * result + Arrays.hashCode(payload);
  }

  @Override
  public @NotNull String toString() {
    return "AppIdentityUsageRequest[appId="
        + appId
        + ", identityId="
        + identityId
        + ", scope="
        + scope.jsonValue()
        + ", payload=<redacted>]";
  }

  private static String normalizePurpose(String value) {
    String text = Objects.requireNonNull(value, "purpose").trim();
    if (text.isEmpty() || text.length() > 96) {
      throw new AppVaultException(
          400, "invalid_usage_purpose", "Identity usage purpose is invalid.");
    }
    if (!text.matches("[A-Za-z0-9._:-]+")) {
      throw new AppVaultException(
          400, "invalid_usage_purpose", "Identity usage purpose is invalid.");
    }
    return text;
  }
}
