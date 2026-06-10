package network.crypta.platform.api.appservices;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Durable grant record authorizing one consumer/provider/service relationship.
 *
 * <p>The grant id is a stable local identifier, not a bearer secret. Public JSON never contains raw
 * tokens, request bodies, local paths, private insert URIs, or provider-private data.
 *
 * <p>Grants move through a small lifecycle: pending records capture a consumer request, active
 * records authorize future invocations while the manifests still match, and revoked or inactive
 * records do not authorize calls. The coordinator computes effective inactivity at read time when a
 * provider is uninstalled, stops advertising the service, or the consumer no longer declares the
 * required permission.
 *
 * <p>The meaning of {@code contexts} follows the provider descriptor. For contextual services the
 * list is the exact-approved context set. For unscoped services the list must be empty; it is not a
 * wildcard over future contexts a provider might add later.
 *
 * <p>The record is immutable. State transitions return new records so file-backed storage can
 * rewrite one bounded properties file per grant.
 *
 * @param grantId stable local grant identifier, not a bearer credential
 * @param consumerAppId consumer app id that requested or uses the service
 * @param providerAppId provider app id that advertises the service
 * @param serviceId public service id used by discovery and invocation routes
 * @param scopes approved or requested scopes/actions for the service
 * @param contexts approved or requested contexts, or empty for unscoped services
 * @param purpose operator-facing reason supplied by the consumer app
 * @param status stored grant lifecycle state
 * @param createdAt timestamp when the grant record was created
 * @param updatedAt timestamp when the grant record last changed
 * @param approvedAt approval timestamp, or {@code null} until approval
 * @param revokedAt revocation timestamp, or {@code null} until revocation
 * @param lastUsedAt last successful invocation timestamp, or {@code null}
 * @param useCount number of successful invocations recorded for this grant
 * @param tokenFingerprint optional token fingerprint; PR-243 does not issue raw service tokens
 * @param bundleId optional grant-bundle id that approved or renewed this grant
 * @param expiresAt optional expiry timestamp after which the grant is non-authorizing
 * @param renewedAt optional timestamp of the latest explicit operator renewal
 * @param compatibilityFingerprint approval-time safe descriptor compatibility fingerprint
 * @param providerServiceVersionAtApproval provider service version observed at approval time
 */
public record AppServiceGrant(
    String grantId,
    String consumerAppId,
    String providerAppId,
    String serviceId,
    List<String> scopes,
    List<String> contexts,
    String purpose,
    AppServiceGrantStatus status,
    Instant createdAt,
    Instant updatedAt,
    Instant approvedAt,
    Instant revokedAt,
    Instant lastUsedAt,
    long useCount,
    String tokenFingerprint,
    String bundleId,
    Instant expiresAt,
    Instant renewedAt,
    String compatibilityFingerprint,
    String providerServiceVersionAtApproval) {
  /** Backward-compatible constructor for legacy tests and pre-expiry grant creation. */
  public AppServiceGrant(
      String grantId,
      String consumerAppId,
      String providerAppId,
      String serviceId,
      List<String> scopes,
      List<String> contexts,
      String purpose,
      AppServiceGrantStatus status,
      Instant createdAt,
      Instant updatedAt,
      Instant approvedAt,
      Instant revokedAt,
      Instant lastUsedAt,
      long useCount,
      String tokenFingerprint) {
    this(
        grantId,
        consumerAppId,
        providerAppId,
        serviceId,
        scopes,
        contexts,
        purpose,
        status,
        createdAt,
        updatedAt,
        approvedAt,
        revokedAt,
        lastUsedAt,
        useCount,
        tokenFingerprint,
        null,
        null,
        null,
        null,
        null);
  }

  /**
   * Creates a validated grant.
   *
   * <p>Identifier, scope, and context values are normalized so stored grants compare consistently
   * with manifest descriptors and invocation parameters. Negative use counts are rejected because
   * they would make operator-facing usage evidence ambiguous.
   */
  public AppServiceGrant {
    grantId = AppServiceManifestParser.normalizeGrantId(grantId);
    consumerAppId = AppServiceManifestParser.normalizeAppId(consumerAppId);
    providerAppId = AppServiceManifestParser.normalizeAppId(providerAppId);
    serviceId = AppServiceManifestParser.normalizeServiceId(serviceId);
    scopes = AppServiceManifestParser.normalizeTokens("scopes", scopes, 16);
    contexts = AppServiceManifestParser.normalizeTokens("contexts", contexts, 16);
    purpose = AppServiceManifestParser.requiredStoredPurposeText(purpose);
    java.util.Objects.requireNonNull(status, "status");
    java.util.Objects.requireNonNull(createdAt, "createdAt");
    java.util.Objects.requireNonNull(updatedAt, "updatedAt");
    if (useCount < 0) {
      throw new IllegalArgumentException("useCount must not be negative");
    }
    tokenFingerprint = AppServiceManifestParser.optionalText(tokenFingerprint, 128);
    bundleId = bundleId == null ? null : AppServiceManifestParser.normalizeBundleId(bundleId);
    compatibilityFingerprint = AppServiceManifestParser.optionalText(compatibilityFingerprint, 128);
    providerServiceVersionAtApproval =
        providerServiceVersionAtApproval == null
            ? null
            : AppServiceManifestParser.requiredText(
                "providerServiceVersionAtApproval", providerServiceVersionAtApproval, 40);
  }

  /**
   * Returns the grant with a new lifecycle status.
   *
   * <p>The transition preserves creation time, purpose, scopes, contexts, and use counters. First
   * approval and first revocation timestamps are captured when the target status reaches {@code
   * ACTIVE} or {@code REVOKED}; later transitions keep those original lifecycle markers.
   *
   * @param newStatus target stored lifecycle status
   * @param now update timestamp to store in {@code updatedAt}
   * @return updated grant record with the requested status
   */
  public AppServiceGrant withStatus(AppServiceGrantStatus newStatus, Instant now) {
    Instant approved = approvedAt;
    Instant revoked = revokedAt;
    if (newStatus == AppServiceGrantStatus.ACTIVE && approved == null) {
      approved = now;
    }
    if (newStatus == AppServiceGrantStatus.REVOKED && revoked == null) {
      revoked = now;
    }
    return new AppServiceGrant(
        grantId,
        consumerAppId,
        providerAppId,
        serviceId,
        scopes,
        contexts,
        purpose,
        newStatus,
        createdAt,
        now,
        approved,
        revoked,
        lastUsedAt,
        useCount,
        tokenFingerprint,
        bundleId,
        expiresAt,
        renewedAt,
        compatibilityFingerprint,
        providerServiceVersionAtApproval);
  }

  AppServiceGrant withApprovalMetadata(
      Instant now,
      String newBundleId,
      Instant newExpiresAt,
      Instant newRenewedAt,
      String newCompatibilityFingerprint,
      String newProviderServiceVersion) {
    Instant approved = approvedAt == null ? now : approvedAt;
    return new AppServiceGrant(
        grantId,
        consumerAppId,
        providerAppId,
        serviceId,
        scopes,
        contexts,
        purpose,
        AppServiceGrantStatus.ACTIVE,
        createdAt,
        now,
        approved,
        revokedAt,
        lastUsedAt,
        useCount,
        tokenFingerprint,
        newBundleId,
        newExpiresAt,
        newRenewedAt,
        newCompatibilityFingerprint,
        newProviderServiceVersion);
  }

  /**
   * Returns the grant after one successful use.
   *
   * <p>The coordinator calls this only after adapter invocation succeeds. Denied invocations are
   * audited separately and do not change {@code lastUsedAt} or {@code useCount}.
   *
   * @param now successful invocation timestamp
   * @return updated grant record with incremented use count
   */
  public AppServiceGrant recordUse(Instant now) {
    return new AppServiceGrant(
        grantId,
        consumerAppId,
        providerAppId,
        serviceId,
        scopes,
        contexts,
        purpose,
        status,
        createdAt,
        now,
        approvedAt,
        revokedAt,
        now,
        useCount + 1,
        tokenFingerprint,
        bundleId,
        expiresAt,
        renewedAt,
        compatibilityFingerprint,
        providerServiceVersionAtApproval);
  }

  /**
   * Returns public grant JSON.
   *
   * <p>This overload exposes the stored status. Callers that need runtime availability checks, such
   * as Platform API route responses, should use {@link #toJson(AppServiceGrantStatus)} with the
   * coordinator's effective status.
   *
   * @return deterministic JSON-compatible grant map using the stored status
   */
  public java.util.Map<String, Object> toJson() {
    return toJson(status);
  }

  /**
   * Returns public grant JSON with an effective status override.
   *
   * <p>The override lets callers report {@code inactive} when an active stored grant no longer maps
   * to an installed provider service. The serialized shape remains identical so SDK and Web Shell
   * code can render grant records without knowing whether the status was stored or computed.
   *
   * @param effectiveStatus status to expose for current availability
   * @return deterministic JSON-compatible grant map with stable key order
   */
  public java.util.Map<String, Object> toJson(AppServiceGrantStatus effectiveStatus) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(20);
    json.put("grantId", grantId);
    json.put("consumerAppId", consumerAppId);
    json.put("providerAppId", providerAppId);
    json.put("serviceId", serviceId);
    json.put("scopes", scopes);
    json.put("contexts", contexts);
    json.put("purpose", purpose);
    json.put("status", effectiveStatus.jsonValue());
    json.put("createdAt", createdAt.toString());
    json.put("updatedAt", updatedAt.toString());
    json.put("approvedAt", approvedAt == null ? null : approvedAt.toString());
    json.put("revokedAt", revokedAt == null ? null : revokedAt.toString());
    json.put("lastUsedAt", lastUsedAt == null ? null : lastUsedAt.toString());
    json.put("useCount", useCount);
    json.put("tokenFingerprint", tokenFingerprint);
    json.put("bundleId", bundleId);
    json.put("expiresAt", expiresAt == null ? null : expiresAt.toString());
    json.put("renewedAt", renewedAt == null ? null : renewedAt.toString());
    json.put("compatibilityFingerprint", compatibilityFingerprint);
    json.put("providerServiceVersionAtApproval", providerServiceVersionAtApproval);
    return json;
  }
}
