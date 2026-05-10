package network.crypta.platform.api.identityvault;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.appvault.AppIdentityGrant;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Handles host/operator Platform API calls for vault identities and grants.
 *
 * <p>This handler backs the {@code /api/v1/identity-vault} route family. Those routes are not
 * app-facing: the router requires the trusted host/operator principal before dispatching here. App
 * processes and browser sessions use the app-vault route family instead, where grants and metadata
 * are filtered to the caller's app id.
 *
 * <p>Operator routes expose enough metadata to create identities, bind them to apps, change grant
 * status, and revoke access. They still keep the same redaction boundary as app-facing routes:
 * private key material, secret values, local paths, wrapping keys, and bearer/session tokens never
 * appear in the maps produced by this handler.
 *
 * @see AppVaultService
 */
public final class IdentityVaultApiHandler {
  private static final String FIELD_IDENTITY_ID = "identityId";
  private static final String FIELD_SCOPES = "scopes";
  private static final String FIELD_STATUS = "status";

  private final AppVaultService appVaultService;

  /**
   * Creates an operator-facing identity-vault handler backed by the shared vault service.
   *
   * <p>The handler does not cache identity or grant state. Each request delegates to the service so
   * operator changes, app update cleanup, and uninstall cleanup all observe the same durable store.
   *
   * @param appVaultService shared vault service used for identity and grant management
   */
  public IdentityVaultApiHandler(AppVaultService appVaultService) {
    this.appVaultService = Objects.requireNonNull(appVaultService, "appVaultService");
  }

  /**
   * Lists all vault identities without private key material.
   *
   * <p>The list is intended for operator management views. It includes app-owned and
   * operator-managed identities, but each entry contains only public identity metadata and
   * supported usage scopes.
   *
   * @return JSON-compatible identity summaries suitable for host/operator responses
   */
  public List<Map<String, Object>> listIdentities() {
    return appVaultService.listIdentities().stream()
        .map(IdentityVaultApiHandler::identitySummary)
        .toList();
  }

  /**
   * Creates an operator-managed identity.
   *
   * <p>If {@code kind} is omitted, the handler creates a local Ed25519 signing identity. The
   * optional {@code ownerAppId} parameter is retained as metadata for cases where the operator is
   * creating an identity on behalf of one app, but grant creation is still a separate explicit
   * operation.
   *
   * @param queryParameters decoded request parameters with optional kind, label, owner, and scopes
   * @return JSON-compatible public metadata for the newly created identity
   */
  public Map<String, Object> createIdentity(Map<String, List<String>> queryParameters) {
    AppIdentityKind kind =
        AppIdentityKind.fromJsonValue(
            Objects.requireNonNullElse(
                PlatformApiParameters.readOptionalString(queryParameters, "kind"),
                AppIdentityKind.LOCAL_ED25519_SIGNING.jsonValue()));
    String label = PlatformApiParameters.readOptionalString(queryParameters, "label");
    String ownerAppId = PlatformApiParameters.readOptionalString(queryParameters, "ownerAppId");
    return identitySummary(
        appVaultService.createOperatorIdentity(
            kind, label, ownerAppId, parseScopes(queryParameters)));
  }

  /**
   * Reads one identity.
   *
   * <p>Host/operator reads are not filtered by app grant state. They are used for management and
   * troubleshooting, while the returned summary still excludes encrypted private material.
   *
   * @param identityId identity id segment from the request path
   * @return JSON-compatible public metadata for the requested identity
   */
  public Map<String, Object> getIdentity(String identityId) {
    return identitySummary(appVaultService.getIdentity(identityId));
  }

  /**
   * Deletes one identity and revokes its grants.
   *
   * <p>Deletion is explicit operator action. The service revokes grants for the identity before
   * removing its metadata and private envelope so app-facing routes cannot continue to authorize a
   * removed identity.
   *
   * @param identityId identity id segment from the request path
   * @return JSON-compatible deletion result indicating whether a record was removed
   */
  public Map<String, Object> deleteIdentity(String identityId) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(FIELD_IDENTITY_ID, identityId);
    json.put("deleted", appVaultService.deleteIdentity(identityId));
    return json;
  }

  /**
   * Lists all identity grants.
   *
   * <p>Unlike the app-facing grant list, this management view includes inactive and revoked grants.
   * That lets Web Shell surface historical state, retained records, and cleanup results without
   * exposing private key or secret material.
   *
   * @return JSON-compatible grant summaries for host/operator management
   */
  public List<Map<String, Object>> listGrants() {
    return appVaultService.listGrants().stream()
        .map(IdentityVaultApiHandler::grantSummary)
        .toList();
  }

  /**
   * Grants one identity to one app.
   *
   * <p>The caller must provide explicit {@code scopes}. Empty or omitted scopes are rejected so an
   * older client or malformed form does not accidentally grant every scope supported by the
   * identity. Optional review and expiry metadata are persisted with the grant for operator audit
   * and later lifecycle decisions.
   *
   * @param queryParameters decoded request parameters naming identity, app, scopes, and metadata
   * @return JSON-compatible summary for the created grant
   */
  public Map<String, Object> createGrant(Map<String, List<String>> queryParameters) {
    String identityId = PlatformApiParameters.requireString(queryParameters, FIELD_IDENTITY_ID);
    String appId = PlatformApiParameters.requireString(queryParameters, "appId");
    return grantSummary(
        appVaultService.grantIdentity(
            identityId,
            appId,
            parseRequiredScopes(queryParameters),
            Objects.requireNonNullElse(
                PlatformApiParameters.readOptionalString(queryParameters, "grantedBy"), "operator"),
            PlatformApiParameters.readOptionalString(queryParameters, "reason"),
            parseInstant(PlatformApiParameters.readOptionalString(queryParameters, "expiresAt")),
            PlatformApiParameters.readOptionalString(queryParameters, "sourceReviewReceiptId")));
  }

  /**
   * Changes one grant status.
   *
   * <p>Status updates preserve identity id, app id, scopes, expiry, and operator metadata while
   * moving the grant to a new lifecycle state. Typical callers use this route to reactivate an
   * inactive grant after review or to suspend access without deleting the historical record.
   *
   * @param grantId grant id segment from the request path
   * @param queryParameters decoded request parameters containing the required status value
   * @return JSON-compatible summary for the updated grant
   */
  public Map<String, Object> updateGrantStatus(
      String grantId, Map<String, List<String>> queryParameters) {
    return grantSummary(
        appVaultService.updateGrantStatus(
            grantId,
            AppIdentityGrantStatus.fromJsonValue(
                PlatformApiParameters.requireString(queryParameters, FIELD_STATUS))));
  }

  /**
   * Revokes one grant.
   *
   * <p>Revocation is the permanent operator path for stopping identity access. The response reports
   * the normalized grant id and revoked status, but the full retained record remains available
   * through the management list for audit and cleanup visibility.
   *
   * @param grantId grant id segment from the request path
   * @return JSON-compatible revocation result with the new stable status value
   */
  public Map<String, Object> revokeGrant(String grantId) {
    appVaultService.revokeGrant(grantId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("grantId", grantId);
    json.put(FIELD_STATUS, AppIdentityGrantStatus.REVOKED.jsonValue());
    return json;
  }

  private static Map<String, Object> identitySummary(AppIdentityRecord identity) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put(FIELD_IDENTITY_ID, identity.identityId());
    json.put("kind", identity.kind().jsonValue());
    json.put("label", identity.label());
    json.put("ownerAppId", identity.ownerAppId());
    json.put("createdAt", identity.createdAt().toString());
    json.put("updatedAt", identity.updatedAt().toString());
    json.put("publicSummary", identity.publicSummary());
    json.put("fingerprint", identity.fingerprint());
    json.put(
        "usageScopes",
        identity.usageScopes().stream().map(AppIdentityGrantScope::jsonValue).toList());
    return json;
  }

  private static Map<String, Object> grantSummary(AppIdentityGrant grant) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("grantId", grant.grantId());
    json.put(FIELD_IDENTITY_ID, grant.identityId());
    json.put("appId", grant.appId());
    json.put(FIELD_SCOPES, grant.scopes().stream().map(AppIdentityGrantScope::jsonValue).toList());
    json.put(FIELD_STATUS, grant.status().jsonValue());
    json.put("createdAt", grant.createdAt().toString());
    json.put("updatedAt", grant.updatedAt().toString());
    json.put("expiresAt", grant.expiresAt() == null ? null : grant.expiresAt().toString());
    json.put("grantedBy", grant.grantedBy());
    json.put("reason", grant.reason());
    json.put("sourceReviewReceiptId", grant.sourceReviewReceiptId());
    return json;
  }

  private static Set<AppIdentityGrantScope> parseRequiredScopes(
      Map<String, List<String>> queryParameters) {
    return parseScopes(PlatformApiParameters.requireString(queryParameters, FIELD_SCOPES));
  }

  private static Set<AppIdentityGrantScope> parseScopes(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, FIELD_SCOPES);
    if (raw == null || raw.isBlank()) {
      return Set.of();
    }
    return parseScopes(raw);
  }

  private static Set<AppIdentityGrantScope> parseScopes(String raw) {
    TreeSet<AppIdentityGrantScope> scopes = new TreeSet<>();
    for (String part : raw.split(",", -1)) {
      String trimmed = part.trim();
      if (trimmed.isEmpty()) {
        throw invalidQuery("Query parameter '" + FIELD_SCOPES + "' must not contain empty scopes.");
      }
      scopes.add(AppIdentityGrantScope.fromJsonValue(trimmed));
    }
    return Set.copyOf(scopes);
  }

  private static Instant parseInstant(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (java.time.DateTimeException _) {
      throw invalidQuery("Query parameter 'expiresAt' must be an ISO-8601 instant.");
    }
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
