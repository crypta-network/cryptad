package network.crypta.platform.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class AppVaultApiRouterTest {
  private static final String APP_ID = "demo.app";

  @TempDir private Path tempDir;

  @Test
  void route_whenAppProcessStoresSecret_expectListRedactsAndReadRequiresProcessPermission()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    String rawSecret = "raw-secret-value";

    PlatformApiResponse put =
        router.route(
            request(
                "PUT",
                List.of("app-vault", "secrets", "api-token"),
                Map.of("valueUtf8", List.of(rawSecret), "metadata.accessToken", List.of(rawSecret)),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.secrets.write"))));
    PlatformApiResponse list =
        router.route(
            request(
                "GET",
                List.of("app-vault", "secrets"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.secrets.read"))));
    PlatformApiResponse read =
        router.route(
            request(
                "GET",
                List.of("app-vault", "secrets", "api-token"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.secrets.read"))));
    PlatformApiResponse browserRead =
        router.route(
            request(
                "GET",
                List.of("app-vault", "secrets", "api-token"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("vault.secrets.read"))));

    assertEquals(200, put.statusCode());
    assertFalse(put.body().contains(rawSecret));
    assertEquals(200, list.statusCode());
    assertFalse(list.body().contains(rawSecret));
    assertTrue(list.body().contains("<redacted>"));
    assertEquals(200, read.statusCode());
    assertTrue(
        read.body()
            .contains(
                Base64.getEncoder().encodeToString(rawSecret.getBytes(StandardCharsets.UTF_8))));
    assertTrue(read.body().contains("\"secret\":{\"appId\":\"" + APP_ID + "\""));
    assertTrue(read.body().contains("\"valueBase64\""));
    assertFalse(read.body().contains("\"secret\":{\"secret\""));
    assertFalse(read.body().contains("\"lastUsedAt\":null"));
    assertFalse(read.body().contains(rawSecret));
    assertEquals(403, browserRead.statusCode());
  }

  @Test
  void route_whenAppLacksVaultPermission_expectDeniedBeforeHandler() throws IOException {
    PlatformApiResponse response =
        router(AppVaultService.open(tempDir.resolve("vault")))
            .route(
                request(
                    "GET",
                    List.of("app-vault", "identities"),
                    Map.of(),
                    PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void route_whenBrowserCreatesAppOwnedIdentity_expectPublicMetadataOnly() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("app-vault", "identities"),
                Map.of(
                    "label",
                    List.of("Profile identity"),
                    "scopes",
                    List.of(
                        AppIdentityGrantScope.METADATA_READ.jsonValue()
                            + ","
                            + AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue())),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of("vault.identities.create"))));

    assertEquals(201, response.statusCode());
    assertTrue(response.body().contains("\"identity\":{"));
    assertTrue(response.body().contains("\"ownerAppId\":\"" + APP_ID + "\""));
    assertTrue(response.body().contains(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue()));
    assertFalse(response.body().contains("privateKey"));
    assertFalse(response.body().contains("private.envelope"));
    assertFalse(response.body().contains("seed"));
    assertEquals(1, vaultService.listGrantsForApp(APP_ID).size());
  }

  @Test
  void route_whenBrowserCreatesIdentityWithoutCapability_expectForbidden() throws IOException {
    PlatformApiResponse response =
        router(AppVaultService.open(tempDir.resolve("vault")))
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities"),
                    Map.of("label", List.of("Profile identity")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void route_whenHostGrantsIdentity_expectAppCanListMetadataWithoutPrivateKey() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse grant =
        router.route(
            request(
                "POST",
                List.of("identity-vault", "grants"),
                Map.of(
                    "identityId",
                    List.of(identity.identityId()),
                    "appId",
                    List.of(APP_ID),
                    "scopes",
                    List.of(
                        AppIdentityGrantScope.METADATA_READ.jsonValue()
                            + ","
                            + AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue())),
                PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse appList =
        router.route(
            request(
                "GET",
                List.of("app-vault", "identities"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.identities.read"))));

    assertEquals(201, grant.statusCode());
    assertEquals(200, appList.statusCode());
    assertTrue(appList.body().contains(identity.identityId()));
    assertTrue(appList.body().contains(identity.fingerprint()));
    assertFalse(appList.body().contains("privateKey"));
    assertFalse(appList.body().contains("private.envelope"));
  }

  @Test
  void route_whenAppUsesGrantedIdentity_expectSignatureAndAuditWithoutPrivateKey()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    vaultService.grantIdentity(
        identity.identityId(),
        APP_ID,
        java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        "operator",
        "sign feed entries",
        null,
        null);
    String payload = "feed entry payload";

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("app-vault", "identities", identity.identityId(), "use"),
                Map.of(
                    "purpose",
                    List.of("publish.feed"),
                    "payloadBase64",
                    List.of(
                        Base64.getEncoder()
                            .encodeToString(payload.getBytes(StandardCharsets.UTF_8))),
                    "scope",
                    List.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue())),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.identities.use"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"usage\":{"));
    assertTrue(response.body().contains("\"algorithm\":\"Ed25519\""));
    assertTrue(response.body().contains("\"signatureBase64\""));
    assertTrue(
        response
            .body()
            .contains(
                "\"domainSeparatedPayload\":\"CryptaAppVault:v1:"
                    + APP_ID
                    + ":"
                    + identity.identityId()
                    + ":publish.feed:"));
    assertFalse(response.body().contains(payload));
    assertFalse(response.body().contains("privateKey"));
    assertFalse(response.body().contains("private.envelope"));
    var audit = vaultService.recentAuditForApp(APP_ID, 1);
    assertEquals(1, audit.size());
    assertEquals("identity.use", audit.getFirst().operation());
    assertEquals(identity.identityId(), audit.getFirst().targetId());
    assertEquals("allowed", audit.getFirst().outcome());
  }

  @Test
  void route_whenBrowserCreatesProfileDocument_expectSignedPublicDocument() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                Map.of(
                    "displayName",
                    List.of("Ada Example"),
                    "bio",
                    List.of("Publishes signed Crypta profile documents."),
                    "website",
                    List.of("USK@example/profile/1/"),
                    "tags",
                    List.of("crypta,reference")),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"profileDocument\":{"));
    assertTrue(response.body().contains("\"schema\":\"crypta.profile.v1\""));
    assertTrue(response.body().contains("\"displayName\":\"Ada Example\""));
    assertTrue(response.body().contains("\"appId\":\"" + APP_ID + "\""));
    assertTrue(response.body().contains("\"identityId\":\"" + identity.identityId() + "\""));
    assertTrue(response.body().contains("\"purpose\":\"profile.publish.v1\""));
    assertTrue(response.body().contains("\"scope\":\"sign.domain-separated\""));
    assertTrue(response.body().contains("\"signatureBase64\""));
    assertTrue(
        response
            .body()
            .contains(
                "\"domainSeparatedPayload\":\"CryptaAppVault:v1:"
                    + APP_ID
                    + ":"
                    + identity.identityId()
                    + ":profile.publish.v1:"));
    assertFalse(response.body().contains("privateKey"));
    assertFalse(response.body().contains("private.envelope"));
    assertFalse(response.body().contains("payloadBase64"));
    assertFalse(response.body().contains(tempDir.toString()));
  }

  @Test
  void route_whenProfileDocumentBioHasLineBreaks_expectSignedPublicDocument() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of(
                        "displayName",
                        List.of("Ada Example"),
                        "bio",
                        List.of("Line one\nLine two\r\nLine three")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"bio\":\"Line one\\nLine two\\r\\nLine three\""));
    assertTrue(response.body().contains("\"signatureBase64\""));
  }

  @Test
  void route_whenProfileDocumentBioHasNonLineBreakControl_expectBadRequest() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of(
                        "displayName",
                        List.of("Ada Example"),
                        "bio",
                        List.of("Line one" + (char) 0 + "Line two")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_query_parameter"));
    assertTrue(response.body().contains("bio"));
  }

  @Test
  void route_whenBrowserCreatesProfileDocumentWithoutUseCapability_expectForbidden()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of("displayName", List.of("Ada Example")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void route_whenProfileDocumentGrantLacksSigningScope_expectVaultDenial() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Shared profile",
            null,
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    vaultService.grantIdentity(
        identity.identityId(),
        APP_ID,
        java.util.Set.of(AppIdentityGrantScope.METADATA_READ),
        "operator",
        "metadata only",
        null,
        null);

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of("displayName", List.of("Ada Example")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("identity_grant_denied"));
    assertFalse(response.body().contains("privateKey"));
  }

  @Test
  void route_whenProfileDocumentGrantInactive_expectVaultDenial() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Shared profile",
            null,
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    vaultService.grantIdentity(
        identity.identityId(),
        APP_ID,
        java.util.Set.of(AppIdentityGrantScope.METADATA_READ),
        "operator",
        "metadata",
        null,
        null);
    var signGrant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "profile signing",
            null,
            null);
    vaultService.updateGrantStatus(signGrant.grantId(), AppIdentityGrantStatus.INACTIVE);

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of("displayName", List.of("Ada Example")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("identity_grant_denied"));
  }

  @Test
  void route_whenProfileDocumentFieldTooLarge_expectDeterministicBadRequest() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "profile-document"),
                    Map.of("displayName", List.of("x".repeat(81))),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.read", "vault.identities.use"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_query_parameter"));
    assertTrue(response.body().contains("displayName"));
  }

  @Test
  void route_whenBrowserCallsGenericIdentityUse_expectProcessOnlyRouteStillDenied()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createAppOwnedIdentity(
            APP_ID,
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse response =
        router(vaultService)
            .route(
                request(
                    "POST",
                    List.of("app-vault", "identities", identity.identityId(), "use"),
                    Map.of(
                        "purpose",
                        List.of("profile.publish.v1"),
                        "payloadBase64",
                        List.of(
                            Base64.getEncoder()
                                .encodeToString("{}".getBytes(StandardCharsets.UTF_8))),
                        "scope",
                        List.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue())),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("vault.identities.use"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void route_whenBrowserRequestsGrant_expectMetadataOnlyStatusAndNoStoredGrant()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("app-vault", "grants", "request"),
                Map.of(
                    "identityId",
                    List.of("id-future"),
                    "scopes",
                    List.of(AppIdentityGrantScope.METADATA_READ.jsonValue()),
                    "reason",
                    List.of("show publisher profile")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("vault.identities.read"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"grantRequest\":{"));
    assertTrue(response.body().contains("\"status\":\"operator_review_required\""));
    assertTrue(response.body().contains("\"appId\":\"" + APP_ID + "\""));
    assertTrue(response.body().contains("\"identityId\":\"id-future\""));
    assertTrue(response.body().contains("\"secretMaterialIncluded\":false"));
    assertFalse(response.body().contains("privateKey"));
    assertFalse(response.body().contains("signatureBase64"));
    assertTrue(vaultService.listGrants().isEmpty());
  }

  @Test
  void route_whenAppListsGrantsAfterUninstallCleanup_expectRetainedRevokedGrantsHidden()
      throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    var retainedGrant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.METADATA_READ),
            "operator",
            "metadata",
            null,
            null);
    PlatformApiResponse activeList =
        router.route(
            request(
                "GET",
                List.of("app-vault", "grants"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.identities.read"))));

    vaultService.revokeGrantsForApp(APP_ID);
    PlatformApiResponse appList =
        router.route(
            request(
                "GET",
                List.of("app-vault", "grants"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of("vault.identities.read"))));
    PlatformApiResponse operatorList =
        router.route(
            request(
                "GET",
                List.of("identity-vault", "grants"),
                Map.of(),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(200, activeList.statusCode());
    assertTrue(activeList.body().contains(retainedGrant.grantId()));
    assertEquals(200, appList.statusCode());
    assertTrue(appList.body().contains("\"grants\":[]"));
    assertFalse(appList.body().contains(retainedGrant.grantId()));
    assertFalse(appList.body().contains(identity.identityId()));
    assertEquals(200, operatorList.statusCode());
    assertTrue(operatorList.body().contains(retainedGrant.grantId()));
    assertTrue(operatorList.body().contains("\"status\":\"revoked\""));
  }

  @Test
  void route_whenHostGrantOmitsScopes_expectBadRequestAndNoGrant() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    PlatformApiRouter router = router(vaultService);
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    PlatformApiResponse missingScopes =
        router.route(
            request(
                "POST",
                List.of("identity-vault", "grants"),
                Map.of("identityId", List.of(identity.identityId()), "appId", List.of(APP_ID)),
                PlatformApiPrincipal.hostOperator()));
    PlatformApiResponse blankScopes =
        router.route(
            request(
                "POST",
                List.of("identity-vault", "grants"),
                Map.of(
                    "identityId",
                    List.of(identity.identityId()),
                    "appId",
                    List.of(APP_ID),
                    "scopes",
                    List.of(" ")),
                PlatformApiPrincipal.hostOperator()));

    assertEquals(400, missingScopes.statusCode());
    assertTrue(missingScopes.body().contains("invalid_query_parameter"));
    assertEquals(400, blankScopes.statusCode());
    assertTrue(blankScopes.body().contains("invalid_query_parameter"));
    assertTrue(vaultService.listGrants().isEmpty());
  }

  @Test
  void route_whenAppPrincipalListsApps_expectVaultMetadataOmitted() throws IOException {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    vaultService.grantIdentity(
        identity.identityId(),
        APP_ID,
        java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        "operator",
        "test grant",
        null,
        null);
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "raw-secret-value".getBytes(StandardCharsets.UTF_8),
        Map.of("label", "primary"));
    AppHost appHost = appHostWithInstalledApp();
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            appHost,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            vaultService);

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("apps"),
                Map.of(),
                PlatformApiPrincipal.appToken("reader.app", List.of("apps.read"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"vault\":{\"available\":true}"));
    assertFalse(response.body().contains("api-token"));
    assertFalse(response.body().contains("raw-secret-value"));
    assertFalse(response.body().contains(identity.identityId()));
    assertFalse(response.body().contains("secretNames"));
    assertFalse(response.body().contains("recentAudit"));
  }

  private static PlatformApiRouter router(AppVaultService vaultService) {
    return new PlatformApiRouter(
        runtimePorts(), null, null, null, AppUiOriginRegistry.sameOriginOnly(), vaultService);
  }

  private AppHost appHostWithInstalledApp() throws IOException {
    AppHost appHost = mock(AppHost.class, Answers.CALLS_REAL_METHODS);
    InstalledAppSnapshot snapshot =
        new InstalledAppSnapshot(
            new AppManifest(
                1,
                APP_ID,
                "Demo App",
                "1.0.0",
                "bin/launch.sh",
                AppUiMode.NONE,
                null,
                List.of(),
                null,
                null),
            new InstalledAppPaths(
                APP_ID,
                tempDir.resolve("installed").resolve(APP_ID),
                tempDir.resolve("data").resolve(APP_ID),
                tempDir.resolve("cache").resolve(APP_ID),
                tempDir.resolve("run").resolve(APP_ID)));
    when(appHost.listInstalled()).thenReturn(List.of(snapshot));
    when(appHost.listRunning()).thenReturn(List.of());
    when(appHost.runtimeStatus(APP_ID))
        .thenReturn(
            new AppRuntimeStatusSnapshot(
                APP_ID, AppRuntimeState.STOPPED, false, null, null, null, null, 0, 0, false, null));
    return appHost;
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, queryParameters, principal);
  }

  private static RuntimePorts runtimePorts() {
    return mock(
        RuntimePorts.class,
        invocation -> {
          Object defaultValue = Answers.RETURNS_DEFAULTS.answer(invocation);
          if (defaultValue != null || invocation.getMethod().getReturnType().isPrimitive()) {
            return defaultValue;
          }
          Class<?> returnType = invocation.getMethod().getReturnType();
          return returnType.isInterface() ? mock(returnType) : null;
        });
  }
}
