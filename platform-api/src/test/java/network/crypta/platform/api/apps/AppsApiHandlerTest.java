package network.crypta.platform.api.apps;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.AppAuditLog;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppQuotaPolicy;
import network.crypta.platform.apphost.AppQuotaStatus;
import network.crypta.platform.apphost.AppQuotaUsage;
import network.crypta.platform.apphost.AppQuotaWarning;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.AppUninstallOptions;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.sandbox.AppSandboxException;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;
import network.crypta.platform.apphost.sandbox.AppSandboxSupportLevel;
import network.crypta.platform.appui.AppUiOrigin;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppsApiHandlerTest {
  private static final String APP_ID = "demo-app";
  private static final String ERROR_INVALID_APP_BUNDLE = "invalid_app_bundle";
  private static final String FIELD_MAX_BYTES = "maxBytes";
  private static final String FIELD_RUNNING = "running";
  private static final String FIELD_UI_ENTRY = "uiEntry";
  private static final String FIELD_UI_MODE = "uiMode";
  private static final String FIELD_UI_URL = "uiUrl";
  private static final String SAMPLE_INSTANT_TEXT = "2024-01-02T03:04:05Z";
  private static final String SHELL_PANEL_ENTRY = "/app/node/#queue";
  private static final String SIGNED_BUNDLE_FAILURE_MESSAGE =
      "Staged app bundle must pass trusted signature verification.";
  private static final String STAGED_DIR_PARAMETER = "stagedDir";

  @TempDir private Path tempDir;

  @Test
  void install_whenSignedBundleVerificationFails_expectBadRequestWithoutAbsolutePathLeak()
      throws IOException {
    ThrowingAppHost appHost = new ThrowingAppHost();
    appHost.installFailure =
        new AppBundleVerificationException(
            "signature sidecar missing in copied bundle: /srv/node/apps/installed/demo-app");
    AppsApiHandler handler = new AppsApiHandler(appHost);
    Path stagedDir = stageApp(tempDir.resolve("staged-install"));
    Map<String, List<String>> installParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.install(installParameters));

    assertEquals(400, exception.statusCode());
    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals(SIGNED_BUNDLE_FAILURE_MESSAGE, exception.getMessage());
  }

  @Test
  void update_whenSignedBundleVerificationFails_expectBadRequestWithoutAbsolutePathLeak()
      throws IOException {
    ThrowingAppHost appHost = new ThrowingAppHost();
    appHost.updateFailure =
        new AppBundleVerificationException(
            "trusted key not found for bundle at C:\\cryptad\\apps\\installed\\demo-app");
    AppsApiHandler handler = new AppsApiHandler(appHost);
    Path stagedDir = stageApp(tempDir.resolve("staged-update"));
    Map<String, List<String>> updateParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.update(APP_ID, updateParameters));

    assertEquals(400, exception.statusCode());
    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals(SIGNED_BUNDLE_FAILURE_MESSAGE, exception.getMessage());
  }

  @Test
  void install_whenStaticUiEntryValidationFails_expectInvalidAppBundle() throws IOException {
    ThrowingAppHost appHost = new ThrowingAppHost();
    appHost.installFailure =
        new AppHostException(
            "app.ui.entry does not resolve to a file in copied bundle: static/index.html");
    AppsApiHandler handler = new AppsApiHandler(appHost);
    Path stagedDir = stageApp(tempDir.resolve("staged-static-ui-install"));
    Map<String, List<String>> installParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.install(installParameters));

    assertEquals(400, exception.statusCode());
    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals(
        "app.ui.entry does not resolve to a file in copied bundle: static/index.html",
        exception.getMessage());
  }

  @Test
  void update_whenStaticUiEntryValidationFails_expectInvalidAppBundle() throws IOException {
    ThrowingAppHost appHost = new ThrowingAppHost();
    appHost.updateFailure =
        new AppHostException("app.ui.entry must not traverse links in copied bundle");
    AppsApiHandler handler = new AppsApiHandler(appHost);
    Path stagedDir = stageApp(tempDir.resolve("staged-static-ui-update"));
    Map<String, List<String>> updateParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.update(APP_ID, updateParameters));

    assertEquals(400, exception.statusCode());
    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
    assertEquals("app.ui.entry must not traverse links in copied bundle", exception.getMessage());
  }

  @Test
  void install_whenTrustConfigurationFails_expectInternalError() throws IOException {
    ThrowingAppHost appHost = new ThrowingAppHost();
    appHost.installFailure =
        new AppHostConfigurationException("Failed to load trusted app keys file.");
    AppsApiHandler handler = new AppsApiHandler(appHost);
    Path stagedDir = stageApp(tempDir.resolve("staged-config"));
    Map<String, List<String>> installParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.install(installParameters));

    assertEquals(500, exception.statusCode());
    assertEquals("internal_error", exception.errorCode());
    assertEquals("Failed to install app.", exception.getMessage());
  }

  @Test
  void get_whenStaticUiAppInstalled_expectUiModeEntryAndUrl() {
    AppsApiHandler handler =
        new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.STATIC, "static/index.html")));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("static", summary.get(FIELD_UI_MODE));
    assertEquals("static/index.html", summary.get(FIELD_UI_ENTRY));
    assertEquals("/apps/demo-app/static/", summary.get(FIELD_UI_URL));
    assertEquals("/apps/demo-app/", summary.get("sameOriginFallbackUrl"));
    Map<?, ?> sandbox = (Map<?, ?>) summary.get("sandbox");
    assertEquals("none", sandbox.get("mode"));
    assertEquals("none", sandbox.get("supportLevel"));
    assertEquals("no-sandbox", sandbox.get("provider"));
  }

  @Test
  void get_whenStaticUiOriginBindingExists_expectIsolatedUiSummaryFields() {
    InstalledAppSnapshot snapshot = snapshot(AppUiMode.STATIC, "static/index.html");
    AppUiOriginBinding binding =
        AppUiOriginBinding.isolatedLoopback(
            snapshot.manifest(),
            AppUiOrigin.loopback(APP_ID, 12345),
            "http://127.0.0.1:8888/api/v1/",
            "http://127.0.0.1:8888/app/node/");
    AppsApiHandler handler =
        new AppsApiHandler(new SingleAppHost(snapshot), new AppAuditLog(), registryWith(binding));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("http://127.0.0.1:12345/static/", summary.get(FIELD_UI_URL));
    assertEquals("http://127.0.0.1:12345", summary.get("uiOrigin"));
    assertEquals("isolated-loopback", summary.get("uiOriginMode"));
    assertEquals("active", summary.get("uiOriginStatus"));
    assertEquals("/apps/demo-app/", summary.get("sameOriginFallbackUrl"));
    org.junit.jupiter.api.Assertions.assertFalse(summary.toString().contains(tempDir.toString()));
  }

  @Test
  void get_whenRunningAppHasEnforcedSandbox_expectSandboxSummaryIsTokenAndPathFree() {
    InstalledAppSnapshot snapshot = snapshot(AppUiMode.NONE, null);
    SingleAppHost appHost = new SingleAppHost(snapshot);
    appHost.runningStatus =
        new RunningAppSnapshot(
            snapshot.manifest(),
            snapshot.paths(),
            "secret-token",
            4242L,
            java.time.Instant.parse(SAMPLE_INSTANT_TEXT),
            enforcedSandboxStatus());
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> summary = handler.get(APP_ID);

    Map<?, ?> sandbox = (Map<?, ?>) summary.get("sandbox");
    assertEquals("restricted-process", sandbox.get("mode"));
    assertEquals("enforced", sandbox.get("supportLevel"));
    assertEquals("bubblewrap", sandbox.get("provider"));
    assertEquals(true, sandbox.get("active"));
    assertFalse(summary.toString().contains("secret-token"));
    assertFalse(summary.toString().contains(tempDir.toString()));
  }

  @Test
  void get_whenStoppedAppHostReportsProviderOverride_expectSandboxUsesInactiveHostStatus() {
    SingleAppHost appHost = new SingleAppHost(optionalRestrictedSandboxSnapshot());
    AppSandboxPolicy policy = new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false);
    appHost.inactiveSandboxStatus =
        AppSandboxStatus.unsupported(
            policy, "restricted-process sandbox is not available on this host");
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> summary = handler.get(APP_ID);

    Map<?, ?> sandbox = (Map<?, ?>) summary.get("sandbox");
    assertEquals("restricted-process", sandbox.get("mode"));
    assertEquals(false, sandbox.get("required"));
    assertEquals("unsupported", sandbox.get("supportLevel"));
    assertEquals("unsupported", sandbox.get("provider"));
    assertEquals(false, sandbox.get("active"));
  }

  @Test
  void get_whenShellPanelAppInstalled_expectShellPanelUrlPreserved() {
    AppsApiHandler handler =
        new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.SHELL_PANEL, SHELL_PANEL_ENTRY)));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("shell-panel", summary.get(FIELD_UI_MODE));
    assertEquals(SHELL_PANEL_ENTRY, summary.get(FIELD_UI_ENTRY));
    assertEquals(SHELL_PANEL_ENTRY, summary.get(FIELD_UI_URL));
  }

  @Test
  void update_whenUiModeStopsBeingStatic_expectOriginRegistryRefreshesStaleBinding()
      throws IOException {
    InstalledAppSnapshot staticSnapshot = snapshot(AppUiMode.STATIC, "static/index.html");
    AppUiOriginBinding staleBinding =
        AppUiOriginBinding.isolatedLoopback(
            staticSnapshot.manifest(),
            AppUiOrigin.loopback(APP_ID, 12345),
            "http://127.0.0.1:8888/api/v1/",
            "http://127.0.0.1:8888/app/node/");
    RecordingOriginRegistry registry = new RecordingOriginRegistry(staleBinding);
    InstalledAppSnapshot updatedSnapshot = snapshot(AppUiMode.SHELL_PANEL, SHELL_PANEL_ENTRY);
    SingleAppHost appHost = new SingleAppHost(updatedSnapshot);
    appHost.updateResult = updatedSnapshot;
    AppsApiHandler handler = new AppsApiHandler(appHost, new AppAuditLog(), registry);
    Path stagedDir = stageApp(tempDir.resolve("staged-shell-panel-update"));
    Map<String, List<String>> updateParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    Map<String, Object> summary = handler.update(APP_ID, updateParameters);

    assertEquals(1, appHost.updateCalls);
    assertEquals(1, registry.bindingForAppCalls);
    assertEquals(APP_ID, registry.lastAppId);
    assertEquals("shell-panel", summary.get(FIELD_UI_MODE));
    assertEquals(SHELL_PANEL_ENTRY, summary.get(FIELD_UI_URL));
    assertNull(summary.get("uiOrigin"));
    assertNull(summary.get("uiOriginMode"));
    assertNull(summary.get("uiOriginStatus"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void update_whenVaultCleanupFailsAfterReplacement_expectCommittedSummaryWithWarning()
      throws IOException {
    InstalledAppSnapshot updatedSnapshot = snapshot(AppUiMode.NONE, null);
    SingleAppHost appHost = new SingleAppHost(updatedSnapshot);
    appHost.updateResult = updatedSnapshot;
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    var grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    Files.writeString(
        tempDir.resolve("vault").resolve("grants").resolve(grant.grantId() + ".properties"),
        """
        grantId=%s
        identityId=%s
        appId=%s
        scopes=sign.domain-separated
        status=not-a-status
        createdAt=%s
        updatedAt=%s
        """
            .formatted(
                grant.grantId(),
                grant.identityId(),
                grant.appId(),
                grant.createdAt(),
                grant.updatedAt()),
        StandardCharsets.UTF_8);
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);
    Path stagedDir = stageApp(tempDir.resolve("staged-vault-cleanup-update"));
    Map<String, List<String>> updateParameters =
        Map.of(STAGED_DIR_PARAMETER, List.of(stagedDir.toString()));

    Map<String, Object> summary = handler.update(APP_ID, updateParameters);

    assertEquals(1, appHost.updateCalls);
    assertEquals(APP_ID, summary.get("appId"));
    assertEquals(
        List.of("Vault grant cleanup failed and requires operator review."),
        summary.get("warnings"));
    Map<String, Object> vault = (Map<String, Object>) summary.get("vault");
    assertEquals("unavailable", vault.get("status"));
    assertEquals("unsupported_grant_status", vault.get("errorCode"));
  }

  @Test
  void get_whenNoUiAppInstalled_expectUiUrlIsNull() {
    AppsApiHandler handler = new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.NONE, null)));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("none", summary.get(FIELD_UI_MODE));
    assertNull(summary.get(FIELD_UI_ENTRY));
    assertNull(summary.get(FIELD_UI_URL));
  }

  @Test
  void get_whenManifestDeclaresQuota_expectSummaryIncludesEffectiveUsageAndWarnings() {
    AppsApiHandler handler =
        new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.NONE, null, 1024L, 0L)));

    Map<String, Object> summary = handler.get(APP_ID);

    Map<?, ?> quota = (Map<?, ?>) summary.get("quota");
    assertEquals(1024L, quota.get("dataBytes"));
    assertEquals(0L, quota.get("cacheBytes"));
    assertEquals(1024L, quota.get("effectiveDataBytes"));
    assertNull(quota.get("effectiveCacheBytes"));
    assertEquals(12L, quota.get("dataUsageBytes"));
    assertEquals(34L, quota.get("cacheUsageBytes"));
    assertEquals(true, quota.get("dataQuotaEnforced"));
    assertEquals(false, quota.get("cacheQuotaEnforced"));
    org.junit.jupiter.api.Assertions.assertFalse(summary.toString().contains(tempDir.toString()));
  }

  @Test
  void list_whenAppDisappearsBeforeQuotaLookup_expectSummaryWithoutMeasuredQuotaUsage() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null, 4096L, 1024L));
    appHost.runtimeStatusFailure = new AppHostException("app is not installed: " + APP_ID);
    AppsApiHandler handler = new AppsApiHandler(appHost);

    List<Map<String, Object>> apps = handler.list();

    assertEquals(1, apps.size());
    Map<?, ?> quota = (Map<?, ?>) apps.getFirst().get("quota");
    assertEquals(4096L, quota.get("dataBytes"));
    assertEquals(1024L, quota.get("cacheBytes"));
    assertEquals(4096L, quota.get("effectiveDataBytes"));
    assertEquals(1024L, quota.get("effectiveCacheBytes"));
    assertNull(quota.get("dataUsageBytes"));
    assertNull(quota.get("cacheUsageBytes"));
    assertNull(quota.get("processLogSizeBytes"));
  }

  @Test
  void start_whenQuotaStatusReadFailsAfterLaunch_expectManifestOnlyQuotaSummary() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null, 4096L, 1024L));
    appHost.runtimeStatusFailure = new IOException("process log unavailable");
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> summary = handler.start(APP_ID);

    assertEquals(true, summary.get(FIELD_RUNNING));
    Map<?, ?> quota = (Map<?, ?>) summary.get("quota");
    assertEquals(4096L, quota.get("dataBytes"));
    assertEquals(1024L, quota.get("cacheBytes"));
    assertEquals(4096L, quota.get("effectiveDataBytes"));
    assertEquals(1024L, quota.get("effectiveCacheBytes"));
    assertNull(quota.get("dataUsageBytes"));
    assertNull(quota.get("cacheUsageBytes"));
    assertNull(quota.get("processLogSizeBytes"));
  }

  @Test
  void runtime_whenAppRunning_expectTokenFreeRuntimeStatus() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.runtimeStatus =
        new AppRuntimeStatusSnapshot(
            APP_ID,
            AppRuntimeState.RUNNING,
            true,
            4242L,
            java.time.Instant.parse(SAMPLE_INSTANT_TEXT),
            null,
            null,
            1,
            1,
            true,
            128L,
            network.crypta.platform.apphost.sandbox.AppSandboxProviders.inactiveStatus(
                network.crypta.platform.apphost.sandbox.AppSandboxPolicy.defaults()),
            new AppQuotaStatus(
                new AppQuotaPolicy(1024L, 0L, 2048L),
                new AppQuotaUsage(128L, 64L, 128L),
                List.of(AppQuotaWarning.cacheQuotaExceeded())),
            List.of("Automatic restart suppressed after 5 attempts within 300000 ms."));
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> runtime = handler.runtime(APP_ID);

    assertEquals("RUNNING", runtime.get("state"));
    assertEquals(true, runtime.get(FIELD_RUNNING));
    assertEquals(4242L, runtime.get("pid"));
    assertEquals(SAMPLE_INSTANT_TEXT, runtime.get("startedAt"));
    Map<?, ?> sandbox = (Map<?, ?>) runtime.get("sandbox");
    assertEquals("none", sandbox.get("mode"));
    assertEquals(false, sandbox.get("active"));
    Map<?, ?> quota = (Map<?, ?>) runtime.get("quota");
    assertEquals(1024L, quota.get("dataBytes"));
    assertEquals(0L, quota.get("cacheBytes"));
    assertEquals(1024L, quota.get("effectiveDataBytes"));
    assertNull(quota.get("effectiveCacheBytes"));
    assertEquals(128L, quota.get("dataUsageBytes"));
    assertEquals(64L, quota.get("cacheUsageBytes"));
    assertEquals(true, quota.get("dataQuotaEnforced"));
    assertEquals(false, quota.get("cacheQuotaEnforced"));
    assertEquals(2048L, quota.get("processLogMaxBytes"));
    assertEquals(128L, quota.get("processLogSizeBytes"));
    assertEquals(List.of("Cache usage exceeds the configured app quota."), quota.get("warnings"));
    assertEquals(
        List.of("Automatic restart suppressed after 5 attempts within 300000 ms."),
        runtime.get("warnings"));
    org.junit.jupiter.api.Assertions.assertFalse(runtime.toString().contains("token"));
  }

  @Test
  void runtime_whenSandboxIsEnforced_expectSupportLevelAndProviderSerialized() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.runtimeStatus =
        new AppRuntimeStatusSnapshot(
            APP_ID,
            AppRuntimeState.RUNNING,
            true,
            4242L,
            java.time.Instant.parse(SAMPLE_INSTANT_TEXT),
            null,
            null,
            0,
            0,
            true,
            64L,
            enforcedSandboxStatus(),
            new AppQuotaStatus(
                new AppQuotaPolicy(null, null, AppHost.DEFAULT_PROCESS_LOG_MAX_BYTES),
                new AppQuotaUsage(0L, 0L, 64L),
                List.of()),
            List.of());
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> runtime = handler.runtime(APP_ID);

    Map<?, ?> sandbox = (Map<?, ?>) runtime.get("sandbox");
    assertEquals("restricted-process", sandbox.get("mode"));
    assertEquals("enforced", sandbox.get("supportLevel"));
    assertEquals("bubblewrap", sandbox.get("provider"));
    assertEquals(true, sandbox.get("active"));
    assertFalse(runtime.toString().contains("secret-token"));
    assertFalse(runtime.toString().contains(tempDir.toString()));
  }

  @Test
  @SuppressWarnings("unchecked")
  void get_whenVaultHasSecretsAndGrants_expectSummaryShowsOnlyAvailability() throws IOException {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
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
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);

    Map<String, Object> app = handler.get(APP_ID, false);

    Map<String, Object> vault = (Map<String, Object>) app.get("vault");
    assertEquals(Map.of("available", true), vault);
    String summary = app.toString();
    assertFalse(summary.contains("api-token"));
    assertFalse(summary.contains("raw-secret-value"));
    assertFalse(summary.contains(identity.identityId()));
    assertFalse(summary.contains("secretNames"));
    assertFalse(summary.contains("recentAudit"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void uninstall_whenVaultMaterialExists_expectPurgesSecretsAndRevokesGrants() throws IOException {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
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
    AppIdentityRecord appOwnedIdentity =
        vaultService.createAppOwnedIdentity(
            APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, "App signing key", null);
    var otherAppGrant =
        vaultService.grantIdentity(
            appOwnedIdentity.identityId(),
            "other.app",
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "shared app-owned identity",
            null,
            null);
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "raw-secret-value".getBytes(StandardCharsets.UTF_8),
        Map.of("label", "primary"));
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);

    Map<String, Object> app = handler.uninstall(APP_ID, false);

    Map<String, Object> vault = (Map<String, Object>) app.get("vault");
    assertEquals(false, app.get("installed"));
    assertEquals(false, app.get("dataPreserved"));
    assertEquals(1, appHost.uninstallCalls);
    assertEquals(AppUninstallOptions.removeAll(), appHost.lastUninstallOptions);
    assertEquals(Map.of("available", true), vault);
    assertTrue(vaultService.listSecrets(APP_ID).isEmpty());
    assertEquals(
        "secret_not_found",
        assertThrows(
                AppVaultException.class, () -> vaultService.readSecretValue(APP_ID, "api-token"))
            .errorCode());
    assertTrue(
        vaultService.listGrantsForApp(APP_ID).stream()
            .allMatch(grant -> grant.status() == AppIdentityGrantStatus.REVOKED));
    assertEquals(
        AppIdentityGrantStatus.REVOKED,
        vaultService.listGrants().stream()
            .filter(grant -> grant.grantId().equals(otherAppGrant.grantId()))
            .findFirst()
            .orElseThrow()
            .status());
    String appOwnedIdentityId = appOwnedIdentity.identityId();
    assertEquals(
        "identity_not_found",
        assertThrows(AppVaultException.class, () -> vaultService.getIdentity(appOwnedIdentityId))
            .errorCode());
    assertFalse(vaultService.hasRetainedAppState(APP_ID));
  }

  @Test
  void uninstall_whenPreserveDataRequested_expectAppHostReceivesPreserveOption() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> app = handler.uninstall(APP_ID, false, true);

    assertEquals(false, app.get("installed"));
    assertEquals(true, app.get("dataPreserved"));
    assertEquals(1, appHost.uninstallCalls);
    assertEquals(AppUninstallOptions.preservingData(), appHost.lastUninstallOptions);
    assertFalse(appHost.installed);
  }

  @Test
  void uninstall_whenVaultAccessBlockCannotBeWritten_expectAppHostNotMutated() throws IOException {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    Path vaultRoot = tempDir.resolve("vault-block-failure");
    AppVaultService vaultService = AppVaultService.open(vaultRoot);
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "raw-secret-value".getBytes(StandardCharsets.UTF_8),
        Map.of("label", "primary"));
    Path accessBlocksRoot = vaultRoot.resolve("app-access-blocks");
    Files.delete(accessBlocksRoot);
    Files.writeString(accessBlocksRoot, "not-a-directory", StandardCharsets.UTF_8);
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);

    AppVaultException exception =
        assertThrows(AppVaultException.class, () -> handler.uninstall(APP_ID, false));

    assertEquals("vault_storage_failed", exception.errorCode());
    assertEquals(0, appHost.uninstallCalls);
    assertTrue(appHost.installed);
    assertEquals(
        "raw-secret-value",
        new String(vaultService.readSecretValue(APP_ID, "api-token"), StandardCharsets.UTF_8));
  }

  @Test
  void uninstall_whenVaultUnavailableAndAppDeclaresVaultPermission_expectAppHostNotMutated() {
    SingleAppHost appHost =
        new SingleAppHost(
            snapshotWithPermissions(List.of("vault.secrets.read", "vault.secrets.write")));
    AppsApiHandler handler = new AppsApiHandler(appHost);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.uninstall(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("app_vault_unavailable", exception.errorCode());
    assertEquals(0, appHost.uninstallCalls);
    assertTrue(appHost.installed);
  }

  @Test
  @SuppressWarnings("unchecked")
  void uninstall_whenVaultUnavailableAndAppHasNoVaultPermission_expectAppHostUninstalled() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> app = handler.uninstall(APP_ID, false);

    Map<String, Object> vault = (Map<String, Object>) app.get("vault");
    assertEquals(false, app.get("installed"));
    assertEquals(false, app.get("dataPreserved"));
    assertEquals(Map.of("available", false), vault);
    assertEquals(1, appHost.uninstallCalls);
    assertFalse(appHost.installed);
  }

  @Test
  void uninstall_whenAppHostFailsAfterVaultBlock_expectVaultAccessRestored() throws IOException {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.uninstallFailure = new AppHostException("cannot uninstall now");
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "raw-secret-value".getBytes(StandardCharsets.UTF_8),
        Map.of("label", "primary"));
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.uninstall(APP_ID, false));

    assertEquals("internal_error", exception.errorCode());
    assertEquals(1, appHost.uninstallCalls);
    assertEquals(AppUninstallOptions.removeAll(), appHost.lastUninstallOptions);
    assertTrue(appHost.installed);
    assertFalse(vaultService.appAccessBlocked(APP_ID));
    assertEquals(
        "raw-secret-value",
        new String(vaultService.readSecretValue(APP_ID, "api-token"), StandardCharsets.UTF_8));
  }

  @Test
  @SuppressWarnings("unchecked")
  void uninstall_whenAppAlreadyMissingButVaultStateRetained_expectRetriesVaultCleanup()
      throws IOException {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.installed = false;
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    vaultService.putSecret(
        APP_ID,
        "api-token",
        "generic",
        "raw-secret-value".getBytes(StandardCharsets.UTF_8),
        Map.of("label", "primary"));
    vaultService.disableAppAccess(APP_ID, "app_uninstall_cleanup");
    AppsApiHandler handler =
        new AppsApiHandler(
            appHost, new AppAuditLog(), AppUiOriginRegistry.sameOriginOnly(), vaultService);

    Map<String, Object> app = handler.uninstall(APP_ID, false);

    Map<String, Object> vault = (Map<String, Object>) app.get("vault");
    assertEquals(false, app.get("installed"));
    assertEquals(false, app.get("dataPreserved"));
    assertEquals(1, appHost.uninstallCalls);
    assertEquals(Map.of("available", true), vault);
    assertFalse(vaultService.appAccessBlocked(APP_ID));
    assertFalse(vaultService.hasRetainedAppState(APP_ID));
    assertTrue(vaultService.listSecrets(APP_ID).isEmpty());
  }

  @Test
  void start_whenRequiredSandboxUnsupported_expectUnsupportedSandboxError() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.startFailure =
        new AppSandboxException(
            "unsupported_sandbox",
            "App requires sandbox mode wasm-preview, but no provider can support it on this host");
    AppsApiHandler handler = new AppsApiHandler(appHost);

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.start(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("unsupported_sandbox", exception.errorCode());
    org.junit.jupiter.api.Assertions.assertFalse(exception.getMessage().contains("secret-token"));
  }

  @Test
  void start_whenDataQuotaExceeded_expectConflict() {
    assertStartFailureIsQuotaConflict("app data quota exceeded: " + APP_ID);
  }

  @Test
  void start_whenCacheQuotaExceeded_expectConflict() {
    assertStartFailureIsQuotaConflict("app cache quota exceeded: " + APP_ID);
  }

  @Test
  void start_whenDataQuotaScanIncomplete_expectConflict() {
    assertStartFailureIsQuotaConflict("app data quota scan incomplete: " + APP_ID);
  }

  @Test
  void start_whenCacheQuotaScanIncomplete_expectConflict() {
    assertStartFailureIsQuotaConflict("app cache quota scan incomplete: " + APP_ID);
  }

  @Test
  void logs_whenAppLogExists_expectTokenFreeProcessLog() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.processLog =
        new AppProcessLogSnapshot(
            APP_ID,
            true,
            true,
            16,
            64L,
            "CRYPTAD_APP_TOKEN=[REDACTED]\nready\n",
            java.time.Instant.parse(SAMPLE_INSTANT_TEXT));
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> logs = handler.logs(APP_ID, Map.of(FIELD_MAX_BYTES, List.of("16")));

    assertEquals(true, logs.get("available"));
    assertEquals(true, logs.get("truncated"));
    assertEquals(16, logs.get(FIELD_MAX_BYTES));
    assertEquals("CRYPTAD_APP_TOKEN=[REDACTED]\nready\n", logs.get("text"));
    org.junit.jupiter.api.Assertions.assertFalse(logs.toString().contains("secret-token"));
  }

  private void assertStartFailureIsQuotaConflict(String message) {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.startFailure = new AppHostException(message);
    AppsApiHandler handler = new AppsApiHandler(appHost);

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.start(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_conflict", exception.errorCode());
    assertEquals(message, exception.getMessage());
  }

  @Test
  void logs_whenMaxBytesMalformed_expectInvalidQueryParameter() {
    AppsApiHandler handler = new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.NONE, null)));
    Map<String, List<String>> queryParameters = Map.of(FIELD_MAX_BYTES, List.of("0"));

    PlatformApiException exception =
        org.junit.jupiter.api.Assertions.assertThrows(
            PlatformApiException.class, () -> handler.logs(APP_ID, queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void stop_whenAppIsRestarting_expectDelegatesStopAndReturnsInstalledSummary() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.runtimeStatus =
        new AppRuntimeStatusSnapshot(
            APP_ID, AppRuntimeState.RESTARTING, false, null, null, null, 7, 0, 1, true, 64L);
    appHost.stopResult = true;
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> summary = handler.stop(APP_ID);

    assertEquals(APP_ID, summary.get("appId"));
    assertEquals(false, summary.get(FIELD_RUNNING));
    assertEquals(1, appHost.stopCalls);
  }

  @Test
  void stop_whenRestartingAppManifestUnreadable_expectCancelsRestartAndReturnsFallbackSummary() {
    SingleAppHost appHost = new SingleAppHost(snapshot(AppUiMode.NONE, null));
    appHost.describeFailure = new IOException("manifest unreadable");
    appHost.stopResult = true;
    AppsApiHandler handler = new AppsApiHandler(appHost);

    Map<String, Object> summary = handler.stop(APP_ID);

    assertEquals(APP_ID, summary.get("appId"));
    assertNull(summary.get("name"));
    assertEquals(true, summary.get("installed"));
    assertEquals(false, summary.get(FIELD_RUNNING));
    assertEquals(1, appHost.stopCalls);
  }

  private Path stageApp(Path stagedDir) throws IOException {
    Files.createDirectories(stagedDir);
    Files.writeString(
        stagedDir.resolve(AppManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=Demo App
        app.version=1.0.0
        app.exec=bin/launch.sh
        app.ui.entry=/
        app.permissions=network.access
        quota.data.bytes=1024
        quota.cache.bytes=512
        """
            .formatted(APP_ID),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private InstalledAppSnapshot snapshot(AppUiMode uiMode, String uiEntry) {
    return snapshot(uiMode, uiEntry, null, null);
  }

  private InstalledAppSnapshot snapshotWithPermissions(List<String> permissions) {
    return snapshot(AppUiMode.NONE, null, permissions, null, null);
  }

  private InstalledAppSnapshot snapshot(
      AppUiMode uiMode, String uiEntry, Long dataQuotaBytes, Long cacheQuotaBytes) {
    return snapshot(uiMode, uiEntry, List.of(), dataQuotaBytes, cacheQuotaBytes);
  }

  private InstalledAppSnapshot snapshot(
      AppUiMode uiMode,
      String uiEntry,
      List<String> permissions,
      Long dataQuotaBytes,
      Long cacheQuotaBytes) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Demo App",
            "1.0.0",
            "bin/launch.sh",
            uiMode,
            uiEntry,
            permissions,
            dataQuotaBytes,
            cacheQuotaBytes);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private InstalledAppSnapshot optionalRestrictedSandboxSnapshot() {
    AppManifest manifest =
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
            null,
            AppSandboxMode.RESTRICTED_PROCESS,
            false);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private static AppSandboxStatus enforcedSandboxStatus() {
    return new AppSandboxStatus(
        AppSandboxMode.RESTRICTED_PROCESS,
        true,
        AppSandboxSupportLevel.ENFORCED,
        "bubblewrap",
        true,
        "Linux bubblewrap sandbox active",
        List.of(
            "Filesystem sandbox active for installed bundle and AppHost-managed mutable"
                + " directories",
            "CPU, memory, and network restrictions are not enforced by this provider"));
  }

  private static AppUiOriginRegistry registryWith(AppUiOriginBinding binding) {
    return appId -> binding.appId().equals(appId) ? Optional.of(binding) : Optional.empty();
  }

  private static final class RecordingOriginRegistry implements AppUiOriginRegistry {
    private final AppUiOriginBinding binding;
    private int bindingForAppCalls;
    private String lastAppId;

    private RecordingOriginRegistry(AppUiOriginBinding binding) {
      this.binding = binding;
    }

    @Override
    public Optional<AppUiOriginBinding> bindingForApp(String appId) {
      bindingForAppCalls++;
      lastAppId = appId;
      return binding.appId().equals(appId) ? Optional.of(binding) : Optional.empty();
    }
  }

  private static final class ThrowingAppHost implements AppHost {
    private IOException installFailure;
    private IOException updateFailure;

    @Override
    public InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) throws IOException {
      throw installFailure;
    }

    @Override
    public InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory)
        throws IOException {
      throw updateFailure;
    }

    @Override
    public void uninstall(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<InstalledAppSnapshot> listInstalled() {
      return List.of();
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) {
      return Optional.empty();
    }

    @Override
    public RunningAppSnapshot start(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean stop(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Optional<RunningAppSnapshot> status(String appId) {
      return Optional.empty();
    }

    @Override
    public List<RunningAppSnapshot> listRunning() {
      return List.of();
    }

    @Override
    public AppRuntimeStatusSnapshot runtimeStatus(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<AppRuntimeStatusSnapshot> listRuntimeStatus() {
      return List.of();
    }

    @Override
    public AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) {
      throw new UnsupportedOperationException();
    }
  }

  private static final class SingleAppHost implements AppHost {
    private final InstalledAppSnapshot snapshot;
    private InstalledAppSnapshot updateResult;
    private boolean installed = true;
    private AppRuntimeStatusSnapshot runtimeStatus;
    private RunningAppSnapshot runningStatus;
    private AppSandboxStatus inactiveSandboxStatus;
    private AppProcessLogSnapshot processLog;
    private IOException describeFailure;
    private IOException runtimeStatusFailure;
    private IOException startFailure;
    private AppHostException uninstallFailure;
    private int updateCalls;
    private int uninstallCalls;
    private AppUninstallOptions lastUninstallOptions;
    private boolean stopResult;
    private int stopCalls;

    private SingleAppHost(InstalledAppSnapshot snapshot) {
      this.snapshot = snapshot;
    }

    @Override
    public InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory)
        throws IOException {
      updateCalls++;
      if (!APP_ID.equals(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      if (updateResult == null) {
        throw new UnsupportedOperationException();
      }
      return updateResult;
    }

    @Override
    public void uninstall(String appId) throws IOException {
      uninstall(appId, AppUninstallOptions.removeAll());
    }

    @Override
    public void uninstall(String appId, AppUninstallOptions options) throws IOException {
      uninstallCalls++;
      lastUninstallOptions = options;
      if (uninstallFailure != null) {
        throw uninstallFailure;
      }
      if (!APP_ID.equals(appId) || !installed) {
        throw new AppHostException("app is not installed: " + appId);
      }
      installed = false;
    }

    @Override
    public List<InstalledAppSnapshot> listInstalled() {
      return installed ? List.of(snapshot) : List.of();
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) throws IOException {
      if (describeFailure != null) {
        throw describeFailure;
      }
      return APP_ID.equals(appId) && installed ? Optional.of(snapshot) : Optional.empty();
    }

    @Override
    public RunningAppSnapshot start(String appId) throws IOException {
      if (startFailure != null) {
        throw startFailure;
      }
      if (!APP_ID.equals(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new RunningAppSnapshot(
          snapshot.manifest(),
          snapshot.paths(),
          "secret-token",
          4242L,
          java.time.Instant.parse(SAMPLE_INSTANT_TEXT));
    }

    @Override
    public boolean stop(String appId) {
      stopCalls++;
      return stopResult;
    }

    @Override
    public Optional<RunningAppSnapshot> status(String appId) {
      return APP_ID.equals(appId) ? Optional.ofNullable(runningStatus) : Optional.empty();
    }

    @Override
    public List<RunningAppSnapshot> listRunning() {
      return runningStatus == null ? List.of() : List.of(runningStatus);
    }

    @Override
    public AppSandboxStatus inactiveSandboxStatus(AppSandboxPolicy policy) {
      return inactiveSandboxStatus == null
          ? AppHost.super.inactiveSandboxStatus(policy)
          : inactiveSandboxStatus;
    }

    @Override
    public AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException {
      if (runtimeStatusFailure != null) {
        throw runtimeStatusFailure;
      }
      if (!APP_ID.equals(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      if (runtimeStatus != null) {
        return runtimeStatus;
      }
      return new AppRuntimeStatusSnapshot(
          appId,
          AppRuntimeState.STOPPED,
          false,
          null,
          null,
          null,
          null,
          0,
          0,
          false,
          null,
          network.crypta.platform.apphost.sandbox.AppSandboxProviders.inactiveStatus(
              snapshot.manifest().sandboxPolicy()),
          new AppQuotaStatus(
              AppQuotaPolicy.fromManifest(snapshot.manifest()),
              new AppQuotaUsage(12L, 34L, null),
              List.of()),
          List.of());
    }

    @Override
    public List<AppRuntimeStatusSnapshot> listRuntimeStatus() throws IOException {
      return List.of(runtimeStatus(APP_ID));
    }

    @Override
    public AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) throws IOException {
      if (!APP_ID.equals(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return processLog == null
          ? new AppProcessLogSnapshot(appId, false, false, maxBytes, 0L, "", null)
          : processLog;
    }
  }
}
