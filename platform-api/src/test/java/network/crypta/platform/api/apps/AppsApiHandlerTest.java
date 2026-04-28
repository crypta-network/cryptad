package network.crypta.platform.api.apps;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
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
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.sandbox.AppSandboxException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
    Map<?, ?> sandbox = (Map<?, ?>) summary.get("sandbox");
    assertEquals("none", sandbox.get("mode"));
    assertEquals("none", sandbox.get("supportLevel"));
    assertEquals("no-sandbox", sandbox.get("provider"));
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

  private InstalledAppSnapshot snapshot(
      AppUiMode uiMode, String uiEntry, Long dataQuotaBytes, Long cacheQuotaBytes) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Demo App",
            "1.0.0",
            "bin/launch.sh",
            uiMode,
            uiEntry,
            List.of(),
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
    private AppRuntimeStatusSnapshot runtimeStatus;
    private AppProcessLogSnapshot processLog;
    private IOException describeFailure;
    private IOException runtimeStatusFailure;
    private IOException startFailure;
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
    public InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void uninstall(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<InstalledAppSnapshot> listInstalled() {
      return List.of(snapshot);
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) throws IOException {
      if (describeFailure != null) {
        throw describeFailure;
      }
      return APP_ID.equals(appId) ? Optional.of(snapshot) : Optional.empty();
    }

    @Override
    public RunningAppSnapshot start(String appId) throws IOException {
      if (startFailure != null) {
        throw startFailure;
      }
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean stop(String appId) {
      stopCalls++;
      return stopResult;
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
