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
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class AppsApiHandlerTest {
  private static final String APP_ID = "demo-app";
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
    assertEquals("invalid_app_bundle", exception.errorCode());
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
    assertEquals("invalid_app_bundle", exception.errorCode());
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
    assertEquals("invalid_app_bundle", exception.errorCode());
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
    assertEquals("invalid_app_bundle", exception.errorCode());
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

    assertEquals("static", summary.get("uiMode"));
    assertEquals("static/index.html", summary.get("uiEntry"));
    assertEquals("/apps/demo-app/static/", summary.get("uiUrl"));
  }

  @Test
  void get_whenShellPanelAppInstalled_expectShellPanelUrlPreserved() {
    AppsApiHandler handler =
        new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.SHELL_PANEL, "/app/node/#queue")));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("shell-panel", summary.get("uiMode"));
    assertEquals("/app/node/#queue", summary.get("uiEntry"));
    assertEquals("/app/node/#queue", summary.get("uiUrl"));
  }

  @Test
  void get_whenNoUiAppInstalled_expectUiUrlIsNull() {
    AppsApiHandler handler = new AppsApiHandler(new SingleAppHost(snapshot(AppUiMode.NONE, null)));

    Map<String, Object> summary = handler.get(APP_ID);

    assertEquals("none", summary.get("uiMode"));
    assertNull(summary.get("uiEntry"));
    assertNull(summary.get("uiUrl"));
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
            null,
            null);
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
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class SingleAppHost implements AppHost {
    private final InstalledAppSnapshot snapshot;

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
    public Optional<InstalledAppSnapshot> describe(String appId) {
      return APP_ID.equals(appId) ? Optional.of(snapshot) : Optional.empty();
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
  }
}
