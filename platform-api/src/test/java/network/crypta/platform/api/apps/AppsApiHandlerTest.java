package network.crypta.platform.api.apps;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
}
