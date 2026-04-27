package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppUiBootstrapServiceTest {
  private static final String APP_ID = "demo-app";

  @TempDir private Path tempDir;

  @Test
  void resolve_whenStaticAppBootstrapRequested_expectBootstrapMetadata() throws Exception {
    AppUiBootstrapService service = service(app(AppUiMode.STATIC, "static/index.html"));

    AppUiBootstrap bootstrap =
        service
            .resolve(
                "/apps/demo-app/.well-known/cryptad-bootstrap.json",
                "/api/v1/",
                "/app/node/",
                "form-secret")
            .orElseThrow();

    assertEquals(APP_ID, bootstrap.appId());
    assertEquals("Demo App", bootstrap.name());
    assertEquals("/apps/demo-app/", bootstrap.uiRoot());
    assertEquals("/apps/demo-app/static/", bootstrap.assetRoot());
    assertEquals("/api/v1/", bootstrap.platformApiRoot());
    assertEquals("/app/node/", bootstrap.shellRoot());
    assertEquals("form-secret", bootstrap.formPassword());
  }

  @Test
  void resolve_whenOrdinaryAssetRequested_expectEmpty() throws Exception {
    AppUiBootstrapService service = service(app(AppUiMode.STATIC, "static/index.html"));

    Optional<AppUiBootstrap> bootstrap =
        service.resolve("/apps/demo-app/static/app.js", "/api/v1/", "/app/node/", "form-secret");

    assertTrue(bootstrap.isEmpty());
  }

  @Test
  void resolve_whenAppMissing_expectEmpty() throws Exception {
    AppUiBootstrapService service = service();

    Optional<AppUiBootstrap> bootstrap =
        service.resolve(
            "/apps/demo-app/.well-known/cryptad-bootstrap.json",
            "/api/v1/",
            "/app/node/",
            "form-secret");

    assertTrue(bootstrap.isEmpty());
  }

  @Test
  void resolve_whenAppIsNotStatic_expectEmpty() throws Exception {
    AppUiBootstrapService service = service(app(AppUiMode.SHELL_PANEL, "/app/node/#queue"));

    Optional<AppUiBootstrap> bootstrap =
        service.resolve(
            "/apps/demo-app/.well-known/cryptad-bootstrap.json",
            "/api/v1/",
            "/app/node/",
            "form-secret");

    assertTrue(bootstrap.isEmpty());
  }

  @Test
  void isBootstrapRequest_whenReservedRouteProvided_expectTrue() throws Exception {
    assertTrue(
        AppUiBootstrapService.isBootstrapRequest(
            "/apps/demo-app/.well-known/cryptad-bootstrap.json"));
  }

  @Test
  void isBootstrapRequest_whenEncodedTraversalProvided_expectBadRequest() {
    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class,
            () ->
                AppUiBootstrapService.isBootstrapRequest(
                    "/apps/demo-app/.well-known/%2e%2e/secret.json"));

    assertEquals(400, exception.statusCode());
  }

  private AppUiBootstrapService service(InstalledAppSnapshot... snapshots) {
    return new AppUiBootstrapService(new InMemoryAppHost(snapshots));
  }

  private InstalledAppSnapshot app(AppUiMode uiMode, String uiEntry) {
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

  private static final class InMemoryAppHost implements AppHost {
    private final Map<String, InstalledAppSnapshot> snapshots = new LinkedHashMap<>();

    private InMemoryAppHost(InstalledAppSnapshot... snapshots) {
      for (InstalledAppSnapshot snapshot : snapshots) {
        this.snapshots.put(snapshot.appId(), snapshot);
      }
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
      return List.copyOf(snapshots.values());
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) {
      return Optional.ofNullable(snapshots.get(appId));
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
    public AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException {
      InstalledAppSnapshot snapshot = snapshots.get(appId);
      if (snapshot == null) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppRuntimeStatusSnapshot(
          appId, AppRuntimeState.STOPPED, false, null, null, null, null, 0, 0, false, null);
    }

    @Override
    public List<AppRuntimeStatusSnapshot> listRuntimeStatus() {
      return snapshots.keySet().stream()
          .map(
              appId ->
                  new AppRuntimeStatusSnapshot(
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
                      null))
          .toList();
    }

    @Override
    public AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) throws IOException {
      if (!snapshots.containsKey(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppProcessLogSnapshot(appId, false, false, maxBytes, 0L, "", null);
    }
  }
}
