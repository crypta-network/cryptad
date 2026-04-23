package network.crypta.platform.appui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
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
class AppStaticAssetServiceTest {
  private static final String APP_ID = "demo-app";

  @TempDir private Path tempDir;

  @Test
  void resolve_whenRootRouteRequested_expectDeclaredEntry() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(
        snapshot.paths().installedRoot().resolve("static/index.html"), "<html></html>");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/").orElseThrow();

    assertEquals("static/index.html", asset.relativePath());
    assertEquals("text/html; charset=UTF-8", asset.contentType());
    assertTrue(asset.path().endsWith(Path.of("static", "index.html")));
  }

  @Test
  void resolve_whenStaticAssetRequested_expectBundleAsset() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), "export {};");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/static/app.js").orElseThrow();

    assertEquals("static/app.js", asset.relativePath());
    assertEquals("text/javascript; charset=UTF-8", asset.contentType());
  }

  @Test
  void resolve_whenEntryDirectoryRequested_expectDeclaredEntry() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(
        snapshot.paths().installedRoot().resolve("static/index.html"), "<html></html>");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/static/").orElseThrow();

    assertEquals("static/index.html", asset.relativePath());
    assertTrue(asset.path().endsWith(Path.of("static", "index.html")));
  }

  @Test
  void canonicalRootRedirect_whenNestedEntryRootRequested_expectEntryDirectoryUrl()
      throws Exception {
    AppStaticAssetService service = service(staticApp("static/index.html"));

    assertEquals(
        Optional.of("/apps/demo-app/static/"), service.canonicalRootRedirect("/apps/demo-app/"));
  }

  @Test
  void canonicalRootRedirect_whenRootEntryRootRequested_expectEmpty() throws Exception {
    AppStaticAssetService service = service(staticApp("index.html"));

    assertTrue(service.canonicalRootRedirect("/apps/demo-app/").isEmpty());
  }

  @Test
  void canonicalRootRedirect_whenAssetRequested_expectEmpty() throws Exception {
    AppStaticAssetService service = service(staticApp("static/index.html"));

    assertTrue(service.canonicalRootRedirect("/apps/demo-app/shared.js").isEmpty());
  }

  @Test
  void resolve_whenWasmAssetRequested_expectWebAssemblyContentType() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.wasm"), "wasm");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/static/app.wasm").orElseThrow();

    assertEquals("static/app.wasm", asset.relativePath());
    assertEquals("application/wasm", asset.contentType());
  }

  @Test
  void
      resolve_whenRootRelativeAssetBesideNestedEntryRequestedAndBundleRootMissing_expectEntryDirectoryFallback()
          throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), "export {};");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/app.js").orElseThrow();

    assertEquals("static/app.js", asset.relativePath());
    assertTrue(asset.path().endsWith(Path.of("static", "app.js")));
  }

  @Test
  void resolve_whenCanonicalParentRelativeAssetExistsAtBundleRoot_expectBundleRelativePrecedence()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/shared.js"), "nested");
    Files.writeString(snapshot.paths().installedRoot().resolve("shared.js"), "root");
    AppStaticAssetService service = service(snapshot);

    AppStaticAsset asset = service.resolve("/apps/demo-app/shared.js").orElseThrow();

    assertEquals("shared.js", asset.relativePath());
    assertTrue(asset.path().endsWith(Path.of("shared.js")));
  }

  @Test
  void resolve_whenEncodedTraversalRequested_expectBadRequest() {
    AppStaticAssetService service = service(staticApp("static/index.html"));

    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class,
            () -> service.resolve("/apps/demo-app/static/%2e%2e/secret.txt"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void resolve_whenNonEntryDirectoryPathEndsWithSlash_expectEmpty() throws Exception {
    AppStaticAssetService service = service(staticApp("static/index.html"));

    assertTrue(service.resolve("/apps/demo-app/assets/").isEmpty());
  }

  @Test
  void resolve_whenAssetSymlinkEscapesBundle_expectBadRequest() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Path external = tempDir.resolve("external.js");
    Files.writeString(external, "alert(1);");
    Path link = snapshot.paths().installedRoot().resolve("static/link.js");
    try {
      Files.createSymbolicLink(link, external);
    } catch (UnsupportedOperationException | IOException exception) {
      org.junit.jupiter.api.Assumptions.abort(
          "symbolic links are unavailable: " + exception.getMessage());
    }
    AppStaticAssetService service = service(snapshot);

    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class, () -> service.resolve("/apps/demo-app/static/link.js"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void resolve_whenAppMissing_expectEmpty() throws Exception {
    AppStaticAssetService service = service();

    assertTrue(service.resolve("/apps/missing-app/").isEmpty());
  }

  @Test
  void resolve_whenAppIsNotStatic_expectEmpty() throws Exception {
    InstalledAppSnapshot snapshot = app(AppUiMode.SHELL_PANEL, "/app/node/#queue");
    AppStaticAssetService service = service(snapshot);

    assertTrue(service.resolve("/apps/demo-app/").isEmpty());
  }

  private AppStaticAssetService service(InstalledAppSnapshot... snapshots) {
    return new AppStaticAssetService(new InMemoryAppHost(snapshots));
  }

  private InstalledAppSnapshot staticApp(String uiEntry) {
    return app(AppUiMode.STATIC, uiEntry);
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
  }
}
