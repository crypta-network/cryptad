package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogSignature;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppCatalogSourceStore;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
class PlatformApiAppsIntegrationTest {
  private static final String APP_ID = "demo-app";
  private static final String APP_NAME = "Demo App";
  private static final String APP_VERSION = "1.2.3";
  private static final String TRUSTED_KEY_ID = "local-dev";
  private static final String UI_ENTRY = "/";
  private static final String CATALOG_ID = "core";

  @TempDir private Path tempDir;

  private AppHostLayout appHostLayout;
  private PlatformApiRouter router;

  @BeforeEach
  void setUp() {
    appHostLayout =
        new AppHostLayout(
            tempDir.resolve("data"), tempDir.resolve("cache"), tempDir.resolve("run"));
    router = createRouter(allowUnsignedHost());
  }

  @Test
  void route_whenLifecycleRunsAgainstRealAppHost_expectStableJsonShapes() throws Exception {
    assertEquals("{\"apps\":[]}", router.route(request("GET", List.of("apps"), Map.of())).body());

    Path stagedDir = stageApp();

    PlatformApiResponse installResponse =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(201, installResponse.statusCode());
    assertTrue(installResponse.body().contains("\"appId\":\"demo-app\""));
    assertTrue(installResponse.body().contains("\"installed\":true"));
    assertTrue(installResponse.body().contains("\"running\":false"));
    assertFalse(installResponse.body().contains("token"));

    PlatformApiResponse startResponse =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(200, startResponse.statusCode());
    assertTrue(startResponse.body().contains("\"running\":true"));
    assertTrue(startResponse.body().contains("\"pid\":"));
    assertTrue(startResponse.body().contains("\"startedAt\":\""));
    assertFalse(startResponse.body().contains("token"));

    PlatformApiResponse stopResponse =
        router.route(request("POST", List.of("apps", APP_ID, "stop"), Map.of()));

    assertEquals(200, stopResponse.statusCode());
    assertTrue(stopResponse.body().contains("\"running\":false"));
    assertFalse(stopResponse.body().contains("token"));

    PlatformApiResponse deleteResponse =
        router.route(request("DELETE", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, deleteResponse.statusCode());
    assertTrue(deleteResponse.body().contains("\"installed\":false"));
    assertTrue(deleteResponse.body().contains("\"running\":false"));

    assertEquals("{\"apps\":[]}", router.route(request("GET", List.of("apps"), Map.of())).body());
  }

  @Test
  void route_whenStoppedInstalledAppUpdated_expectStableJsonAndPreservedMutableLayout()
      throws Exception {
    Path stagedV1 = stageApp("staged-v1", "1.0.0");
    Path stagedV2 = stageApp("staged-v2", "9.9.9");

    PlatformApiResponse installResponse =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedV1.toString()))));
    assertEquals(201, installResponse.statusCode());

    Files.writeString(tempDir.resolve("data/apps/data/" + APP_ID + "/sentinel.txt"), "data");
    Files.writeString(tempDir.resolve("cache/apps/" + APP_ID + "/sentinel.txt"), "cache");
    Files.writeString(tempDir.resolve("run/apps/" + APP_ID + "/sentinel.txt"), "run");

    PlatformApiResponse updateResponse =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedV2.toString()))));

    assertEquals(200, updateResponse.statusCode());
    assertTrue(updateResponse.body().contains("\"version\":\"9.9.9\""));
    assertTrue(updateResponse.body().contains("\"installed\":true"));
    assertTrue(updateResponse.body().contains("\"running\":false"));
    assertEquals(
        "data", Files.readString(tempDir.resolve("data/apps/data/" + APP_ID + "/sentinel.txt")));
    assertEquals(
        "cache", Files.readString(tempDir.resolve("cache/apps/" + APP_ID + "/sentinel.txt")));
    assertEquals("run", Files.readString(tempDir.resolve("run/apps/" + APP_ID + "/sentinel.txt")));
  }

  @Test
  void route_whenInstalledManifestMissingDuringUpdate_expectRepairResponse() throws Exception {
    Path stagedV1 = stageApp("staged-v1", "1.0.0");
    Path stagedV2 = stageApp("staged-v2", "9.9.9");

    PlatformApiResponse installResponse =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedV1.toString()))));
    assertEquals(201, installResponse.statusCode());
    Files.delete(appHostLayout.pathsFor(APP_ID).manifestFile());

    PlatformApiResponse updateResponse =
        router.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedV2.toString()))));
    PlatformApiResponse getResponse =
        router.route(request("GET", List.of("apps", APP_ID), Map.of()));

    assertEquals(200, updateResponse.statusCode());
    assertTrue(updateResponse.body().contains("\"version\":\"9.9.9\""));
    assertEquals(200, getResponse.statusCode());
    assertTrue(getResponse.body().contains("\"version\":\"9.9.9\""));
  }

  @Test
  void route_whenAppMissing_expect404() {
    PlatformApiResponse response =
        router.route(request("GET", List.of("apps", "missing"), Map.of()));

    assertEquals(404, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"app_not_found\",\"message\":\"App not found.\"}}", response.body());
  }

  @Test
  void route_whenInstallAndStartRepeated_expectConflictResponses() throws Exception {
    Path stagedDir = stageApp();

    router.route(
        request(
            "POST",
            List.of("apps", "install"),
            Map.of("stagedDir", List.of(stagedDir.toString()))));

    PlatformApiResponse reinstallResponse =
        router.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(409, reinstallResponse.statusCode());
    assertTrue(reinstallResponse.body().contains("\"code\":\"app_conflict\""));

    router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    PlatformApiResponse repeatedStartResponse =
        router.route(request("POST", List.of("apps", APP_ID, "start"), Map.of()));

    assertEquals(409, repeatedStartResponse.statusCode());
    assertTrue(repeatedStartResponse.body().contains("\"code\":\"app_conflict\""));
  }

  @Test
  void route_whenProductionPolicyReceivesUnsignedBundle_expectInvalidAppBundle() throws Exception {
    PlatformApiRouter productionRouter =
        createRouter(
            new LocalProcessAppHost(appHostLayout, Duration.ofSeconds(2), new SecureRandom()));
    Path stagedDir = stageApp();

    PlatformApiResponse response =
        productionRouter.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedDir.toString()))));

    assertEquals(400, response.statusCode());
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_bundle\",\"message\":\"Staged app bundle must pass"
            + " trusted signature verification.\"}}",
        response.body());
  }

  @Test
  void route_whenProductionPolicyReceivesSignedBundle_expectInstallAndUpdateSuccess()
      throws Exception {
    KeyPair keyPair =
        KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            new TrustedAppKey(
                TRUSTED_KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
    PlatformApiRouter productionRouter = createRouter(signedHost(trustedKeys));
    Path stagedV1 = stageSignedApp("signed-v1", "1.0.0", keyPair);
    Path stagedV2 = stageSignedApp("signed-v2", "9.9.9", keyPair);

    PlatformApiResponse installResponse =
        productionRouter.route(
            request(
                "POST",
                List.of("apps", "install"),
                Map.of("stagedDir", List.of(stagedV1.toString()))));
    assertEquals(201, installResponse.statusCode());
    assertTrue(installResponse.body().contains("\"version\":\"1.0.0\""));

    PlatformApiResponse updateResponse =
        productionRouter.route(
            request(
                "POST",
                List.of("apps", APP_ID, "update"),
                Map.of("stagedDir", List.of(stagedV2.toString()))));

    assertEquals(200, updateResponse.statusCode());
    assertTrue(updateResponse.body().contains("\"version\":\"9.9.9\""));
  }

  @Test
  void route_whenCatalogSourceInstalledAndUpdated_expectVerifiedCatalogFlow() throws Exception {
    KeyPair keyPair =
        KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            new TrustedAppKey(
                TRUSTED_KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
    PlatformApiRouter productionRouter =
        createRouter(signedHost(trustedKeys), catalogManager(trustedKeys));
    Path stagedV1 = stageSignedApp("catalog-v1", "1.0.0", keyPair);
    Path artifactV1 = zipDirectory(stagedV1, tempDir.resolve("catalog-v1.zip"));
    Path catalog = writeSignedCatalog(artifactV1, "1.0.0", keyPair);

    PlatformApiResponse addResponse =
        productionRouter.route(
            request(
                "POST",
                List.of("app-catalogs", "add"),
                Map.of("source", List.of(catalog.toString()))));
    PlatformApiResponse listAppsResponse =
        productionRouter.route(
            request("GET", List.of("app-catalogs", CATALOG_ID, "apps"), Map.of()));
    PlatformApiResponse installResponse =
        productionRouter.route(
            request(
                "POST", List.of("app-catalogs", CATALOG_ID, "apps", APP_ID, "install"), Map.of()));

    assertEquals(201, addResponse.statusCode());
    assertEquals(200, listAppsResponse.statusCode());
    assertTrue(listAppsResponse.body().contains("\"appId\":\"demo-app\""));
    assertEquals(201, installResponse.statusCode());
    assertTrue(installResponse.body().contains("\"version\":\"1.0.0\""));

    Path stagedV2 = stageSignedApp("catalog-v2", "9.9.9", keyPair);
    Path artifactV2 = zipDirectory(stagedV2, tempDir.resolve("catalog-v2.zip"));
    writeSignedCatalog(artifactV2, "9.9.9", keyPair);

    PlatformApiResponse refreshResponse =
        productionRouter.route(
            request("POST", List.of("app-catalogs", CATALOG_ID, "refresh"), Map.of()));
    PlatformApiResponse updateResponse =
        productionRouter.route(
            request(
                "POST", List.of("app-catalogs", CATALOG_ID, "apps", APP_ID, "update"), Map.of()));

    assertEquals(200, refreshResponse.statusCode());
    assertEquals(200, updateResponse.statusCode());
    assertTrue(updateResponse.body().contains("\"version\":\"9.9.9\""));
  }

  private PlatformApiRequest request(
      String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
    return new PlatformApiRequest(method, pathSegments, queryParameters);
  }

  private PlatformApiRouter createRouter(AppHost appHost) {
    RuntimePorts runtimePorts = mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
    return new PlatformApiRouter(runtimePorts, appHost);
  }

  private PlatformApiRouter createRouter(AppHost appHost, AppCatalogManager appCatalogManager) {
    RuntimePorts runtimePorts = mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
    return new PlatformApiRouter(runtimePorts, appHost, appCatalogManager);
  }

  private AppHost allowUnsignedHost() {
    return new LocalProcessAppHost(
        appHostLayout,
        Duration.ofSeconds(2),
        new SecureRandom(),
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
  }

  private AppHost signedHost(TrustedAppKeys trustedKeys) {
    return new LocalProcessAppHost(
        appHostLayout,
        Duration.ofSeconds(2),
        new SecureRandom(),
        AppInstallVerificationPolicy.requireSigned(
            copiedBundleDirectory -> AppBundleVerifier.verify(copiedBundleDirectory, trustedKeys)));
  }

  private AppCatalogManager catalogManager(TrustedAppKeys trustedKeys) {
    return new AppCatalogManager(
        new AppCatalogSourceStore(tempDir.resolve("catalog-store")), () -> trustedKeys);
  }

  private Path stageApp() throws Exception {
    return stageApp("staged", APP_VERSION);
  }

  private Path stageApp(String stagedDirectoryName, String appVersion) throws Exception {
    AppEnv appEnv = new AppEnv();
    String scriptName = appEnv.isWindows() ? "launch.cmd" : "launch.sh";
    Path stagedDir = Files.createDirectories(tempDir.resolve(stagedDirectoryName).resolve(APP_ID));
    Path binDir = Files.createDirectories(stagedDir.resolve("bin"));
    Path launcher = binDir.resolve(scriptName);
    Files.writeString(launcher, scriptContent(appEnv), StandardCharsets.UTF_8);
    if (!appEnv.isWindows()) {
      assertTrue(launcher.toFile().setExecutable(true, false));
    }
    Files.writeString(
        stagedDir.resolve(AppManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/%s
        app.ui.entry=%s
        app.permissions=network.access,file.read
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(APP_ID, APP_NAME, appVersion, scriptName, UI_ENTRY),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private Path stageSignedApp(String stagedDirectoryName, String appVersion, KeyPair keyPair)
      throws Exception {
    Path stagedDir = stageApp(stagedDirectoryName, appVersion);
    AppBundleSigner.sign(stagedDir, TRUSTED_KEY_ID, keyPair.getPrivate());
    return stagedDir;
  }

  private Path writeSignedCatalog(Path artifact, String appVersion, KeyPair keyPair)
      throws Exception {
    Path catalogDir = Files.createDirectories(tempDir.resolve("catalog"));
    Path catalog = catalogDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Files.writeString(
        catalog,
        """
        catalog.version=1
        catalog.id=%s
        catalog.name=Crypta Core Apps
        catalog.generatedAt=%s
        catalog.entries=%s
        app.%s.id=%s
        app.%s.name=%s
        app.%s.version=%s
        app.%s.summary=Manage local Crypta transfer queues.
        app.%s.bundle.uri=%s
        app.%s.bundle.sha256=%s
        app.%s.bundle.size.bytes=%d
        app.%s.bundle.type=zip
        app.%s.permissions=queue.read,queue.write
        """
            .formatted(
                CATALOG_ID,
                Instant.parse("2026-04-21T18:22:40Z"),
                APP_ID,
                APP_ID,
                APP_ID,
                APP_ID,
                APP_NAME,
                APP_ID,
                appVersion,
                APP_ID,
                APP_ID,
                artifact.toUri(),
                APP_ID,
                sha256(artifact),
                APP_ID,
                Files.size(artifact),
                APP_ID,
                APP_ID),
        StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, TRUSTED_KEY_ID, keyPair.getPrivate());
    return catalog;
  }

  private static Path zipDirectory(Path sourceRoot, Path targetZip) throws Exception {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip));
        var paths = Files.walk(sourceRoot)) {
      for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        String relative = sourceRoot.relativize(path).toString().replace('\\', '/');
        zip.putNextEntry(new ZipEntry(relative));
        Files.copy(path, zip);
        zip.closeEntry();
      }
    }
    return targetZip;
  }

  private static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(Files.readAllBytes(path));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static String scriptContent(AppEnv appEnv) {
    if (appEnv.isWindows()) {
      return """
      @echo off
      :loop
      timeout /t 1 /nobreak >nul
      goto loop
      """;
    }
    return """
    #!/bin/sh
    trap 'exit 0' TERM INT
    while :; do
      sleep 0.1
    done
    """;
  }
}
