package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostLayout;
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
  private static final String UI_ENTRY = "/";

  @TempDir private Path tempDir;

  private PlatformApiRouter router;

  @BeforeEach
  void setUp() {
    RuntimePorts runtimePorts = mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
    AppHost appHost =
        new LocalProcessAppHost(
            new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve("cache"), tempDir.resolve("run")),
            Duration.ofSeconds(2),
            new SecureRandom());
    router = new PlatformApiRouter(runtimePorts, appHost);
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

  private PlatformApiRequest request(
      String method, List<String> pathSegments, Map<String, List<String>> queryParameters) {
    return new PlatformApiRequest(method, pathSegments, queryParameters);
  }

  private Path stageApp() throws Exception {
    AppEnv appEnv = new AppEnv();
    String scriptName = appEnv.isWindows() ? "launch.cmd" : "launch.sh";
    Path stagedDir = Files.createDirectories(tempDir.resolve("staged").resolve(APP_ID));
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
            .formatted(APP_ID, APP_NAME, APP_VERSION, scriptName, UI_ENTRY),
        StandardCharsets.UTF_8);
    return stagedDir;
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
