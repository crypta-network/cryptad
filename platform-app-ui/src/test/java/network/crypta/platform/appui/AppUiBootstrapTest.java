package network.crypta.platform.appui;

import java.time.Instant;
import java.util.List;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppUiBootstrapTest {
  private static final Instant EXPIRES_AT = Instant.parse("2026-04-28T12:00:00Z");

  @Test
  void forManifest_whenStaticAppProvided_expectRouteMetadataAndBrowserSession() {
    AppUiBootstrap bootstrap =
        AppUiBootstrap.forManifest(
            manifest(),
            "/api/v1/",
            "/app/node/",
            new AppBrowserSessionIssue("session-token", EXPIRES_AT));

    assertEquals("demo-app", bootstrap.appId());
    assertEquals("Demo App", bootstrap.name());
    assertEquals("/apps/demo-app/", bootstrap.uiRoot());
    assertEquals("/apps/demo-app/static/", bootstrap.assetRoot());
    assertEquals("/api/v1/", bootstrap.platformApiRoot());
    assertEquals("/app/node/", bootstrap.shellRoot());
    assertEquals("same-origin-fallback", bootstrap.uiOriginMode());
    assertEquals("fallback", bootstrap.uiOriginStatus());
    assertEquals("/apps/demo-app/", bootstrap.sameOriginFallbackUrl());
    assertEquals("session-token", bootstrap.browserSessionToken());
    assertEquals(EXPIRES_AT, bootstrap.browserSessionExpiresAt());
  }

  @Test
  void forManifest_whenIsolatedBindingProvided_expectAbsoluteOriginsAndFallbackRoot() {
    AppManifest manifest = manifest();
    AppUiOriginBinding binding =
        AppUiOriginBinding.isolatedLoopback(
            manifest,
            AppUiOrigin.loopback("demo-app", 12345),
            "http://127.0.0.1:8888/api/v1/",
            "http://127.0.0.1:8888/app/node/");

    AppUiBootstrap bootstrap =
        AppUiBootstrap.forManifest(
            manifest,
            "/api/v1/",
            "/app/node/",
            new AppBrowserSessionIssue("session-token", EXPIRES_AT),
            binding);

    assertEquals("http://127.0.0.1:12345/", bootstrap.uiRoot());
    assertEquals("http://127.0.0.1:12345/static/", bootstrap.assetRoot());
    assertEquals("http://127.0.0.1:8888/api/v1/", bootstrap.platformApiRoot());
    assertEquals("http://127.0.0.1:8888/app/node/", bootstrap.shellRoot());
    assertEquals("http://127.0.0.1:12345", bootstrap.uiOrigin());
    assertEquals("isolated-loopback", bootstrap.uiOriginMode());
    assertEquals("active", bootstrap.uiOriginStatus());
    assertEquals("/apps/demo-app/", bootstrap.sameOriginFallbackUrl());
  }

  @Test
  void constructor_whenBlankBrowserSessionTokenProvided_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppUiBootstrap(
                "demo-app",
                "Demo App",
                "/apps/demo-app/",
                "/apps/demo-app/static/",
                "/api/v1/",
                "/app/node/",
                " ",
                EXPIRES_AT));
  }

  @Test
  void constructor_whenRouteRootOmitsTrailingSlash_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppUiBootstrap(
                "demo-app",
                "Demo App",
                "/apps/demo-app/",
                "/apps/demo-app/static/",
                "/api/v1",
                "/app/node/",
                "session-token",
                EXPIRES_AT));
  }

  @Test
  void serialize_whenBootstrapContainsSensitiveLookingText_expectEscapedJsonWithoutAppToken() {
    AppUiBootstrap bootstrap =
        new AppUiBootstrap(
            "demo-app",
            "Demo <App>",
            "/apps/demo-app/",
            "/apps/demo-app/static/",
            "/api/v1/",
            "/app/node/",
            "secret&value",
            EXPIRES_AT);

    String json = AppUiBootstrapJson.serialize(bootstrap);

    assertEquals(
        "{\"appId\":\"demo-app\","
            + "\"name\":\"Demo \\u003cApp\\u003e\","
            + "\"uiRoot\":\"/apps/demo-app/\","
            + "\"assetRoot\":\"/apps/demo-app/static/\","
            + "\"platformApiRoot\":\"/api/v1/\","
            + "\"shellRoot\":\"/app/node/\","
            + "\"uiOrigin\":null,"
            + "\"uiOriginMode\":\"same-origin-fallback\","
            + "\"uiOriginStatus\":\"fallback\","
            + "\"sameOriginFallbackUrl\":\"/apps/demo-app/\","
            + "\"browserSessionToken\":\"secret\\u0026value\","
            + "\"browserSessionExpiresAt\":\"2026-04-28T12:00:00Z\"}",
        json);
    assertTrue(json.contains("\"name\":\"Demo \\u003cApp\\u003e\""));
    assertTrue(json.contains("\"browserSessionToken\":\"secret\\u0026value\""));
    assertFalse(json.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(json.contains("launchToken"));
    assertFalse(json.contains("formPassword"));
  }

  @Test
  void toString_whenBrowserSessionPresent_expectTokenRedacted() {
    AppUiBootstrap bootstrap =
        new AppUiBootstrap(
            "demo-app",
            "Demo App",
            "/apps/demo-app/",
            "/apps/demo-app/static/",
            "/api/v1/",
            "/app/node/",
            "secret-token",
            EXPIRES_AT);

    String text = bootstrap.toString();

    assertTrue(text.contains("browserSessionToken=[REDACTED]"));
    assertFalse(text.contains("secret-token"));
  }

  @Test
  void isBootstrapAssetPath_whenReservedPathProvided_expectTrue() {
    assertTrue(AppUiBootstrap.isBootstrapAssetPath(".well-known/cryptad-bootstrap.json"));
  }

  @Test
  void isBootstrapAssetPath_whenOrdinaryAssetProvided_expectFalse() {
    assertFalse(AppUiBootstrap.isBootstrapAssetPath("static/app.js"));
  }

  private static AppManifest manifest() {
    return new AppManifest(
        1,
        "demo-app",
        "Demo App",
        "1.0.0",
        "bin/launch.sh",
        AppUiMode.STATIC,
        "static/index.html",
        List.of(),
        null,
        null);
  }
}
