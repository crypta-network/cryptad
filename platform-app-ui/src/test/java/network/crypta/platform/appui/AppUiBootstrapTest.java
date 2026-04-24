package network.crypta.platform.appui;

import java.util.List;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.manifest.AppManifest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppUiBootstrapTest {
  @Test
  void forManifest_whenStaticAppProvided_expectRouteMetadataOnly() {
    AppUiBootstrap bootstrap =
        AppUiBootstrap.forManifest(manifest(), "/api/v1/", "/app/node/", "form-secret");

    assertEquals("demo-app", bootstrap.appId());
    assertEquals("Demo App", bootstrap.name());
    assertEquals("/apps/demo-app/", bootstrap.uiRoot());
    assertEquals("/apps/demo-app/static/", bootstrap.assetRoot());
    assertEquals("/api/v1/", bootstrap.platformApiRoot());
    assertEquals("/app/node/", bootstrap.shellRoot());
    assertEquals("form-secret", bootstrap.formPassword());
  }

  @Test
  void constructor_whenBlankFormPasswordProvided_expectReadOnlyBootstrap() {
    AppUiBootstrap bootstrap =
        new AppUiBootstrap(
            "demo-app",
            "Demo App",
            "/apps/demo-app/",
            "/apps/demo-app/static/",
            "/api/v1/",
            "/app/node/",
            " ");

    assertNull(bootstrap.formPassword());
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
                null));
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
            "secret&value");

    String json = AppUiBootstrapJson.serialize(bootstrap);

    assertTrue(json.contains("\"name\":\"Demo \\u003cApp\\u003e\""));
    assertTrue(json.contains("\"formPassword\":\"secret\\u0026value\""));
    assertFalse(json.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(json.contains("launchToken"));
  }

  @Test
  void serialize_whenFormPasswordIsNull_expectNullJsonField() {
    AppUiBootstrap bootstrap =
        new AppUiBootstrap(
            "demo-app",
            "Demo App",
            "/apps/demo-app/",
            "/apps/demo-app/static/",
            "/api/v1/",
            "/app/node/",
            null);

    String json = AppUiBootstrapJson.serialize(bootstrap);

    assertTrue(json.contains("\"formPassword\":null"));
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
