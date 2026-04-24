package network.crypta.platform.sdk.js;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaPlatformSdkResourceTest {
  private static final String SDK_RESOURCE_PATH =
      "/network/crypta/platform/sdk/js/crypta-platform.js";

  @Test
  void classpathResource_whenSdkRequested_expectReadableBrowserScript() throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("window.CryptaPlatform"));
    assertTrue(script.contains("bootstrap:"));
    assertTrue(script.contains("api:"));
    assertTrue(script.contains("queue:"));
    assertTrue(script.contains("content:"));
    assertTrue(script.contains("dom:"));
    assertTrue(script.contains("sanitizeFragment"));
    assertTrue(script.contains("formPassword"));
    assertFalse(script.contains("CRYPTAD_APP_TOKEN"));
  }

  @Test
  void classpathResource_whenAppIdCanonicalizationRequested_expectComparisonUsesNormalizedIds()
      throws IOException {
    String script = readSdkScript();

    int requestedNormalization = script.indexOf("const requestedAppId = normalizeAppId(rawAppId);");
    int fetchWithNormalizedId = script.indexOf("fetchBootstrap(requestedAppId)");
    int bootstrapNormalization =
        script.indexOf("bootstrap.appId = normalizeAppId(bootstrap.appId);");
    int normalizedComparison = script.indexOf("bootstrap.appId && bootstrap.appId !== appId");

    assertTrue(script.contains("const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;"));
    assertTrue(script.contains("const normalized = appId.trim().toLowerCase();"));
    assertTrue(script.contains("const requestedAppId = normalizeAppId(rawAppId);"));
    assertTrue(script.contains("bootstrap.appId = normalizeAppId(bootstrap.appId);"));
    assertTrue(requestedNormalization >= 0);
    assertTrue(fetchWithNormalizedId > requestedNormalization);
    assertTrue(bootstrapNormalization >= 0);
    assertTrue(normalizedComparison > bootstrapNormalization);
  }

  private static String readSdkScript() throws IOException {
    try (InputStream stream =
        CryptaPlatformSdkResourceTest.class.getResourceAsStream(SDK_RESOURCE_PATH)) {
      assertNotNull(stream, "SDK resource must be available on the module classpath.");
      return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }
  }
}
