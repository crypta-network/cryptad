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
  void classpathResource_whenSdkRequested_expectPublicBrowserSurface() throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("window.CryptaPlatform"));
    assertTrue(script.contains("bootstrap:"));
    assertTrue(script.contains("api:"));
    assertTrue(script.contains("queue:"));
    assertTrue(script.contains("content:"));
    assertTrue(script.contains("vault:"));
    assertTrue(script.contains("dom:"));
    assertTrue(script.contains("sanitizeFragment"));
    assertTrue(script.contains("browserSessionToken"));
    assertTrue(script.contains("X-Crypta-App-Session"));
    assertTrue(script.contains("invalid_app_browser_session"));
    assertTrue(script.contains("origin_mismatch"));
    assertTrue(script.contains("sessionRefreshRequired"));
    assertTrue(script.contains("credentials: \"omit\""));
  }

  @Test
  void classpathResource_whenBootstrapRequested_expectIsolatedOriginBootstrapFlow()
      throws IOException {
    String script = readSdkScript();

    assertTrue(
        script.contains("const bootstrapResourcePath = \".well-known/cryptad-bootstrap.json\";"));
    assertTrue(script.contains("const bootstrapNonceHeader = \"X-Crypta-App-Bootstrap-Nonce\";"));
    assertTrue(
        script.contains("const bootstrapNonceFragmentParameter = \"cryptadBootstrapNonce\";"));
    assertTrue(script.contains("function bootstrapHeaders()"));
    assertTrue(script.contains("headers[bootstrapNonceHeader] = nonce;"));
    assertTrue(script.contains("function bootstrapNonceFromHash(hash)"));
    assertTrue(script.contains("function bootstrapUrls(appId)"));
    assertTrue(script.contains("const rootBootstrapUrl = `/${bootstrapResourcePath}`;"));
    assertTrue(script.contains("if (!appId || !legacyAdminAppPath(appId))"));
    assertTrue(script.contains("function legacyAdminAppPath(appId)"));
    assertTrue(script.contains("if (index + 1 >= urls.length)"));
    assertTrue(
        script.contains(
            "throw new Error(\"Bootstrap response did not include a Cryptad app id.\")"));
    assertTrue(script.contains("copyStringField(source, bootstrap, \"platformApiRoot\");"));
    assertTrue(script.contains("copyStringField(source, bootstrap, \"uiOrigin\");"));
  }

  @Test
  void classpathResource_whenApiRequested_expectAbsoluteApiRootAndSessionRefreshFlow()
      throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("function fetchApiGet"));
    assertFalse(script.contains("return new URL(value, window.location.origin);"));
    assertTrue(script.contains("return new URL(value, rootUrl);"));
    assertTrue(script.contains("function refreshBootstrap(options)"));
    assertTrue(script.contains("function refreshBootstrapForMutation"));
    assertTrue(script.contains("currentBrowserSessionLive()"));
    assertTrue(script.contains("function browserSessionExpiresAtMillis(bootstrap)"));
    assertTrue(script.contains("Date.parse(value)"));
    assertTrue(script.contains("await refreshBootstrap(requestOptions);"));
    assertTrue(script.contains("return fetchApiGet(path, requestOptions);"));
    assertTrue(script.contains("await refreshBootstrapForMutation(requestOptions);"));
    assertTrue(script.contains("function fetchFormMutation(method, path, body, requestOptions)"));
    assertTrue(
        script.contains("return await fetchFormMutation(method, path, body, requestOptions);"));
    assertTrue(script.contains("return fetchFormMutation(method, path, body, requestOptions);"));
    assertTrue(
        script.contains(
            "hostname.startsWith(\"[\") && hostname.endsWith(\"]\") ? hostname.slice(1, -1)"));
    assertTrue(script.contains("normalizedHostname === \"::1\""));
    assertTrue(script.contains("normalizedHostname === \"0:0:0:0:0:0:0:1\""));
  }

  @Test
  void classpathResource_whenSdkRequested_expectNoHostCredentialsOrPersistentStorage()
      throws IOException {
    String script = readSdkScript();

    assertFalse(script.contains("formPassword"));
    assertFalse(script.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(script.contains("localStorage"));
    assertFalse(script.contains("sessionStorage"));
    assertFalse(script.contains("valueBase64"));
    assertFalse(script.contains("signatureBase64"));
    assertFalse(script.contains("privateKey"));
  }

  @Test
  void classpathResource_whenVaultRequested_expectMetadataOnlyBrowserHelpers() throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("function listVaultIdentities(options)"));
    assertTrue(script.contains("return apiGet(\"app-vault/identities\", options);"));
    assertTrue(script.contains("function getVaultIdentity(identityId, options)"));
    assertTrue(script.contains("function listVaultGrants(options)"));
    assertTrue(script.contains("return apiGet(\"app-vault/grants\", options);"));
    assertTrue(script.contains("function requestVaultGrant(request, options)"));
    assertTrue(script.contains("return apiPostForm(\"app-vault/grants/request\""));
    assertTrue(script.contains("function normalizeVaultGrantRequest(request)"));
    assertTrue(script.contains("function normalizeVaultGrantScope(scope)"));
    assertTrue(script.contains("normalized !== \"sign.domain-separated\""));
    assertTrue(script.contains("identities: Object.freeze({"));
    assertTrue(script.contains("grants: Object.freeze({"));
    assertFalse(script.contains("app-vault/secrets"));
    assertFalse(script.contains("useIdentity"));
  }

  @Test
  void classpathResource_whenAppIdCanonicalizationRequested_expectComparisonUsesNormalizedIds()
      throws IOException {
    String script = readSdkScript();

    int requestedNormalization =
        script.indexOf("const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;");
    int fetchWithNormalizedId = script.indexOf("fetchBootstrap(requestedAppId)");
    int bootstrapNormalization =
        script.indexOf("bootstrap.appId = normalizeAppId(bootstrap.appId);");
    int normalizedComparison =
        script.indexOf("bootstrap.appId && appId && bootstrap.appId !== appId");

    assertTrue(script.contains("const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;"));
    assertTrue(script.contains("const normalized = appId.trim().toLowerCase();"));
    assertTrue(
        script.contains("const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;"));
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
