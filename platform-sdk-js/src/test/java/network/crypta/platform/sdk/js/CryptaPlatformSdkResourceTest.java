package network.crypta.platform.sdk.js;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaPlatformSdkResourceTest {
  private static final String SDK_RESOURCE_PATH =
      "/network/crypta/platform/sdk/js/crypta-platform.js";

  @TempDir private Path tempDir;

  @Test
  void classpathResource_whenSdkRequested_expectPublicBrowserSurface() throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("window.CryptaPlatform"));
    assertTrue(script.contains("bootstrap:"));
    assertTrue(script.contains("api:"));
    assertTrue(script.contains("queue:"));
    assertTrue(script.contains("content:"));
    assertTrue(script.contains("feed:"));
    assertTrue(script.contains("vault:"));
    assertTrue(script.contains("profile:"));
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
    assertTrue(script.contains("function createVaultIdentity(options)"));
    assertTrue(script.contains("return apiPostForm("));
    assertTrue(script.contains("\"app-vault/identities\""));
    assertTrue(script.contains("function createProfileDocument(identityId, profile, options)"));
    assertTrue(script.contains("function normalizeProfileDocument(profile)"));
    assertTrue(script.contains("copyStringParam(source, params, \"displayName\");"));
    assertTrue(script.contains("appendTagsParam(source.tags, params);"));
    assertTrue(script.contains("/profile-document`"));
    assertTrue(script.contains("function normalizeVaultGrantScope(scope)"));
    assertTrue(script.contains("normalized !== \"sign.domain-separated\""));
    assertTrue(script.contains("identities: Object.freeze({"));
    assertTrue(script.contains("create: createVaultIdentity"));
    assertTrue(script.contains("createProfileDocument"));
    assertTrue(script.contains("grants: Object.freeze({"));
    assertFalse(script.contains("app-vault/secrets"));
    assertFalse(script.contains("useIdentity"));
  }

  @Test
  void classpathResource_whenJsonDocumentHelpersRequested_expectEncodedFormMutations()
      throws IOException {
    String script = readSdkScript();

    assertJsonDocumentHelperFragments(script);
    assertNoRawMutationFetches(script);
  }

  @Test
  void classpathResource_whenContentFetchRequested_expectSessionHeaderUsed() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/fetch"
              && options.method === "POST";
          },
          { contentText: "feed text", requestedUri: "CHK@feed", bytesLength: 9, format: "text" });

        const response = await CryptaPlatform.content.fetchText({ uri: "CHK@feed", maxBytes: 4096 });

        assert.equal(response.contentText, "feed text");
        assert.equal(calls.length, 2);
        assert.equal(calls[1].method, "POST");
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.match(
          headerValue(calls[1].headers, "Content-Type"),
          /^application\\/x-www-form-urlencoded/);
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("uri"), "CHK@feed");
        assert.equal(params.get("maxBytes"), "4096");
        assert.equal(params.get("format"), "text");
        assert.equal(calls[1].credentials, "omit");
        """);
  }

  @Test
  void classpathResource_whenFeedParserReceivesCanonicalJson_expectNormalizedSnapshot()
      throws Exception {
    runSdkNode(
        """
        context.executed = false;
        const snapshot = CryptaPlatform.feed.parseSnapshot(JSON.stringify({
          type: "crypta.feed.snapshot.v1",
          title: " Example Feed ",
          updatedAt: " 2026-05-16T00:00:00Z ",
          source: {
            uri: " USK@feed ",
            resolvedUri: " USK@feed/42/feed.json "
          },
          author: {
            name: " Alice ",
            profileUri: " USK@alice/profile.json "
          },
          items: [{
            id: " entry-1 ",
            title: " Hello ",
            summary: " <script>globalThis.executed = true;</script> ",
            uri: " CHK@entry ",
            contentHtml: "<img src=x onerror=globalThis.executed=true>",
            tags: [" beta ", "alpha", "alpha", ""]
          }]
        }));

        assert.deepStrictEqual(JSON.parse(JSON.stringify(snapshot)), {
          type: "crypta.feed.snapshot.v1",
          title: "Example Feed",
          updatedAt: "2026-05-16T00:00:00Z",
          source: {
            uri: "USK@feed",
            resolvedUri: "USK@feed/42/feed.json"
          },
          author: {
            name: "Alice",
            profileUri: "USK@alice/profile.json"
          },
          items: [{
            id: "entry-1",
            title: "Hello",
            summary: "<script>globalThis.executed = true;</script>",
            uri: "CHK@entry",
            tags: ["alpha", "beta"]
          }]
        });
        assert.equal(context.executed, false);
        assert.equal(Object.hasOwn(snapshot.items[0], "contentHtml"), false);
        """);
  }

  @Test
  void classpathResource_whenFeedParserReceivesInvalidSnapshot_expectRejection() throws Exception {
    runSdkNode(
        """
        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "wrong",
            items: []
          })),
          /Feed snapshot type must be crypta\\.feed\\.snapshot\\.v1/);

        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "crypta.feed.snapshot.v1",
            items: Array.from({ length: 101 }, () => ({}))
          })),
          /at most 100 items/);
        """);
  }

  @Test
  void classpathResource_whenFeedSnapshotPublished_expectAppDocumentOptions() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "insert-1" });

        const result = await CryptaPlatform.feed.publishSnapshot({
          insertUri: "USK@feed",
          identifier: "feed-root",
          snapshot: {
            type: "crypta.feed.snapshot.v1",
            title: " Feed ",
            items: []
          },
          contentType: "text/plain",
          targetFilename: "unsafe.html",
          compress: true,
          headers: { "X-Custom": "value" }
        });

        assert.equal(result.requestId, "insert-1");
        assert.equal(calls.length, 2);
        const post = calls[1];
        assert.equal(headerValue(post.headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(headerValue(post.headers, "X-Custom"), "value");
        assert.match(
          headerValue(post.headers, "Content-Type"),
          /^application\\/x-www-form-urlencoded/);

        const params = decodeFormBody(post);
        assert.equal(params.get("insertUri"), "USK@feed");
        assert.equal(params.get("identifier"), "feed-root");
        assert.equal(params.get("contentType"), "application/vnd.crypta.feed+json");
        assert.equal(params.get("targetFilename"), "feed.json");
        assert.equal(params.get("compress"), "true");

        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        assert.deepStrictEqual(JSON.parse(documentJson), {
          type: "crypta.feed.snapshot.v1",
          title: "Feed",
          source: {},
          author: {},
          items: []
        });
        """);
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

  private static void assertJsonDocumentHelperFragments(String script) {
    String[] expectedFragments = {
      "function insertAppDocument(options)",
      "function fetchText(uriOrOptions, options)",
      "function fetchBase64(uriOrOptions, options)",
      "\"content/fetch\"",
      "normalizeContentFetchParams(source, format)",
      "\"queue/inserts/app-document\"",
      "function normalizeAppDocumentInsert(options)",
      "params.set(\"documentBase64\"",
      "copyStringParamAs(options, params, \"mimeType\", \"contentType\");",
      "jsonDocumentBase64(document, \"App document\")",
      "function jsonDocumentBase64(value, description)",
      "JSON.stringify(value)",
      "function utf8Base64(value)",
      "new TextEncoder().encode(value)",
      "return btoa(binary);",
      "function publishProfile(options)",
      "const profileDocumentResponse = await createProfileDocument(",
      "function profilePublishInsertOptions(source, document)",
      "options.identifier = `profile-${vaultPathSegment(source.identityId)}`;",
      "options.targetFilename = \"profile.json\";",
      "application/vnd.crypta.profile+json",
      "insertAppDocument(",
      "profile: Object.freeze({",
      "publish: publishProfile"
    };
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          script.contains(expectedFragment),
          () -> "Expected fragment missing: " + expectedFragment);
    }
  }

  private static void assertNoRawMutationFetches(String script) {
    String[] forbiddenFragments = {
      "fetch(apiUrl(\"queue/inserts/app-document\"", "fetch(apiUrl(\"app-vault/identities\""
    };
    for (String forbiddenFragment : forbiddenFragments) {
      assertFalse(
          script.contains(forbiddenFragment),
          () -> "Forbidden fragment present: " + forbiddenFragment);
    }
  }

  private void runSdkNode(String scriptBody) throws Exception {
    Assumptions.assumeTrue(nodeAvailable(), "Node.js is required for SDK behavior tests.");
    Path sdkScript = tempDir.resolve("crypta-platform.js");
    Path harness = tempDir.resolve("sdk-harness.js");
    Files.writeString(sdkScript, readSdkScript(), StandardCharsets.UTF_8);
    Files.writeString(harness, nodeHarness(scriptBody), StandardCharsets.UTF_8);

    Process process = new ProcessBuilder("node", harness.toString(), sdkScript.toString()).start();
    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
    }
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
            + new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(finished, output);
    assertEquals(0, process.exitValue(), output);
  }

  private static boolean nodeAvailable() {
    try {
      Process process = new ProcessBuilder("node", "--version").start();
      boolean finished = process.waitFor(5, TimeUnit.SECONDS);
      if (!finished) {
        process.destroyForcibly();
        return false;
      }
      return process.exitValue() == 0;
    } catch (IOException _) {
      return false;
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  private static String nodeHarness(String scriptBody) {
    return """
    const fs = require("fs");
    const vm = require("vm");
    const assert = require("assert");
    const { TextEncoder } = require("util");

    class SimpleHeaders {
      constructor(init = {}) {
        this.values = new Map();
        if (typeof init.forEach === "function") {
          init.forEach((value, key) => this.set(key, value));
        } else if (Array.isArray(init)) {
          init.forEach(([key, value]) => this.set(key, value));
        } else {
          Object.entries(init).forEach(([key, value]) => this.set(key, value));
        }
      }

      set(name, value) {
        this.values.set(String(name).toLowerCase(), String(value));
      }

      get(name) {
        return this.values.get(String(name).toLowerCase()) || null;
      }

      has(name) {
        return this.values.has(String(name).toLowerCase());
      }

      forEach(callback) {
        this.values.forEach((value, key) => callback(value, key));
      }
    }

    class MockResponse {
      constructor(status, body, statusText = "OK") {
        this.status = status;
        this.statusText = statusText;
        this.ok = status >= 200 && status < 300;
        this.body = body;
      }

      async json() {
        return this.body;
      }
    }

    const HeadersImpl = global.Headers || SimpleHeaders;
    const calls = [];
    const responses = [];
    const bootstrap = {
      appId: "feed-reader",
      name: "Feed Reader",
      platformApiRoot: "http://127.0.0.1:8181/api/v1/",
      browserSessionToken: "session-token",
      browserSessionExpiresAt: "2999-01-01T00:00:00Z"
    };

    function enqueueResponse(matcher, body, status = 200, statusText = "OK") {
      responses.push({ matcher, body, status, statusText });
    }

    function enqueueBootstrap() {
      enqueueResponse((url) => url.endsWith("/.well-known/cryptad-bootstrap.json"), bootstrap);
    }

    function headerValue(headers, name) {
      if (!headers) {
        return null;
      }
      if (typeof headers.get === "function") {
        return headers.get(name);
      }
      return headers[name] || headers[name.toLowerCase()] || null;
    }

    function decodeFormBody(call) {
      return new URLSearchParams(call.body || "");
    }

    const context = {
      console,
      URL,
      URLSearchParams,
      TextEncoder,
      Headers: HeadersImpl,
      btoa: (value) => Buffer.from(value, "binary").toString("base64"),
      DOMParser: class {
        constructor() {
          throw new Error("DOMParser must not be used by feed helpers.");
        }
      },
      document: {
        createDocumentFragment() {
          throw new Error("document must not be used by feed helpers.");
        }
      },
      window: {
        location: {
          href: "http://127.0.0.1:3000/apps/feed-reader/static/index.html",
          pathname: "/apps/feed-reader/static/index.html",
          hash: ""
        }
      }
    };

    context.fetch = async (url, options = {}) => {
      const call = {
        url: String(url),
        method: options.method || "GET",
        headers: options.headers,
        body: options.body,
        credentials: options.credentials
      };
      calls.push(call);
      const response = responses.shift();
      assert.ok(response, `unexpected fetch: ${call.method} ${call.url}`);
      assert.ok(
        response.matcher(call.url, options),
        `unexpected fetch: ${call.method} ${call.url}`);
      return new MockResponse(response.status, response.body, response.statusText);
    };

    vm.createContext(context);
    const sdk = fs.readFileSync(process.argv[2], "utf8");
    vm.runInContext(sdk, context, { filename: "crypta-platform.js" });
    const CryptaPlatform = context.window.CryptaPlatform;

    (async () => {
    """
        + scriptBody
        + """
        })().catch((error) => {
          console.error(error && error.stack ? error.stack : error);
          process.exit(1);
        });
        """;
  }
}
