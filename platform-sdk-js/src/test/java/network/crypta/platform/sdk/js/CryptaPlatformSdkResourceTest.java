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
    assertTrue(script.contains("subscriptions: Object.freeze({"));
    assertTrue(script.contains("data:"));
    assertTrue(script.contains("records: Object.freeze({"));
    assertTrue(script.contains("namespaces: Object.freeze({"));
    assertTrue(script.contains("feed:"));
    assertTrue(script.contains("trust:"));
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
    assertFalse(script.contains("signatureBase64"));
    assertFalse(script.contains("privateKey"));
  }

  @Test
  void classpathResource_whenVaultRequested_expectMetadataOnlyBrowserHelpers() throws IOException {
    String script = readSdkScript();

    assertVaultMetadataBrowserHelperFragments(script);
    assertNoVaultPrivateBrowserHelpers(script);
  }

  @Test
  void classpathResource_whenJsonDocumentHelpersRequested_expectEncodedFormMutations()
      throws IOException {
    String script = readSdkScript();

    assertJsonDocumentHelperFragments(script);
    assertNoRawMutationFetches(script);
  }

  @Test
  void classpathResource_whenTrustHelpersRequested_expectBrowserSafeTrustSurface()
      throws IOException {
    String script = readSdkScript();

    assertTrue(
        script.contains(
            "const trustStatementContentType = \"application/vnd.crypta.trust+json\";"));
    assertTrue(script.contains("const trustStatementTargetFilename = \"trust.json\";"));
    assertTrue(script.contains("function trustStatus(options)"));
    assertTrue(script.contains("function listTrustAnchors(options)"));
    assertTrue(script.contains("function addTrustAnchor(request, options)"));
    assertTrue(script.contains("function removeTrustAnchor(fingerprintOrOptions, options)"));
    assertTrue(script.contains("function importTrustStatement(request, options)"));
    assertTrue(script.contains("function trustSubjects(options)"));
    assertTrue(script.contains("function trustStatements(request, options)"));
    assertTrue(script.contains("function trustScore(request, options)"));
    assertTrue(script.contains("function publishTrustStatement(options)"));
    assertTrue(script.contains("\"trust-graph/score\""));
    assertTrue(script.contains("\"trust-graph/import\""));
    assertTrue(script.contains("/trust-statement`"));
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
  void classpathResource_whenContentSubscriptionRequested_expectRoutesAndFormFields()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions"
              && options.method === "POST";
          },
          { subscription: { subscriptionId: "sub-alpha" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions"
              && options.method === "GET";
          },
          { subscriptions: [] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha"
              && options.method === "GET";
          },
          { subscription: { subscriptionId: "sub-alpha" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/refresh"
              && options.method === "POST";
          },
          { subscription: { status: "success" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/pause"
              && options.method === "POST";
          },
          { subscription: { status: "paused" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/resume"
              && options.method === "POST";
          },
          { subscription: { status: "scheduled" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha"
              && options.method === "DELETE";
          },
          { subscription: { status: "deleted" } });

        const created = await CryptaPlatform.content.subscriptions.create({
          uri: "crypta:USK@example/feed/7/feed.json",
          label: "Daily feed",
          pollIntervalSeconds: 300,
          maxBytes: 262144,
          timeoutMillis: 30000,
          headers: { "X-Custom": "value" }
        });
        const createParams = decodeFormBody(calls[1]);
        assert.equal(created.subscription.subscriptionId, "sub-alpha");
        assert.equal(createParams.get("uri"), "crypta:USK@example/feed/7/feed.json");
        assert.equal(createParams.get("label"), "Daily feed");
        assert.equal(createParams.get("pollIntervalSeconds"), "300");
        assert.equal(createParams.get("maxBytes"), "262144");
        assert.equal(createParams.get("timeoutMillis"), "30000");
        assert.equal(headerValue(calls[1].headers, "X-Custom"), "value");
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");

        await CryptaPlatform.content.subscriptions.list();
        await CryptaPlatform.content.subscriptions.get("sub-alpha");
        await CryptaPlatform.content.subscriptions.refresh("sub-alpha");
        await CryptaPlatform.content.subscriptions.pause({ subscriptionId: "sub-alpha" });
        await CryptaPlatform.content.subscriptions.resume("sub-alpha");
        await CryptaPlatform.content.subscriptions.remove("sub-alpha");

        assert.equal(calls.length, 8);
        assert.throws(
          () => CryptaPlatform.content.subscriptions.get("../secret"),
          /normalized local path segment/);
        """);
  }

  @Test
  void classpathResource_whenAppDataHelpersRequested_expectRoutesAndFormFields() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/records"
              && options.method === "POST";
          },
          { record: { namespace: "ui-state", key: "settings", valueText: "{\\"theme\\":\\"dark\\"}" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/records/ui-state/settings"
              && options.method === "GET";
          },
          { record: { namespace: "ui-state", key: "settings", valueText: "{\\"theme\\":\\"dark\\"}" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/namespaces/ui-state/schema"
              && options.method === "POST";
          },
          { namespace: { namespace: "ui-state", schemaVersion: 2 } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/export"
              && parsed.searchParams.get("namespace") === "ui-state"
              && options.method === "GET";
          },
          { export: { payloadBase64: "eyJleHBvcnRWZXJzaW9uIjoxfQ" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/import"
              && options.method === "POST";
          },
          { import: { imported: true, recordCount: 1 } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/import"
              && options.method === "POST";
          },
          { import: { imported: true, recordCount: 1 } });

        const stored = await CryptaPlatform.data.records.putJson({
          namespace: "ui-state",
          key: "settings",
          schemaVersion: 1,
          value: { theme: "dark" },
          headers: { "X-Custom": "value" }
        });
        assert.equal(stored.namespace, "ui-state");
        const putParams = decodeFormBody(calls[1]);
        assert.equal(putParams.get("namespace"), "ui-state");
        assert.equal(putParams.get("key"), "settings");
        assert.equal(putParams.get("schemaVersion"), "1");
        assert.equal(putParams.get("contentType"), "application/json");
        assert.deepStrictEqual(JSON.parse(putParams.get("valueJson")), { theme: "dark" });
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(headerValue(calls[1].headers, "X-Custom"), "value");

        const value = await CryptaPlatform.data.records.getJson("ui-state", "settings");
        assert.equal(value.theme, "dark");

        const namespace = await CryptaPlatform.data.namespaces.migrate("ui-state", {
          fromSchemaVersion: 1,
          toSchemaVersion: 2,
          summary: "settings migration"
        });
        assert.equal(namespace.schemaVersion, 2);
        const migrationParams = decodeFormBody(calls[3]);
        assert.equal(migrationParams.get("fromSchemaVersion"), "1");
        assert.equal(migrationParams.get("toSchemaVersion"), "2");
        assert.equal(migrationParams.get("summary"), "settings migration");

        const exported = await CryptaPlatform.data.export({ namespace: "ui-state" });
        assert.equal(exported.payloadBase64, "eyJleHBvcnRWZXJzaW9uIjoxfQ");

        const imported = await CryptaPlatform.data.import(exported, { mode: "merge" });
        assert.equal(imported.imported, true);
        const importParams = decodeFormBody(calls[5]);
        assert.equal(importParams.get("mode"), "merge");
        assert.equal(importParams.get("payloadBase64"), "eyJleHBvcnRWZXJzaW9uIjoxfQ");

        await CryptaPlatform.data.import({ exportVersion: 1, records: [] }, { mode: "merge" });
        const importJsonParams = decodeFormBody(calls[6]);
        assert.deepStrictEqual(
          JSON.parse(Buffer.from(importJsonParams.get("payloadBase64"), "base64").toString("utf8")),
          { exportVersion: 1, records: [] });

        assert.throws(
          () => CryptaPlatform.data.records.get("ui-state", "../secret"),
          /normalized local path segment/);
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
  void classpathResource_whenTrustScoreRequested_expectScoreRouteAndQueryParams() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/score"
              && parsed.searchParams.get("subjectKind") === "profile"
              && parsed.searchParams.get("subjectUri") === "USK@alice/profile.json"
              && parsed.searchParams.get("context") === "profile"
              && parsed.searchParams.get("includeEvidence") === "true"
              && options.method === "GET";
          },
          { score: { status: "trusted", score: 42, confidence: 73 } });

        const result = await CryptaPlatform.trust.score({
          subjectKind: "profile",
          subjectUri: "USK@alice/profile.json",
          context: "profile",
          includeEvidence: true
        });

        assert.equal(result.status, "trusted");
        assert.equal(result.score, 42);
        assert.equal(calls.length, 2);
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(calls[1].credentials, "omit");
        """);
  }

  @Test
  void classpathResource_whenTrustStatementPublished_expectAppDocumentDefaults() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-1" });

        const result = await CryptaPlatform.trust.publishStatement({
          insertUri: "USK@trust",
          identifier: "trust-root",
          statement: {
            trustStatement: {
              identity: { identityId: "issuer", publicKeyFingerprint: "fingerprint", appId: "trust-graph" },
              payloadHash: "metadata-wrapper-hash",
              domain: "crypta.trust.statement.v1",
              trustStatement: {
                type: "crypta.trust.statement.v1",
                payload: {
                  issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
                  subject: { kind: "profile", uri: "USK@alice/profile.json" },
                  context: "profile",
                  score: 50,
                  confidence: 80,
                  issuedAt: "2026-05-16T00:00:00Z"
                },
                signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
              }
            }
          },
          contentType: "text/plain",
          targetFilename: "unsafe.json"
        });

        assert.equal(result.requestId, "trust-insert-1");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("insertUri"), "USK@trust");
        assert.equal(params.get("identifier"), "trust-root");
        assert.equal(params.get("contentType"), "application/vnd.crypta.trust+json");
        assert.equal(params.get("targetFilename"), "trust.json");
        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        const document = JSON.parse(documentJson);
        assert.equal(document.type, "crypta.trust.statement.v1");
        assert.equal(document.signature.value, "fixture");
        assert.equal(document.payloadHash, undefined);
        """);
  }

  @Test
  void classpathResource_whenSerializedTrustStatementResponsePublished_expectInnerDocument()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-serialized" });

        const signedResponse = JSON.stringify({
          identity: { identityId: "issuer", publicKeyFingerprint: "fingerprint", appId: "trust-graph" },
          payloadHash: "metadata-wrapper-hash",
          domain: "crypta.trust.statement.v1",
          trustStatement: {
            type: "crypta.trust.statement.v1",
            payload: {
              issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
              subject: { kind: "profile", uri: "USK@alice/profile.json" },
              context: "profile",
              score: 50,
              confidence: 80,
              issuedAt: "2026-05-16T00:00:00Z"
            },
            signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
          }
        });

        const result = await CryptaPlatform.trust.publishStatement({
          insertUri: "USK@trust",
          identifier: "trust-root",
          statement: signedResponse
        });

        assert.equal(result.requestId, "trust-insert-serialized");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("contentType"), "application/vnd.crypta.trust+json");
        assert.equal(params.get("targetFilename"), "trust.json");
        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        const document = JSON.parse(documentJson);
        assert.equal(document.type, "crypta.trust.statement.v1");
        assert.equal(document.signature.value, "fixture");
        assert.equal(document.payloadHash, undefined);
        """);
  }

  @Test
  void classpathResource_whenTrustStatementSigned_expectBoundedVaultRoute() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-vault/identities/trust-id/trust-statement"
              && options.method === "POST";
          },
          { trustStatement: { type: "crypta.trust.statement.v1" } });

        const result = await CryptaPlatform.vault.identities.createTrustStatement("trust-id", {
          subjectKind: "profile",
          subjectUri: "USK@alice/profile.json",
          context: "profile",
          score: 50,
          confidence: 80,
          reason: "known publisher",
          tags: ["local", "preview"],
          expiresAt: "2026-11-16T00:00:00Z"
        });

        assert.equal(result.trustStatement.type, "crypta.trust.statement.v1");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("subjectKind"), "profile");
        assert.equal(params.get("subjectUri"), "USK@alice/profile.json");
        assert.equal(params.get("context"), "profile");
        assert.equal(params.get("score"), "50");
        assert.equal(params.get("confidence"), "80");
        assert.equal(params.get("tags"), "local,preview");
        assert.equal(params.get("expiresAt"), "2026-11-16T00:00:00Z");
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
      "function createContentSubscription(options)",
      "function contentSubscriptionPathSegment(value, description)",
      "\"content/fetch\"",
      "\"content/subscriptions\"",
      "normalizeContentFetchParams(source, format)",
      "normalizeContentSubscriptionCreate(source)",
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

  private static void assertVaultMetadataBrowserHelperFragments(String script) {
    String[] expectedFragments = {
      "function listVaultIdentities(options)",
      "return apiGet(\"app-vault/identities\", options);",
      "function getVaultIdentity(identityId, options)",
      "function listVaultGrants(options)",
      "return apiGet(\"app-vault/grants\", options);",
      "function requestVaultGrant(request, options)",
      "return apiPostForm(\"app-vault/grants/request\"",
      "function normalizeVaultGrantRequest(request)",
      "function createVaultIdentity(options)",
      "return apiPostForm(",
      "\"app-vault/identities\"",
      "function createProfileDocument(identityId, profile, options)",
      "function createTrustStatement(identityIdOrOptions, payload, options)",
      "function normalizeProfileDocument(profile)",
      "function normalizeTrustStatementPayload(source)",
      "copyStringParam(source, params, \"displayName\");",
      "appendTagsParam(source.tags, params);",
      "/profile-document`",
      "function normalizeVaultGrantScope(scope)",
      "normalized !== \"sign.domain-separated\"",
      "identities: Object.freeze({",
      "create: createVaultIdentity",
      "createProfileDocument",
      "createTrustStatement",
      "grants: Object.freeze({"
    };
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          script.contains(expectedFragment),
          () -> "Expected vault helper fragment missing: " + expectedFragment);
    }
  }

  private static void assertNoVaultPrivateBrowserHelpers(String script) {
    String[] forbiddenFragments = {"app-vault/secrets", "useIdentity"};
    for (String forbiddenFragment : forbiddenFragments) {
      assertFalse(
          script.contains(forbiddenFragment),
          () -> "Forbidden vault helper fragment present: " + forbiddenFragment);
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
    const { TextDecoder, TextEncoder } = require("util");

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
      TextDecoder,
      Headers: HeadersImpl,
      btoa: (value) => Buffer.from(value, "binary").toString("base64"),
      atob: (value) => Buffer.from(value, "base64").toString("binary"),
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
