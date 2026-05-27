package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.trustgraph.InMemoryTrustGraphStore;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
class TrustGraphApiRouterTest {
  private static final String APP_ID = "trust-reader";

  @Test
  void route_whenAppHasTrustRead_expectStatusAllowed() {
    PlatformApiResponse response =
        router()
            .route(
                request(
                    "GET",
                    List.of("trust-graph", "status"),
                    Map.of(),
                    PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"service\":\"trust-graph-preview\""));
    assertTrue(response.body().contains("\"completeWot\":false"));
  }

  @Test
  void route_whenAppLacksTrustRead_expectForbiddenBeforeHandler() {
    PlatformApiResponse response =
        router()
            .route(
                request(
                    "GET",
                    List.of("trust-graph", "score"),
                    Map.of(
                        "subjectKind",
                        List.of("profile"),
                        "subjectUri",
                        List.of("USK@example/subject/profile.json"),
                        "context",
                        List.of("profile")),
                    PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("queue.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void
      route_whenWriterImportsUnverifiedStatementAndAnchors_expectReaderSeesNonContributingEvidence() {
    PlatformApiRouter router = router();
    PlatformApiResponse importResponse =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of(validStatement()), "sourceLabel", List.of("fixture")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"))));
    PlatformApiResponse anchorResponse =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "anchors"),
                Map.of(
                    "issuerFingerprint",
                    List.of("fingerprint-1"),
                    "label",
                    List.of("Alice"),
                    "source",
                    List.of("manual")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"))));

    PlatformApiResponse scoreResponse =
        router.route(
            request(
                "GET",
                List.of("trust-graph", "score"),
                Map.of(
                    "subjectKind",
                    List.of("profile"),
                    "subjectUri",
                    List.of("USK@example/subject/profile.json"),
                    "context",
                    List.of("profile"),
                    "includeEvidence",
                    List.of("true")),
                PlatformApiPrincipal.appBrowserSession("other-reader", List.of("trust.read"))));

    assertEquals(200, importResponse.statusCode());
    assertTrue(importResponse.body().contains("\"imported\":true"));
    assertTrue(importResponse.body().contains("\"signatureVerified\":false"));
    assertFalse(importResponse.body().contains("signature-value"));
    assertEquals(201, anchorResponse.statusCode());
    assertEquals(200, scoreResponse.statusCode());
    assertTrue(scoreResponse.body().contains("\"status\":\"unknown\""));
    assertTrue(scoreResponse.body().contains("\"contributing\":false"));
    assertTrue(scoreResponse.body().contains("\"signatureVerified\":false"));
    assertFalse(scoreResponse.body().contains("signature-value"));
  }

  @Test
  void route_whenImportDocumentMalformedOrOversized_expectBadRequest() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal principal =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));

    PlatformApiResponse malformed =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of("{\"type\":\"wrong\"}")),
                principal));
    PlatformApiResponse oversized =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of("x".repeat(65 * 1024))),
                principal));

    assertEquals(400, malformed.statusCode());
    assertTrue(malformed.body().contains("invalid_trust_statement"));
    assertEquals(400, oversized.statusCode());
    assertTrue(oversized.body().contains("trust_statement_too_large"));
  }

  @Test
  void route_whenAuditReadAfterImport_expectRedactedAuditEvents() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal writer =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));
    PlatformApiPrincipal reader =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"));

    router.route(
        request(
            "POST",
            List.of("trust-graph", "import"),
            Map.of("document", List.of(validStatement()), "sourceUri", List.of("CHK@statement")),
            writer));
    PlatformApiResponse audit =
        router.route(request("GET", List.of("trust-graph", "audit"), Map.of(), reader));

    assertEquals(200, audit.statusCode());
    assertTrue(audit.body().contains("\"eventType\":\"statement_imported\""));
    assertTrue(audit.body().contains("\"documentFingerprint\""));
    assertTrue(audit.body().contains("\"sourceUriHash\""));
    assertFalse(audit.body().contains("signature-value"));
    assertFalse(audit.body().contains("\"sourceUri\":\"CHK@statement\""));
  }

  @Test
  void route_whenImportSourceClaimsLocalPublish_expectAuditRemainsImportEvent() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal writer =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));
    PlatformApiPrincipal reader =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"));

    router.route(
        request(
            "POST",
            List.of("trust-graph", "import"),
            Map.of("document", List.of(validStatement()), "source", List.of("local-publish")),
            writer));
    PlatformApiResponse audit =
        router.route(request("GET", List.of("trust-graph", "audit"), Map.of(), reader));

    assertEquals(200, audit.statusCode());
    assertTrue(audit.body().contains("\"eventType\":\"statement_imported\""));
    assertTrue(audit.body().contains("\"source\":\"local-publish\""));
    assertFalse(audit.body().contains("statement_published_queued"));
  }

  @Test
  void route_whenImportSourceContainsUnsafeRequestText_expectAuditUsesSafeSource() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal writer =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));
    PlatformApiPrincipal reader =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"));
    String requestSource = "/tmp/CRYPTAD_APP_TOKEN";

    PlatformApiResponse imported =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of("document", List.of(validStatement()), "source", List.of(requestSource)),
                writer));
    PlatformApiResponse audit =
        router.route(request("GET", List.of("trust-graph", "audit"), Map.of(), reader));

    assertEquals(200, imported.statusCode());
    assertTrue(imported.body().contains("\"source\":\"local-import\""));
    assertFalse(imported.body().contains(requestSource));
    assertEquals(200, audit.statusCode());
    assertTrue(audit.body().contains("\"source\":\"local-import\""));
    assertFalse(audit.body().contains(requestSource));
  }

  @Test
  void route_whenRejectedImportSourceUriHasUnknownPrefix_expectAuditUsesGenericUriSummary() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal writer =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));
    PlatformApiPrincipal reader =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"));
    String unsafeSourceUri = "token@secret-material";

    PlatformApiResponse imported =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of(
                    "document", List.of(validStatement()), "sourceUri", List.of(unsafeSourceUri)),
                writer));
    PlatformApiResponse audit =
        router.route(request("GET", List.of("trust-graph", "audit"), Map.of(), reader));

    assertEquals(400, imported.statusCode());
    assertTrue(imported.body().contains("invalid_trust_statement"));
    assertEquals(200, audit.statusCode());
    assertTrue(audit.body().contains("\"eventType\":\"statement_import_rejected\""));
    assertTrue(audit.body().contains("\"sourceSummary\":\"uri:sha256:"));
    assertFalse(audit.body().contains("\"sourceSummary\":\"token:sha256:"));
    assertFalse(audit.body().contains(unsafeSourceUri));
    assertFalse(audit.body().contains("secret-material"));
  }

  @Test
  void route_whenRejectedImportSourceUriHasCryptaKeyPrefix_expectAuditKeepsOnlyKnownFamily() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal writer =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));
    PlatformApiPrincipal reader =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"));
    String wrappedSourceUri = "crypta:USK@statement";

    PlatformApiResponse imported =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import"),
                Map.of(
                    "document",
                    List.of("{\"type\":\"wrong\"}"),
                    "sourceUri",
                    List.of(wrappedSourceUri)),
                writer));
    PlatformApiResponse audit =
        router.route(request("GET", List.of("trust-graph", "audit"), Map.of(), reader));

    assertEquals(400, imported.statusCode());
    assertEquals(200, audit.statusCode());
    assertTrue(audit.body().contains("\"sourceSummary\":\"crypta_USK:sha256:"));
    assertFalse(audit.body().contains(wrappedSourceUri));
    assertFalse(audit.body().contains("USK@statement"));
  }

  @Test
  void route_whenImportUriHasContentFetchCapability_expectFetchedStatementImported() {
    ContentFetchPort fetchPort =
        request ->
            new BoundedContentFetchResult(
                validStatement().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                request.uri(),
                request.uri(),
                "ok");
    PlatformApiRouter router = router(fetchPort, new TrustGraphApiHandler());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-uri"),
                Map.of("uri", List.of("CHK@statement"), "sourceLabel", List.of("fixture")),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of("trust.write", "content.fetch"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"source\":\"content-fetch\""));
    assertTrue(response.body().contains("\"sourceUri\":\"CHK@sha256:"));
    assertTrue(response.body().contains("\"sourceUriHash\""));
    assertFalse(response.body().contains("CHK@statement"));
    assertFalse(response.body().contains("signature-value"));
  }

  @Test
  void route_whenImportUriLacksContentFetchCapability_expectForbiddenBeforeHandler() {
    PlatformApiResponse response =
        router()
            .route(
                request(
                    "POST",
                    List.of("trust-graph", "import-uri"),
                    Map.of("uri", List.of("CHK@statement")),
                    PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("forbidden"));
  }

  @Test
  void route_whenImportUriMaxBytesInvalid_expectBadRequestBeforeFetch() {
    AtomicBoolean fetchCalled = new AtomicBoolean(false);
    ContentFetchPort fetchPort =
        request -> {
          fetchCalled.set(true);
          return new BoundedContentFetchResult(new byte[0], request.uri(), request.uri(), "ok");
        };
    PlatformApiRouter router = router(fetchPort, new TrustGraphApiHandler());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-uri"),
                Map.of("uri", List.of("CHK@statement"), "maxBytes", List.of("0")),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of("trust.write", "content.fetch"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_query_parameter"));
    assertFalse(fetchCalled.get());
  }

  @Test
  void route_whenImportUriMaxBytesExceedsTrustLimit_expectBadRequestBeforeFetch() {
    AtomicBoolean fetchCalled = new AtomicBoolean(false);
    ContentFetchPort fetchPort =
        request -> {
          fetchCalled.set(true);
          return new BoundedContentFetchResult(new byte[0], request.uri(), request.uri(), "ok");
        };
    PlatformApiRouter router = router(fetchPort, new TrustGraphApiHandler());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "import-uri"),
                Map.of("uri", List.of("CHK@statement"), "maxBytes", List.of("65537")),
                PlatformApiPrincipal.appBrowserSession(
                    APP_ID, List.of("trust.write", "content.fetch"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_query_parameter"));
    assertFalse(fetchCalled.get());
  }

  @Test
  void route_whenImportUriFetchServiceUnavailable_expectServiceUnavailable() {
    PlatformApiResponse response =
        router()
            .route(
                request(
                    "POST",
                    List.of("trust-graph", "import-uri"),
                    Map.of("uri", List.of("CHK@statement")),
                    PlatformApiPrincipal.appBrowserSession(
                        APP_ID, List.of("trust.write", "content.fetch"))));

    assertEquals(503, response.statusCode());
    assertTrue(response.body().contains("content_fetch_failed"));
  }

  @Test
  void route_whenAuditLimitInvalid_expectBadRequest() {
    PlatformApiResponse response =
        router()
            .route(
                request(
                    "GET",
                    List.of("trust-graph", "audit"),
                    Map.of("limit", List.of("0")),
                    PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("invalid_query_parameter"));
  }

  @Test
  void route_whenSharedTrustGraphHandlerInjected_expectStateSharedByRouter() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore();
    PlatformApiRouter router =
        router(null, new TrustGraphApiHandler(store, java.time.Clock.systemUTC()));
    store.addAnchor("fingerprint-shared", "Shared", "test");

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("trust-graph", "anchors"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("fingerprint-shared"));
  }

  @Test
  void route_whenInjectedTrustGraphHandlerUnavailable_expectServiceUnavailableNotInternalError() {
    PlatformApiRouter router = router(null, TrustGraphApiHandler.unavailable());

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of("trust-graph", "status"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.read"))));

    assertEquals(503, response.statusCode());
    assertTrue(response.body().contains("trust_graph_store_unavailable"));
    assertFalse(response.body().contains("internal_error"));
  }

  @Test
  void route_whenAnchorFieldsAreInvalid_expectBadRequest() {
    PlatformApiRouter router = router();
    PlatformApiPrincipal principal =
        PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"));

    PlatformApiResponse overlong =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "anchors"),
                Map.of("issuerFingerprint", List.of("x".repeat(129))),
                principal));
    PlatformApiResponse invalidDelete =
        router.route(
            request(
                "DELETE", List.of("trust-graph", "anchors", "x".repeat(129)), Map.of(), principal));

    assertEquals(400, overlong.statusCode());
    assertTrue(overlong.body().contains("invalid_trust_statement"));
    assertFalse(overlong.body().contains("internal_error"));
    assertEquals(400, invalidDelete.statusCode());
    assertTrue(invalidDelete.body().contains("invalid_trust_statement"));
    assertFalse(invalidDelete.body().contains("internal_error"));
  }

  private static PlatformApiRouter router() {
    return new PlatformApiRouter(runtimePorts());
  }

  private static PlatformApiRouter router(
      ContentFetchPort contentFetchPort, TrustGraphApiHandler trustGraphApiHandler) {
    return new PlatformApiRouter(
        runtimePorts(contentFetchPort),
        null,
        null,
        null,
        AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.of(null, null, null, null, trustGraphApiHandler));
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, queryParameters, principal);
  }

  private static RuntimePorts runtimePorts() {
    return runtimePorts(null);
  }

  private static RuntimePorts runtimePorts(ContentFetchPort contentFetchPort) {
    return mock(
        RuntimePorts.class,
        invocation -> {
          if ("contentFetch".equals(invocation.getMethod().getName())) {
            return contentFetchPort;
          }
          Object defaultValue = Answers.RETURNS_DEFAULTS.answer(invocation);
          if (defaultValue != null || invocation.getMethod().getReturnType().isPrimitive()) {
            return defaultValue;
          }
          Class<?> returnType = invocation.getMethod().getReturnType();
          return returnType.isInterface() ? mock(returnType) : null;
        });
  }

  private static String validStatement() {
    return """
    {
      "type": "crypta.trust.statement.v1",
      "payload": {
        "issuer": {
          "identityId": "issuer-1",
          "publicKeyFingerprint": "fingerprint-1",
          "profileUri": "USK@example/profile.json"
        },
        "subject": {
          "kind": "profile",
          "uri": "USK@example/subject/profile.json"
        },
        "context": "profile",
        "score": 50,
        "confidence": 80,
        "reason": "known publisher",
        "tags": ["example"],
        "issuedAt": "2026-05-16T00:00:00Z"
      },
      "signature": {
        "algorithm": "app-vault-ed25519-preview",
        "domain": "crypta.trust.statement.v1",
        "value": "signature-value"
      }
    }
    """;
  }
}
