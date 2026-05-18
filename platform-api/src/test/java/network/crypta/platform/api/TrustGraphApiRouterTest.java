package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
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

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, queryParameters, principal);
  }

  private static RuntimePorts runtimePorts() {
    return mock(
        RuntimePorts.class,
        invocation -> {
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
