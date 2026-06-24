package network.crypta.platform.devtools.devserver;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Deterministic mock Platform API used by {@code crypta-app dev} and app tests.
 *
 * <p>The handler implements the small Platform API subset needed by scaffold templates and offline
 * smoke tests: node metadata, Platform API contract metadata, queue reads and mutations, content
 * insert requests, app-vault identity/grant examples, and current-app metadata. Every endpoint
 * requires the {@code X-Crypta-App-Session} header value issued by the dev bootstrap response,
 * which keeps local examples aligned with the browser SDK's production calling convention.
 *
 * <p>This is not a daemon simulator. Responses are deterministic JSON fixtures or simple mutation
 * acknowledgements, and no request reaches FCP, a live node, disk-backed queue state, or real vault
 * identity material. Form validation is intentionally limited to fields that live Platform API
 * handlers require from the generated templates.
 */
final class MockPlatformApi {
  /** Browser-session header required by all mock API endpoints. */
  static final String SESSION_HEADER = "X-Crypta-App-Session";

  private static final String INSERT_URI_FIELD = "insertUri";
  private static final String IDENTIFIER_FIELD = "identifier";
  private static final String APP_VAULT_IDENTITIES_PREFIX = "/app-vault/identities/";

  /** Validator supplied by the dev server's browser-session issuer. */
  private final Predicate<String> sessionValidator;

  /** Fixture source for deterministic JSON responses. */
  private final MockPlatformApiFixtures fixtures;

  /**
   * Creates a mock API handler.
   *
   * @param sessionValidator predicate that accepts the current non-expired browser-session token
   * @param fixtures fixture provider for read endpoints and mutation acknowledgements
   */
  MockPlatformApi(Predicate<String> sessionValidator, MockPlatformApiFixtures fixtures) {
    this.sessionValidator = sessionValidator;
    this.fixtures = fixtures;
  }

  /**
   * Handles one request under {@code /api/v1/}.
   *
   * @param exchange incoming JDK HTTP exchange
   * @throws IOException if fixture loading or response writing fails
   */
  void handle(HttpExchange exchange) throws IOException {
    if (!sessionValid(exchange)) {
      sendJson(
          exchange,
          401,
          """
          {"error":{"code":"invalid_app_browser_session","message":"Invalid app browser session."}}
          """);
      return;
    }
    String method = exchange.getRequestMethod();
    String path = exchange.getRequestURI().getRawPath();
    String suffix = path.substring("/api/v1".length());
    try {
      route(exchange, method, suffix);
    } catch (UnsupportedOperationException _) {
      sendJson(
          exchange,
          404,
          "{\"error\":{\"code\":\"mock_endpoint_not_found\",\"message\":\"Mock endpoint not"
              + " found.\"}}");
    }
  }

  /**
   * Checks whether the request carries a valid mock browser session header.
   *
   * @param exchange incoming API request
   * @return {@code true} when any header value matches the current non-expired session
   */
  private boolean sessionValid(HttpExchange exchange) {
    List<String> values = exchange.getRequestHeaders().get(SESSION_HEADER);
    return values != null && values.stream().anyMatch(value -> sessionValidator.test(value.trim()));
  }

  /**
   * Routes one authorized mock API request.
   *
   * @param exchange authorized incoming request
   * @param method HTTP method from the exchange
   * @param suffix raw path suffix after {@code /api/v1}
   * @throws IOException if a fixture or response cannot be written
   */
  private void route(HttpExchange exchange, String method, String suffix) throws IOException {
    switch (method) {
      case "GET" -> routeGet(exchange, suffix);
      case "POST" -> routePost(exchange, suffix);
      case "DELETE" -> routeDelete(exchange, suffix);
      default -> throw new UnsupportedOperationException(suffix);
    }
  }

  private void routeGet(HttpExchange exchange, String suffix) throws IOException {
    if (suffix.equals("/node") || suffix.equals("/node/greeting")) {
      sendJson(exchange, 200, fixtures.node());
    } else if (suffix.equals("/queue")) {
      sendJson(exchange, 200, fixtures.queue());
    } else if (suffix.equals("/app-vault/identities")) {
      sendJson(exchange, 200, fixtures.vaultIdentities());
    } else if (suffix.matches("/app-vault/identities/[^/]+")) {
      sendJson(exchange, 200, oneIdentity(suffix.substring(APP_VAULT_IDENTITIES_PREFIX.length())));
    } else if (suffix.equals("/app-vault/grants")) {
      sendJson(exchange, 200, fixtures.vaultGrants());
    } else if (suffix.equals("/apps/current")) {
      sendJson(exchange, 200, fixtures.appsCurrent());
    } else if (suffix.equals("/platform/contract")) {
      sendJson(exchange, 200, fixtures.platformContract());
    } else if (suffix.equals("/content/subscriptions")) {
      sendJson(exchange, 200, fixtures.contentSubscriptions());
    } else if (suffix.matches("/content/subscriptions/[^/]+")) {
      sendJson(exchange, 200, fixtures.contentSubscription());
    } else if (suffix.equals("/trust-graph/status")) {
      sendJson(exchange, 200, fixtures.trustGraphStatus());
    } else if (suffix.equals("/trust-graph/anchors")) {
      sendJson(exchange, 200, fixtures.trustGraphAnchors());
    } else if (suffix.equals("/trust-graph/audit")) {
      sendJson(exchange, 200, fixtures.trustGraphAudit());
    } else if (suffix.equals("/trust-graph/score")) {
      sendJson(exchange, 200, fixtures.trustGraphScore());
    } else {
      throw new UnsupportedOperationException(suffix);
    }
  }

  private void routePost(HttpExchange exchange, String suffix) throws IOException {
    if (suffix.startsWith("/queue/")) {
      routeQueuePost(exchange, suffix);
    } else if (suffix.equals("/content/fetch")) {
      routeContentFetchPost(exchange);
    } else if (suffix.equals("/content/subscriptions")) {
      sendFormMutation(exchange, "content.subscriptions.create", "uri");
    } else if (suffix.matches("/content/subscriptions/[^/]+/(refresh|pause|resume)")) {
      sendJson(exchange, 200, fixtures.mutation("content.subscriptions.update"));
    } else if (suffix.equals("/app-vault/identities")) {
      sendJson(exchange, 201, MockPlatformApiFixtures.CREATED_IDENTITY_RESPONSE);
    } else if (suffix.matches("/app-vault/identities/[^/]+/profile-document")) {
      routeProfileDocumentPost(exchange, suffix);
    } else if (suffix.matches("/app-vault/identities/[^/]+/trust-statement")) {
      routeTrustStatementPost(exchange, suffix);
    } else if (suffix.matches("/app-vault/identities/[^/]+/social-message")) {
      routeSocialMessagePost(exchange, suffix);
    } else if (suffix.equals("/app-vault/grants/request")) {
      sendJson(exchange, 200, fixtures.mutation("app-vault.grants.request"));
    } else if (suffix.equals("/trust-graph/anchors")) {
      sendFormMutation(exchange, "trust-graph.anchors.add", "issuerFingerprint");
    } else if (suffix.equals("/trust-graph/import")) {
      routeTrustImportPost(exchange, "document");
    } else if (suffix.equals("/trust-graph/import-uri")) {
      routeTrustImportPost(exchange, "uri");
    } else {
      throw new UnsupportedOperationException(suffix);
    }
  }

  private void routeContentFetchPost(HttpExchange exchange) throws IOException {
    if (hasRequiredFormFields(exchange, "uri")) {
      sendJson(exchange, 200, MockPlatformApiFixtures.CONTENT_FETCH_TRUST_STATEMENT_RESPONSE);
    }
  }

  private void routeTrustImportPost(HttpExchange exchange, String requiredField)
      throws IOException {
    if (hasRequiredFormFields(exchange, requiredField)) {
      sendJson(exchange, 200, MockPlatformApiFixtures.TRUST_GRAPH_IMPORT_RESPONSE);
    }
  }

  private void routeDelete(HttpExchange exchange, String suffix) throws IOException {
    if (suffix.matches("/trust-graph/anchors/[^/]+")) {
      sendJson(exchange, 200, fixtures.mutation("trust-graph.anchors.remove"));
      return;
    }
    if (suffix.matches("/content/subscriptions/[^/]+")) {
      sendJson(exchange, 200, fixtures.mutation("content.subscriptions.remove"));
      return;
    }
    throw new UnsupportedOperationException(suffix);
  }

  private void routeProfileDocumentPost(HttpExchange exchange, String suffix) throws IOException {
    if (hasRequiredFormFields(exchange, "displayName")) {
      int prefixLength = APP_VAULT_IDENTITIES_PREFIX.length();
      int suffixLength = "/profile-document".length();
      String identityId = suffix.substring(prefixLength, suffix.length() - suffixLength);
      sendJson(exchange, 200, fixtures.profileDocument(identityId));
    }
  }

  private void routeTrustStatementPost(HttpExchange exchange, String suffix) throws IOException {
    if (hasRequiredFormFields(
        exchange, "subjectKind", "subjectUri", "context", "score", "confidence")) {
      int prefixLength = APP_VAULT_IDENTITIES_PREFIX.length();
      int suffixLength = "/trust-statement".length();
      String identityId = suffix.substring(prefixLength, suffix.length() - suffixLength);
      sendJson(exchange, 200, fixtures.trustStatement(identityId));
    }
  }

  private void routeSocialMessagePost(HttpExchange exchange, String suffix) throws IOException {
    if (hasRequiredFormFields(exchange, "body")) {
      int prefixLength = APP_VAULT_IDENTITIES_PREFIX.length();
      int suffixLength = "/social-message".length();
      String identityId = suffix.substring(prefixLength, suffix.length() - suffixLength);
      sendJson(exchange, 200, fixtures.socialMessage(identityId));
    }
  }

  private void routeQueuePost(HttpExchange exchange, String suffix) throws IOException {
    switch (suffix) {
      case "/queue/downloads" ->
          sendJson(exchange, 200, fixtures.mutation("queue.downloads.create"));
      case "/queue/inserts/file" ->
          sendFormMutation(
              exchange, "queue.inserts.file", "sourcePath", INSERT_URI_FIELD, IDENTIFIER_FIELD);
      case "/queue/inserts/directory" ->
          sendFormMutation(
              exchange,
              "queue.inserts.directory",
              "sourcePath",
              INSERT_URI_FIELD,
              IDENTIFIER_FIELD);
      case "/queue/inserts/app-document" -> sendAppDocumentInsert(exchange);
      case "/queue/requests/remove" ->
          sendJson(exchange, 200, fixtures.mutation("queue.requests.remove"));
      case "/queue/requests/restart" ->
          sendJson(exchange, 200, fixtures.mutation("queue.requests.restart"));
      case "/queue/requests/priority" ->
          sendFormMutation(exchange, "queue.requests.priority", IDENTIFIER_FIELD, "priority");
      default -> routeQueueItemMutation(exchange, suffix);
    }
  }

  private void sendAppDocumentInsert(HttpExchange exchange) throws IOException {
    if (hasRequiredFormFields(exchange, INSERT_URI_FIELD, IDENTIFIER_FIELD, "documentBase64")) {
      sendJson(exchange, 200, MockPlatformApiFixtures.APP_DOCUMENT_INSERT_RESPONSE);
    }
  }

  private void routeQueueItemMutation(HttpExchange exchange, String suffix) throws IOException {
    if (!suffix.matches("/queue/[^/]+/(cancel|restart|priority)")) {
      throw new UnsupportedOperationException(suffix);
    }
    sendJson(exchange, 200, fixtures.mutation(suffix.substring(1).replace('/', '.')));
  }

  private void sendFormMutation(HttpExchange exchange, String mutation, String... fieldNames)
      throws IOException {
    if (hasRequiredFormFields(exchange, fieldNames)) {
      sendJson(exchange, 200, fixtures.mutation(mutation));
    }
  }

  /**
   * Confirms that a form mutation contains required fields.
   *
   * <p>When a field is missing, this method sends the same deterministic {@code 400} response the
   * live Platform API would surface through the SDK error path.
   *
   * @param exchange mutation request whose body contains form data
   * @param fieldNames required form field names for the endpoint
   * @return {@code true} when the request can proceed
   * @throws IOException if the request body or rejection response cannot be processed
   */
  private static boolean hasRequiredFormFields(HttpExchange exchange, String... fieldNames)
      throws IOException {
    Map<String, List<String>> form = readForm(exchange);
    for (String fieldName : fieldNames) {
      if (!hasNonBlankValue(form, fieldName)) {
        sendJson(
            exchange,
            400,
            "{\"error\":{\"code\":\"invalid_mock_form\",\"message\":\"Missing required form field '"
                + MockPlatformApiFixtures.Json.escape(fieldName)
                + "'.\"}}");
        return false;
      }
    }
    return true;
  }

  /**
   * Parses an {@code application/x-www-form-urlencoded}-style body into ordered field values.
   *
   * @param exchange request containing the mutation body
   * @return ordered map of decoded field names to decoded field values
   * @throws IOException if the request body cannot be read
   */
  private static Map<String, List<String>> readForm(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    LinkedHashMap<String, List<String>> form = new LinkedHashMap<>();
    if (body.isBlank()) {
      return form;
    }
    for (String pair : body.split("&", -1)) {
      if (pair.isEmpty()) {
        continue;
      }
      int separator = pair.indexOf('=');
      String key = decodeFormComponent(separator < 0 ? pair : pair.substring(0, separator));
      String value = separator < 0 ? "" : decodeFormComponent(pair.substring(separator + 1));
      form.computeIfAbsent(key, ignored -> new ArrayList<>()).add(value);
    }
    return form;
  }

  /**
   * Decodes one URL-encoded form component using UTF-8.
   *
   * @param value raw form key or value component
   * @return decoded component text
   */
  private static String decodeFormComponent(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  /**
   * Checks whether a parsed form contains a non-blank value for a field.
   *
   * @param form parsed form data
   * @param fieldName field name to inspect
   * @return {@code true} when at least one submitted value is non-blank
   */
  private static boolean hasNonBlankValue(Map<String, List<String>> form, String fieldName) {
    List<String> values = form.get(fieldName);
    return values != null && values.stream().anyMatch(value -> !value.isBlank());
  }

  /**
   * Builds a deterministic single-identity response for an app-vault identity route.
   *
   * @param identityId decoded identity id suffix from the request route
   * @return compact JSON object for the requested mock identity
   */
  private static String oneIdentity(String identityId) {
    return "{\"id\":\""
        + MockPlatformApiFixtures.Json.escape(identityId)
        + "\",\"identityId\":\""
        + MockPlatformApiFixtures.Json.escape(identityId)
        + "\",\"label\":\"Local Profile\",\"displayName\":\"Local"
        + " Profile\",\"kind\":\"mock\",\"status\":\"available\",\"usageScopes\":[\"metadata.read\",\"sign.domain-separated\"]}";
  }

  /**
   * Sends a JSON response with conservative cache headers.
   *
   * @param exchange request to complete
   * @param status HTTP response status code
   * @param json JSON text to strip and send as UTF-8
   * @throws IOException if response headers or body cannot be written
   */
  static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
    byte[] bytes = json.strip().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
    exchange.getResponseHeaders().set("Cache-Control", "no-store");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream body = exchange.getResponseBody()) {
      body.write(bytes);
    }
  }
}
