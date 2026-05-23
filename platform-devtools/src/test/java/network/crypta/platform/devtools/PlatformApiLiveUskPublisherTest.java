package network.crypta.platform.devtools;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class PlatformApiLiveUskPublisherTest {
  private static final byte[] CATALOG_BYTES = "catalog bytes".getBytes(StandardCharsets.UTF_8);
  private static final byte[] SIGNATURE_BYTES = "signature bytes".getBytes(StandardCharsets.UTF_8);

  @TempDir private Path tempDir;

  @Test
  void publish_whenCatalogFetchResolvesEdition_expectSignatureFetchedFromResolvedSibling()
      throws Exception {
    ArrayList<String> fetchedUris = new ArrayList<>();
    AtomicInteger fetchCount = new AtomicInteger();
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/api/v1/queue/inserts/directory",
        exchange -> sendJson(exchange, 201, "{\"outcome\":\"STARTED\"}"));
    server.createContext(
        "/api/v1/content/fetch",
        exchange ->
            handleFetch(
                exchange,
                fetchedUris,
                fetchCount,
                "USK@PUBLIC/catalog/42/cryptad-app-catalog.properties"));
    server.start();
    try {
      PlatformApiLiveUskPublisher publisher = new PlatformApiLiveUskPublisher();
      URI nodeBaseUrl = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1");
      LiveUskPublishRequest request = requestWithLiveFetchVerification(nodeBaseUrl);

      LiveUskPublishResponse response = publisher.publish(request);

      assertEquals("queued", response.catalogInsertStatus());
      assertEquals("queued", response.signatureInsertStatus());
      assertEquals("verified", response.postPublishVerificationStatus());
      assertEquals(
          Optional.of("crypta:USK@PUBLIC/catalog/42/cryptad-app-catalog.properties"),
          response.resolvedCatalogSource());
      assertEquals(
          List.of(
              "crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.properties",
              "crypta:USK@PUBLIC/catalog/42/cryptad-app-catalog.signature"),
          fetchedUris);
    } finally {
      server.stop(0);
    }
  }

  @Test
  void publish_whenResolvedUriIsUnsafe_expectSignatureFetchedFromOriginalSibling()
      throws Exception {
    ArrayList<String> fetchedUris = new ArrayList<>();
    AtomicInteger fetchCount = new AtomicInteger();
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/api/v1/queue/inserts/directory",
        exchange -> sendJson(exchange, 201, "{\"outcome\":\"STARTED\"}"));
    server.createContext(
        "/api/v1/content/fetch",
        exchange ->
            handleFetch(
                exchange,
                fetchedUris,
                fetchCount,
                "USK@PUBLIC/catalog/42/cryptad-app-catalog.properties?edition=42"));
    server.start();
    try {
      PlatformApiLiveUskPublisher publisher = new PlatformApiLiveUskPublisher();
      URI nodeBaseUrl = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1");

      LiveUskPublishResponse response =
          publisher.publish(requestWithLiveFetchVerification(nodeBaseUrl));

      assertEquals(Optional.empty(), response.resolvedCatalogSource());
      assertEquals(
          List.of(
              "crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.properties",
              "crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.signature"),
          fetchedUris);
    } finally {
      server.stop(0);
    }
  }

  @Test
  void publish_whenQueueOutcomeIsNotStarted_expectSanitizedFailure() throws Exception {
    LinkedHashMap<String, String> queueForm = new LinkedHashMap<>();
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/api/v1/queue/inserts/directory",
        exchange -> {
          queueForm.putAll(readForm(exchange));
          sendJson(exchange, 200, "{\"outcome\":\"FAILED\",\"message\":\"ignored secret body\"}");
        });
    server.start();
    try {
      PlatformApiLiveUskPublisher publisher = new PlatformApiLiveUskPublisher();
      URI nodeBaseUrl = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
      LiveUskPublishRequest request =
          LiveUskPublishRequest.builder()
              .nodeBaseUrl(nodeBaseUrl)
              .formPassword("redacted-form-password")
              .privateInsertUri("redacted-insert-uri")
              .stagingDirectory(tempDir)
              .identifier("cryptad-catalog-dev")
              .publicCatalogSource("crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.properties")
              .publicSignatureSource("crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.signature")
              .catalogBytes(CATALOG_BYTES)
              .signatureBytes(SIGNATURE_BYTES)
              .verifyLiveFetch(false)
              .build();

      AppDistributionException exception =
          assertThrows(AppDistributionException.class, () -> publisher.publish(request));

      assertEquals(
          "live_publish_failed: node did not start catalog USK insert", exception.getMessage());
      assertEquals("redacted-form-password", queueForm.get("formPassword"));
      assertEquals("redacted-insert-uri", queueForm.get("insertUri"));
      assertEquals(tempDir.toString(), queueForm.get("sourcePath"));
      assertFalse(exception.getMessage().contains("redacted-form-password"));
      assertFalse(exception.getMessage().contains("redacted-insert-uri"));
      assertFalse(exception.getMessage().contains(tempDir.toString()));
    } finally {
      server.stop(0);
    }
  }

  private static void handleFetch(
      HttpExchange exchange, List<String> fetchedUris, AtomicInteger fetchCount, String resolvedUri)
      throws IOException {
    Map<String, String> form = readForm(exchange);
    fetchedUris.add(form.get("uri"));
    if (fetchCount.getAndIncrement() == 0) {
      sendJson(
          exchange,
          200,
          "{\"contentBase64\":\"%s\",\"resolvedUri\":\"%s\"}"
              .formatted(Base64.getEncoder().encodeToString(CATALOG_BYTES), resolvedUri));
      return;
    }
    sendJson(
        exchange,
        200,
        "{\"contentBase64\":\"%s\"}"
            .formatted(Base64.getEncoder().encodeToString(SIGNATURE_BYTES)));
  }

  private static LiveUskPublishRequest requestWithLiveFetchVerification(URI nodeBaseUrl) {
    return LiveUskPublishRequest.builder()
        .nodeBaseUrl(nodeBaseUrl)
        .formPassword("form-password")
        .privateInsertUri("redacted-insert-uri")
        .stagingDirectory(Path.of("redacted-staging"))
        .identifier("cryptad-catalog-dev")
        .publicCatalogSource("crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.properties")
        .publicSignatureSource("crypta:USK@PUBLIC/catalog/-1/cryptad-app-catalog.signature")
        .catalogBytes(CATALOG_BYTES)
        .signatureBytes(SIGNATURE_BYTES)
        .verifyLiveFetch(true)
        .build();
  }

  private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    LinkedHashMap<String, String> form = new LinkedHashMap<>();
    int start = 0;
    while (start <= body.length()) {
      int ampersand = body.indexOf('&', start);
      int end = ampersand < 0 ? body.length() : ampersand;
      if (end > start) {
        addFormPair(form, body.substring(start, end));
      }
      if (ampersand < 0) {
        break;
      }
      start = ampersand + 1;
    }
    return form;
  }

  private static void addFormPair(Map<String, String> form, String pair) {
    int equals = pair.indexOf('=');
    String name = equals < 0 ? pair : pair.substring(0, equals);
    String value = equals < 0 ? "" : pair.substring(equals + 1);
    form.put(
        URLDecoder.decode(name, StandardCharsets.UTF_8),
        URLDecoder.decode(value, StandardCharsets.UTF_8));
  }

  private static void sendJson(HttpExchange exchange, int statusCode, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream outputStream = exchange.getResponseBody()) {
      outputStream.write(bytes);
    }
  }
}
