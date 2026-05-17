package network.crypta.platform.api.content;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ContentApiHandlerTest {
  @Test
  void fetch_whenValidCryptaUri_expectDefaultsAndTextResponse() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    "hello".getBytes(StandardCharsets.UTF_8),
                    request.uri(),
                    "USK@site/doc/2",
                    "token /tmp/raw-content"));

    Map<String, Object> result =
        new ContentApiHandler(port).fetch(Map.of("uri", List.of("crypta:USK@site/doc/1")));

    assertEquals("crypta:USK@site/doc/1", result.get("requestedUri"));
    assertEquals("USK@site/doc/2", result.get("resolvedUri"));
    assertEquals(5, result.get("bytesLength"));
    assertEquals("text", result.get("format"));
    assertEquals("hello", result.get("contentText"));
    assertNull(result.get("contentBase64"));
    assertEquals("Fetched 5 bytes", result.get("statusMessage"));
    assertEquals("USK@site/doc/1", port.lastRequest.uri());
    assertEquals(262_144L, port.lastRequest.maxBytes());
    assertEquals(Duration.ofSeconds(30), port.lastRequest.timeout());
    assertEquals("reference-app", port.lastRequest.purpose());
  }

  @Test
  void fetch_whenBase64Requested_expectBase64Response() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    new byte[] {(byte) 0xff, 0x00}, request.uri(), null, null));

    Map<String, Object> result =
        new ContentApiHandler(port)
            .fetch(Map.of("uri", List.of("CHK@binary-content"), "format", List.of("base64")));

    assertEquals("base64", result.get("format"));
    assertEquals("/wA=", result.get("contentBase64"));
    assertNull(result.get("contentText"));
  }

  @Test
  void fetch_whenRuntimeReturnsMoreBytesThanRequested_expectTooLargeError() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    "too large".getBytes(StandardCharsets.UTF_8), request.uri(), null, null));
    Map<String, List<String>> parameters =
        Map.of("uri", List.of("CHK@feed"), "maxBytes", List.of("1"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(502, exception.statusCode());
    assertEquals("content_fetch_too_large", exception.errorCode());
    assertEquals("Fetched content exceeded the configured byte bound.", exception.getMessage());
  }

  @Test
  void fetch_whenResolvedUriContainsUnsafeDiagnostic_expectResolvedUriRedacted() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    "ok".getBytes(StandardCharsets.UTF_8),
                    request.uri(),
                    "CHK@feed?token=/tmp/private",
                    null));

    Map<String, Object> result =
        new ContentApiHandler(port).fetch(Map.of("uri", List.of("CHK@feed")));

    assertNull(result.get("resolvedUri"));
    assertEquals("ok", result.get("contentText"));
  }

  @Test
  void fetch_whenKskSourceProvided_expectRuntimeFetchAllowed() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    "feed".getBytes(StandardCharsets.UTF_8),
                    request.uri(),
                    "KSK@feed-snapshot",
                    null));

    Map<String, Object> result =
        new ContentApiHandler(port).fetch(Map.of("uri", List.of("crypta:KSK@feed-snapshot")));

    assertEquals("crypta:KSK@feed-snapshot", result.get("requestedUri"));
    assertEquals("KSK@feed-snapshot", result.get("resolvedUri"));
    assertEquals("KSK@feed-snapshot", port.lastRequest.uri());
  }

  @Test
  void fetch_whenTextRequestedForBinaryContent_expectUnsupportedEncoding() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    new byte[] {(byte) 0xff, 0x00}, request.uri(), null, null));
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@binary-content"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(415, exception.statusCode());
    assertEquals("unsupported_content_encoding", exception.errorCode());
  }

  @Test
  void fetch_whenSourceIsNotCryptaContentKey_expectRejectedBeforeRuntimePort() {
    List<String> invalidSources =
        List.of(
            "file:///tmp/content",
            "http://example.invalid/content",
            "https://example.invalid/content",
            "/tmp/content",
            "relative/content",
            "crypta:file:///tmp/content",
            "CHK@key\nSSK@other",
            "crypta:CHK@key?token=secret");

    for (String invalidSource : invalidSources) {
      FakeContentFetchPort port =
          new FakeContentFetchPort(
              request -> new BoundedContentFetchResult(new byte[] {}, request.uri(), null, null));
      Map<String, List<String>> parameters = Map.of("uri", List.of(invalidSource));

      PlatformApiException exception =
          assertFetchFails(new ContentApiHandler(port), parameters, invalidSource);

      assertEquals(400, exception.statusCode(), invalidSource);
      assertEquals("unsupported_content_source", exception.errorCode(), invalidSource);
      assertNull(port.lastRequest, invalidSource);
    }
  }

  @Test
  void fetch_whenMaximumBoundsProvided_expectCapsPassedToRuntimePort() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request ->
                new BoundedContentFetchResult(
                    "ok".getBytes(StandardCharsets.UTF_8), request.uri(), null, null));

    new ContentApiHandler(port)
        .fetch(
            Map.of(
                "uri",
                List.of("SSK@site/doc"),
                "maxBytes",
                List.of("1048576"),
                "timeoutMillis",
                List.of("60000"),
                "purpose",
                List.of("feed-source")));

    assertEquals(1_048_576L, port.lastRequest.maxBytes());
    assertEquals(Duration.ofMinutes(1), port.lastRequest.timeout());
    assertEquals("feed-source", port.lastRequest.purpose());
  }

  @Test
  void fetch_whenBoundsExceedCaps_expectInvalidQuery() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            request -> new BoundedContentFetchResult(new byte[] {}, request.uri(), null, null));
    Map<String, List<String>> parameters =
        Map.of("uri", List.of("CHK@key"), "maxBytes", List.of("1048577"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
    assertNull(port.lastRequest);
  }

  @Test
  void fetch_whenRuntimeFailureContainsSensitiveText_expectStableRedactedError() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            _ -> {
              throw new ContentFetchException(
                  ContentFetchException.CATALOG_FETCH_FAILED,
                  "token=/tmp/secret CHK@raw-content java.lang.IllegalStateException");
            });
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@key"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(502, exception.statusCode());
    assertEquals("content_fetch_failed", exception.errorCode());
    assertEquals("Content fetch failed.", exception.getMessage());
    assertFalse(exception.getMessage().contains("/tmp"));
    assertFalse(exception.getMessage().contains("token"));
    assertFalse(exception.getMessage().contains("CHK@raw-content"));
    assertFalse(exception.getMessage().contains("IllegalStateException"));
  }

  @Test
  void fetch_whenRuntimeReportsOversizedContent_expectTooLargeError() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            _ -> {
              throw new ContentFetchException(
                  ContentFetchException.CATALOG_FETCH_TOO_LARGE,
                  "Fetched content exceeded 262144 bytes for feed-preview");
            });
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@key"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(502, exception.statusCode());
    assertEquals("content_fetch_too_large", exception.errorCode());
    assertEquals("Fetched content exceeded the configured byte bound.", exception.getMessage());
  }

  @Test
  void fetch_whenRuntimeFailureMessageMentionsExceededButNotSize_expectGenericFetchFailed() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            _ -> {
              throw new ContentFetchException(
                  ContentFetchException.CATALOG_FETCH_FAILED,
                  "Content fetch redirect limit exceeded for feed-preview");
            });
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@key"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(502, exception.statusCode());
    assertEquals("content_fetch_failed", exception.errorCode());
    assertEquals("Content fetch failed.", exception.getMessage());
  }

  @Test
  void fetch_whenRuntimeReportsInvalidCatalogSource_expectInvalidContentUri() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            _ -> {
              throw new ContentFetchException(
                  ContentFetchException.INVALID_CATALOG_SOURCE,
                  "file:///tmp/private must not leak to apps");
            });
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@key"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_content_uri", exception.errorCode());
    assertEquals("The content URI is malformed or unsupported.", exception.getMessage());
    assertFalse(exception.getMessage().contains("/tmp/private"));
  }

  @Test
  void fetch_whenRuntimeReportsTimeout_expectTimeoutError() {
    FakeContentFetchPort port =
        new FakeContentFetchPort(
            _ -> {
              throw new ContentFetchException(
                  ContentFetchException.CATALOG_FETCH_TIMEOUT,
                  "request token timed out while reading CHK@body");
            });
    Map<String, List<String>> parameters = Map.of("uri", List.of("CHK@key"));

    PlatformApiException exception = assertFetchFails(new ContentApiHandler(port), parameters);

    assertEquals(504, exception.statusCode());
    assertEquals("content_fetch_timeout", exception.errorCode());
    assertEquals("Content fetch timed out.", exception.getMessage());
    assertFalse(exception.getMessage().contains("request token"));
  }

  private static PlatformApiException assertFetchFails(
      ContentApiHandler handler, Map<String, List<String>> parameters) {
    return assertThrows(PlatformApiException.class, () -> handler.fetch(parameters));
  }

  private static PlatformApiException assertFetchFails(
      ContentApiHandler handler, Map<String, List<String>> parameters, String message) {
    return assertThrows(PlatformApiException.class, () -> handler.fetch(parameters), message);
  }

  private static final class FakeContentFetchPort implements ContentFetchPort {
    private final FetchOperation operation;
    private BoundedContentFetchRequest lastRequest;

    private FakeContentFetchPort(FetchOperation operation) {
      this.operation = operation;
    }

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
        throws ContentFetchException {
      lastRequest = request;
      return operation.fetch(request);
    }
  }

  @FunctionalInterface
  private interface FetchOperation {
    BoundedContentFetchResult fetch(BoundedContentFetchRequest request)
        throws ContentFetchException;
  }
}
