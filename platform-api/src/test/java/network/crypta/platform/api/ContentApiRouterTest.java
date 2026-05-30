package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ContentApiRouterTest {
  @Test
  void route_whenBrowserAppHasContentFetchCapability_expectRuntimeFetchResponse() {
    AtomicReference<BoundedContentFetchRequest> capturedRequest = new AtomicReference<>();
    ContentFetchPort fetchPort =
        request -> {
          capturedRequest.set(request);
          return new BoundedContentFetchResult(
              "hello".getBytes(StandardCharsets.UTF_8), request.uri(), "CHK@resolved", null);
        };
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"requestedUri\":\"CHK@requested\""));
    assertTrue(response.body().contains("\"resolvedUri\":\"CHK@resolved\""));
    assertTrue(response.body().contains("\"contentText\":\"hello\""));
    assertNotNull(capturedRequest.get());
    assertEquals("CHK@requested", capturedRequest.get().uri());
  }

  @Test
  void route_whenBrowserAppLacksContentFetchCapability_expectForbiddenWithoutRuntimeFetch() {
    AtomicReference<BoundedContentFetchRequest> capturedRequest = new AtomicReference<>();
    ContentFetchPort fetchPort =
        request -> {
          capturedRequest.set(request);
          return new BoundedContentFetchResult(new byte[] {}, request.uri(), null, null);
        };
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of())));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    assertNull(capturedRequest.get());
  }

  @Test
  void route_whenContentFetchUriIsUnsafe_expectRejectedWithoutRuntimeFetch() {
    AtomicReference<BoundedContentFetchRequest> capturedRequest = new AtomicReference<>();
    ContentFetchPort fetchPort =
        request -> {
          capturedRequest.set(request);
          return new BoundedContentFetchResult(new byte[] {}, request.uri(), null, null);
        };
    PlatformApiRouter router = router(fetchPort);

    for (String unsafeUri :
        List.of(
            "http://example.invalid/feed?token=SECRET",
            "https://example.invalid/feed",
            "file:///tmp/private",
            "//example.invalid/feed",
            "/var/lib/cryptad/feed",
            "C:\\Users\\private\\feed",
            "CHK@valid\\confused",
            "CHK@valid?token=SECRET",
            "CHK@valid#fragment")) {
      PlatformApiResponse response =
          router.route(
              request(
                  List.of("content", "fetch"),
                  Map.of("uri", List.of(unsafeUri)),
                  PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

      assertEquals(400, response.statusCode(), unsafeUri);
      assertTrue(response.body().contains("\"code\":\"unsupported_content_source\""));
      assertFalse(response.body().contains("SECRET"));
      assertFalse(response.body().contains("example.invalid"));
      assertFalse(response.body().contains("/tmp/private"));
      assertFalse(response.body().contains("C:\\\\Users"));
      assertNull(capturedRequest.get());
    }
  }

  @Test
  void route_whenContentFetchMaxBytesExceedsHardLimit_expectRejectedWithoutRuntimeFetch() {
    AtomicReference<BoundedContentFetchRequest> capturedRequest = new AtomicReference<>();
    ContentFetchPort fetchPort =
        request -> {
          capturedRequest.set(request);
          return new BoundedContentFetchResult(new byte[] {}, request.uri(), null, null);
        };
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested"), "maxBytes", List.of("1048577")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"invalid_query_parameter\""));
    assertFalse(response.body().contains("CHK@requested"));
    assertNull(capturedRequest.get());
  }

  @Test
  void route_whenTextFetchReturnsInvalidUtf8_expectUnsupportedEncodingWithoutPayloadEcho() {
    ContentFetchPort fetchPort =
        request ->
            new BoundedContentFetchResult(
                new byte[] {(byte) 0xc3, 0x28}, request.uri(), request.uri(), null);
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested"), "format", List.of("text")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

    assertEquals(415, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"unsupported_content_encoding\""));
    assertFalse(response.body().contains("CHK@requested"));
  }

  @Test
  void route_whenRuntimeFetchThrowsUnexpectedException_expectGenericRedactedFailure() {
    ContentFetchPort fetchPort =
        _ -> {
          throw new IllegalStateException("failed below /tmp/private?token=SECRET");
        };
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

    assertEquals(502, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"content_fetch_failed\""));
    assertFalse(response.body().contains("SECRET"));
    assertFalse(response.body().contains("/tmp/private"));
    assertFalse(response.body().contains("CHK@requested"));
  }

  @Test
  void route_whenRuntimeReportsUnsafeResolvedUri_expectResolvedUriOmitted() {
    ContentFetchPort fetchPort =
        request ->
            new BoundedContentFetchResult(
                "hello".getBytes(StandardCharsets.UTF_8),
                request.uri(),
                "CHK@resolved?token=SECRET",
                null);
    PlatformApiRouter router = router(fetchPort);

    PlatformApiResponse response =
        router.route(
            request(
                List.of("content", "fetch"),
                Map.of("uri", List.of("CHK@requested")),
                PlatformApiPrincipal.appBrowserSession("reader.app", List.of("content.fetch"))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"resolvedUri\":null"));
    assertFalse(response.body().contains("SECRET"));
  }

  private static PlatformApiRouter router(ContentFetchPort contentFetchPort) {
    RuntimePorts runtimePorts = runtimePorts();
    when(runtimePorts.contentFetch()).thenReturn(contentFetchPort);
    return new PlatformApiRouter(runtimePorts);
  }

  private static PlatformApiRequest request(
      List<String> segments,
      Map<String, List<String>> queryParameters,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest("POST", segments, queryParameters, principal);
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
}
