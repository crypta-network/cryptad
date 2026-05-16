package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiContentRouterTest {
  @Test
  void route_whenBrowserAppLacksContentFetch_expectForbiddenBeforeRuntimeFetch() {
    RecordingContentFetchPort fetchPort = new RecordingContentFetchPort();
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(fetchPort));

    PlatformApiResponse response =
        router.route(
            request(PlatformApiPrincipal.appBrowserSession("feed-reader", List.of("queue.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
    assertFalse(fetchPort.called);
  }

  @Test
  void route_whenBrowserAppHasContentFetch_expectFetchResponse() {
    RecordingContentFetchPort fetchPort = new RecordingContentFetchPort();
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(fetchPort));

    PlatformApiResponse response =
        router.route(
            request(
                PlatformApiPrincipal.appBrowserSession("feed-reader", List.of("content.fetch"))));

    assertEquals(200, response.statusCode());
    assertTrue(fetchPort.called);
    assertEquals("USK@example/feed/42/feed.json", fetchPort.lastRequest.uri());
    assertTrue(
        response.body().contains("\"requestedUri\":\"crypta:USK@example/feed/42/feed.json\""));
    assertTrue(response.body().contains("\"bytesLength\":9"));
    assertTrue(response.body().contains("\"contentText\":\"feed body\""));
    assertFalse(response.body().contains("private"));
    assertFalse(response.body().contains("CRYPTAD_APP_TOKEN"));
  }

  @Test
  void route_whenContentFetchPortUnavailable_expectServiceUnavailable() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(null));

    PlatformApiResponse response =
        router.route(
            request(
                PlatformApiPrincipal.appBrowserSession("feed-reader", List.of("content.fetch"))));

    assertEquals(503, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"content_fetch_failed\""));
    assertTrue(response.body().contains("Content fetch service is unavailable."));
  }

  private static PlatformApiRequest request(PlatformApiPrincipal principal) {
    return new PlatformApiRequest(
        "POST",
        List.of("content", "fetch"),
        Map.of("uri", List.of("crypta:USK@example/feed/42/feed.json"), "format", List.of("text")),
        principal);
  }

  private static RuntimePorts runtimePorts(ContentFetchPort fetchPort) {
    RuntimePorts runtimePorts =
        mock(
            RuntimePorts.class,
            invocation -> {
              Object defaultValue = Answers.RETURNS_DEFAULTS.answer(invocation);
              if (defaultValue != null || invocation.getMethod().getReturnType().isPrimitive()) {
                return defaultValue;
              }
              Class<?> returnType = invocation.getMethod().getReturnType();
              return returnType.isInterface() ? mock(returnType) : null;
            });
    when(runtimePorts.contentFetch()).thenReturn(fetchPort);
    return runtimePorts;
  }

  private static final class RecordingContentFetchPort implements ContentFetchPort {
    private boolean called;
    private BoundedContentFetchRequest lastRequest;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      called = true;
      lastRequest = request;
      assertNotNull(request);
      return new BoundedContentFetchResult(
          "feed body".getBytes(StandardCharsets.UTF_8),
          request.uri(),
          request.uri(),
          "Fetched 9 bytes");
    }
  }
}
