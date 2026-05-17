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
