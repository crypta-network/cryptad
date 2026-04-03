package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlatformApiToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private PlatformApiRouter router;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private PlatformApiToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new PlatformApiToadlet(client, router);
  }

  @Test
  void handleMethodGET_whenPeerIdentifierContainsEncodedSlash_routesDecodedIdentifier()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("peer", "alice/bob")));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/peers/alice%2Fbob"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("GET", captor.getValue().method());
    assertEquals(List.of("peers", "alice/bob"), captor.getValue().pathSegments());
    assertEquals(Map.of(), captor.getValue().queryParameters());
  }

  @Test
  void findSupportedMethods_whenPlatformApiToadlet_expectAllBridgeHandledMethods() {
    Set<String> methods = Set.copyOf(Arrays.asList(toadlet.findSupportedMethods().split(", ")));

    assertEquals(
        Set.of("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"), methods);
  }

  @Test
  void handleMethodOPTIONS_whenUnsupportedVerb_expectRouterBackedJson405() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodOPTIONS(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("OPTIONS", List.of("node", "greeting"), Map.of()));
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, replyHeaders.length());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(0, bodyWrite.offset());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, bodyWrite.length());
    assertEquals(response.body(), bodyWrite.bodyText());
  }

  @Test
  void handleMethodHEAD_whenUnsupportedVerb_expectHeaderOnly405() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodHEAD(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("HEAD", List.of("node", "greeting"), Map.of()));
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, replyHeaders.length());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  private ReplyHeadersCapture captureReplyHeaders() throws Exception {
    ArgumentCaptor<Integer> statusCode = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> reasonPhrase = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headers = multiValueTableCaptor();
    ArgumentCaptor<String> mimeType = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> length = ArgumentCaptor.forClass(Long.class);

    verify(ctx)
        .sendReplyHeaders(
            statusCode.capture(),
            reasonPhrase.capture(),
            headers.capture(),
            mimeType.capture(),
            length.capture());

    return new ReplyHeadersCapture(
        statusCode.getValue(),
        reasonPhrase.getValue(),
        headers.getValue(),
        mimeType.getValue(),
        length.getValue());
  }

  @SuppressWarnings("unchecked")
  private static ArgumentCaptor<MultiValueTable<String, String>> multiValueTableCaptor() {
    return (ArgumentCaptor<MultiValueTable<String, String>>)
        (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
  }

  private BodyWriteCapture captureBodyWrite() throws Exception {
    ArgumentCaptor<byte[]> body = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offset = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> length = ArgumentCaptor.forClass(Integer.class);

    verify(ctx).writeData(body.capture(), offset.capture(), length.capture());

    return new BodyWriteCapture(
        new String(body.getValue(), StandardCharsets.UTF_8), offset.getValue(), length.getValue());
  }

  private record ReplyHeadersCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length) {}

  private record BodyWriteCapture(String bodyText, int offset, int length) {}
}
