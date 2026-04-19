package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlatformApiToadletTest {

  @Mock private PlatformApiRouter router;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private Bucket requestBody;

  private PlatformApiToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new PlatformApiToadlet(router);
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
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenAppInstallRequested_routesDecodedInstallRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("stagedDir"));
    when(request.getMultipleParam("stagedDir")).thenReturn(new String[] {"/tmp/staged"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST", List.of("apps", "install"), Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppInstallUsesFormPart_routesInstallRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"stagedDir"});
    when(request.getPartAsStringFailsafe("stagedDir", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("/tmp/staged");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST", List.of("apps", "install"), Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppUpdateRequested_routesDecodedUpdateRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("stagedDir"));
    when(request.getMultipleParam("stagedDir")).thenReturn(new String[] {"/tmp/staged"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/alpha/update"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", "alpha", "update"),
                Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppUpdateUsesFormPart_routesUpdateRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"stagedDir"});
    when(request.getPartAsStringFailsafe("stagedDir", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("/tmp/staged");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/alpha/update"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", "alpha", "update"),
                Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenQueueRemoveRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("identifier-0", "identifier-1"));
    when(request.getMultipleParam("identifier-0")).thenReturn(new String[] {"download-1"});
    when(request.getMultipleParam("identifier-1")).thenReturn(new String[] {"download-2"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of(
                    "identifier-0", List.of("download-1"),
                    "identifier-1", List.of("download-2"))));
  }

  @Test
  void handleMethodPOST_whenQueueRemoveUsesFormParts_routesDecodedMutationRequest()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"identifier-0", "identifier-1"});
    when(request.getPartAsStringFailsafe("identifier-0", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("download-1");
    when(request.getPartAsStringFailsafe("identifier-1", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("download-2");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of(
                    "identifier-0", List.of("download-1"),
                    "identifier-1", List.of("download-2"))));
    verify(request).getPartAsStringFailsafe("identifier-0", QueueToadlet.MAX_KEY_LENGTH);
    verify(request).getPartAsStringFailsafe("identifier-1", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenQueueRemoveUsesRepeatedUrlEncodedBody_routesAllIdentifiers()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getHeader("content-type")).thenReturn("application/x-www-form-urlencoded");
    when(request.getRawData())
        .thenReturn(
            new SimpleReadOnlyArrayBucket(
                "identifier=download-1&identifier=download-2".getBytes(StandardCharsets.US_ASCII)));
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of("identifier", List.of("download-1", "download-2"))));
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenUrlEncodedBodyOverlapsQuery_expectQueryValuesPreserved()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("expectedMimeType"));
    when(request.getMultipleParam("expectedMimeType")).thenReturn(new String[] {"text/html"});
    when(request.getHeader("content-type"))
        .thenReturn("application/x-www-form-urlencoded; charset=UTF-8");
    when(request.getRawData())
        .thenReturn(
            new SimpleReadOnlyArrayBucket(
                ("fetchUri=KSK@direct-download&expectedMimeType=text/plain&filterData=on"
                        + "&formPassword=secret")
                    .getBytes(StandardCharsets.US_ASCII)));
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "downloads"),
                Map.of(
                    "expectedMimeType", List.of("text/html"),
                    "fetchUri", List.of("KSK@direct-download"),
                    "filterData", List.of("on"))));
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenUrlEncodedBodyExceedsLegacyLimit_expectJson400WithoutRouting()
      throws Exception {
    byte[] oversizedBody = new byte[1024 * 1024 + 1];
    Arrays.fill(oversizedBody, (byte) 'a');

    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getHeader("content-type")).thenReturn("application/x-www-form-urlencoded");
    when(request.getRawData()).thenReturn(new SimpleReadOnlyArrayBucket(oversizedBody));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(400, replyHeaders.statusCode());
    assertEquals("Bad Request", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_request_body\",\"message\":\"URL-encoded request body"
            + " exceeds the 1048576 byte limit.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenQueueDownloadUsesFormParts_routesDecodedCreationRequest()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts())
        .thenReturn(new String[] {"fetchUri", "filterData", "expectedMimeType"});
    when(request.getPartAsStringFailsafe("fetchUri", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("KSK@direct-download");
    when(request.getPartAsStringFailsafe("filterData", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("on");
    when(request.getPartAsStringFailsafe("expectedMimeType", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("text/plain");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "downloads"),
                Map.of(
                    "fetchUri", List.of("KSK@direct-download"),
                    "filterData", List.of("on"),
                    "expectedMimeType", List.of("text/plain"))));
    verify(request).getPartAsStringFailsafe("fetchUri", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenPeerAddRequested_routesDecodedAddRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames())
        .thenReturn(List.of("referenceText", "trust", "visibility", "privateNoteText"));
    when(request.getMultipleParam("referenceText"))
        .thenReturn(
            new String[] {
"""
identity=peer-123
lastGoodVersion=1
myName=Alice
physical.udp=127.0.0.1:9481
End
"""
            });
    when(request.getMultipleParam("trust")).thenReturn(new String[] {"NORMAL"});
    when(request.getMultipleParam("visibility")).thenReturn(new String[] {"YES"});
    when(request.getMultipleParam("privateNoteText")).thenReturn(new String[] {"friend note"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/peers/add"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                        List.of(
                            """
                            identity=peer-123
                            lastGoodVersion=1
                            myName=Alice
                            physical.udp=127.0.0.1:9481
                            End
                            """),
                    "trust", List.of("NORMAL"),
                    "visibility", List.of("YES"),
                    "privateNoteText", List.of("friend note"))));
  }

  @Test
  void handleMethodPOST_whenPeerSettingsRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("trust", "visibility"));
    when(request.getMultipleParam("trust")).thenReturn(new String[] {"HIGH"});
    when(request.getMultipleParam("visibility")).thenReturn(new String[] {"NAME_ONLY"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer%2F123/settings"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "peer/123", "settings"),
                Map.of("trust", List.of("HIGH"), "visibility", List.of("NAME_ONLY"))));
  }

  @Test
  void handleMethodPOST_whenPeerNoteUsesFormPart_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"noteText"});
    when(request.getPartAsStringFailsafe("noteText", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("updated note");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer-123/note"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "peer-123", "note"),
                Map.of("noteText", List.of("updated note"))));
    verify(request).getPartAsStringFailsafe("noteText", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenAlertDismissRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/alerts/-17/dismiss"), request, ctx);

    verify(router)
        .route(new PlatformApiRequest("POST", List.of("alerts", "-17", "dismiss"), Map.of()));
  }

  @Test
  void handleMethodPOST_whenQueueMutationPasswordMissing_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenPeerMutationPasswordMissing_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer-123/remove"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://localhost/api/v1/config/overrides",
        "http://localhost/api/v1/security-levels/network",
        "http://localhost/api/v1/updates/core/download",
        "http://localhost/api/v1/alerts/42/dismiss",
        "http://localhost/api/v1/wizard/first-time/apply",
      })
  void handleMethodPOST_whenProtectedMutationPasswordMissing_expectJson403WithoutRouting(
      String requestUri) throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create(requestUri), request, ctx);

    verifyNoInteractions(router);
    assertForbiddenBody();
  }

  @Test
  void handleMethodPOST_whenNonAppsRoute_expectRouterJson405WithoutPasswordCheck()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("POST", List.of("node", "greeting"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/node/greeting");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(response.body(), bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenMalformedAppsPath_expectRouterJson404WithoutPasswordCheck()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(404, "not_found", "Platform API route not found.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/apps/alpha/restart"), request, ctx);

    verify(router)
        .route(new PlatformApiRequest("POST", List.of("apps", "alpha", "restart"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha/restart");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(404, replyHeaders.statusCode());
    assertEquals("Not Found", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(response.body(), bodyWrite.bodyText());
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

  @Test
  void handleMethodDELETE_whenAppRemovalRequested_routesDecodedDeleteRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodDELETE(URI.create("http://localhost/api/v1/apps/alpha"), request, ctx);

    verify(router).route(new PlatformApiRequest("DELETE", List.of("apps", "alpha"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
  }

  @Test
  void handleMethodPOST_whenFullAccessMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Full access is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenFormPasswordMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/install");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodDELETE_whenFormPasswordMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodDELETE(URI.create("http://localhost/api/v1/apps/alpha"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodDELETE_whenQueryFormPasswordProvided_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodDELETE(
        URI.create("http://localhost/api/v1/apps/alpha?formPassword=secret"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
    verify(ctx, never()).getFormPassword();
    verify(request, never()).getParam("formPassword");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
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

  private void assertForbiddenBody() throws Exception {
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  private record ReplyHeadersCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length) {}

  private record BodyWriteCapture(String bodyText, int offset, int length) {}
}
