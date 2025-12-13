package network.crypta.clients.http.ajaxpush;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Base64;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PushNotificationToadletTest {

  private static final URI REQUEST_URI = URI.create("http://localhost/pushnotifications/");
  private static final String REQUEST_ID_PARAM = "requestId";
  private static final String REQUEST_ID_1 = "request-1";

  private static Stream<Arguments> successPayloadCases() {
    return Stream.of(
        Arguments.of("reqFromParam", "eventReq", "element-1"),
        Arguments.of("ignored", "żółć", ""),
        Arguments.of(null, "eventReq2", "element-3"));
  }

  @ParameterizedTest
  @MethodSource("successPayloadCases")
  void handleMethodGET_whenUpdateEventPresent_writesSuccessPayloadFromEvent(
      String requestIdParam, String eventRequestId, String elementId)
      throws ToadletContextClosedException, IOException, RedirectException {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CapturingPushNotificationToadlet toadlet = new CapturingPushNotificationToadlet(client);

    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);
    PushDataManager.UpdateEvent event = mock(PushDataManager.UpdateEvent.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(requestIdParam);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.getNextNotification(requestIdParam)).thenReturn(event);
    when(event.getRequestId()).thenReturn(eventRequestId);
    when(event.getElementId()).thenReturn(elementId);

    toadlet.handleMethodGET(REQUEST_URI, request, context);

    assertEquals(1, toadlet.replyCount);
    assertEquals(200, toadlet.lastCode);
    assertEquals("OK", toadlet.lastDescription);
    assertNotNull(toadlet.lastContext);
    assertEquals(context, toadlet.lastContext);

    String expectedPayload =
        UpdaterConstants.SUCCESS
            + ":"
            + Base64.encodeStandard(eventRequestId.getBytes(StandardCharsets.UTF_8))
            + UpdaterConstants.SEPARATOR
            + elementId;
    assertEquals(expectedPayload, toadlet.lastReply);

    verify(request).getParam(REQUEST_ID_PARAM);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).getNextNotification(requestIdParam);
    verify(event).getRequestId();
    verify(event).getElementId();
    verifyNoMoreInteractions(request, context, server, pushDataManager, event);
    verifyNoMoreInteractions(client);
  }

  @Test
  void handleMethodGET_whenWriteHtmlReplyThrows_propagatesIOException() {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    PushNotificationToadlet toadlet = new ThrowingPushNotificationToadlet(client);

    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);
    PushDataManager.UpdateEvent event = mock(PushDataManager.UpdateEvent.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn("req");
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.getNextNotification("req")).thenReturn(event);
    when(event.getRequestId()).thenReturn("eventReq");
    when(event.getElementId()).thenReturn("element-1");

    assertThrows(IOException.class, () -> toadlet.handleMethodGET(REQUEST_URI, request, context));

    verify(request).getParam(REQUEST_ID_PARAM);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).getNextNotification("req");
    verify(event).getRequestId();
    verify(event).getElementId();
    verifyNoMoreInteractions(request, context, server, pushDataManager, event);
    verifyNoMoreInteractions(client);
  }

  @Test
  void handleMethodGET_whenUpdateEventMissing_writesFailurePayload()
      throws ToadletContextClosedException, IOException, RedirectException {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CapturingPushNotificationToadlet toadlet = new CapturingPushNotificationToadlet(client);

    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(REQUEST_ID_1);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.getNextNotification(REQUEST_ID_1)).thenReturn(null);

    toadlet.handleMethodGET(REQUEST_URI, request, context);

    assertEquals(1, toadlet.replyCount);
    assertEquals(200, toadlet.lastCode);
    assertEquals("OK", toadlet.lastDescription);
    assertEquals(UpdaterConstants.FAILURE, toadlet.lastReply);

    verify(request).getParam(REQUEST_ID_PARAM);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).getNextNotification(REQUEST_ID_1);
    verifyNoMoreInteractions(request, context, server, pushDataManager);
    verifyNoMoreInteractions(client);
  }

  @Test
  void handleMethodGET_whenRequestIdMissing_passesNullToPushManagerAndWritesFailure()
      throws ToadletContextClosedException, IOException, RedirectException {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CapturingPushNotificationToadlet toadlet = new CapturingPushNotificationToadlet(client);

    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(null);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.getNextNotification(null)).thenReturn(null);

    toadlet.handleMethodGET(REQUEST_URI, request, context);

    assertEquals(1, toadlet.replyCount);
    assertEquals(UpdaterConstants.FAILURE, toadlet.lastReply);

    verify(request).getParam(REQUEST_ID_PARAM);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).getNextNotification(null);
    verifyNoMoreInteractions(request, context, server, pushDataManager);
    verifyNoMoreInteractions(client);
  }

  @Test
  void handleMethodGET_whenContainerIsNotSimpleToadletServer_expectClassCastException() {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    PushNotificationToadlet toadlet = new PushNotificationToadlet(client);

    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    ToadletContainer container = mock(ToadletContainer.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(REQUEST_ID_1);
    when(context.getContainer()).thenReturn(container);

    assertThrows(
        ClassCastException.class, () -> toadlet.handleMethodGET(REQUEST_URI, request, context));

    verify(request).getParam(REQUEST_ID_PARAM);
    verify(context).getContainer();
    verifyNoMoreInteractions(request, context);
    verifyNoMoreInteractions(client);
  }

  @Test
  void path_returnsNotificationPath() {
    PushNotificationToadlet toadlet =
        new PushNotificationToadlet(mock(HighLevelSimpleClient.class));

    String result = toadlet.path();

    assertEquals(UpdaterConstants.notificationPath, result);
  }

  private static final class CapturingPushNotificationToadlet extends PushNotificationToadlet {
    private int replyCount;
    private ToadletContext lastContext;
    private int lastCode;
    private String lastDescription;
    private String lastReply;

    private CapturingPushNotificationToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      replyCount++;
      lastContext = ctx;
      lastCode = code;
      lastDescription = desc;
      lastReply = reply;
    }
  }

  private static final class ThrowingPushNotificationToadlet extends PushNotificationToadlet {
    private ThrowingPushNotificationToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
        throws IOException {
      throw new IOException("boom");
    }
  }
}
