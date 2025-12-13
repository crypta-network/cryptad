package network.crypta.clients.http.ajaxpush;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.util.stream.Stream;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PushKeepaliveToadletTest {

  private static final String BASE_URL = "http://localhost";
  private static final String PARAM_REQUEST_ID = "requestId";
  private static final String REQUEST_ID = "req-1";

  @Mock private HighLevelSimpleClient client;
  @Mock private HTTPRequest request;
  @Mock private ToadletContext context;
  @Mock private SimpleToadletServer server;
  @Mock private PushDataManager pushDataManager;

  @Test
  void path_whenCalled_expectKeepalivePath() {
    // Arrange
    PushKeepaliveToadlet toadlet = new PushKeepaliveToadlet(client);

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.keepalivePath, path);
  }

  @ParameterizedTest(name = "success={0}")
  @MethodSource("keepAliveOutcomes")
  void handleMethodGET_whenKeepAliveProcessed_expectCorrespondingReply(
      boolean success, String expectedBody)
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    URI uri = keepaliveUriWithRequestId();
    when(request.getParam(PARAM_REQUEST_ID)).thenReturn(REQUEST_ID);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.keepAliveReceived(REQUEST_ID)).thenReturn(success);

    CapturingPushKeepaliveToadlet toadlet = new CapturingPushKeepaliveToadlet(client);

    // Act
    toadlet.handleMethodGET(uri, request, context);

    // Assert
    assertEquals(200, toadlet.lastCode);
    assertEquals("OK", toadlet.lastDescription);
    assertEquals(expectedBody, toadlet.lastBody);
    assertEquals(1, toadlet.writeCalls);

    verify(request).getParam(PARAM_REQUEST_ID);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).keepAliveReceived(REQUEST_ID);
    verifyNoMoreInteractions(request, context, server, pushDataManager);
  }

  static Stream<Arguments> keepAliveOutcomes() {
    return Stream.of(
        Arguments.of(true, UpdaterConstants.SUCCESS),
        Arguments.of(false, UpdaterConstants.FAILURE));
  }

  @Test
  void handleMethodGET_whenRequestIdMissing_expectNullPassedToManagerAndReplyWritten()
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    URI uri = keepaliveUri();
    when(request.getParam(PARAM_REQUEST_ID)).thenReturn(null);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.keepAliveReceived(null)).thenReturn(true);

    CapturingPushKeepaliveToadlet toadlet = new CapturingPushKeepaliveToadlet(client);

    // Act
    toadlet.handleMethodGET(uri, request, context);

    // Assert
    assertEquals(UpdaterConstants.SUCCESS, toadlet.lastBody);
    assertEquals(context, toadlet.lastContext);
    assertEquals(1, toadlet.writeCalls);

    verify(request).getParam(PARAM_REQUEST_ID);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verify(pushDataManager).keepAliveReceived(null);
    verifyNoMoreInteractions(request, context, server, pushDataManager);
  }

  @Test
  void handleMethodGET_whenContainerIsNotSimpleToadletServer_expectClassCastException() {
    // Arrange
    URI uri = keepaliveUri();
    when(request.getParam(PARAM_REQUEST_ID)).thenReturn(REQUEST_ID);
    ToadletContainer nonServerContainer = org.mockito.Mockito.mock(ToadletContainer.class);
    when(context.getContainer()).thenReturn(nonServerContainer);

    CapturingPushKeepaliveToadlet toadlet = new CapturingPushKeepaliveToadlet(client);

    // Act + Assert
    assertThrows(
        ClassCastException.class,
        () -> toadlet.handleMethodGET(uri, request, context),
        "ToadletContext containers that are not SimpleToadletServer should fail fast.");

    verify(request).getParam(PARAM_REQUEST_ID);
    verify(context).getContainer();
    verifyNoMoreInteractions(request, context);
  }

  @Test
  void handleMethodGET_whenPushDataManagerIsNull_expectNullPointerException() {
    // Arrange
    URI uri = keepaliveUri();
    when(request.getParam(PARAM_REQUEST_ID)).thenReturn(REQUEST_ID);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(null);

    CapturingPushKeepaliveToadlet toadlet = new CapturingPushKeepaliveToadlet(client);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> toadlet.handleMethodGET(uri, request, context));

    verify(request).getParam(PARAM_REQUEST_ID);
    verify(context).getContainer();
    verify(server).getPushDataManager();
    verifyNoMoreInteractions(request, context, server);
  }

  private static URI keepaliveUri() {
    return URI.create(BASE_URL + UpdaterConstants.keepalivePath);
  }

  private static URI keepaliveUriWithRequestId() {
    return URI.create(
        BASE_URL + UpdaterConstants.keepalivePath + "?" + PARAM_REQUEST_ID + "=" + REQUEST_ID);
  }

  private static final class CapturingPushKeepaliveToadlet extends PushKeepaliveToadlet {
    private int writeCalls;
    private int lastCode = -1;
    private String lastDescription;
    private String lastBody;
    private ToadletContext lastContext;

    private CapturingPushKeepaliveToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      writeCalls++;
      lastCode = code;
      lastDescription = desc;
      lastBody = reply;
      lastContext = ctx;
    }
  }
}
