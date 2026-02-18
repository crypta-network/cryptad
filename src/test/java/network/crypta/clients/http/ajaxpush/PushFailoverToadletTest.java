package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
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
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PushFailoverToadletTest {

  private static final String REQUEST_ID_PARAM = "requestId";
  private static final String ORIGINAL_REQUEST_ID_PARAM = "originalRequestId";

  private static final URI REQUEST_URI = URI.create("http://example.invalid/failover/");

  private static final class CapturingPushFailoverToadlet extends PushFailoverToadlet {
    private Integer lastCode;
    private String lastDesc;
    private String lastReply;

    private CapturingPushFailoverToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      lastCode = code;
      lastDesc = desc;
      lastReply = reply;
    }
  }

  @Test
  void handleMethodGET_whenFailoverSucceeds_writesSuccessReplyAndCallsFailover()
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    CapturingPushFailoverToadlet toadlet =
        new CapturingPushFailoverToadlet(mock(HighLevelSimpleClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    String requestId = "request-2";
    String originalRequestId = "request-1";
    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(requestId);
    when(request.getParam(ORIGINAL_REQUEST_ID_PARAM)).thenReturn(originalRequestId);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.failover(originalRequestId, requestId)).thenReturn(true);

    // Act
    toadlet.handleMethodGET(REQUEST_URI, request, context);

    // Assert
    verify(pushDataManager).failover(originalRequestId, requestId);
    assertEquals(200, toadlet.lastCode);
    assertEquals("OK", toadlet.lastDesc);
    assertEquals(UpdaterConstants.SUCCESS, toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenFailoverFails_writesFailureReplyAndCallsFailover()
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    CapturingPushFailoverToadlet toadlet =
        new CapturingPushFailoverToadlet(mock(HighLevelSimpleClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    String requestId = "new-request";
    String originalRequestId = "old-request";
    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(requestId);
    when(request.getParam(ORIGINAL_REQUEST_ID_PARAM)).thenReturn(originalRequestId);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.failover(originalRequestId, requestId)).thenReturn(false);

    // Act
    toadlet.handleMethodGET(REQUEST_URI, request, context);

    // Assert
    verify(pushDataManager).failover(originalRequestId, requestId);
    assertEquals(UpdaterConstants.FAILURE, toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenParamsMissing_passesEmptyStringsToFailover()
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    CapturingPushFailoverToadlet toadlet =
        new CapturingPushFailoverToadlet(mock(HighLevelSimpleClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn("");
    when(request.getParam(ORIGINAL_REQUEST_ID_PARAM)).thenReturn("");
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.failover("", "")).thenReturn(true);

    // Act
    toadlet.handleMethodGET(REQUEST_URI, request, context);

    // Assert
    verify(pushDataManager).failover("", "");
    assertEquals(UpdaterConstants.SUCCESS, toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenContainerNotSimpleToadletServer_throwsClassCastException() {
    // Arrange
    CapturingPushFailoverToadlet toadlet =
        new CapturingPushFailoverToadlet(mock(HighLevelSimpleClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    ToadletContainer wrongContainer = mock(ToadletContainer.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn("request");
    when(request.getParam(ORIGINAL_REQUEST_ID_PARAM)).thenReturn("original");
    when(context.getContainer()).thenReturn(wrongContainer);

    // Act + Assert
    assertThrows(
        ClassCastException.class, () -> toadlet.handleMethodGET(REQUEST_URI, request, context));
    assertNull(toadlet.lastCode);
    assertNull(toadlet.lastReply);
  }

  @Test
  void path_whenCalled_returnsUpdaterFailoverPath() {
    // Arrange
    PushFailoverToadlet toadlet = new PushFailoverToadlet(mock(HighLevelSimpleClient.class));

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.FAILOVER_PATH, path);
  }
}
