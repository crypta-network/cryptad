package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.BrowseContentClient;
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
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PushLeavingToadletTest {

  private static final String REQUEST_ID_PARAM = "requestId";

  private static final URI REQUEST_URI = URI.create("http://example.invalid/leaving/");

  private static final class CapturingPushLeavingToadlet extends PushLeavingToadlet {
    private Integer lastCode;
    private String lastDesc;
    private String lastReply;

    private CapturingPushLeavingToadlet(BrowseContentClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      lastCode = code;
      lastDesc = desc;
      lastReply = reply;
    }
  }

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void handleMethodGET_whenLeavingReturnsAnyValue_writesSuccessReplyAndCallsLeaving(boolean deleted)
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    CapturingPushLeavingToadlet toadlet =
        new CapturingPushLeavingToadlet(mock(BrowseContentClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    String requestId = "request-1";
    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(requestId);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.leaving(requestId)).thenReturn(deleted);

    // Act
    toadlet.handleMethodGET(REQUEST_URI, request, context);

    // Assert
    verify(pushDataManager).leaving(requestId);
    assertEquals(200, toadlet.lastCode);
    assertEquals("OK", toadlet.lastDesc);
    assertEquals(UpdaterConstants.SUCCESS, toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenRequestIdIsNull_passesNullToLeavingAndWritesSuccessReply()
      throws ToadletContextClosedException, IOException, RedirectException {
    // Arrange
    CapturingPushLeavingToadlet toadlet =
        new CapturingPushLeavingToadlet(mock(BrowseContentClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(null);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.leaving(null)).thenReturn(true);

    // Act
    toadlet.handleMethodGET(REQUEST_URI, request, context);

    // Assert
    verify(pushDataManager).leaving(null);
    assertEquals(UpdaterConstants.SUCCESS, toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenContainerNotSimpleToadletServer_throwsClassCastException() {
    // Arrange
    CapturingPushLeavingToadlet toadlet =
        new CapturingPushLeavingToadlet(mock(BrowseContentClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    ToadletContainer wrongContainer = mock(ToadletContainer.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenReturn("request");
    when(context.getContainer()).thenReturn(wrongContainer);

    // Act + Assert
    assertThrows(
        ClassCastException.class, () -> toadlet.handleMethodGET(REQUEST_URI, request, context));
    assertNull(toadlet.lastCode);
    assertNull(toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenLeavingThrowsRuntimeException_propagatesAndDoesNotWriteReply() {
    // Arrange
    CapturingPushLeavingToadlet toadlet =
        new CapturingPushLeavingToadlet(mock(BrowseContentClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);
    PushDataManager pushDataManager = mock(PushDataManager.class);

    String requestId = "request-1";
    when(request.getParam(REQUEST_ID_PARAM)).thenReturn(requestId);
    when(context.getContainer()).thenReturn(server);
    when(server.getPushDataManager()).thenReturn(pushDataManager);
    when(pushDataManager.leaving(requestId)).thenThrow(new IllegalStateException("boom"));

    // Act + Assert
    assertThrows(
        IllegalStateException.class, () -> toadlet.handleMethodGET(REQUEST_URI, request, context));
    verify(pushDataManager).leaving(requestId);
    assertNull(toadlet.lastCode);
    assertNull(toadlet.lastReply);
  }

  @Test
  void handleMethodGET_whenGetParamThrowsRuntimeException_propagatesAndDoesNotTouchContext() {
    // Arrange
    CapturingPushLeavingToadlet toadlet =
        new CapturingPushLeavingToadlet(mock(BrowseContentClient.class));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext context = mock(ToadletContext.class);

    when(request.getParam(REQUEST_ID_PARAM)).thenThrow(new IllegalArgumentException("bad request"));

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> toadlet.handleMethodGET(REQUEST_URI, request, context));
    verifyNoInteractions(context);
    assertNull(toadlet.lastCode);
    assertNull(toadlet.lastReply);
  }

  @Test
  void path_whenCalled_returnsUpdaterLeavingPath() {
    // Arrange
    PushLeavingToadlet toadlet = new PushLeavingToadlet(mock(BrowseContentClient.class));

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.LEAVING_PATH, path);
  }
}
