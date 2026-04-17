package network.crypta.clients.http.ajaxpush;

import java.net.URI;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DismissAlertToadletTest {

  @Mock private BrowseContentClient client;
  @Mock private HTTPRequest request;
  @Mock private ToadletContext context;

  @Test
  void handleMethodGET_whenAnchorContainsHtmlEntities_writesSuccessReplyAndStatus200()
      throws Exception {
    // Arrange
    CapturingDismissAlertToadlet toadlet = new CapturingDismissAlertToadlet(client);
    URI uri = URI.create("/dismissalert/?anchor=foo");
    org.mockito.Mockito.when(request.getParam("anchor")).thenReturn("foo&amp;bar");

    // Act
    toadlet.handleMethodGET(uri, request, context);

    // Assert
    assertEquals(context, toadlet.capturedContext);
    assertEquals(200, toadlet.capturedCode);
    assertEquals("OK", toadlet.capturedDescription);
    assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
  }

  @Test
  void handleMethodGET_whenAnchorEmpty_writesSuccessReply() throws Exception {
    // Arrange
    CapturingDismissAlertToadlet toadlet = new CapturingDismissAlertToadlet(client);
    URI uri = URI.create("/dismissalert/?anchor=");
    org.mockito.Mockito.when(request.getParam("anchor")).thenReturn("");

    // Act
    toadlet.handleMethodGET(uri, request, context);

    // Assert
    assertEquals(200, toadlet.capturedCode);
    assertEquals(UpdaterConstants.SUCCESS, toadlet.capturedReply);
  }

  @Test
  void handleMethodGET_whenAnchorParamNull_throwsNullPointerException() {
    // Arrange
    DismissAlertToadlet toadlet = new DismissAlertToadlet(client);
    URI uri = URI.create("/dismissalert/");
    org.mockito.Mockito.when(request.getParam("anchor")).thenReturn(null);

    // Act / Assert
    assertThrows(NullPointerException.class, () -> toadlet.handleMethodGET(uri, request, context));
  }

  @Test
  void path_whenCalled_returnsDismissAlertPathConstant() {
    // Arrange
    DismissAlertToadlet toadlet = new DismissAlertToadlet(client);

    // Act
    String path = toadlet.path();

    // Assert
    assertEquals(UpdaterConstants.DISMISS_ALERT_PATH, path);
  }

  private static final class CapturingDismissAlertToadlet extends DismissAlertToadlet {
    private ToadletContext capturedContext;
    private int capturedCode;
    private String capturedDescription;
    private String capturedReply;

    private CapturingDismissAlertToadlet(BrowseContentClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      this.capturedContext = ctx;
      this.capturedCode = code;
      this.capturedDescription = desc;
      this.capturedReply = reply;
    }
  }
}
