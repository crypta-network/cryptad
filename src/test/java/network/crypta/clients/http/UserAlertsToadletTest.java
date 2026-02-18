package network.crypta.clients.http;

import java.net.URI;
import javax.naming.SizeLimitExceededException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.node.useralerts.AbstractNodeToNodeFileOfferUserAlert;
import network.crypta.node.useralerts.NodeToNodeMessageUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserAlertsToadletTest {

  private static final URI ALERTS_URI = URI.create("http://localhost/alerts/");

  @Mock private HighLevelSimpleClient client;
  @Mock private ToadletContext context;
  @Mock private PageMaker pageMaker;
  @Mock private UserAlertManager alertManager;

  private UserAlertsToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet = new UserAlertsToadlet(client);

    when(context.getAlertManager()).thenReturn(alertManager);
    when(context.getPageMaker()).thenReturn(pageMaker);
    when(context.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(context.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });

    doNothing()
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing().when(context).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void path_returnsAlertsPath() {
    assertEquals("/alerts/", toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_doesNotRender() throws Exception {
    when(context.checkFullAccess(toadlet)).thenReturn(false);
    HTTPRequest request = mock(HTTPRequest.class);

    toadlet.handleMethodGET(ALERTS_URI, request, context);

    verify(context).checkFullAccess(toadlet);
    verify(pageMaker, never()).getPageNode(anyString(), any(ToadletContext.class));
    verify(alertManager, never()).createAlerts(anyBoolean());
    verify(context, never()).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodGET_whenNoAlerts_showsInfoboxWithoutBulkActions() throws Exception {
    PageNode pageNode = createPageNode();
    when(pageMaker.getPageNode(anyString(), eq(context))).thenReturn(pageNode);
    HTMLNode emptyAlerts = new HTMLNode("#", "");
    when(alertManager.createAlerts(false)).thenReturn(emptyAlerts);
    HTTPRequest request = mock(HTTPRequest.class);

    toadlet.handleMethodGET(ALERTS_URI, request, context);

    HTMLNode content = pageNode.getContentNode();
    assertNotNull(findFirstByClass(content, "infobox"));
    assertNull(findFirstByClass(content, "dismiss-all-alerts-container"));
  }

  @Test
  void handleMethodGET_whenAlertsPresent_addsBulkDismissForms() throws Exception {
    PageNode pageNode = createPageNode();
    when(pageMaker.getPageNode(anyString(), eq(context))).thenReturn(pageNode);

    HTMLNode alertsNode = new HTMLNode("div");
    alertsNode.addChild("p", "message");
    when(alertManager.createAlerts(false)).thenReturn(alertsNode);
    HTTPRequest request = mock(HTTPRequest.class);

    toadlet.handleMethodGET(ALERTS_URI, request, context);

    HTMLNode container =
        findFirstByClass(pageNode.getContentNode(), "dismiss-all-alerts-container");
    assertNotNull(container);
    assertNotNull(findFirstInputByName(container, "dismissAllAlerts"));
    assertNotNull(findFirstInputByName(container, "deleteAllMessages"));
    assertNotNull(findFirstInputByName(container, "reallyDeleteAffirmed"));
    verify(alertManager).createAlerts(false);
  }

  @Test
  void handleMethodPOST_whenDismissingSingleAlert_delegatesToManager() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("dismiss-user-alert")).thenReturn(true);
    when(request.getIntPart("disable", -1)).thenReturn(42);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024)).thenReturn("/alerts/");

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    verify(alertManager).dismissAlert(42);
    assertRedirectLocation("/alerts/");
  }

  @Test
  void handleMethodPOST_whenDismissingAll_skipsNonDismissibleAndNodeMessages() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("dismissAllAlerts")).thenReturn(true);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024)).thenReturn("/alerts/");

    UserAlert dismissible = new SimpleAlert(true, 101);
    UserAlert nonDismissible = new SimpleAlert(false, 202);
    UserAlert nodeMessage = new MessageAlert(true, 303);

    when(alertManager.getAlerts())
        .thenReturn(new UserAlert[] {dismissible, nonDismissible, nodeMessage});

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    verify(alertManager).dismissAlert(101);
    verify(alertManager, never()).dismissAlert(202);
    verify(alertManager, never()).dismissAlert(303);
    assertRedirectLocation("/alerts/");
  }

  @Test
  void handleMethodPOST_whenDeletingMessages_deletesOnlyDismissibleMessages() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("deleteAllMessages")).thenReturn(true);
    when(request.isPartSet("reallyDeleteAffirmed")).thenReturn(true);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024)).thenReturn("/alerts/");

    UserAlert dismissibleMessage = new MessageAlert(true, 111);
    UserAlert nonDismissibleMessage = new MessageAlert(false, 222);
    UserAlert fileOffer = new FileOfferAlert(true, 333);
    UserAlert nonMessage = new SimpleAlert(true, 444);

    when(alertManager.getAlerts())
        .thenReturn(
            new UserAlert[] {dismissibleMessage, nonDismissibleMessage, fileOffer, nonMessage});

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    verify(alertManager).dismissAlert(111);
    verify(alertManager, never()).dismissAlert(222);
    verify(alertManager, never()).dismissAlert(333);
    verify(alertManager, never()).dismissAlert(444);
    assertRedirectLocation("/alerts/");
  }

  @Test
  void handleMethodPOST_whenRedirectNotAllowed_fallsBackToDot() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024))
        .thenReturn("http://example.com");

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    assertRedirectLocation(".");
  }

  @Test
  void handleMethodPOST_whenRedirectAllowed_usesProvidedValue() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024)).thenReturn("/#bookmarks");

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    assertRedirectLocation("/#bookmarks");
  }

  @Test
  void handleMethodPOST_whenRedirectParameterTooLarge_defaultsToDot() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringThrowing("redirectToAfterDisable", 1024))
        .thenThrow(new SizeLimitExceededException());

    toadlet.handleMethodPOST(ALERTS_URI, request, context);

    assertRedirectLocation(".");
  }

  @SuppressWarnings({"unchecked"})
  private void assertRedirectLocation(String expected) throws Exception {
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(context)
        .sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals(expected, headersCaptor.getValue().getFirst("Location"));
  }

  private PageNode createPageNode() {
    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode body = outer.addChild("body");
    HTMLNode content = body.addChild("div");
    return new PageNode(outer, head, content);
  }

  private HTMLNode findFirstByClass(HTMLNode root, String className) {
    if (className.equals(root.getAttribute("class"))) {
      return root;
    }
    for (HTMLNode child : root.getChildren()) {
      HTMLNode found = findFirstByClass(child, className);
      if (found != null) {
        return found;
      }
    }
    return null;
  }

  private HTMLNode findFirstInputByName(HTMLNode root, String name) {
    if ("input".equals(root.getName()) && name.equals(root.getAttribute("name"))) {
      return root;
    }
    for (HTMLNode child : root.getChildren()) {
      HTMLNode found = findFirstInputByName(child, name);
      if (found != null) {
        return found;
      }
    }
    return null;
  }

  private static class SimpleAlert implements UserAlert {
    private final boolean dismissible;
    private final int hash;
    private boolean valid = true;

    SimpleAlert(boolean dismissible, int hash) {
      this.dismissible = dismissible;
      this.hash = hash;
    }

    @Override
    public boolean userCanDismiss() {
      return dismissible;
    }

    @Override
    public String getTitle() {
      return null;
    }

    @Override
    public String getText() {
      return null;
    }

    @Override
    public HTMLNode getHTMLText() {
      return null;
    }

    @Override
    public String getShortText() {
      return null;
    }

    @Override
    public short getPriorityClass() {
      return MINOR;
    }

    @Override
    public boolean isValid() {
      return valid;
    }

    @Override
    public void isValid(boolean validity) {
      this.valid = validity;
    }

    @Override
    public String dismissButtonText() {
      return null;
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return false;
    }

    @Override
    public void onDismiss() {
      // No-op: test stub does not track dismissal side effects.
    }

    @Override
    public String anchor() {
      return Integer.toString(hash);
    }

    @Override
    @SuppressWarnings("java:S1185") // Explicit override keeps stub self-contained and readable.
    public boolean isEventNotification() {
      // Stub alerts behave as non-event notifications in these tests.
      return false;
    }

    @Override
    public FCPMessage getFCPMessage() {
      return null;
    }

    @Override
    public long getUpdatedTime() {
      return 0;
    }

    @Override
    public int hashCode() {
      return hash;
    }
  }

  private static class MessageAlert extends SimpleAlert implements NodeToNodeMessageUserAlert {
    MessageAlert(boolean dismissible, int hash) {
      super(dismissible, hash);
    }
  }

  private static class FileOfferAlert extends AbstractNodeToNodeFileOfferUserAlert {
    private final boolean dismissible;
    private final int hash;

    FileOfferAlert(boolean dismissible, int hash) {
      this.dismissible = dismissible;
      this.hash = hash;
    }

    @Override
    public boolean userCanDismiss() {
      return dismissible;
    }

    @Override
    public String getTitle() {
      return null;
    }

    @Override
    public String getText() {
      return null;
    }

    @Override
    public HTMLNode getHTMLText() {
      return null;
    }

    @Override
    public String getShortText() {
      return null;
    }

    @Override
    public short getPriorityClass() {
      return MINOR;
    }

    @Override
    public boolean isValid() {
      return true;
    }

    @Override
    public void isValid(boolean validity) {
      // Immutable test stub; validity changes are intentionally ignored.
    }

    @Override
    public String dismissButtonText() {
      return null;
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return false;
    }

    @Override
    public void onDismiss() {
      // No-op: test stub; dismissal hooks are irrelevant for these assertions.
    }

    @Override
    public String anchor() {
      return Integer.toString(hash);
    }

    @Override
    @SuppressWarnings("java:S1185") // Keeping explicit override to make stub intent clear.
    public boolean isEventNotification() {
      return false;
    }

    @Override
    public FCPMessage getFCPMessage() {
      return null;
    }

    @Override
    public long getUpdatedTime() {
      return 0;
    }

    @Override
    public int hashCode() {
      return hash;
    }
  }
}
