package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleHelpToadletTest {

  @Test
  void handleMethodGET_whenFullAccess_addsSummaryAndWritesHtml() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    NodeClientCore core = mock(NodeClientCore.class);
    SimpleHelpToadlet toadlet = spy(new SimpleHelpToadlet(client, core));

    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    PageNode pageNode = mock(PageNode.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode summaryNode = new HTMLNode("div");
    UserAlertManager alertManager = mock(UserAlertManager.class);
    HTTPRequest request = mock(HTTPRequest.class);

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn("generated-page");
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(summaryNode);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), anyBoolean()))
        .thenAnswer(invocation -> new HTMLNode("div"));

    AtomicReference<Integer> statusCode = new AtomicReference<>();
    AtomicReference<String> reasonPhrase = new AtomicReference<>();
    AtomicReference<String> body = new AtomicReference<>();
    doAnswer(
            invocation -> {
              statusCode.set(invocation.getArgument(1));
              reasonPhrase.set(invocation.getArgument(2));
              body.set(invocation.getArgument(3));
              return null;
            })
        .when(toadlet)
        .writeHTMLReply(eq(ctx), anyInt(), anyString(), anyString());

    toadlet.handleMethodGET(new URI("http://localhost/help/"), request, ctx);

    assertTrue(contentNode.getChildren().contains(summaryNode));
    assertEquals(200, statusCode.get());
    assertEquals("OK", reasonPhrase.get());
    assertEquals("generated-page", body.get());

    String expectedTitle = "Crypta " + NodeL10n.getBase().getString("FProxyToadlet.help");
    verify(pageMaker).getPageNode(expectedTitle, ctx);
  }

  @Test
  void handleMethodGET_whenRestricted_doesNotAddSummary() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    NodeClientCore core = mock(NodeClientCore.class);
    SimpleHelpToadlet toadlet = spy(new SimpleHelpToadlet(client, core));

    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    PageNode pageNode = mock(PageNode.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode summaryNode = new HTMLNode("div");

    HTTPRequest request = mock(HTTPRequest.class);

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn("generated-page");
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), anyBoolean()))
        .thenAnswer(invocation -> new HTMLNode("div"));

    doAnswer(invocation -> null)
        .when(toadlet)
        .writeHTMLReply(eq(ctx), anyInt(), anyString(), anyString());

    toadlet.handleMethodGET(new URI("http://localhost/help/"), request, ctx);

    assertFalse(contentNode.getChildren().contains(summaryNode));
    verify(toadlet).writeHTMLReply(ctx, 200, "OK", "generated-page");
  }

  @Test
  void path_whenCalled_returnsHelpPath() {
    SimpleHelpToadlet toadlet =
        new SimpleHelpToadlet(mock(HighLevelSimpleClient.class), mock(NodeClientCore.class));
    assertEquals("/help/", toadlet.path());
  }
}
