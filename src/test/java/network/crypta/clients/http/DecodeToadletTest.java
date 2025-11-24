package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.NodeClientCore;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DecodeToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private NodeClientCore core;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private PageMaker pageMaker;
  @Mock private PageNode pageNode;
  @Mock private HTMLNode contentNode;
  @Mock private HTMLNode infoboxContentNode;
  @Mock private UserAlertManager alertManager;

  private DecodeToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = spy(new DecodeToadlet(client, core));
  }

  private void mockPageRenderingChain() {
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode("Redirect to Decoded link", ctx)).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageMaker.getInfobox(
            "infobox-warning", "Decode Link", contentNode, "decode-not-redirected", true))
        .thenReturn(infoboxContentNode);
  }

  @Test
  void handleMethodGET_whenFullAccess_addsAlertSummaryAndRedirects() throws Exception {
    mockPageRenderingChain();
    String generatedHtml = "<html>page</html>";
    when(pageNode.generate()).thenReturn(generatedHtml);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    HTMLNode summaryNode = new HTMLNode("div", "summary");
    when(alertManager.createSummary()).thenReturn(summaryNode);
    when(request.getPath()).thenReturn("/decode/abc");

    doNothing()
        .when(toadlet)
        .writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: /abc", generatedHtml);

    toadlet.handleMethodGET(URI.create("http://localhost/decode/abc"), request, ctx);

    verify(contentNode).addChild(summaryNode);
    verify(pageMaker)
        .getInfobox("infobox-warning", "Decode Link", contentNode, "decode-not-redirected", true);
    verify(infoboxContentNode).addChild("a", "href", "/abc", "Click Here to be re-directed");
    verify(toadlet).writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: /abc", generatedHtml);
  }

  @Test
  void handleMethodGET_whenNotFullAccess_skipsAlertSummary() throws Exception {
    mockPageRenderingChain();
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(request.getPath()).thenReturn("/decode/test");
    when(pageNode.generate()).thenReturn("<html>body</html>");

    doNothing()
        .when(toadlet)
        .writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: /test", "<html>body</html>");

    toadlet.handleMethodGET(URI.create("http://localhost/decode/test"), request, ctx);

    verify(alertManager, never()).createSummary();
    verify(contentNode, never()).addChild(org.mockito.ArgumentMatchers.<HTMLNode>any());
  }

  @Test
  void handleMethodGET_whenRequestIsRoot_redirectsToRootPath() throws Exception {
    mockPageRenderingChain();
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(request.getPath()).thenReturn("/decode/");
    when(pageNode.generate()).thenReturn("<html>root</html>");

    doNothing()
        .when(toadlet)
        .writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: /", "<html>root</html>");

    toadlet.handleMethodGET(URI.create("http://localhost/decode/"), request, ctx);

    verify(infoboxContentNode).addChild("a", "href", "/", "Click Here to be re-directed");
    verify(toadlet).writeHTMLReply(ctx, 301, "Moved Permanently\nLocation: /", "<html>root</html>");
  }

  @Test
  void path_whenInvoked_returnsDecodePath() {
    DecodeToadlet freshToadlet = new DecodeToadlet(mock(HighLevelSimpleClient.class), core);

    assertEquals("/decode/", freshToadlet.path());
  }
}
