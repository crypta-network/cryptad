package network.crypta.clients.http;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Arrays;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BrowserTestToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock private HTTPRequest request;

  @Mock private ToadletContext ctx;

  @Mock private PageMaker pageMaker;

  @Mock private PageNode pageNode;

  @Mock private UserAlertManager alertManager;

  @Test
  void path_whenCalled_returnsTestEndpoint() {
    BrowserTestToadlet toadlet = new BrowserTestToadlet(client);

    String result = toadlet.path();

    assertEquals("/test/", result);
  }

  @Test
  void handleMethodGET_whenWontloadParameterSet_exitsEarly() throws Exception {
    BrowserTestToadlet toadlet = new BrowserTestToadlet(client);
    when(request.isParameterSet("wontload")).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/test/"), request, ctx);

    verify(request, times(1)).isParameterSet("wontload");
    verify(ctx, never()).getPageMaker();
    verify(ctx, never())
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodGET_whenFullAccess_addsSummaryAndWritesPage() throws Exception {
    BrowserTestToadlet toadlet = new BrowserTestToadlet(client);
    HTMLNode contentNode = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode mimeInfobox = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode maxConnections = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode javascriptBox = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode summaryNode = mock(HTMLNode.class, Answers.RETURNS_SELF);
    String generatedHtml = "page-html";

    when(request.isParameterSet("wontload")).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(summaryNode);
    when(pageMaker.getPageNode("Crypta browser testing tool", ctx)).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(generatedHtml);
    when(pageMaker.getInfobox(
            "infobox-warning", "MIME Inline", contentNode, "mime-inline-test", true))
        .thenReturn(mimeInfobox);
    when(pageMaker.getInfobox(
            "infobox-warning", "Number of connections", contentNode, "browser-connections", true))
        .thenReturn(maxConnections);
    when(pageMaker.getInfobox(
            "infobox-warning", "Javascript", contentNode, "javascript-test", true))
        .thenReturn(javascriptBox);

    toadlet.handleMethodGET(URI.create("http://localhost/test/"), request, ctx);

    verify(contentNode).addChild(summaryNode);

    ArgumentCaptor<String> mimeTag = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String[]> mimeAttrs = ArgumentCaptor.forClass(String[].class);
    ArgumentCaptor<String[]> mimeValues = ArgumentCaptor.forClass(String[].class);
    verify(mimeInfobox).addChild(mimeTag.capture(), mimeAttrs.capture(), mimeValues.capture());
    String[] capturedAttrs = mimeAttrs.getValue();
    String[] capturedValues = mimeValues.getValue();
    assertEquals("img", mimeTag.getValue());
    assertEquals(Arrays.asList("src", "alt"), Arrays.asList(capturedAttrs));
    assertTrue(capturedValues[0].startsWith("data:image/gif;base64,"));
    assertEquals("Your browser is probably safe.", capturedValues[1]);

    ArgumentCaptor<String> connTag = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String> connText = ArgumentCaptor.forClass(String.class);
    verify(maxConnections).addChild(connTag.capture(), connText.capture());
    assertEquals("#", connTag.getValue());
    assertTrue(connText.getValue().contains("more than 10 connections per server"));
    verify(maxConnections, times(10)).addChild("img", "src", ".?wontload");
    ArgumentCaptor<String> successTag = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String[]> successAttrs = ArgumentCaptor.forClass(String[].class);
    ArgumentCaptor<String[]> successValues = ArgumentCaptor.forClass(String[].class);
    verify(maxConnections)
        .addChild(successTag.capture(), successAttrs.capture(), successValues.capture());
    assertEquals("img", successTag.getValue());
    assertArrayEquals(new String[] {"src", "alt"}, successAttrs.getValue());
    assertArrayEquals(
        new String[] {"/static/themes/clean/success.png", "fail!"}, successValues.getValue());

    verify(javascriptBox).addChild("div");
    ArgumentCaptor<String> jsTag = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String[]> jsAttrs = ArgumentCaptor.forClass(String[].class);
    ArgumentCaptor<String[]> jsValues = ArgumentCaptor.forClass(String[].class);
    verify(javascriptBox).addChild(jsTag.capture(), jsAttrs.capture(), jsValues.capture());
    assertEquals("img", jsTag.getValue());
    assertArrayEquals(new String[] {"id", "src", "alt"}, jsAttrs.getValue());
    assertArrayEquals(
        new String[] {"JSTEST", "/static/themes/clean/success.png", "fail!"}, jsValues.getValue());
    verify(javascriptBox).addChild("script", "type", "text/javascript");
    verify(javascriptBox)
        .addChild(
            "%", "document.getElementById('JSTEST').src = '/static/themes/clean/warning.png';");

    byte[] htmlBytes = generatedHtml.getBytes(UTF_8);
    verify(ctx)
        .sendReplyHeaders(200, "OK", null, "text/html; charset=utf-8", htmlBytes.length, true);
    verify(ctx).writeData(htmlBytes, 0, htmlBytes.length);
  }

  @Test
  void handleMethodGET_whenFullAccessDenied_skipsAlertSummary() throws Exception {
    BrowserTestToadlet toadlet = new BrowserTestToadlet(client);
    HTMLNode contentNode = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode mimeInfobox = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode maxConnections = mock(HTMLNode.class, Answers.RETURNS_SELF);
    HTMLNode javascriptBox = mock(HTMLNode.class, Answers.RETURNS_SELF);
    String generatedHtml = "html";

    when(request.isParameterSet("wontload")).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(pageMaker.getPageNode("Crypta browser testing tool", ctx)).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(generatedHtml);
    when(pageMaker.getInfobox(
            "infobox-warning", "MIME Inline", contentNode, "mime-inline-test", true))
        .thenReturn(mimeInfobox);
    when(pageMaker.getInfobox(
            "infobox-warning", "Number of connections", contentNode, "browser-connections", true))
        .thenReturn(maxConnections);
    when(pageMaker.getInfobox(
            "infobox-warning", "Javascript", contentNode, "javascript-test", true))
        .thenReturn(javascriptBox);

    toadlet.handleMethodGET(URI.create("http://localhost/test/"), request, ctx);

    verify(ctx, never()).getAlertManager();
    verify(contentNode, never()).addChild(any(HTMLNode.class));
    byte[] htmlBytes = generatedHtml.getBytes(UTF_8);
    verify(ctx)
        .sendReplyHeaders(200, "OK", null, "text/html; charset=utf-8", htmlBytes.length, true);
    verify(ctx).writeData(htmlBytes, 0, htmlBytes.length);
  }
}
