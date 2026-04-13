package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class WebShellToadletTest {
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;
  @Mock private HTTPRequest request;

  private WebShellToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new WebShellToadlet();
  }

  @Test
  void path_whenRequested_expectShellRoot() {
    assertEquals(WebShellPaths.SHELL_ROOT, toadlet.path());
  }

  @Test
  void handleMethodGET_whenShellRootRequested_expectRenderedHtmlBootstrap() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.getContainer()).thenReturn(container);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/app/node/"), request, ctx);

    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(200, replyHeaders.statusCode());
    assertEquals("OK", replyHeaders.reasonPhrase());
    assertEquals("text/html; charset=UTF-8", replyHeaders.mimeType());

    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertTrue(bodyWrite.bodyText().contains(WebShellPaths.BOOTSTRAP_ELEMENT_ID));
    assertTrue(bodyWrite.bodyText().contains("\"shellRoot\":\"/app/node/\""));
    assertTrue(bodyWrite.bodyText().contains("\"platformApiRoot\":\"/api/v1/\""));
  }

  @Test
  void handleMethodGET_whenAssetRequested_expectStaticAssetResponse() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/app/node/static/web-shell.js"), request, ctx);

    ArgumentCaptor<String> mimeType = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> length = ArgumentCaptor.forClass(Long.class);
    verify(ctx)
        .sendReplyHeadersStatic(
            eq(200), eq("OK"), isNull(), mimeType.capture(), length.capture(), any());

    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(DefaultMIMETypes.guessMIMEType("web-shell.js", false), mimeType.getValue());
    assertEquals(bodyWrite.length(), length.getValue());
    assertTrue(bodyWrite.bodyText().contains("loadShellData"));
  }

  @Test
  void handleMethodGET_whenFullAccessDenied_expectNoShellBodyWritten() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create("http://localhost/app/node/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenJavascriptDisabled_expectRedirectToLegacyRoot() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.getContainer()).thenReturn(container);
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);

    toadlet.handleMethodGET(URI.create("http://localhost/app/node/"), request, ctx);

    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(302, replyHeaders.statusCode());
    assertEquals("Found", replyHeaders.reasonPhrase());
    assertEquals(
        LauncherReadinessInfo.DEFAULT_UI_ROOT, replyHeaders.headers().getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenRouteUnknown_expectNotFound() throws Exception {
    WebShellToadlet spyToadlet = spy(new WebShellToadlet());
    PageMaker pageMaker = mock(PageMaker.class);
    PageNode pageNode = mock(PageNode.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    AtomicReference<Integer> statusCode = new AtomicReference<>();
    AtomicReference<String> reasonPhrase = new AtomicReference<>();
    AtomicReference<String> body = new AtomicReference<>();

    when(ctx.checkFullAccess(spyToadlet)).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn("generated-page");
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), isNull(), anyBoolean()))
        .thenReturn(infoboxNode);
    doAnswer(
            invocation -> {
              statusCode.set(invocation.getArgument(1));
              reasonPhrase.set(invocation.getArgument(2));
              body.set(invocation.getArgument(3));
              return null;
            })
        .when(spyToadlet)
        .writeHTMLReply(eq(ctx), anyInt(), anyString(), anyString());

    spyToadlet.handleMethodGET(URI.create("http://localhost/app/node/unknown"), request, ctx);

    assertEquals(404, statusCode.get());
    assertEquals("Not Found", reasonPhrase.get());
    assertEquals("generated-page", body.get());
    assertTrue(infoboxNode.generate().contains("Web Shell route not found."));
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

  private record ReplyHeadersCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length) {}

  private record BodyWriteCapture(String bodyText, int offset, int length) {}
}
