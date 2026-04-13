package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class StartupToadletTest {

  private static final String HTML_REPLY = "<html>generated</html>";

  @Test
  void handleMethodGET_withStaticPath_delegatesToStaticToadlet()
      throws IOException, RedirectException, ToadletContextClosedException {
    StaticToadlet staticToadlet = mock(StaticToadlet.class);
    StartupToadlet toadlet = new StartupToadlet(staticToadlet);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest req = mock(HTTPRequest.class);
    URI uri = URI.create(StaticToadlet.ROOT_URL + "file.css");

    toadlet.handleMethodGET(uri, req, ctx);

    InOrder inOrder = inOrder(ctx, staticToadlet);
    inOrder.verify(ctx).forceDisconnect();
    inOrder.verify(staticToadlet).handleMethodGET(uri, req, ctx);
    verifyNoMoreInteractions(staticToadlet);
  }

  @Test
  void handleMethodGET_whenNotStaticAndPrngNotReady_rendersErrorAndRefresh()
      throws IOException, RedirectException, ToadletContextClosedException {
    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    HTMLNode headNode = new HTMLNode("head");
    HTMLNode contentNode = new HTMLNode("div");
    PageNode pageNode = mock(PageNode.class);
    when(pageNode.getHeadNode()).thenReturn(headNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(HTML_REPLY);

    BaseL10n l10n = mock(BaseL10n.class);
    when(l10n.getString(anyString())).thenAnswer(inv -> inv.getArgument(0));
    when(l10n.getString("StartupToadlet.title")).thenReturn("Startup Title");
    when(l10n.getString("StartupToadlet.entropyErrorTitle")).thenReturn("Entropy Error");
    when(l10n.getString("StartupToadlet.entropyErrorContent")).thenReturn("Need Entropy");
    when(l10n.getString("StartupToadlet.isStartingUp")).thenReturn("Starting Up");

    try (MockedStatic<NodeL10n> nodeL10n = org.mockito.Mockito.mockStatic(NodeL10n.class);
        MockedStatic<LegacyWelcomePageSupport> welcomePageSupport =
            org.mockito.Mockito.mockStatic(LegacyWelcomePageSupport.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(l10n);

      when(pageMaker.getPageNode(eq("Startup Title"), eq(ctx), any(RenderParameters.class)))
          .thenReturn(pageNode);

      AtomicReference<HTMLNode> prngInfobox = new AtomicReference<>();
      AtomicReference<HTMLNode> statusInfobox = new AtomicReference<>();
      org.mockito.Mockito.doAnswer(
              invocation -> {
                String header = invocation.getArgument(1);
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode box = new HTMLNode("div");
                parent.addChild(box);
                if ("Entropy Error".equals(header)) {
                  prngInfobox.set(box);
                }
                if ("Startup Title".equals(header)) {
                  statusInfobox.set(box);
                }
                return box;
              })
          .when(pageMaker)
          .getInfobox(anyString(), anyString(), eq(contentNode), isNull(), eq(true));

      StartupToadlet toadlet = new StartupToadlet(null);

      toadlet.handleMethodGET(URI.create("/"), mock(HTTPRequest.class), ctx);

      verify(ctx).forceDisconnect();
      verify(pageMaker).getPageNode(eq("Startup Title"), eq(ctx), any(RenderParameters.class));

      assertTrue(
          headNode.getChildren().stream()
              .anyMatch(
                  child ->
                      "meta".equals(child.getName())
                          && "refresh".equals(child.getAttribute("http-equiv"))
                          && "1; url=".equals(child.getAttribute("content"))),
          "Meta refresh tag should be present");

      HTMLNode prngBox = prngInfobox.get();
      assertTrue(
          prngBox.getChildren().stream()
              .anyMatch(
                  node -> "#".equals(node.getName()) && "Need Entropy".equals(node.getContent())));

      HTMLNode statusBox = statusInfobox.get();
      assertTrue(
          statusBox.getChildren().stream()
              .anyMatch(
                  node -> "#".equals(node.getName()) && "Starting Up".equals(node.getContent())));

      welcomePageSupport.verify(
          () -> LegacyWelcomePageSupport.maybeDisplayWrapperLogfile(ctx, contentNode));

      int expectedLength = HTML_REPLY.getBytes(StandardCharsets.UTF_8).length;
      verify(ctx)
          .sendReplyHeaders(
              eq(503),
              eq("Startup Title"),
              isNull(),
              eq("text/html; charset=utf-8"),
              eq((long) expectedLength));

      ArgumentCaptor<byte[]> bodyCaptor = ArgumentCaptor.forClass(byte[].class);
      ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
      ArgumentCaptor<Integer> lengthCaptor = ArgumentCaptor.forClass(Integer.class);
      verify(ctx).writeData(bodyCaptor.capture(), offsetCaptor.capture(), lengthCaptor.capture());

      assertEquals(HTML_REPLY, new String(bodyCaptor.getValue(), StandardCharsets.UTF_8));
      assertEquals(0, offsetCaptor.getValue());
      assertEquals(expectedLength, lengthCaptor.getValue());
    }
  }

  @Test
  void handleMethodGET_whenPrngReady_skipsEntropyInfobox()
      throws IOException, RedirectException, ToadletContextClosedException {
    ToadletContext ctx = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    HTMLNode headNode = new HTMLNode("head");
    HTMLNode contentNode = new HTMLNode("div");
    PageNode pageNode = mock(PageNode.class);
    when(pageNode.getHeadNode()).thenReturn(headNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(HTML_REPLY);

    BaseL10n l10n = mock(BaseL10n.class);
    when(l10n.getString(anyString())).thenAnswer(inv -> inv.getArgument(0));
    when(l10n.getString("StartupToadlet.title")).thenReturn("Startup Title");
    when(l10n.getString("StartupToadlet.isStartingUp")).thenReturn("Starting Up");

    try (MockedStatic<NodeL10n> nodeL10n = org.mockito.Mockito.mockStatic(NodeL10n.class);
        MockedStatic<LegacyWelcomePageSupport> welcomePageSupport =
            org.mockito.Mockito.mockStatic(LegacyWelcomePageSupport.class)) {
      nodeL10n.when(NodeL10n::getBase).thenReturn(l10n);

      when(pageMaker.getPageNode(eq("Startup Title"), eq(ctx), any(RenderParameters.class)))
          .thenReturn(pageNode);

      org.mockito.Mockito.doAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode box = new HTMLNode("div");
                parent.addChild(box);
                return box;
              })
          .when(pageMaker)
          .getInfobox(anyString(), anyString(), eq(contentNode), isNull(), eq(true));

      StartupToadlet toadlet = new StartupToadlet(null);
      toadlet.setIsPRNGReady();

      toadlet.handleMethodGET(URI.create("/"), mock(HTTPRequest.class), ctx);

      verify(pageMaker, never())
          .getInfobox(
              eq("infobox-error"),
              eq("StartupToadlet.entropyErrorTitle"),
              any(),
              any(),
              anyBoolean());
      assertFalse(
          contentNode.getChildren().stream()
              .flatMap(node -> node.getChildren().stream())
              .anyMatch(child -> "Need Entropy".equals(child.getContent())),
          "Entropy infobox should be skipped when PRNG is ready");

      welcomePageSupport.verify(
          () -> LegacyWelcomePageSupport.maybeDisplayWrapperLogfile(ctx, contentNode));
    }
  }

  @Test
  void path_returnsRoot() {
    StartupToadlet toadlet = new StartupToadlet(null);
    assertEquals("/", toadlet.path());
  }
}
