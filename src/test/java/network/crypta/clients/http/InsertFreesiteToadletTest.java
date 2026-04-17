package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class InsertFreesiteToadletTest {

  @Mock private BrowseContentClient client;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private UserAlertManager alertManager;
  @Mock private PageMaker pageMaker;

  private InsertFreesiteToadlet toadlet;

  @BeforeEach
  void setUp() {
    // Ensure the localization base is initialized for deterministic string lookups.
    new NodeL10n();
    toadlet = new InsertFreesiteToadlet(client);
  }

  @Test
  void path_whenCalled_returnsMountPath() {
    assertEquals("/insertsite/", toadlet.path());
  }

  @Test
  void handleMethodGET_whenCalled_buildsAndWritesHtmlPage() throws Exception {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode head = outer.addChild("head");
    HTMLNode content = outer.addChild("div", "id", "content");
    PageNode pageNode = new PageNode(outer, head, content);

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("summary"));

    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(pageNode);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(content), anyString(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              String category = invocation.getArgument(0);
              String header = invocation.getArgument(1);
              HTMLNode parent = invocation.getArgument(2);
              String title = invocation.getArgument(3);
              boolean isUnique = invocation.getArgument(4);

              HTMLNode infobox =
                  new HTMLNode("div", "class", "infobox " + (category == null ? "" : category));
              if (isUnique && title != null) {
                infobox.addAttribute("id", title);
              }
              infobox.addChild("div", "class", "infobox-header").addChild("#", header);
              HTMLNode contentNode = infobox.addChild("div", "class", "infobox-content");
              parent.addChild(infobox);
              return contentNode;
            });

    doNothing().when(ctx).sendReplyHeaders(eq(200), eq("OK"), isNull(), anyString(), anyLong());
    doNothing().when(ctx).writeData(any(byte[].class), anyInt(), anyInt());

    toadlet.handleMethodGET(new URI("http://localhost/insertsite/"), request, ctx);

    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);
    verify(ctx)
        .sendReplyHeaders(
            eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), lengthCaptor.capture());

    ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> writtenLengthCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(ctx)
        .writeData(dataCaptor.capture(), offsetCaptor.capture(), writtenLengthCaptor.capture());

    String body = new String(dataCaptor.getValue(), StandardCharsets.UTF_8);

    assertEquals(0, offsetCaptor.getValue());
    assertEquals(dataCaptor.getValue().length, writtenLengthCaptor.getValue());
    assertEquals(dataCaptor.getValue().length, lengthCaptor.getValue());

    assertTrue(body.contains("Publish!"));
    assertTrue(body.contains("Freesite HOWTO"));
    assertFalse(body.contains("/plugins/"));
    assertTrue(body.contains("/jSite-15/"));
    assertTrue(body.contains("thingamablog.zip"));
    assertTrue(body.contains("freesite-insert"));
    assertTrue(body.contains("<summary"));
  }
}
