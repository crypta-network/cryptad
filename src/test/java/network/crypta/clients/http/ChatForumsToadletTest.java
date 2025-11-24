package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ChatForumsToadletTest {

  private static final String FREETALK_PLUGIN_CLASS = "plugins.Freetalk.Freetalk";

  @Mock private HighLevelSimpleClient client;
  @Mock private PluginManager pluginManager;
  @Mock private ToadletContext ctx;
  @Mock private PageMaker pageMaker;
  @Mock private UserAlertManager alertManager;
  @Mock private HTTPRequest request;

  private TestableChatForumsToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new TestableChatForumsToadlet(client, pluginManager);
  }

  @Test
  void path_whenCalled_returnsChatRoot() {
    assertEquals("/chat/", toadlet.path());
  }

  @Test
  void isEnabled_whenFreetalkPluginLoaded_returnsFalse() {
    when(pluginManager.isPluginLoaded(FREETALK_PLUGIN_CLASS)).thenReturn(true);

    assertFalse(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_whenFreetalkPluginNotLoaded_returnsTrue() {
    when(pluginManager.isPluginLoaded(FREETALK_PLUGIN_CLASS)).thenReturn(false);

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void handleMethodGET_whenCalled_writesLocalizedChatLinksAndReply()
      throws ToadletContextClosedException, IOException {
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "summary"));

    HTMLNode outer = new HTMLNode("div", "id", "outer");
    HTMLNode content = outer.addChild("div", "id", "content");
    PageNode page = new PageNode(outer, new HTMLNode("head"), content);

    String localizedTitle = NodeL10n.getBase().getString("ChatForumsToadlet.title");
    when(pageMaker.getPageNode(localizedTitle, ctx)).thenReturn(page);
    when(pageMaker.getInfobox(
            anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              String category = invocation.getArgument(0);
              String header = invocation.getArgument(1);
              HTMLNode parent = invocation.getArgument(2);
              String title = invocation.getArgument(3);
              boolean isUnique = invocation.getArgument(4);

              StringBuilder classes = new StringBuilder("infobox");
              if (category != null) {
                classes.append(" ").append(category);
              }
              if (title != null && !isUnique) {
                classes.append(" ").append(title);
              }

              HTMLNode infobox = new HTMLNode("div", "class", classes.toString());
              if (title != null && isUnique) {
                infobox.addAttribute("id", title);
              }

              infobox
                  .addChild("div", "class", "infobox-header")
                  .addChild(new HTMLNode("#", header));
              HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
              parent.addChild(infobox);
              return infoboxContent;
            });

    toadlet.handleMethodGET(URI.create("http://localhost/chat/"), request, ctx);

    assertEquals(200, toadlet.lastStatusCode);
    assertEquals("OK", toadlet.lastReasonPhrase);
    assertNotNull(toadlet.lastReplyBody);
    assertTrue(
        toadlet.lastReplyBody.contains(
            "/USK@t5zaONbYd5DvGNNSokVnDCdrIEytn9U5SSD~pYF0RTE,guWyS9aCMcywU5PFBrKsMiXs7LzwKfQlGSRi17fpffc,AQACAAE/fsng/-56/"),
        () -> toadlet.lastReplyBody);
    assertTrue(
        toadlet.lastReplyBody.contains(
            "/USK@0npnMrqZNKRCRoGojZV93UNHCMN-6UU3rRSAmP6jNLE,~BG-edFtdCC1cSH4O3BWdeIYa8Sw5DfyrSV-TKdO5ec,AQACAAE/fms/-137/"),
        () -> toadlet.lastReplyBody);
    assertTrue(
        toadlet.lastReplyBody.contains(
            "/USK@nwa8lHa271k2QvJ8aa0Ov7IHAV-DFOCFgmDt3X6BpCI,DuQSUZiI~agF8c-6tjsFFGuZ8eICrzWCILB60nT8KKo,AQACAAE/sone/-72/"),
        () -> toadlet.lastReplyBody);
    assertTrue(toadlet.lastReplyBody.contains("id=\"summary\""), () -> toadlet.lastReplyBody);

    verify(pageMaker).getPageNode(localizedTitle, ctx);
  }

  private static final class TestableChatForumsToadlet extends ChatForumsToadlet {

    private Integer lastStatusCode;
    private String lastReasonPhrase;
    private String lastReplyBody;

    TestableChatForumsToadlet(HighLevelSimpleClient client, PluginManager plugins) {
      super(client, plugins);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      this.lastStatusCode = code;
      this.lastReasonPhrase = desc;
      this.lastReplyBody = reply;
    }
  }
}
