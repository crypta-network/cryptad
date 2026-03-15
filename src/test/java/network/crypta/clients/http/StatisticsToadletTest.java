package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerStatusCounts;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.StatisticsPageSnapshot;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class StatisticsToadletTest {

  private static final String TEST_FORM_PASSWORD = "test-form-password";

  @Mock private HighLevelSimpleClient client;
  @Mock private StatisticsPort statistics;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private StatisticsToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new StatisticsToadlet(client, statistics);
  }

  @Test
  void path_returnsStatsPath() {
    assertEquals("/stats/", toadlet.path());
  }

  @Test
  void path_whenCustomPathConfigured_returnsConfiguredPath() {
    StatisticsToadlet customPathToadlet =
        new StatisticsToadlet(client, statistics, "/custom-stats/");

    assertEquals("/custom-stats/", customPathToadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_returnsWithoutFurtherInteraction() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create("/stats/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoInteractions(statistics);
    verify(ctx, never()).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenOverviewRequested_rendersDetachedOverviewAndRequestContextContent()
      throws Exception {
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert-summary"));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.getPath()).thenReturn("/stats/");
    when(statistics.overview(false))
        .thenReturn(
            new StatisticsPageSnapshot(
                """
                <div id="detached-overview">overview</div>
                <!--CRYPTA_ALERT_SUMMARY-->
                <!--CRYPTA_STAT_GATHERING_BOX-->
                """,
                true,
                true));
    stubFormChild(ctx);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/stats/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("detached-overview"));
    assertTrue(html.contains("alert-summary"));
    assertTrue(html.contains("threadDumpForm"));
    assertTrue(html.contains("formPassword"));
    assertTrue(html.contains(TEST_FORM_PASSWORD));
    assertTrue(html.contains("/?latestlog"));
    verify(statistics).overview(false);
    verify(statistics, never()).requesters();
  }

  @Test
  void handleMethodGET_whenAdvancedOverviewRequested_callsAdvancedSnapshot() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.getPath()).thenReturn("/stats/");
    when(statistics.overview(true))
        .thenReturn(
            new StatisticsPageSnapshot(
                """
                <div id="advanced-overview">advanced</div>
                <!--CRYPTA_ALERT_SUMMARY-->
                <!--CRYPTA_STAT_GATHERING_BOX-->
                """,
                false,
                false));

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/stats/"), request, ctx);

    assertTrue(body.toString(StandardCharsets.UTF_8).contains("advanced-overview"));
    verify(statistics).overview(true);
    verify(statistics, never()).requesters();
  }

  @Test
  void handleMethodGET_whenRequestersRequested_callsRequestersOnly() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.getPath()).thenReturn("/stats/requesters.html");
    when(statistics.requesters())
        .thenReturn(
            new StatisticsPageSnapshot("<div id=\"requesters\">requesters</div>", false, false));

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/stats/requesters.html"), request, ctx);

    assertTrue(body.toString(StandardCharsets.UTF_8).contains("requesters"));
    verify(statistics).requesters();
    verify(statistics, never()).overview(false);
    verify(statistics, never()).overview(true);
  }

  @Test
  void drawPeerStatsBox_whenCountsZero_doesNotRenderStatusEntries() {
    HTMLNode infobox = new HTMLNode("div");
    Node nodeWithoutOpennet = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkWithoutOpennet =
        mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(nodeWithoutOpennet.network()).thenReturn(networkWithoutOpennet);
    when(networkWithoutOpennet.opennet()).thenReturn(null);

    StatisticsToadlet.drawPeerStatsBox(
        infobox,
        false,
        new PeerStatusCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        nodeWithoutOpennet);

    String rendered = infobox.generate();

    assertTrue(rendered.contains("<ul>"));
    assertFalse(rendered.contains("peer_connected"));
    assertFalse(rendered.contains("peer_backed_off"));
  }

  @Test
  void drawPeerStatsBox_whenCountsPresent_rendersEntriesAndOpennetTotals() {
    HTMLNode infobox = new HTMLNode("div");
    Node nodeWithOpennet = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    OpennetManager opennet = mock(OpennetManager.class);
    when(opennet.getNumberOfConnectedPeersToAimIncludingDarknet()).thenReturn(7);
    when(opennet.getNumberOfConnectedPeersToAim()).thenReturn(3);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkWithOpennet =
        mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(nodeWithOpennet.network()).thenReturn(networkWithOpennet);
    when(networkWithOpennet.opennet()).thenReturn(opennet);

    StatisticsToadlet.drawPeerStatsBox(
        infobox,
        true,
        new PeerStatusCounts(2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
        nodeWithOpennet);

    String rendered = infobox.generate();

    assertTrue(rendered.contains("peer_connected"));
    assertTrue(rendered.contains("peer_backed_off"));
    assertTrue(rendered.contains("peer_too_new"));
    assertTrue(rendered.contains("peer_listening"));
    assertTrue(rendered.contains("7"));
    assertTrue(rendered.contains("3"));
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    return pageMaker;
  }

  private void stubFormChild(ToadletContext context) {
    doAnswer(
            invocation -> {
              HTMLNode parentNode = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode formNode =
                  parentNode
                      .addChild("div")
                      .addChild(
                          "form",
                          new String[] {"action", "method", "enctype", "id", "accept-charset"},
                          new String[] {target, "post", "multipart/form-data", id, "utf-8"});
              formNode.addChild(
                  "input",
                  new String[] {"type", "name", "value"},
                  new String[] {"hidden", "formPassword", TEST_FORM_PASSWORD});
              return formNode;
            })
        .when(context)
        .addFormChild(any(HTMLNode.class), anyString(), anyString());
  }

  private ByteArrayOutputStream captureBody(ToadletContext context) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    doAnswer(_ -> null)
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doAnswer(
            invocation -> {
              byte[] data = invocation.getArgument(0);
              int offset = invocation.getArgument(1);
              int length = invocation.getArgument(2);
              body.write(data, offset, length);
              return null;
            })
        .when(context)
        .writeData(any(byte[].class), anyInt(), anyInt());
    return body;
  }
}
