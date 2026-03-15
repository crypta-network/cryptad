package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.ConnectivityPortForwardStatus;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficInitiator;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConnectivityToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private ConnectivityPort connectivity;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private ConnectivityToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new ConnectivityToadlet(client, connectivity);
  }

  @Test
  void path_whenCalled_returnsConnectivityPath() {
    assertEquals(ConnectivityToadlet.CONNECTIVITY_PATH, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAdvancedDisabled_rendersPortSummaryAndAlertBox() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    when(connectivity.snapshot(false)).thenReturn(nonAdvancedSnapshot(null));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("12345"), "Should list darknet FNP port");
    assertTrue(html.contains("33333"), "Should list opennet FNP port when configured");
    assertTrue(html.contains("8080"), "Should list enabled fproxy port");
    assertTrue(html.contains("udp-9999"), "Should render the socket summary row");
    assertTrue(
        html.contains(
            NodeL10n.getBase()
                .getString(
                    "ConnectivityToadlet.status."
                        + ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED)),
        "Should render the localized socket status");
    assertTrue(html.contains("alert"), "Should render alert summary for full access users");

    verify(connectivity).snapshot(false);
    verify(ctx).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodGET_whenAdvancedEnabled_rendersPeerAndIpTables() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    when(connectivity.snapshot(true)).thenReturn(advancedSnapshot());

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("1.1.1.1:4242"), "Peer table should include peer address");
    assertTrue(html.contains("/2.2.2.2"), "IP table should include raw IP");
    assertTrue(html.contains("udp-9999"), "Summary should list handler title");
    assertTrue(
        html.contains(NodeL10n.getBase().getString("ConnectivityToadlet.local")),
        "Advanced table should render initiator labels");

    verify(connectivity).snapshot(true);
  }

  @Test
  void handleMethodGET_whenGapHistoryShorterThanHeader_padsRenderedGapCells() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    when(connectivity.snapshot(true))
        .thenReturn(
            advancedSnapshot(
                List.of(
                    new ConnectivityGapSnapshot(10_000L, 20_000L),
                    new ConnectivityGapSnapshot(5_000L, 15_000L)),
                null));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertEquals(12, renderedTableCellCount(html), "Should render five gap cells for the row");
  }

  @Test
  void handleMethodGET_whenGapHistoryLongerThanHeader_clampsRenderedGapCells() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    when(connectivity.snapshot(true))
        .thenReturn(
            advancedSnapshot(
                null,
                List.of(
                    new ConnectivityGapSnapshot(10_000L, 20_000L),
                    new ConnectivityGapSnapshot(20_000L, 30_000L),
                    new ConnectivityGapSnapshot(30_000L, 40_000L),
                    new ConnectivityGapSnapshot(40_000L, 50_000L),
                    new ConnectivityGapSnapshot(50_000L, 60_000L),
                    new ConnectivityGapSnapshot(60_000L, 70_000L))));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertEquals(12, renderedTableCellCount(html), "Should clamp the row to five gap cells");
  }

  @Test
  void handleMethodGET_whenNoticePresent_rendersDetachedConnectionTypeAlertHtml() throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    ConnectivityNoticeSnapshot notice =
        new ConnectivityNoticeSnapshot(
            "Connection Type",
            "Port restricted NAT detected",
            """
            <div class="infobox infobox-warning">
            \t<div class="infobox-header">Connection Type</div>
            \t<div class="infobox-content"><a href="/help">Forward a port</a><form><div><input type="submit" name="dismiss-user-alert" value="Hide" /></div></form></div>
            </div>
            """);
    when(connectivity.snapshot(false)).thenReturn(nonAdvancedSnapshot(notice));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains("infobox-warning"), "Should preserve the alert severity infobox");
    assertTrue(html.contains("Forward a port"), "Should preserve the actionable help link");
    assertTrue(html.contains("dismiss-user-alert"), "Should preserve the dismiss control");
  }

  @Test
  void handleMethodGET_whenRenderedNoticeHtmlUnavailable_rendersDetachedConnectionTypeNotice()
      throws Exception {
    HTMLNode content = new HTMLNode("div");
    PageMaker pageMaker = stubPageMaker(content);
    ConnectivityNoticeSnapshot notice =
        new ConnectivityNoticeSnapshot("Connection Type", "Port restricted NAT detected", "");
    when(connectivity.snapshot(false)).thenReturn(nonAdvancedSnapshot(notice));

    UserAlertManager alertManager = mock(UserAlertManager.class);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.getPageMaker()).thenReturn(pageMaker);

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/connectivity/"), request, ctx);

    String html = body.toString(StandardCharsets.UTF_8);

    assertTrue(html.contains(notice.title()), "Should render the notice title");
    assertTrue(html.contains(notice.text()), "Should render the notice body");
  }

  private ConnectivitySnapshot nonAdvancedSnapshot(ConnectivityNoticeSnapshot notice) {
    return new ConnectivitySnapshot(
        12345,
        33333,
        new ConnectivityListenerPortSnapshot(true, 8080),
        new ConnectivityListenerPortSnapshot(false, 0),
        new ConnectivityListenerPortSnapshot(false, 0),
        notice,
        List.of(
            new ConnectivitySocketSnapshot(
                "udp-9999",
                ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED,
                -1,
                List.of(),
                List.of())));
  }

  private ConnectivitySnapshot advancedSnapshot() {
    return advancedSnapshot(gapHistory(), gapHistory());
  }

  private ConnectivitySnapshot advancedSnapshot(
      List<ConnectivityGapSnapshot> peerGaps, List<ConnectivityGapSnapshot> ipGaps) {
    return new ConnectivitySnapshot(
        54321,
        0,
        new ConnectivityListenerPortSnapshot(false, 0),
        new ConnectivityListenerPortSnapshot(true, 9481),
        new ConnectivityListenerPortSnapshot(true, 2222),
        null,
        List.of(
            new ConnectivitySocketSnapshot(
                "udp-9999",
                ConnectivityPortForwardStatus.DEFINITELY_PORT_FORWARDED,
                12_345L,
                peerEntries(peerGaps),
                ipEntries(ipGaps))));
  }

  private List<ConnectivityTrafficEntrySnapshot> peerEntries(List<ConnectivityGapSnapshot> gaps) {
    if (gaps == null) {
      return List.of();
    }
    return List.of(
        new ConnectivityTrafficEntrySnapshot(
            "1.1.1.1:4242", 1, 1, ConnectivityTrafficInitiator.LOCAL, 1_000L, 3_000L, gaps));
  }

  private List<ConnectivityTrafficEntrySnapshot> ipEntries(List<ConnectivityGapSnapshot> gaps) {
    if (gaps == null) {
      return List.of();
    }
    return List.of(
        new ConnectivityTrafficEntrySnapshot(
            "/2.2.2.2", 1, 1, ConnectivityTrafficInitiator.REMOTE, 2_000L, 4_000L, gaps));
  }

  private List<ConnectivityGapSnapshot> gapHistory() {
    return List.of(
        new ConnectivityGapSnapshot(10_000L, 20_000L),
        new ConnectivityGapSnapshot(0L, 0L),
        new ConnectivityGapSnapshot(0L, 0L),
        new ConnectivityGapSnapshot(0L, 0L),
        new ConnectivityGapSnapshot(0L, 0L));
  }

  private int renderedTableCellCount(String html) {
    return html.split(java.util.regex.Pattern.quote("<td"), -1).length - 1;
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(page);
    lenient()
        .doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div", "class", "infobox");
              parent.addChild(infobox);
              infobox.addChild("div", "class", "header", invocation.getArgument(1));
              return infobox.addChild("div", "class", "content");
            })
        .when(pageMaker)
        .getInfobox(anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean());
    return pageMaker;
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
