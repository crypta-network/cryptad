package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.bookmark.BookmarkItem;
import network.crypta.runtime.alerts.AbstractUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;
import network.crypta.runtime.spi.WelcomePageSnapshot;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class WelcomeToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock private WelcomePagePort welcomePagePort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private WelcomeActionPort welcomeActionPort;
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;
  @Mock private UserAlertManager alertManager;
  @Mock private HTTPRequest request;

  private WelcomeToadletRuntimePorts runtimePorts;
  private WelcomeToadlet toadlet;
  private String originalUserDir;

  @BeforeEach
  void setUp() {
    runtimePorts =
        new WelcomeToadletRuntimePorts(
            welcomePagePort, darknetConnectionsPort, lifecyclePort, welcomeActionPort);
    toadlet = new WelcomeToadlet(client, runtimePorts);
    toadlet.container = container;
    originalUserDir = System.getProperty("user.dir");

    when(ctx.getContainer()).thenReturn(container);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(ctx.getHeaders()).thenReturn(new MultiValueTable<>());
    when(ctx.getFormPassword()).thenReturn("form-password");
    when(container.publicGatewayMode()).thenReturn(false);
    when(container.enableActivelinks()).thenReturn(true);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("div", "id", "alert-summary"));
    when(request.getParam("newbookmark")).thenReturn("");
    when(request.getPartAsStringFailsafe("updateconfirm", 32)).thenReturn("");
    when(request.getPartAsStringFailsafe("update", 32)).thenReturn("");
    when(ctx.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });
  }

  @AfterEach
  void tearDown() {
    if (originalUserDir != null) {
      System.setProperty("user.dir", originalUserDir);
    }
  }

  @Test
  void allowPOSTWithoutPassword_alwaysTrue() {
    assertTrue(toadlet.allowPOSTWithoutPassword());
  }

  @Test
  void showSearchBox_whenCalled_returnsFalse() {
    assertFalse(toadlet.showSearchBox());
  }

  @Test
  void showSearchBox_whenContextChanges_returnsStillFalse() {
    assertFalse(toadlet.showSearchBox());
  }

  @Test
  void showSearchBoxLoading_whenCalled_returnsFalse() {
    assertFalse(toadlet.showSearchBoxLoading());
  }

  @Test
  void showSearchBoxLoading_whenContextChanges_returnsStillFalse() {
    assertFalse(toadlet.showSearchBoxLoading());
  }

  @Test
  void path_returnsRootSlash() {
    assertEquals(WelcomeToadlet.ROOT_PATH, toadlet.path());
  }

  @Test
  void constructor_whenRuntimePortsProvided_noLongerNeedsNodeDependency() {
    assertEquals(1, WelcomeToadlet.class.getDeclaredConstructors().length);
    assertArrayEquals(
        new Class<?>[] {HighLevelSimpleClient.class, WelcomeToadletRuntimePorts.class},
        WelcomeToadlet.class.getDeclaredConstructors()[0].getParameterTypes());
  }

  @Test
  void redirectToRoot_sends302LocationRoot() throws Exception {
    ToadletContext redirectContext = mock(ToadletContext.class);

    toadlet.redirectToRoot(redirectContext);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(redirectContext)
        .sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));

    MultiValueTable<String, String> headers = headersCaptor.getValue();
    assertEquals("/", headers.getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenLatestLogRequested_readsLogTailFromWelcomePagePort() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    AtomicReference<String> body = new AtomicReference<>();
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.isParameterSet("latestlog")).thenReturn(true);
    when(welcomePagePort.latestNodeLogTail()).thenReturn("latest log tail");
    doAnswer(
            invocation -> {
              body.set(invocation.getArgument(3));
              return null;
            })
        .when(spyToadlet)
        .writeTextReply(eq(ctx), eq(200), eq("OK"), anyString());

    spyToadlet.handleMethodGET(URI.create("http://localhost/?latestlog"), request, ctx);

    assertEquals("latest log tail", body.get());
    verify(welcomePagePort).latestNodeLogTail();
  }

  @Test
  void handleMethodGET_whenFetchKeyBoxConfiguredAbove_rendersItBeforeBookmarks() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    AtomicReference<String> html = captureHtmlReply(spyToadlet);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(welcomePagePort.snapshot()).thenReturn(new WelcomePageSnapshot(true));

    spyToadlet.handleMethodGET(URI.create("http://localhost/"), request, ctx);

    String body = html.get();
    assertTrue(body.contains("id=\"keyfetchbox\""));
    assertTrue(body.indexOf("id=\"keyfetchbox\"") < body.indexOf("id=\"bookmarks\""));
    verify(welcomePagePort).snapshot();
  }

  @Test
  void handleMethodGET_whenFetchKeyBoxConfiguredBelow_rendersItAfterBookmarks() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    AtomicReference<String> html = captureHtmlReply(spyToadlet);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    when(welcomePagePort.snapshot()).thenReturn(new WelcomePageSnapshot(false));

    spyToadlet.handleMethodGET(URI.create("http://localhost/"), request, ctx);

    String body = html.get();
    assertTrue(body.contains("id=\"keyfetchbox\""));
    assertTrue(body.indexOf("id=\"keyfetchbox\"") > body.indexOf("id=\"bookmarks\""));
    verify(welcomePagePort).snapshot();
  }

  @Test
  void handleMethodPOST_whenUpdateConfirmed_delegatesToWelcomeActionPort() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.getPartAsStringFailsafe("updateconfirm", 32)).thenReturn("update-now");
    captureHtmlReply(spyToadlet);

    spyToadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    verify(welcomeActionPort).armNodeUpdate();
  }

  @Test
  void handleMethodPOST_whenShutdownConfirmed_redirectsAndDelegatesToWelcomeActionPort()
      throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(request.isPartSet("shutdownconfirm")).thenReturn(true);

    toadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));
    assertEquals(
        "/?terminated&formPassword=form-password", headersCaptor.getValue().getFirst("Location"));
    verify(welcomeActionPort).queueShutdownFromWelcome();
  }

  @Test
  void handleMethodPOST_whenRestartConfirmed_redirectsAndDelegatesToWelcomeActionPort()
      throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(request.isPartSet("restartconfirm")).thenReturn(true);

    toadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));
    assertEquals(
        "/?restarted&formPassword=form-password", headersCaptor.getValue().getFirst("Location"));
    verify(welcomeActionPort).queueRestartFromWelcome();
  }

  @Test
  void handleMethodPOST_whenUpgradeConnectionSpeedSubmitted_delegatesToWelcomeActionPort()
      throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(request.isPartSet("upgradeConnectionSpeed")).thenReturn(true);
    when(request.getPartAsStringFailsafe("inputBandwidthLimit", Byte.MAX_VALUE)).thenReturn("4KiB");
    when(request.getPartAsStringFailsafe("outputBandwidthLimit", Byte.MAX_VALUE))
        .thenReturn("1KiB");

    toadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    verify(welcomeActionPort).applyUpgradeConnectionSpeed("4KiB", "1KiB");
  }

  @Test
  void handleMethodPOST_whenThreadDumpRequested_checksLifecyclePort() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(request.isPartSet("getThreadDump")).thenReturn(true);
    when(lifecyclePort.isUsingWrapper()).thenReturn(false);
    captureHtmlReply(spyToadlet);

    spyToadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    verify(lifecyclePort).isUsingWrapper();
  }

  @Test
  void handleMethodPOST_whenDismissEventsSubmitted_dismissesMatchingEventAlertsViaSurface()
      throws Exception {
    UserAlert bookmarkEvent = new TestUserAlert("bookmark", true);
    UserAlert peerEvent = new TestUserAlert("peer", true);
    UserAlert nonEvent = new TestUserAlert("other", false);
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(request.isPartSet("dismiss-events")).thenReturn(true);
    when(request.getPartAsStringFailsafe("events", Integer.MAX_VALUE)).thenReturn("bookmark,peer");
    when(alertManager.getAlerts()).thenReturn(new UserAlert[] {bookmarkEvent, nonEvent, peerEvent});

    toadlet.handleMethodPOST(URI.create("http://localhost/"), request, ctx);

    verify(alertManager).dismissAlert(bookmarkEvent.hashCode());
    verify(alertManager).dismissAlert(peerEvent.hashCode());
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));
    assertEquals("/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenWrapperInUse_rendersRestartButtonFromLifecyclePort() throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    AtomicReference<String> html = captureHtmlReply(spyToadlet);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(welcomePagePort.snapshot()).thenReturn(new WelcomePageSnapshot(false));
    when(lifecyclePort.isUsingWrapper()).thenReturn(true);

    spyToadlet.handleMethodGET(URI.create("http://localhost/"), request, ctx);

    assertTrue(html.get().contains("restart2"));
    verify(lifecyclePort).isUsingWrapper();
  }

  @Test
  void handleMethodGET_whenConfirmingBookmark_rendersDetachedDarknetPeersAndJavascriptGate()
      throws Exception {
    WelcomeToadlet spyToadlet = createSpyToadlet();
    AtomicReference<String> html = captureHtmlReply(spyToadlet);
    PageMaker pageMaker = stubPageMaker(new HTMLNode("div"));
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParam("newbookmark")).thenReturn("CHK@bookmark");
    when(request.getParam("desc")).thenReturn("Bookmark description");
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(alicePeer()));

    spyToadlet.handleMethodGET(
        URI.create("http://localhost/?newbookmark=CHK@bookmark"), request, ctx);

    String body = html.get();
    assertTrue(body.contains("Alice"));
    assertTrue(body.contains("node_42"));
    assertTrue(body.contains("/static/js/checkall.js"));
    verify(darknetConnectionsPort).listPeers();
  }

  @Test
  void addBookmarkItemRow_whenBookmarkUpdated_rendersDismissFormUsingAlertSurfaceData()
      throws Exception {
    BookmarkItem item = mock(BookmarkItem.class);
    UserAlert userAlert = new TestUserAlert("bookmark", false);
    HTMLNode table = new HTMLNode("table");
    when(item.hasAnActivelink()).thenReturn(false);
    when(item.hasUpdated()).thenReturn(true);
    when(item.getKey()).thenReturn("CHK@bookmark");
    when(item.getDescription()).thenReturn("Bookmark description");
    when(item.getVisibleName()).thenReturn("Bookmark");
    when(item.getShortDescription()).thenReturn("");
    when(item.getUserAlert()).thenReturn(userAlert);

    Method method =
        WelcomeToadlet.class.getDeclaredMethod(
            "addBookmarkItemRow",
            boolean.class,
            HTMLNode.class,
            BookmarkItem.class,
            ToadletContext.class);
    method.setAccessible(true);
    method.invoke(toadlet, false, table, item, ctx);

    String html = table.generate();
    assertTrue(html.contains("action=\"/alerts/\""));
    assertTrue(html.contains("name=\"disable\""));
    assertTrue(html.contains("value=\"" + userAlert.hashCode() + "\""));
    assertTrue(html.contains("name=\"formPassword\""));
    assertTrue(html.contains("value=\"form-password\""));
    assertTrue(html.contains("name=\"redirectToAfterDisable\""));
    assertTrue(html.contains("value=\"/#bookmarks\""));
  }

  @Test
  void disableMatchingAlert_whenAlertShouldUnregister_usesAlertSurfaceDismissal() throws Exception {
    UserAlert userAlert = new TestUserAlert("dismiss", false);

    Method method =
        WelcomeToadlet.class.getDeclaredMethod(
            "disableMatchingAlert", ToadletContext.class, UserAlert.class);
    method.setAccessible(true);
    method.invoke(toadlet, ctx, userAlert);

    verify(alertManager).dismissAlert(userAlert.hashCode());
  }

  @Test
  void sendRestartingPageInner_addsMetaRefreshAndContent() {
    ToadletContext restartContext = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    when(restartContext.getPageMaker()).thenReturn(pageMaker);

    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode content = outer.addChild("body");
    PageNode pageNode = new PageNode(outer, head, content);

    when(pageMaker.getInfobox(anyString(), anyString(), eq(content), anyString(), eq(true)))
        .thenReturn(new HTMLNode("div"));

    when(pageMaker.getPageNode(eq("Node Restart"), eq(restartContext), any(RenderParameters.class)))
        .thenReturn(pageNode);

    HTMLNode result = WelcomeToadlet.sendRestartingPageInner(restartContext);

    Optional<HTMLNode> metaNode =
        head.getChildren().stream().filter(child -> "meta".equals(child.getName())).findFirst();
    assertTrue(metaNode.isPresent(), "Meta refresh tag should be added");
    assertEquals("refresh", metaNode.get().getAttribute("http-equiv"));
    assertEquals("20; url=", metaNode.get().getAttribute("content"));

    assertFalse(result.getChildren().isEmpty(), "Page should contain body content");
  }

  @Test
  void maybeDisplayWrapperLogfile_readsLogWhenPresent() throws Exception {
    Path logFile = Path.of(System.getProperty("user.dir"), "wrapper.log");
    boolean existed = Files.exists(logFile);
    byte[] previous = existed ? Files.readAllBytes(logFile) : new byte[0];
    Files.writeString(logFile, "first line\nsecond line\n");

    ToadletContext wrapperContext = mock(ToadletContext.class);
    PageMaker pageMaker = mock(PageMaker.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infobox = new HTMLNode("div");

    when(wrapperContext.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), anyBoolean()))
        .thenReturn(infobox);

    try {
      WelcomeToadlet.maybeDisplayWrapperLogfile(wrapperContext, contentNode);

      verify(pageMaker)
          .getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true));
      assertFalse(infobox.getChildren().isEmpty(), "Infobox should contain log lines");
    } finally {
      if (existed) {
        Files.write(logFile, previous);
      } else {
        Files.deleteIfExists(logFile);
      }
    }
  }

  @Test
  void maybeDisplayWrapperLogfile_noInteractionWhenMissingFile() {
    Path missingDir = Path.of(originalUserDir).resolve("build/nonexistent");
    System.setProperty("user.dir", missingDir.toString());

    ToadletContext wrapperContext = mock(ToadletContext.class);

    WelcomeToadlet.maybeDisplayWrapperLogfile(wrapperContext, new HTMLNode("div"));

    verifyNoInteractions(wrapperContext);
  }

  private AtomicReference<String> captureHtmlReply(WelcomeToadlet spyToadlet) throws Exception {
    AtomicReference<String> html = new AtomicReference<>();
    doAnswer(
            invocation -> {
              html.set(invocation.getArgument(3));
              return null;
            })
        .when(spyToadlet)
        .writeHTMLReply(eq(ctx), anyInt(), anyString(), anyString());
    return html;
  }

  private WelcomeToadlet createSpyToadlet() {
    WelcomeToadlet spyToadlet = spy(new WelcomeToadlet(client, runtimePorts));
    spyToadlet.container = container;
    return spyToadlet;
  }

  private PageMaker stubPageMaker(HTMLNode content) {
    HTMLNode root = new HTMLNode("html");
    HTMLNode head = root.addChild("head");
    root.addChild(content);
    PageNode page = new PageNode(root, head, content);

    PageMaker stub = mock(PageMaker.class);
    when(stub.getPageNode(anyString(), eq(ctx))).thenReturn(page);
    when(stub.getTheme()).thenReturn(PageMaker.THEME.CRYPTAFORGE);
    doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              return parent.addChild("div");
            })
        .when(stub)
        .getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean());
    return stub;
  }

  private static DarknetConnectionPeerSnapshot alicePeer() {
    return new DarknetConnectionPeerSnapshot(42, "peer-1", "Alice", "", false);
  }

  private static final class TestUserAlert extends AbstractUserAlert {

    private final String anchor;
    private final boolean eventNotification;

    private TestUserAlert(String anchor, boolean eventNotification) {
      super(
          true,
          "Title",
          Body.of("Text", "Short", new HTMLNode("div", "Alert")),
          UserAlert.MINOR,
          true,
          new DismissOptions("Dismiss", true));
      this.anchor = anchor;
      this.eventNotification = eventNotification;
    }

    @Override
    public String anchor() {
      return anchor;
    }

    @Override
    public boolean isEventNotification() {
      return eventNotification;
    }
  }
}
