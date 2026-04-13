package network.crypta.clients.http;

import java.io.BufferedWriter;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeFile;
import network.crypta.runtime.spi.ConnectionsInstallerSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DarknetAddRefToadletTest {

  @Mock private ConnectionsSupportPort connectionsSupportPort;
  @Mock private NodeInfoPort nodeInfoPort;
  @Mock private DarknetConnectionsToadlet friendsToadlet;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private TestableDarknetAddRefToadlet toadlet;

  @BeforeEach
  void setUp() {
    lenient()
        .when(connectionsSupportPort.windowsInstaller())
        .thenReturn(
            new ConnectionsInstallerSnapshot(
                NodeFile.INSTALLER_WINDOWS.getFilename(), null, "CHK@windows-installer"));
    lenient()
        .when(connectionsSupportPort.nonWindowsInstaller())
        .thenReturn(
            new ConnectionsInstallerSnapshot(
                NodeFile.INSTALLER_NON_WINDOWS.getFilename(), null, "CHK@nonwindows-installer"));
    lenient()
        .when(nodeInfoPort.exportReference(NodeReferenceView.DARKNET_PUBLIC, false))
        .thenReturn(sampleNoderefSnapshot());
    toadlet =
        new TestableDarknetAddRefToadlet(connectionsSupportPort, nodeInfoPort, friendsToadlet);
  }

  @Test
  void handleMethodGET_whenWindowsInstallerExists_servesExecutableBucket() throws Exception {
    File installer = File.createTempFile("installer-win", ".exe");
    installer.deleteOnExit();
    try (BufferedWriter writer =
        Files.newBufferedWriter(installer.toPath(), StandardCharsets.UTF_8)) {
      writer.write("win");
    }

    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(connectionsSupportPort.windowsInstaller())
        .thenReturn(
            new ConnectionsInstallerSnapshot(
                NodeFile.INSTALLER_WINDOWS.getFilename(), installer, "CHK@windows-installer"));

    URI path = new URI(toadlet.path() + NodeFile.INSTALLER_WINDOWS.getFilename());
    toadlet.handleMethodGET(path, request, ctx);

    assertTrue(toadlet.writeReplyCalled);
    assertEquals(200, toadlet.lastCode);
    assertEquals("application/x-msdownload", toadlet.lastMimeType);
    assertEquals("OK", toadlet.lastDescription);
    assertInstanceOf(FileBucket.class, toadlet.lastBucket);
    assertEquals(installer.getAbsoluteFile(), ((FileBucket) toadlet.lastBucket).getFile());
  }

  @Test
  void handleMethodGET_whenNonWindowsInstallerExists_servesJarBucket() throws Exception {
    File installer = File.createTempFile("installer-nonwin", ".jar");
    installer.deleteOnExit();
    try (BufferedWriter writer =
        Files.newBufferedWriter(installer.toPath(), StandardCharsets.UTF_8)) {
      writer.write("jar");
    }

    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(connectionsSupportPort.nonWindowsInstaller())
        .thenReturn(
            new ConnectionsInstallerSnapshot(
                NodeFile.INSTALLER_NON_WINDOWS.getFilename(),
                installer,
                "CHK@nonwindows-installer"));

    URI path = new URI(toadlet.path() + NodeFile.INSTALLER_NON_WINDOWS.getFilename());
    toadlet.handleMethodGET(path, request, ctx);

    assertTrue(toadlet.writeReplyCalled);
    assertEquals(200, toadlet.lastCode);
    assertEquals("application/x-java-archive", toadlet.lastMimeType);
    assertEquals("OK", toadlet.lastDescription);
    assertInstanceOf(FileBucket.class, toadlet.lastBucket);
    assertEquals(installer.getAbsoluteFile(), ((FileBucket) toadlet.lastBucket).getFile());
  }

  @Test
  void handleMethodGET_whenAccessDenied_doesNotTouchRuntimePorts() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    URI path = new URI(toadlet.path() + NodeFile.INSTALLER_WINDOWS.getFilename());
    toadlet.handleMethodGET(path, request, ctx);

    assertFalse(toadlet.writeReplyCalled);
    verify(ctx, times(1)).checkFullAccess(toadlet);
    verifyNoMoreInteractions(connectionsSupportPort, nodeInfoPort);
  }

  @Test
  void handleMethodGET_whenInstallersMissing_rendersHtmlPage() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    HTMLNode content = new HTMLNode("div");
    HTMLNode pageOuter = new HTMLNode("div");
    HTMLNode head = pageOuter.addChild("head");
    pageOuter.addChild(content);
    PageNode page = new PageNode(pageOuter, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(page);
    network.crypta.runtime.alerts.UserAlertManager alertManager =
        mock(network.crypta.runtime.alerts.UserAlertManager.class);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("#", "summary"));

    when(pageMaker.getInfobox(anyString(), anyString(), eq(content), anyString(), eq(true)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div", "id", "infobox");
              parent.addChild(infobox);
              HTMLNode boxContent = new HTMLNode("div", "class", "content");
              infobox.addChild(boxContent);
              return boxContent;
            });

    String friendsPath = "/friends/";
    when(friendsToadlet.path()).thenReturn(friendsPath);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<ConnectionsToadlet> connections = mockStatic(ConnectionsToadlet.class)) {

      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      when(baseL10n.getString(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
      doAnswer(_ -> null).when(baseL10n).addL10nSubstitution(any(), anyString(), any(), any());

      toadlet.handleMethodGET(new URI(toadlet.path()), request, ctx);

      assertTrue(toadlet.writeHtmlCalled);
      assertEquals(200, toadlet.lastCode);
      assertTrue(toadlet.lastHtml.contains("summary"));

      connections.verify(
          () -> ConnectionsToadlet.drawAddPeerBox(content, ctx, false, friendsPath), times(1));
      verify(nodeInfoPort).exportReference(NodeReferenceView.DARKNET_PUBLIC, false);
      verify(friendsToadlet, times(1))
          .drawNoderefBox(eq(content), argThat(DarknetAddRefToadletTest::isExpectedNoderef));
    }
  }

  @Test
  void handleMethodGET_whenInstallerPathRequestedWithoutLocalFile_rendersHtmlPageFallback()
      throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    HTMLNode content = new HTMLNode("div");
    stubPageRendering(content);
    when(friendsToadlet.path()).thenReturn("/friends/");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<ConnectionsToadlet> connections = mockStatic(ConnectionsToadlet.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      when(baseL10n.getString(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
      doAnswer(_ -> null).when(baseL10n).addL10nSubstitution(any(), anyString(), any(), any());

      URI path = new URI(toadlet.path() + NodeFile.INSTALLER_WINDOWS.getFilename());
      toadlet.handleMethodGET(path, request, ctx);

      assertFalse(toadlet.writeReplyCalled);
      assertTrue(toadlet.writeHtmlCalled);
      connections.verify(
          () -> ConnectionsToadlet.drawAddPeerBox(content, ctx, false, "/friends/"), times(1));
    }
  }

  @Test
  void getNoderef_returnsSimpleFieldSetConvertedFromRuntimeExport() {
    SimpleFieldSet actual = toadlet.getNoderef();
    SimpleFieldSet physical = actual.subset("physical");

    assertEquals("alice", actual.get("myName"));
    assertNotNull(physical);
    assertEquals("127.0.0.1", physical.get("udp"));
    verify(nodeInfoPort).exportReference(NodeReferenceView.DARKNET_PUBLIC, false);
  }

  @Test
  void path_returnsConstantAddFriendPath() {
    assertEquals(DarknetAddRefToadlet.PATH, toadlet.path());
  }

  private static final class TestableDarknetAddRefToadlet extends DarknetAddRefToadlet {
    boolean writeReplyCalled;
    boolean writeHtmlCalled;
    int lastCode;
    String lastMimeType;
    String lastDescription;
    Bucket lastBucket;
    String lastHtml;

    TestableDarknetAddRefToadlet(
        ConnectionsSupportPort connectionsSupportPort,
        NodeInfoPort nodeInfoPort,
        DarknetConnectionsToadlet friendsToadlet) {
      super(connectionsSupportPort, nodeInfoPort, friendsToadlet);
    }

    @Override
    protected void writeReply(ToadletContext ctx, ReplyHeaders replyHeaders, Bucket data) {
      this.writeReplyCalled = true;
      this.lastCode = replyHeaders.code();
      this.lastMimeType = replyHeaders.mimeType();
      this.lastDescription = replyHeaders.description();
      this.lastBucket = data;
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      this.writeHtmlCalled = true;
      this.lastCode = code;
      this.lastDescription = desc;
      this.lastHtml = reply;
    }
  }

  private void stubPageRendering(HTMLNode content) {
    HTMLNode pageOuter = new HTMLNode("div");
    HTMLNode head = pageOuter.addChild("head");
    pageOuter.addChild(content);
    PageNode page = new PageNode(pageOuter, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(page);
    network.crypta.runtime.alerts.UserAlertManager alertManager =
        mock(network.crypta.runtime.alerts.UserAlertManager.class);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("#", "summary"));

    when(pageMaker.getInfobox(anyString(), anyString(), eq(content), anyString(), eq(true)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div", "id", "infobox");
              parent.addChild(infobox);
              HTMLNode boxContent = new HTMLNode("div", "class", "content");
              infobox.addChild(boxContent);
              return boxContent;
            });
  }

  private static NodeReferenceSnapshot sampleNoderefSnapshot() {
    return new NodeReferenceSnapshot(
        new NodeFieldSet(
            Map.of("myName", "alice"),
            Map.of("physical", new NodeFieldSet(Map.of("udp", "127.0.0.1"), Map.of()))));
  }

  private static boolean isExpectedNoderef(SimpleFieldSet fieldSet) {
    if (!"alice".equals(fieldSet.get("myName"))) {
      return false;
    }

    SimpleFieldSet physical = fieldSet.subset("physical");
    return physical != null && "127.0.0.1".equals(physical.get("udp"));
  }
}
