package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileWriter;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.updater.NodeUpdateManager;
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

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class DarknetAddRefToadletTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeUpdateManager nodeUpdater;
  @Mock private HighLevelSimpleClient client;
  @Mock private DarknetConnectionsToadlet friendsToadlet;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private TestableDarknetAddRefToadlet toadlet;

  @BeforeEach
  void setUp() {
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    lenient().when(services.nodeUpdater()).thenReturn(nodeUpdater);
    toadlet = new TestableDarknetAddRefToadlet(node, client, friendsToadlet);
  }

  @Test
  void handleMethodGET_whenWindowsInstallerExists_servesExecutableBucket() throws Exception {
    File installer = File.createTempFile("installer-win", ".exe");
    installer.deleteOnExit();
    try (FileWriter writer = new FileWriter(installer)) {
      writer.write("win");
    }

    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(nodeUpdater.getInstallerWindows()).thenReturn(installer);

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
    try (FileWriter writer = new FileWriter(installer)) {
      writer.write("jar");
    }

    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(nodeUpdater.getInstallerNonWindows()).thenReturn(installer);

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
  void handleMethodGET_whenAccessDenied_doesNotTouchNode() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    URI path = new URI(toadlet.path() + NodeFile.INSTALLER_WINDOWS.getFilename());
    toadlet.handleMethodGET(path, request, ctx);

    assertFalse(toadlet.writeReplyCalled);
    verify(ctx, times(1)).checkFullAccess(toadlet);
    verifyNoMoreInteractions(nodeUpdater);
  }

  @Test
  void handleMethodGET_whenInstallersMissing_rendersHtmlPage() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(nodeUpdater.getInstallerWindows()).thenReturn(null);
    when(nodeUpdater.getInstallerNonWindows()).thenReturn(null);
    when(nodeUpdater.getInstallerWindowsURI()).thenReturn(new FreenetURI("CHK", "win"));
    when(nodeUpdater.getInstallerNonWindowsURI()).thenReturn(new FreenetURI("CHK", "unix"));

    HTMLNode content = new HTMLNode("div");
    HTMLNode pageOuter = new HTMLNode("div");
    HTMLNode head = pageOuter.addChild("head");
    pageOuter.addChild(content);
    PageNode page = new PageNode(pageOuter, head, content);

    PageMaker pageMaker = mock(PageMaker.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(page);
    when(ctx.getAlertManager())
        .thenReturn(mock(network.crypta.node.useralerts.UserAlertManager.class));
    when(ctx.getAlertManager().createSummary()).thenReturn(new HTMLNode("#", "summary"));

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

    SimpleFieldSet noderef = new SimpleFieldSet(false);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.exportDarknetPublicFieldSet()).thenReturn(noderef);
    when(friendsToadlet.path()).thenReturn("/friends/");
    doNothing().when(friendsToadlet).drawNoderefBox(content, noderef);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class);
        MockedStatic<ConnectionsToadlet> connections = mockStatic(ConnectionsToadlet.class)) {

      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      when(baseL10n.getString(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
      doAnswer(invocation -> null)
          .when(baseL10n)
          .addL10nSubstitution(any(), anyString(), any(), any());

      toadlet.handleMethodGET(new URI(toadlet.path()), request, ctx);

      assertTrue(toadlet.writeHtmlCalled);
      assertEquals(200, toadlet.lastCode);
      assertTrue(toadlet.lastHtml.contains("summary"));

      connections.verify(
          () -> ConnectionsToadlet.drawAddPeerBox(content, ctx, false, friendsToadlet.path()),
          times(1));
      verify(friendsToadlet, times(1)).drawNoderefBox(content, noderef);
    }
  }

  @Test
  void getNoderef_returnsNodeExport() {
    SimpleFieldSet expected = new SimpleFieldSet(false);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.exportDarknetPublicFieldSet()).thenReturn(expected);

    assertSame(expected, toadlet.getNoderef());
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
        Node node, HighLevelSimpleClient client, DarknetConnectionsToadlet friendsToadlet) {
      super(node, client, friendsToadlet);
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
}
