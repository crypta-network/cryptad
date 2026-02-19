package network.crypta.node.updater;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URI;
import java.nio.file.Path;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ToadletContext;
import network.crypta.fs.AppEnv;
import network.crypta.node.Node;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class CoreActionToadletTest {
  @TempDir Path tempDir;

  @Test
  void path_whenCalled_expectCoreUpdatePath() {
    CoreActionToadlet toadlet =
        new CoreActionToadlet(
            mock(HighLevelSimpleClient.class), mock(Node.class, Answers.RETURNS_DEEP_STUBS));

    assertEquals(UpdaterPaths.CORE_UPDATE_PATH, toadlet.path());
  }

  @Test
  void handleMethodGET_whenCalled_expectRedirectToAlerts() throws Exception {
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet =
        new CoreActionToadlet(
            mock(HighLevelSimpleClient.class), mock(Node.class, Answers.RETURNS_DEEP_STUBS));

    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleMethodGET(URI.create("http://localhost/core-update/"), request, ctx);

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        (ArgumentCaptor<MultiValueTable<String, String>>)
            (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/alerts/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenFormPasswordInvalid_expectNoRedirect() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    when(ctx.checkFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(node, never()).services();
    verify(ctx, never()).sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong());
  }

  @Test
  void handleMethodPOST_whenCoreUpdaterMissing_expectRedirect() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeUpdateManager nodeUpdater = mock(NodeUpdateManager.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(node.services()).thenReturn(services);
    when(services.nodeUpdater()).thenReturn(nodeUpdater);
    when(nodeUpdater.getCoreUpdater()).thenReturn(null);
    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        (ArgumentCaptor<MultiValueTable<String, String>>)
            (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/alerts/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenDownloadAction_expectStartDownloadAndRedirect() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeUpdateManager nodeUpdater = mock(NodeUpdateManager.class);
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(node.services()).thenReturn(services);
    when(services.nodeUpdater()).thenReturn(nodeUpdater);
    when(nodeUpdater.getCoreUpdater()).thenReturn(coreUpdater);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("download");
    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(coreUpdater).startDownloadFromUI();
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        (ArgumentCaptor<MultiValueTable<String, String>>)
            (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/alerts/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenInstallPathInvalid_expectFailurePage() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeUpdateManager nodeUpdater = mock(NodeUpdateManager.class);
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    File baseDir = tempDir.resolve("node").toFile();
    String invalidPath = tempDir.resolve("outside/installer.deb").toFile().getAbsolutePath();
    baseDir.mkdirs();

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(node.services()).thenReturn(services);
    when(services.nodeUpdater()).thenReturn(nodeUpdater);
    when(nodeUpdater.getCoreUpdater()).thenReturn(coreUpdater);
    when(node.getNodeDir()).thenReturn(baseDir);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install");
    when(request.getPartAsStringFailsafe(eq("path"), anyInt())).thenReturn(invalidPath);

    stubHtmlContext(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(ctx)
        .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong());
    verify(ctx).writeData(any(), anyInt(), anyInt());
  }

  @Test
  void handleMethodPOST_whenInstallPathValidInServiceMode_expectFailurePage() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeUpdateManager nodeUpdater = mock(NodeUpdateManager.class);
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    File baseDir = tempDir.resolve("node").toFile();
    File updatesDir = new File(baseDir, "updates/core");
    File installer = new File(updatesDir, "cryptad.deb");
    updatesDir.mkdirs();
    assertTrue(installer.createNewFile());

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(node.services()).thenReturn(services);
    when(services.nodeUpdater()).thenReturn(nodeUpdater);
    when(nodeUpdater.getCoreUpdater()).thenReturn(coreUpdater);
    when(node.getNodeDir()).thenReturn(baseDir);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install");
    when(request.getPartAsStringFailsafe(eq("path"), anyInt()))
        .thenReturn(installer.getAbsolutePath());

    AppEnv appEnv = mock(AppEnv.class);
    when(appEnv.osKind()).thenReturn(AppEnv.OsKind.LINUX);
    when(appEnv.isServiceMode()).thenReturn(true);
    when(appEnv.onPath(anyString())).thenReturn(false);
    replaceAppEnv(toadlet, appEnv);

    stubHtmlContext(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(ctx)
        .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong());
    verify(ctx).writeData(any(), anyInt(), anyInt());
  }

  @Test
  void handleMethodPOST_whenOpenStoreUnknown_expectFailurePage() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    Node node = mock(Node.class, Answers.RETURNS_DEEP_STUBS);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    NodeUpdateManager nodeUpdater = mock(NodeUpdateManager.class);
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, node);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(node.services()).thenReturn(services);
    when(services.nodeUpdater()).thenReturn(nodeUpdater);
    when(nodeUpdater.getCoreUpdater()).thenReturn(coreUpdater);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("openStore");
    when(request.getPartAsStringFailsafe(eq("kind"), anyInt())).thenReturn("unknown");
    when(request.getPartAsStringFailsafe(eq("id"), anyInt())).thenReturn("");
    when(request.getPartAsStringFailsafe(eq("url"), anyInt())).thenReturn("");

    stubHtmlContext(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(ctx)
        .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong());
    verify(ctx).writeData(any(), anyInt(), anyInt());
  }

  private static void stubHtmlContext(ToadletContext ctx) throws Exception {
    PageMaker pageMaker = mock(PageMaker.class);
    PageNode pageNode = mock(PageNode.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx), any(PageMaker.RenderParameters.class)))
        .thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn("<html></html>");
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true)))
        .thenReturn(infoboxNode);

    doNothing().when(ctx).sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong());
    doNothing().when(ctx).writeData(any(), anyInt(), anyInt());
  }

  private static void replaceAppEnv(CoreActionToadlet toadlet, AppEnv appEnv) throws Exception {
    Field field = CoreActionToadlet.class.getDeclaredField("appEnv");
    field.setAccessible(true);
    field.set(toadlet, appEnv);
    assertTrue(field.get(toadlet) == appEnv);
  }
}
