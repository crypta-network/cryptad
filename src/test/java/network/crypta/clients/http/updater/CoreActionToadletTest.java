package network.crypta.clients.http.updater;

import java.io.File;
import java.lang.reflect.Field;
import java.net.URI;
import java.nio.file.Path;
import java.util.Optional;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ToadletContext;
import network.crypta.fs.AppEnv;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.updater.UpdaterPaths;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
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
        new CoreActionToadlet(mock(HighLevelSimpleClient.class), mock(CoreUpdateActionPort.class));

    assertEquals(UpdaterPaths.CORE_UPDATE_PATH, toadlet.path());
  }

  @Test
  void handleMethodGET_whenCalled_expectRedirectToAlerts() throws Exception {
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet =
        new CoreActionToadlet(mock(HighLevelSimpleClient.class), mock(CoreUpdateActionPort.class));

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
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    when(ctx.checkFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(coreUpdateActionPort, never()).isCoreUpdaterAvailable();
    verify(ctx, never()).sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong());
  }

  @Test
  void handleMethodPOST_whenCoreUpdaterMissing_expectRedirect() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(false);
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
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("download");
    doNothing().when(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L));

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(coreUpdateActionPort).startCoreDownloadFromUi();
    verify(coreUpdateActionPort, never()).isCoreUpdaterAvailable();
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        (ArgumentCaptor<MultiValueTable<String, String>>)
            (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals("/alerts/", headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenInstallPathInvalid_expectFailurePage() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    String invalidPath = tempDir.resolve("outside/installer.deb").toFile().getAbsolutePath();

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install");
    when(request.getPartAsStringFailsafe(eq("path"), anyInt())).thenReturn(invalidPath);
    when(coreUpdateActionPort.resolveDownloadedInstaller(invalidPath)).thenReturn(Optional.empty());

    stubHtmlContext(ctx);

    toadlet.handleMethodPOST(URI.create("http://localhost/core-update/"), request, ctx);

    verify(ctx)
        .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong());
    verify(ctx).writeData(any(), anyInt(), anyInt());
  }

  @Test
  void handleMethodPOST_whenInstallPathValidInServiceMode_expectFailurePage() throws Exception {
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    File baseDir = tempDir.resolve("node").toFile();
    File updatesDir = new File(baseDir, "updates/core");
    File installer = new File(updatesDir, "cryptad.deb");
    assertTrue(updatesDir.mkdirs() || updatesDir.isDirectory());
    assertTrue(installer.createNewFile());

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
    when(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install");
    when(request.getPartAsStringFailsafe(eq("path"), anyInt()))
        .thenReturn(installer.getAbsolutePath());
    when(coreUpdateActionPort.resolveDownloadedInstaller(installer.getAbsolutePath()))
        .thenReturn(Optional.of(installer.toPath()));

    AppEnv appEnv = mock(AppEnv.class);
    when(appEnv.osKind()).thenReturn(AppEnv.OsKind.LINUX);
    when(appEnv.isServiceMode()).thenReturn(true);
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
    CoreUpdateActionPort coreUpdateActionPort = mock(CoreUpdateActionPort.class);
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    CoreActionToadlet toadlet = new CoreActionToadlet(client, coreUpdateActionPort);

    when(ctx.checkFormPassword(request)).thenReturn(true);
    when(coreUpdateActionPort.isCoreUpdaterAvailable()).thenReturn(true);
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
    assertSame(field.get(toadlet), appEnv);
  }
}
