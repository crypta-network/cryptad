package network.crypta.clients.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppUiSecurityHeaders;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class AppUiToadletTest {
  @Mock private ToadletContext ctx;
  @Mock private ToadletContainer container;
  @Mock private HTTPRequest request;

  @TempDir private Path tempDir;

  @Test
  void path_whenRequested_expectAppsRoot() {
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost());

    assertEquals("/apps/", toadlet.path());
  }

  @Test
  void handleMethodGET_whenRootEntryRequested_expectDeclaredEntryHtml() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("index.html");
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve("index.html"), "<html></html>");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("OK", reply.reasonPhrase());
    assertEquals("text/html; charset=UTF-8", reply.mimeType());
    assertTrue(reply.forceDisableJavascript());
    assertEquals("nosniff", reply.headers().getFirst("x-content-type-options"));
    assertEquals("no-referrer", reply.headers().getFirst("referrer-policy"));
    assertEquals(
        AppUiSecurityHeaders.CONTENT_SECURITY_POLICY,
        reply.headers().getFirst("content-security-policy"));
    assertEquals(13L, reply.length());
    assertEquals("<html></html>", captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenNestedAppRootRequested_expectRedirectToEntryDirectory()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/"), request, ctx);

    verify(toadlet).writeTemporaryRedirect(ctx, "Redirecting to app UI.", "/apps/demo-app/static/");
  }

  @Test
  void handleMethodGET_whenJavascriptDisabled_expectScriptExecutionBlocked() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(
        snapshot.paths().installedRoot().resolve("static/index.html"), "<html></html>");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(false);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/static/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(
        AppUiSecurityHeaders.JAVASCRIPT_DISABLED_CONTENT_SECURITY_POLICY,
        reply.headers().getFirst("content-security-policy"));
    assertEquals("<html></html>", captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenStaticAssetRequested_expectJavascriptContentType() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), "export {};");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/static/app.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals("text/javascript; charset=UTF-8", reply.mimeType());
    assertEquals(10L, reply.length());
    assertEquals("export {};", captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenBootstrapRequested_expectOperatorScopedJsonWithoutAppToken()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(ctx.getFormPassword()).thenReturn("form-secret");
    enableJavascript(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json"),
        request,
        ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("application/json; charset=UTF-8", reply.mimeType());
    assertEquals("no-store", reply.headers().getFirst("cache-control"));
    String body = captureByteArrayWriteText();
    assertTrue(body.contains("\"appId\":\"demo-app\""));
    assertTrue(body.contains("\"name\":\"Demo App\""));
    assertTrue(body.contains("\"uiRoot\":\"/apps/demo-app/\""));
    assertTrue(body.contains("\"assetRoot\":\"/apps/demo-app/static/\""));
    assertTrue(body.contains("\"platformApiRoot\":\"/api/v1/\""));
    assertTrue(body.contains("\"shellRoot\":\"/app/node/\""));
    assertTrue(body.contains("\"formPassword\":\"form-secret\""));
    assertFalse(body.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(body.contains("launchToken"));
  }

  @Test
  void handleMethodHEAD_whenBootstrapRequestedForStaticApp_expectHeadersOnlyJson()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getFormPassword()).thenReturn("form-secret");
    enableJavascript(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json"),
        request,
        ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("application/json; charset=UTF-8", reply.mimeType());
    assertEquals("no-store", reply.headers().getFirst("cache-control"));
    assertTrue(reply.length() > 0L);
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenBootstrapRequestedForShellPanelApp_expectNotFound() throws Exception {
    InstalledAppSnapshot snapshot = app(AppUiMode.SHELL_PANEL, "/app/node/#queue");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json"),
        request,
        ctx);

    ReplyCapture reply = captureReply();
    assertEquals(404, reply.statusCode());
    assertEquals("Not Found", reply.reasonPhrase());
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodGET_whenCanonicalParentRelativeAssetExistsAtBundleRoot_expectBundleRelativeBody()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/shared.js"), "nested");
    Files.writeString(snapshot.paths().installedRoot().resolve("shared.js"), "root");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/shared.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals("text/javascript; charset=UTF-8", reply.mimeType());
    assertEquals(4L, reply.length());
    assertEquals("root", captureBucketWriteText());
  }

  @Test
  void handleMethodHEAD_whenStaticAssetRequested_expectHeadersOnly() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), "export {};");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/static/app.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals("text/javascript; charset=UTF-8", reply.mimeType());
    assertEquals(10L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodGET_whenEntryDirectoryRequested_expectDeclaredEntryHtml() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    Files.createDirectories(snapshot.paths().installedRoot().resolve("static"));
    Files.writeString(
        snapshot.paths().installedRoot().resolve("static/index.html"), "<html></html>");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/static/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("text/html; charset=UTF-8", reply.mimeType());
    assertEquals("<html></html>", captureBucketWriteText());
  }

  @Test
  void handleMethodHEAD_whenAppRootMissingSlash_expectHeaderOnlyRedirect() throws Exception {
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost());
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(URI.create("http://localhost/apps/demo-app"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(302, reply.statusCode());
    assertEquals("Found", reply.reasonPhrase());
    assertEquals("/apps/demo-app/", reply.headers().getFirst("Location"));
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenAppRootMissingSlashHasQuery_expectRedirectPreservesQuery()
      throws Exception {
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost());
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app?view=queue&filter=a%2Fb"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals("/apps/demo-app/?view=queue&filter=a%2Fb", reply.headers().getFirst("Location"));
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenNestedAppRootHasQuery_expectRedirectPreservesQuery() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/?view=queue&filter=a%2Fb"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(
        "/apps/demo-app/static/?view=queue&filter=a%2Fb", reply.headers().getFirst("Location"));
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenStaticAssetMissing_expectHeaderOnlyNotFound() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/static/missing.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(404, reply.statusCode());
    assertEquals("Not Found", reply.reasonPhrase());
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenTraversalRequested_expectHeaderOnlyBadRequest() throws Exception {
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost());
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/static/%2e%2e/secret.txt"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(400, reply.statusCode());
    assertEquals("Bad Request", reply.reasonPhrase());
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenFullAccessDenied_expectHeaderOnlyForbidden() throws Exception {
    AppHost appHost = mock(AppHost.class);
    AppUiToadlet toadlet = new AppUiToadlet(appHost);
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    toadlet.handleMethodHEAD(URI.create("http://localhost/apps/demo-app/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(403, reply.statusCode());
    assertEquals("Forbidden", reply.reasonPhrase());
    assertEquals(0L, reply.length());
    verify(ctx, never()).checkFullAccess(toadlet);
    verifyNoBodyWrites();
    verifyNoInteractions(appHost);
  }

  @Test
  void handleMethodGET_whenFullAccessDenied_expectNoAssetLookupOrBody() throws Exception {
    AppHost appHost = mock(AppHost.class);
    AppUiToadlet toadlet = new AppUiToadlet(appHost);
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoInteractions(appHost);
  }

  @Test
  void handleMethodGET_whenTraversalRequested_expectBadRequest() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    StubbedErrorPage errorPage = stubErrorPage(toadlet);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/static/%2e%2e/secret.txt"), request, ctx);

    assertEquals(400, errorPage.statusCode.get());
    assertEquals("Bad Request", errorPage.reasonPhrase.get());
    assertEquals("generated-page", errorPage.body.get());
  }

  @Test
  void handleMethodGET_whenNonEntryDirectoryPathEndsWithSlash_expectNotFound() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    StubbedErrorPage errorPage = stubErrorPage(toadlet);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/assets/"), request, ctx);

    assertEquals(404, errorPage.statusCode.get());
    assertEquals("Not Found", errorPage.reasonPhrase.get());
    assertEquals("generated-page", errorPage.body.get());
  }

  private StubbedErrorPage stubErrorPage(AppUiToadlet toadlet) throws Exception {
    PageMaker pageMaker = mock(PageMaker.class);
    PageNode pageNode = mock(PageNode.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    StubbedErrorPage errorPage = new StubbedErrorPage();

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn("generated-page");
    when(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), isNull(), anyBoolean()))
        .thenReturn(infoboxNode);
    doAnswer(
            invocation -> {
              errorPage.statusCode.set(invocation.getArgument(1));
              errorPage.reasonPhrase.set(invocation.getArgument(2));
              errorPage.body.set(invocation.getArgument(3));
              return null;
            })
        .when(toadlet)
        .writeHTMLReply(eq(ctx), org.mockito.ArgumentMatchers.anyInt(), anyString(), anyString());
    return errorPage;
  }

  private ReplyCapture captureReply() throws Exception {
    ArgumentCaptor<Integer> statusCode = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> reasonPhrase = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headers = multiValueTableCaptor();
    ArgumentCaptor<String> mimeType = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> length = ArgumentCaptor.forClass(Long.class);
    ArgumentCaptor<Boolean> forceDisableJavascript = ArgumentCaptor.forClass(Boolean.class);

    verify(ctx)
        .sendReplyHeaders(
            statusCode.capture(),
            reasonPhrase.capture(),
            headers.capture(),
            mimeType.capture(),
            length.capture(),
            forceDisableJavascript.capture());
    return new ReplyCapture(
        statusCode.getValue(),
        reasonPhrase.getValue(),
        headers.getValue(),
        mimeType.getValue(),
        length.getValue(),
        forceDisableJavascript.getValue());
  }

  @SuppressWarnings("unchecked")
  private static ArgumentCaptor<MultiValueTable<String, String>> multiValueTableCaptor() {
    return (ArgumentCaptor<MultiValueTable<String, String>>)
        (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
  }

  private String captureBucketWriteText() throws Exception {
    ArgumentCaptor<Bucket> bucket = ArgumentCaptor.forClass(Bucket.class);

    verify(ctx).writeData(bucket.capture());
    verifyNoByteArrayWrites();

    try (Bucket captured = bucket.getValue();
        InputStream input = captured.getInputStream()) {
      assertNotNull(input);
      return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private String captureByteArrayWriteText() throws Exception {
    ArgumentCaptor<byte[]> bytes = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offset = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> length = ArgumentCaptor.forClass(Integer.class);

    verify(ctx).writeData(bytes.capture(), offset.capture(), length.capture());
    verify(ctx, never()).writeData(any(Bucket.class));

    return new String(
        bytes.getValue(), offset.getValue(), length.getValue(), StandardCharsets.UTF_8);
  }

  private void enableJavascript(boolean enabled) {
    when(ctx.getContainer()).thenReturn(container);
    when(container.isFProxyJavascriptEnabled()).thenReturn(enabled);
  }

  private void verifyNoBodyWrites() throws Exception {
    verify(ctx, never()).writeData(any(Bucket.class));
    verifyNoByteArrayWrites();
  }

  private void verifyNoByteArrayWrites() throws Exception {
    verify(ctx, never()).writeData(any(byte[].class));
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  private InstalledAppSnapshot staticApp(String uiEntry) {
    return app(AppUiMode.STATIC, uiEntry);
  }

  private InstalledAppSnapshot app(AppUiMode uiMode, String uiEntry) {
    AppManifest manifest =
        new AppManifest(
            1,
            "demo-app",
            "Demo App",
            "1.0.0",
            "bin/launch.sh",
            uiMode,
            uiEntry,
            List.of(),
            null,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            "demo-app",
            tempDir.resolve("installed/demo-app"),
            tempDir.resolve("data/demo-app"),
            tempDir.resolve("cache/demo-app"),
            tempDir.resolve("run/demo-app"));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private record ReplyCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length,
      boolean forceDisableJavascript) {}

  private static final class StubbedErrorPage {
    private final AtomicReference<Integer> statusCode = new AtomicReference<>();
    private final AtomicReference<String> reasonPhrase = new AtomicReference<>();
    private final AtomicReference<String> body = new AtomicReference<>();
  }

  private static final class InMemoryAppHost implements AppHost {
    private final Map<String, InstalledAppSnapshot> snapshots = new LinkedHashMap<>();

    private InMemoryAppHost(InstalledAppSnapshot... snapshots) {
      for (InstalledAppSnapshot snapshot : snapshots) {
        this.snapshots.put(snapshot.appId(), snapshot);
      }
    }

    @Override
    public InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void uninstall(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public List<InstalledAppSnapshot> listInstalled() {
      return List.copyOf(snapshots.values());
    }

    @Override
    public Optional<InstalledAppSnapshot> describe(String appId) {
      return Optional.ofNullable(snapshots.get(appId));
    }

    @Override
    public RunningAppSnapshot start(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean stop(String appId) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Optional<RunningAppSnapshot> status(String appId) {
      return Optional.empty();
    }

    @Override
    public List<RunningAppSnapshot> listRunning() {
      return List.of();
    }

    @Override
    public AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException {
      if (!snapshots.containsKey(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppRuntimeStatusSnapshot(
          appId, AppRuntimeState.STOPPED, false, null, null, null, null, 0, 0, false, null);
    }

    @Override
    public List<AppRuntimeStatusSnapshot> listRuntimeStatus() {
      return snapshots.keySet().stream()
          .map(
              appId ->
                  new AppRuntimeStatusSnapshot(
                      appId,
                      AppRuntimeState.STOPPED,
                      false,
                      null,
                      null,
                      null,
                      null,
                      0,
                      0,
                      false,
                      null))
          .toList();
    }

    @Override
    public AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes) throws IOException {
      if (!snapshots.containsKey(appId)) {
        throw new AppHostException("app is not installed: " + appId);
      }
      return new AppProcessLogSnapshot(appId, false, false, maxBytes, 0L, "", null);
    }
  }
}
