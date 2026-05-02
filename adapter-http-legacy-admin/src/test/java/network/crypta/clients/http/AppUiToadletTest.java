package network.crypta.clients.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
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
import network.crypta.platform.appui.AppBrowserSessionIssuer;
import network.crypta.platform.appui.AppBrowserSessionStore;
import network.crypta.platform.appui.AppUiOrigin;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginRegistry;
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
  private static final String CONTENT_SECURITY_POLICY_HEADER = "content-security-policy";

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
        reply.headers().getFirst(CONTENT_SECURITY_POLICY_HEADER));
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
  void handleMethodGET_whenIsolatedOriginActive_expectRootRedirectToIsolatedLaunchUrl()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiOriginBinding binding = isolatedBinding(snapshot);
    String launchUrl = binding.uiUrl() + "#cryptadBootstrapNonce=test-nonce";
    AppUiToadlet toadlet =
        spy(
            new AppUiToadlet(
                new InMemoryAppHost(snapshot),
                mock(AppBrowserSessionIssuer.class),
                registryWithLaunchUrl(binding, launchUrl)));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/?view=queue"), request, ctx);

    String expectedLaunchUrl = binding.uiUrl() + "?view=queue#cryptadBootstrapNonce=test-nonce";
    verify(toadlet).writeTemporaryRedirect(ctx, "Redirecting to app UI.", expectedLaunchUrl);
  }

  @Test
  void loopbackOrigin_whenBootstrapRequested_expectConfiguredHttpsAdminRootsAndIpv4Origin()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "https://127.0.0.1:9443/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      assertTrue(binding.origin().startsWith("http://127.0.0.1:"));
      assertEquals("https://127.0.0.1:9443/api/v1/", binding.platformApiRoot());
      assertEquals("https://127.0.0.1:9443/app/node/", binding.shellRoot());

      String nonce = bootstrapNonceFrom(originServer.launchUrlForApp("demo-app").orElseThrow());
      HttpResponseCapture response =
          httpGet(
              binding.uiRoot() + ".well-known/cryptad-bootstrap.json",
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, nonce));

      assertEquals(200, response.statusCode());
      assertTrue(
          response.body().contains("\"platformApiRoot\":\"https://127.0.0.1:9443/api/v1/\""));
      assertTrue(response.body().contains("\"shellRoot\":\"https://127.0.0.1:9443/app/node/\""));
    }
  }

  @Test
  void loopbackOrigin_whenBootstrapRequestedWithoutLaunchProof_expectUnauthorized()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      HttpResponseCapture response =
          httpGet(binding.uiRoot() + ".well-known/cryptad-bootstrap.json");

      assertEquals(401, response.statusCode());
      assertFalse(response.body().contains("browserSessionToken"));
    }
  }

  @Test
  void loopbackOrigin_whenLaunchProofBelongsToDifferentApp_expectUnauthorized() throws Exception {
    InstalledAppSnapshot firstApp = staticApp("demo-app", "index.html");
    InstalledAppSnapshot secondApp = staticApp("other-app", "index.html");
    InMemoryAppHost appHost = new InMemoryAppHost(firstApp, secondApp);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> true)) {
      AppUiOriginBinding secondBinding = originServer.bindingForApp("other-app").orElseThrow();
      String firstNonce =
          bootstrapNonceFrom(originServer.launchUrlForApp("demo-app").orElseThrow());

      HttpResponseCapture response =
          httpGet(
              secondBinding.uiRoot() + ".well-known/cryptad-bootstrap.json",
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, firstNonce));

      assertEquals(401, response.statusCode());
      assertFalse(response.body().contains("browserSessionToken"));
      assertFalse(response.body().contains("\"appId\":\"other-app\""));
    }
  }

  @Test
  void loopbackOrigin_whenJavascriptDisabled_expectScriptExecutionBlocked() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("index.html");
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve("index.html"), "<html></html>");
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> false)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      HttpResponseCapture response = httpGet(binding.uiUrl());

      assertEquals(200, response.statusCode());
      String contentSecurityPolicy = response.contentSecurityPolicy();
      assertTrue(contentSecurityPolicy.contains("script-src 'none'"));
      assertFalse(contentSecurityPolicy.contains("script-src 'self'"));
      assertTrue(contentSecurityPolicy.contains("connect-src 'self' http://127.0.0.1:8888"));
      assertEquals("<html></html>", response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadAssetRequested_expectAssetLengthWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("index.html");
    String body = "<html>demo</html>";
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve("index.html"), body);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiUrl());

      assertEquals(200, response.statusCode());
      assertEquals(body.getBytes(StandardCharsets.UTF_8).length, response.contentLength());
      assertEquals("", response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadMissingAssetRequested_expectNotFoundWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("index.html");
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve("index.html"), "<html></html>");
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiRoot() + "missing.js");

      assertEquals(404, response.statusCode());
      assertEquals("", response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadTraversalRequested_expectBadRequestWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp("index.html");
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve("index.html"), "<html></html>");
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "http://127.0.0.1:8888/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp("demo-app").orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiRoot() + "%2e%2e/secret");

      assertEquals(400, response.statusCode());
      assertEquals("", response.body());
    }
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
        reply.headers().getFirst(CONTENT_SECURITY_POLICY_HEADER));
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
  void handleMethodGET_whenBootstrapRequested_expectBrowserSessionJsonWithoutHostCredentials()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
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
    assertTrue(body.contains("\"uiOrigin\":null"));
    assertTrue(body.contains("\"uiOriginMode\":\"same-origin-fallback\""));
    assertTrue(body.contains("\"uiOriginStatus\":\"fallback\""));
    assertTrue(body.contains("\"sameOriginFallbackUrl\":\"/apps/demo-app/\""));
    assertTrue(body.contains("\"browserSessionToken\":\""));
    assertTrue(body.contains("\"browserSessionExpiresAt\":\""));
    assertFalse(body.contains("formPassword"));
    assertFalse(body.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(body.contains("launchToken"));
    assertFalse(body.contains(tempDir.toString()));
  }

  @Test
  void handleMethodGET_whenIsolatedOriginActiveAndBootstrapRequested_expectFallbackBootstrap()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppUiOriginBinding binding = isolatedBinding(snapshot);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);
    AppUiToadlet toadlet =
        new AppUiToadlet(appHost, new AppBrowserSessionStore(appHost), registryWith(binding));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json"),
        request,
        ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    String body = captureByteArrayWriteText();
    assertTrue(body.contains("\"uiRoot\":\"/apps/demo-app/\""));
    assertTrue(body.contains("\"assetRoot\":\"/apps/demo-app/static/\""));
    assertTrue(body.contains("\"uiOrigin\":null"));
    assertTrue(body.contains("\"uiOriginMode\":\"same-origin-fallback\""));
    assertFalse(body.contains(binding.origin()));
  }

  @Test
  void handleMethodHEAD_whenBootstrapRequestedForStaticApp_expectHeadersOnlyJson()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp("static/index.html");
    AppBrowserSessionIssuer sessionIssuer = mock(AppBrowserSessionIssuer.class);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot), sessionIssuer);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json"),
        request,
        ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("application/json; charset=UTF-8", reply.mimeType());
    assertEquals("no-store", reply.headers().getFirst("cache-control"));
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
    verify(sessionIssuer, never()).issue(any());
  }

  @Test
  void handleMethodHEAD_whenBootstrapRequestedForShellPanelApp_expectNotFound() throws Exception {
    InstalledAppSnapshot snapshot = shellPanelApp();
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

  private static HttpResponseCapture httpGet(String url) throws IOException {
    return httpRequest("GET", url, Map.of());
  }

  private static HttpResponseCapture httpGet(String url, Map<String, String> headers)
      throws IOException {
    return httpRequest("GET", url, headers);
  }

  private static HttpResponseCapture httpHead(String url) throws IOException {
    return httpRequest("HEAD", url, Map.of());
  }

  private static HttpResponseCapture httpRequest(
      String method, String url, Map<String, String> headers) throws IOException {
    HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
    connection.setRequestMethod(method);
    headers.forEach(connection::setRequestProperty);
    connection.setConnectTimeout(2000);
    connection.setReadTimeout(2000);
    int statusCode = connection.getResponseCode();
    String body = "";
    if (!"HEAD".equals(method)) {
      InputStream stream =
          statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
      if (stream != null) {
        try (stream) {
          body = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
      }
    }
    return new HttpResponseCapture(statusCode, connection, body);
  }

  private static String bootstrapNonceFrom(String launchUrl) {
    String rawFragment = URI.create(launchUrl).getRawFragment();
    assertNotNull(rawFragment);
    String prefix = AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_FRAGMENT_PARAMETER + "=";
    int start = 0;
    while (start <= rawFragment.length()) {
      int ampersand = rawFragment.indexOf('&', start);
      String part =
          ampersand < 0 ? rawFragment.substring(start) : rawFragment.substring(start, ampersand);
      if (part.startsWith(prefix)) {
        return part.substring(prefix.length());
      }
      if (ampersand < 0) {
        break;
      }
      start = ampersand + 1;
    }
    throw new AssertionError("Launch URL did not include app bootstrap nonce.");
  }

  private InstalledAppSnapshot staticApp(String uiEntry) {
    return staticApp("demo-app", uiEntry);
  }

  private InstalledAppSnapshot staticApp(String appId, String uiEntry) {
    return app(appId, AppUiMode.STATIC, uiEntry);
  }

  private static AppUiOriginBinding isolatedBinding(InstalledAppSnapshot snapshot) {
    return AppUiOriginBinding.isolatedLoopback(
        snapshot.manifest(),
        AppUiOrigin.loopback(snapshot.appId(), 12345),
        "http://127.0.0.1:8888/api/v1/",
        "http://127.0.0.1:8888/app/node/");
  }

  private static AppUiOriginRegistry registryWith(AppUiOriginBinding binding) {
    return appId -> binding.appId().equals(appId) ? Optional.of(binding) : Optional.empty();
  }

  private static AppUiOriginRegistry registryWithLaunchUrl(
      AppUiOriginBinding binding, String launchUrl) {
    return new AppUiOriginRegistry() {
      @Override
      public Optional<AppUiOriginBinding> bindingForApp(String appId) {
        return binding.appId().equals(appId) ? Optional.of(binding) : Optional.empty();
      }

      @Override
      public Optional<String> launchUrlForApp(String appId) {
        return binding.appId().equals(appId) ? Optional.of(launchUrl) : Optional.empty();
      }
    };
  }

  private InstalledAppSnapshot shellPanelApp() {
    return app("demo-app", AppUiMode.SHELL_PANEL, "/app/node/#queue");
  }

  private InstalledAppSnapshot app(String appId, AppUiMode uiMode, String uiEntry) {
    AppManifest manifest =
        new AppManifest(
            1, appId, "Demo App", "1.0.0", "bin/launch.sh", uiMode, uiEntry, List.of(), null, null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            tempDir.resolve("installed").resolve(appId),
            tempDir.resolve("data").resolve(appId),
            tempDir.resolve("cache").resolve(appId),
            tempDir.resolve("run").resolve(appId));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private record ReplyCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length,
      boolean forceDisableJavascript) {}

  private record HttpResponseCapture(int statusCode, HttpURLConnection connection, String body) {
    private String contentSecurityPolicy() {
      return connection.getHeaderField(CONTENT_SECURITY_POLICY_HEADER);
    }

    private long contentLength() {
      return connection.getContentLengthLong();
    }
  }

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
