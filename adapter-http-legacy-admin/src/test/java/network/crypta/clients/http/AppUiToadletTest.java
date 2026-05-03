package network.crypta.clients.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
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
import static org.junit.jupiter.api.Assertions.assertNull;
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
  private static final String ACCEPT_HEADER = "Accept";
  private static final String ACCESS_CONTROL_ALLOW_ORIGIN_HEADER = "access-control-allow-origin";
  private static final String ADMIN_ROOT = "http://127.0.0.1:8888/";
  private static final String APP_BOOTSTRAP_URL =
      "http://localhost/apps/demo-app/.well-known/cryptad-bootstrap.json";
  private static final String APP_ID = "demo-app";
  private static final String APP_ROOT_URL = "http://localhost/apps/demo-app/";
  private static final String APPLICATION_JSON = "application/json";
  private static final String BOOTSTRAP_RESOURCE = ".well-known/cryptad-bootstrap.json";
  private static final String BROWSER_SESSION_TOKEN_FIELD = "browserSessionToken";
  private static final String BROWSER_SESSION_TOKEN_JSON = "\"browserSessionToken\":\"";
  private static final String CONTENT_SECURITY_POLICY_HEADER = "content-security-policy";
  private static final String GENERATED_PAGE = "generated-page";
  private static final String HTML_BODY = "<html></html>";
  private static final String INDEX_ENTRY = "index.html";
  private static final String JAVASCRIPT_BODY = "export {};";
  private static final String JAVASCRIPT_CONTENT_TYPE = "text/javascript; charset=UTF-8";
  private static final String LOCATION_HEADER = "Location";
  private static final String NOT_FOUND_REASON = "Not Found";
  private static final String ORIGIN_HEADER = "Origin";
  private static final String REDIRECTING_TO_APP_UI = "Redirecting to app UI.";
  private static final String STATIC_DIRECTORY = "static";
  private static final String STATIC_ENTRY = "static/index.html";
  private static final String UPDATED_APP_NAME = "Updated App";

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
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), HTML_BODY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create(APP_ROOT_URL), request, ctx);

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
    assertEquals(HTML_BODY, captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenNestedAppRootRequested_expectRedirectToEntryDirectory()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create(APP_ROOT_URL), request, ctx);

    verify(toadlet).writeTemporaryRedirect(ctx, REDIRECTING_TO_APP_UI, "/apps/demo-app/static/");
  }

  @Test
  void handleMethodGET_whenIsolatedOriginActive_expectSameOriginFallbackByDefault()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiOriginBinding binding = isolatedBinding(snapshot);
    AppUiToadlet toadlet =
        spy(
            new AppUiToadlet(
                new InMemoryAppHost(snapshot),
                mock(AppBrowserSessionIssuer.class),
                registryWithLaunchUrl(binding, binding.uiUrl() + "#cryptadBootstrapNonce=test")));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/?view=queue"), request, ctx);

    verify(toadlet)
        .writeTemporaryRedirect(ctx, REDIRECTING_TO_APP_UI, "/apps/demo-app/static/?view=queue");
  }

  @Test
  void handleMethodGET_whenIsolatedLaunchRequested_expectRootRedirectToIsolatedLaunchUrl()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiOriginBinding binding = isolatedBinding(snapshot);
    String launchUrl = binding.uiUrl() + "#cryptadBootstrapNonce=test-nonce";
    AppUiToadlet toadlet =
        spy(
            new AppUiToadlet(
                new InMemoryAppHost(snapshot),
                mock(AppBrowserSessionIssuer.class),
                registryWithLaunchUrl(binding, launchUrl)));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/?cryptadIsolatedLaunch=1&view=queue"),
        request,
        ctx);

    String expectedLaunchUrl = binding.uiUrl() + "?view=queue#cryptadBootstrapNonce=test-nonce";
    verify(toadlet).writeTemporaryRedirect(ctx, REDIRECTING_TO_APP_UI, expectedLaunchUrl);
  }

  @Test
  void loopbackOrigin_whenBootstrapRequested_expectConfiguredHttpsAdminRootsAndIpv4Origin()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), "https://127.0.0.1:9443/", () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      assertTrue(binding.origin().startsWith("http://127.0.0.1:"));
      assertEquals("https://127.0.0.1:9443/api/v1/", binding.platformApiRoot());
      assertEquals("https://127.0.0.1:9443/app/node/", binding.shellRoot());

      String nonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());
      HttpResponseCapture response =
          httpGet(
              binding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, nonce));

      assertEquals(200, response.statusCode());
      assertTrue(
          response.body().contains("\"platformApiRoot\":\"https://127.0.0.1:9443/api/v1/\""));
      assertTrue(response.body().contains("\"shellRoot\":\"https://127.0.0.1:9443/app/node/\""));
    }
  }

  @Test
  void loopbackOrigin_whenOriginProbeRequestedFromLocalAdminOrigin_expectCorsMetadata()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      String probeUrl = binding.uiRoot() + AppUiLoopbackOriginServer.ORIGIN_PROBE_PATH.substring(1);
      RawHttpResponseCapture response =
          rawHttpGet(
              probeUrl,
              Map.of(ORIGIN_HEADER, "http://localhost:8888", ACCEPT_HEADER, APPLICATION_JSON));
      RawHttpResponseCapture ipv6LoopbackResponse =
          rawHttpGet(
              probeUrl,
              Map.of(ORIGIN_HEADER, "http://[::1]:8888", ACCEPT_HEADER, APPLICATION_JSON));
      RawHttpResponseCapture remoteOriginResponse =
          rawHttpGet(
              probeUrl,
              Map.of(ORIGIN_HEADER, "http://admin.example:8888", ACCEPT_HEADER, APPLICATION_JSON));

      assertEquals(200, response.statusCode());
      assertEquals("http://localhost:8888", response.accessControlAllowOrigin());
      assertEquals(200, ipv6LoopbackResponse.statusCode());
      assertEquals("http://[::1]:8888", ipv6LoopbackResponse.accessControlAllowOrigin());
      assertTrue(response.body().contains("\"appId\":\"demo-app\""));
      assertTrue(response.body().contains("\"uiOrigin\":\"" + binding.origin() + "\""));
      assertEquals(200, remoteOriginResponse.statusCode());
      assertNull(remoteOriginResponse.accessControlAllowOrigin());
    }
  }

  @Test
  void loopbackOrigin_whenBrowserSessionExpires_expectLaunchProofStillCoversRenewal() {
    assertTrue(
        AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_LIFETIME.compareTo(
                AppBrowserSessionStore.DEFAULT_LIFETIME)
            > 0);
  }

  @Test
  void loopbackOrigin_whenBootstrapRequestedWithoutLaunchProof_expectUnauthorized()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      HttpResponseCapture response = httpGet(binding.uiRoot() + BOOTSTRAP_RESOURCE);

      assertEquals(401, response.statusCode());
      assertFalse(response.body().contains(BROWSER_SESSION_TOKEN_FIELD));
    }
  }

  @Test
  void loopbackOrigin_whenLaunchProofBelongsToDifferentApp_expectUnauthorized() throws Exception {
    InstalledAppSnapshot firstApp = staticApp(APP_ID, INDEX_ENTRY);
    InstalledAppSnapshot secondApp = staticApp("other-app", INDEX_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(firstApp, secondApp);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding secondBinding = originServer.bindingForApp("other-app").orElseThrow();
      String firstNonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());

      HttpResponseCapture response =
          httpGet(
              secondBinding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, firstNonce));

      assertEquals(401, response.statusCode());
      assertFalse(response.body().contains(BROWSER_SESSION_TOKEN_FIELD));
      assertFalse(response.body().contains("\"appId\":\"other-app\""));
    }
  }

  @Test
  void loopbackOrigin_whenAppSnapshotChanges_expectPreviousLaunchProofRejected() throws Exception {
    InstalledAppSnapshot original = staticApp(INDEX_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(original);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();
      String staleNonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());

      appHost.replace(updatedStaticApp());

      HttpResponseCapture rejected =
          httpGet(
              binding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, staleNonce));
      assertEquals(401, rejected.statusCode());
      assertFalse(rejected.body().contains(BROWSER_SESSION_TOKEN_FIELD));

      String currentNonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());
      HttpResponseCapture accepted =
          httpGet(
              binding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, currentNonce));
      assertEquals(200, accepted.statusCode());
      assertTrue(accepted.body().contains("\"name\":\"" + UPDATED_APP_NAME + "\""));
      assertTrue(accepted.body().contains(BROWSER_SESSION_TOKEN_JSON));
    }
  }

  @Test
  void loopbackOrigin_whenManyLaunchProofsIssued_expectOldestLaunchProofEvicted() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();
      String firstNonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());
      String latestNonce = firstNonce;
      for (int index = 0; index < AppUiLoopbackOriginServer.MAX_BOOTSTRAP_NONCES_PER_APP; index++) {
        latestNonce = bootstrapNonceFrom(originServer.launchUrlForApp(APP_ID).orElseThrow());
      }

      HttpResponseCapture rejected =
          httpGet(
              binding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, firstNonce));
      assertEquals(401, rejected.statusCode());
      assertFalse(rejected.body().contains(BROWSER_SESSION_TOKEN_FIELD));

      HttpResponseCapture accepted =
          httpGet(
              binding.uiRoot() + BOOTSTRAP_RESOURCE,
              Map.of(AppUiLoopbackOriginServer.BOOTSTRAP_NONCE_HEADER, latestNonce));
      assertEquals(200, accepted.statusCode());
      assertTrue(accepted.body().contains(BROWSER_SESSION_TOKEN_JSON));
    }
  }

  @Test
  void loopbackOrigin_whenStaleTabRequestsRemovedApp_expectLoopbackListenerStopped()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), HTML_BODY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      appHost.removeDemoApp();

      HttpResponseCapture staleTabResponse = httpGet(binding.uiUrl());
      assertEquals(404, staleTabResponse.statusCode());
      assertEquals("App UI is not available.", staleTabResponse.body());
      assertHttpRequestEventuallyFails(binding.uiUrl());
      assertTrue(originServer.bindingForOrigin(binding.origin()).isEmpty());
    }
  }

  @Test
  void loopbackOrigin_whenJavascriptDisabled_expectScriptExecutionBlocked() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), HTML_BODY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> false)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      HttpResponseCapture response = httpGet(binding.uiUrl());

      assertEquals(200, response.statusCode());
      String contentSecurityPolicy = response.contentSecurityPolicy();
      assertTrue(contentSecurityPolicy.contains("script-src 'none'"));
      assertFalse(contentSecurityPolicy.contains("script-src 'self'"));
      assertTrue(contentSecurityPolicy.contains("connect-src 'self' http://127.0.0.1:8888"));
      assertEquals(HTML_BODY, response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadAssetRequested_expectAssetLengthWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    String body = "<html>demo</html>";
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), body);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiUrl());

      assertEquals(200, response.statusCode());
      assertEquals(body.getBytes(StandardCharsets.UTF_8).length, response.contentLength());
      assertEquals("", response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadMissingAssetRequested_expectNotFoundWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), HTML_BODY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiRoot() + "missing.js");

      assertEquals(404, response.statusCode());
      assertEquals("", response.body());
    }
  }

  @Test
  void loopbackOrigin_whenHeadTraversalRequested_expectBadRequestWithoutBody() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(INDEX_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot());
    Files.writeString(snapshot.paths().installedRoot().resolve(INDEX_ENTRY), HTML_BODY);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);

    try (AppUiLoopbackOriginServer originServer =
        new AppUiLoopbackOriginServer(
            appHost, new AppBrowserSessionStore(appHost), ADMIN_ROOT, () -> true)) {
      AppUiOriginBinding binding = originServer.bindingForApp(APP_ID).orElseThrow();

      HttpResponseCapture response = httpHead(binding.uiRoot() + "%2e%2e/secret");

      assertEquals(400, response.statusCode());
      assertEquals("", response.body());
    }
  }

  @Test
  void handleMethodGET_whenJavascriptDisabled_expectScriptExecutionBlocked() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot().resolve(STATIC_DIRECTORY));
    Files.writeString(snapshot.paths().installedRoot().resolve(STATIC_ENTRY), HTML_BODY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(false);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/static/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(
        AppUiSecurityHeaders.JAVASCRIPT_DISABLED_CONTENT_SECURITY_POLICY,
        reply.headers().getFirst(CONTENT_SECURITY_POLICY_HEADER));
    assertEquals(HTML_BODY, captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenStaticAssetRequested_expectJavascriptContentType() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot().resolve(STATIC_DIRECTORY));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), JAVASCRIPT_BODY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/static/app.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(JAVASCRIPT_CONTENT_TYPE, reply.mimeType());
    assertEquals(10L, reply.length());
    assertEquals(JAVASCRIPT_BODY, captureBucketWriteText());
  }

  @Test
  void handleMethodGET_whenBootstrapRequested_expectBrowserSessionJsonWithoutHostCredentials()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create(APP_BOOTSTRAP_URL), request, ctx);

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
    assertTrue(body.contains(BROWSER_SESSION_TOKEN_JSON));
    assertTrue(body.contains("\"browserSessionExpiresAt\":\""));
    assertFalse(body.contains("formPassword"));
    assertFalse(body.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(body.contains("launchToken"));
    assertFalse(body.contains(tempDir.toString()));
  }

  @Test
  void handleMethodGET_whenIsolatedOriginActiveAndBootstrapRequested_expectFallbackBootstrap()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiOriginBinding binding = isolatedBinding(snapshot);
    InMemoryAppHost appHost = new InMemoryAppHost(snapshot);
    AppUiToadlet toadlet =
        new AppUiToadlet(appHost, new AppBrowserSessionStore(appHost), registryWith(binding));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create(APP_BOOTSTRAP_URL), request, ctx);

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
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppBrowserSessionIssuer sessionIssuer = mock(AppBrowserSessionIssuer.class);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot), sessionIssuer);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodHEAD(URI.create(APP_BOOTSTRAP_URL), request, ctx);

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

    toadlet.handleMethodHEAD(URI.create(APP_BOOTSTRAP_URL), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(404, reply.statusCode());
    assertEquals(NOT_FOUND_REASON, reply.reasonPhrase());
    assertEquals(0L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodGET_whenCanonicalParentRelativeAssetExistsAtBundleRoot_expectBundleRelativeBody()
      throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot().resolve(STATIC_DIRECTORY));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/shared.js"), "nested");
    Files.writeString(snapshot.paths().installedRoot().resolve("shared.js"), "root");
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/shared.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(JAVASCRIPT_CONTENT_TYPE, reply.mimeType());
    assertEquals(4L, reply.length());
    assertEquals("root", captureBucketWriteText());
  }

  @Test
  void handleMethodHEAD_whenStaticAssetRequested_expectHeadersOnly() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot().resolve(STATIC_DIRECTORY));
    Files.writeString(snapshot.paths().installedRoot().resolve("static/app.js"), JAVASCRIPT_BODY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/static/app.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(JAVASCRIPT_CONTENT_TYPE, reply.mimeType());
    assertEquals(10L, reply.length());
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodGET_whenEntryDirectoryRequested_expectDeclaredEntryHtml() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    Files.createDirectories(snapshot.paths().installedRoot().resolve(STATIC_DIRECTORY));
    Files.writeString(snapshot.paths().installedRoot().resolve(STATIC_ENTRY), HTML_BODY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    enableJavascript(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/static/"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(200, reply.statusCode());
    assertEquals("text/html; charset=UTF-8", reply.mimeType());
    assertEquals(HTML_BODY, captureBucketWriteText());
  }

  @Test
  void handleMethodHEAD_whenAppRootMissingSlash_expectHeaderOnlyRedirect() throws Exception {
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost());
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(URI.create("http://localhost/apps/demo-app"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(302, reply.statusCode());
    assertEquals("Found", reply.reasonPhrase());
    assertEquals("/apps/demo-app/", reply.headers().getFirst(LOCATION_HEADER));
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
    assertEquals(
        "/apps/demo-app/?view=queue&filter=a%2Fb", reply.headers().getFirst(LOCATION_HEADER));
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenNestedAppRootHasQuery_expectRedirectPreservesQuery() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/?view=queue&filter=a%2Fb"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(
        "/apps/demo-app/static/?view=queue&filter=a%2Fb",
        reply.headers().getFirst(LOCATION_HEADER));
    verifyNoBodyWrites();
  }

  @Test
  void handleMethodHEAD_whenStaticAssetMissing_expectHeaderOnlyNotFound() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = new AppUiToadlet(new InMemoryAppHost(snapshot));
    when(ctx.isAllowedFullAccess()).thenReturn(true);

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/apps/demo-app/static/missing.js"), request, ctx);

    ReplyCapture reply = captureReply();
    assertEquals(404, reply.statusCode());
    assertEquals(NOT_FOUND_REASON, reply.reasonPhrase());
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

    toadlet.handleMethodHEAD(URI.create(APP_ROOT_URL), request, ctx);

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

    toadlet.handleMethodGET(URI.create(APP_ROOT_URL), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoInteractions(appHost);
  }

  @Test
  void handleMethodGET_whenTraversalRequested_expectBadRequest() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    StubbedErrorPage errorPage = stubErrorPage(toadlet);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(
        URI.create("http://localhost/apps/demo-app/static/%2e%2e/secret.txt"), request, ctx);

    assertEquals(400, errorPage.statusCode.get());
    assertEquals("Bad Request", errorPage.reasonPhrase.get());
    assertEquals(GENERATED_PAGE, errorPage.body.get());
  }

  @Test
  void handleMethodGET_whenNonEntryDirectoryPathEndsWithSlash_expectNotFound() throws Exception {
    InstalledAppSnapshot snapshot = staticApp(STATIC_ENTRY);
    AppUiToadlet toadlet = spy(new AppUiToadlet(new InMemoryAppHost(snapshot)));
    StubbedErrorPage errorPage = stubErrorPage(toadlet);
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);

    toadlet.handleMethodGET(URI.create("http://localhost/apps/demo-app/assets/"), request, ctx);

    assertEquals(404, errorPage.statusCode.get());
    assertEquals(NOT_FOUND_REASON, errorPage.reasonPhrase.get());
    assertEquals(GENERATED_PAGE, errorPage.body.get());
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
    when(pageNode.generate()).thenReturn(GENERATED_PAGE);
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

  private static RawHttpResponseCapture rawHttpGet(String url, Map<String, String> headers)
      throws IOException {
    URI uri = URI.create(url);
    String target =
        uri.getRawQuery() == null ? uri.getRawPath() : uri.getRawPath() + "?" + uri.getRawQuery();
    try (Socket socket = new Socket(uri.getHost(), uri.getPort())) {
      socket.setSoTimeout(2000);
      StringBuilder request = new StringBuilder("GET ").append(target).append(" HTTP/1.1\r\n");
      request
          .append("Host: ")
          .append(uri.getHost())
          .append(':')
          .append(uri.getPort())
          .append("\r\n");
      request.append("Connection: close\r\n");
      headers.forEach(
          (name, value) -> request.append(name).append(": ").append(value).append("\r\n"));
      request.append("\r\n");
      socket.getOutputStream().write(request.toString().getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      return RawHttpResponseCapture.parse(
          new String(socket.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1));
    }
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

  private static void assertHttpRequestEventuallyFails(String url) throws InterruptedException {
    CountDownLatch failureObserved = new CountDownLatch(1);
    AtomicReference<RuntimeException> unexpectedFailure = new AtomicReference<>();
    try (ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor()) {
      ScheduledFuture<?> scheduledProbe =
          executor.scheduleWithFixedDelay(
              () -> probeHttpRequestUntilFails(url, failureObserved, unexpectedFailure),
              0L,
              25L,
              TimeUnit.MILLISECONDS);
      try {
        assertTrue(
            failureObserved.await(2L, TimeUnit.SECONDS),
            () -> "Expected loopback listener to stop: " + url);
        RuntimeException failure = unexpectedFailure.get();
        if (failure != null) {
          throw failure;
        }
      } finally {
        scheduledProbe.cancel(true);
        executor.shutdownNow();
      }
    }
  }

  private static void probeHttpRequestUntilFails(
      String url,
      CountDownLatch failureObserved,
      AtomicReference<RuntimeException> unexpectedFailure) {
    try {
      httpGet(url);
    } catch (IOException _) {
      failureObserved.countDown();
    } catch (RuntimeException failure) {
      unexpectedFailure.compareAndSet(null, failure);
      failureObserved.countDown();
    }
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
    return staticApp(APP_ID, uiEntry);
  }

  private InstalledAppSnapshot staticApp(String appId, String uiEntry) {
    return app(appId, AppUiMode.STATIC, uiEntry);
  }

  private InstalledAppSnapshot updatedStaticApp() {
    return app(APP_ID, UPDATED_APP_NAME, AppUiMode.STATIC, INDEX_ENTRY);
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
    return app(APP_ID, AppUiMode.SHELL_PANEL, "/app/node/#queue");
  }

  private InstalledAppSnapshot app(String appId, AppUiMode uiMode, String uiEntry) {
    return app(appId, "Demo App", uiMode, uiEntry);
  }

  private InstalledAppSnapshot app(String appId, String appName, AppUiMode uiMode, String uiEntry) {
    AppManifest manifest =
        new AppManifest(
            1, appId, appName, "1.0.0", "bin/launch.sh", uiMode, uiEntry, List.of(), null, null);
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

  private record RawHttpResponseCapture(int statusCode, Map<String, String> headers, String body) {
    private static RawHttpResponseCapture parse(String response) {
      int headerEnd = response.indexOf("\r\n\r\n");
      String headerText = headerEnd < 0 ? response : response.substring(0, headerEnd);
      String body = headerEnd < 0 ? "" : response.substring(headerEnd + 4);
      List<String> headerLines = headerText.lines().toList();
      int statusCode = parseStatusCode(headerLines.getFirst());
      Map<String, String> headers = new HashMap<>();
      for (int i = 1; i < headerLines.size(); i++) {
        String headerLine = headerLines.get(i);
        int colon = headerLine.indexOf(':');
        if (colon > 0) {
          headers.put(
              headerLine.substring(0, colon).toLowerCase(Locale.ROOT),
              headerLine.substring(colon + 1).trim());
        }
      }
      return new RawHttpResponseCapture(statusCode, headers, body);
    }

    private static int parseStatusCode(String statusLine) {
      int firstSpace = statusLine.indexOf(' ');
      int secondSpace = statusLine.indexOf(' ', firstSpace + 1);
      return Integer.parseInt(statusLine.substring(firstSpace + 1, secondSpace));
    }

    private String accessControlAllowOrigin() {
      return headers.get(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER);
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

    private void replace(InstalledAppSnapshot snapshot) {
      snapshots.put(snapshot.appId(), snapshot);
    }

    private void removeDemoApp() {
      snapshots.remove(APP_ID);
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
