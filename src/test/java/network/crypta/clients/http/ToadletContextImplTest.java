package network.crypta.clients.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.platform.api.PlatformApiPaths;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.spi.LegacyAdminSurfaceUsage;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ToadletContextImplTest {
  private static final String QUEUE_DOWNLOADS_SURFACE_ID = "queue-downloads";
  private static final String FRIENDS_SURFACE_ID = "friends";
  private static final String QUEUE_MANAGER_APP_ID = "queue-manager";
  private static final String CONFIG_SURFACE_ID = "config";
  private static final String DIAGNOSTIC_SURFACE_ID = "diagnostic";
  private static final String WRONG_FORM_PASSWORD_BODY = "formPassword=wrong&confirm=true";

  @Mock private BucketFactory bucketFactory;
  @Mock private PageMaker pageMaker;
  @Mock private ToadletContainer container;
  @Mock private UserAlertSurface alertManager;
  @Mock private BookmarkManager bookmarkManager;
  @Mock private HTTPRequest request;

  private ByteArrayOutputStream outputStream;
  private ToadletContextImpl context;

  @BeforeEach
  void setUp() throws Exception {
    outputStream = new ByteArrayOutputStream();

    // Minimal stubbing used across tests
    org.mockito.Mockito.when(container.getFormPassword()).thenReturn("secret");
    org.mockito.Mockito.when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    org.mockito.Mockito.when(container.isSSL()).thenReturn(false);

    context = newContext(new MultiValueTable<>());
  }

  @Test
  void parseHTTPDate_whenValidString_parsesEpoch() throws Exception {
    Instant parsed = ToadletContextImpl.parseHTTPDate("Thu, 01 Jan 1970 00:00:00 GMT");
    assertEquals(Instant.EPOCH, parsed);
  }

  @Test
  void parseHTTPDate_whenInvalid_throwsParseException() {
    assertThrows(ParseException.class, () -> ToadletContextImpl.parseHTTPDate("not a date"));
  }

  @Test
  void shouldDisconnectAfterHandled_withCloseHeader_returnsTrue() {
    MultiValueTable<String, String> headers = MultiValueTable.from("connection", "close");
    assertTrue(
        invokeShouldDisconnectAfterHandled(false, headers),
        "close header must force disconnect regardless of version");
  }

  @Test
  void shouldDisconnectAfterHandled_http11WithoutHeader_returnsFalse() {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    assertFalse(invokeShouldDisconnectAfterHandled(false, headers));
  }

  @Test
  void shouldDisconnectAfterHandled_http10WithoutHeader_returnsTrue() {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    assertTrue(invokeShouldDisconnectAfterHandled(true, headers));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenDeleteTargetsPlatformApi_returnsTrue() {
    URI uri = URI.create("http://localhost" + PlatformApiPaths.API_V1_PREFIX + "apps/alpha");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("DELETE", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenPutTargetsPlatformApi_returnsTrue() {
    URI uri =
        URI.create("http://localhost" + PlatformApiPaths.API_V1_PREFIX + "app-vault/secrets/name");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("PUT", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenPatchTargetsPlatformApi_returnsTrue() {
    URI uri =
        URI.create(
            "http://localhost" + PlatformApiPaths.API_V1_PREFIX + "identity-vault/grants/grant-1");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("PATCH", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenHeadTargetsAppUi_returnsTrue() {
    URI uri = URI.create("http://localhost/apps/demo-app/");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("HEAD", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenHeadTargetsPlatformApi_returnsFalse() {
    URI uri = URI.create("http://localhost" + PlatformApiPaths.API_V1_PREFIX + "apps/install");

    assertFalse(ToadletContextImpl.isMethodAllowedInRestrictedMode("HEAD", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenDeleteTargetsNonPlatformRoute_returnsFalse() {
    URI uri = URI.create("http://localhost/chat/");

    assertFalse(ToadletContextImpl.isMethodAllowedInRestrictedMode("DELETE", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenPutTargetsNonPlatformRoute_returnsFalse() {
    URI uri = URI.create("http://localhost/chat/");

    assertFalse(ToadletContextImpl.isMethodAllowedInRestrictedMode("PUT", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenMutatingMethodTargetsRemovedRoute_returnsTrue() {
    URI uri = URI.create("http://localhost/downloads/");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("DELETE", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenMutatingMethodTargetsPartialReplacement_returnsFalse() {
    URI uri = URI.create("http://localhost/alerts/");

    assertFalse(ToadletContextImpl.isMethodAllowedInRestrictedMode("DELETE", uri));
  }

  @Test
  void isMethodAllowedInRestrictedMode_whenHeadTargetsPartialReplacement_returnsTrue() {
    URI uri = URI.create("http://localhost/alerts/");

    assertTrue(ToadletContextImpl.isMethodAllowedInRestrictedMode("HEAD", uri));
  }

  @Test
  void hasFormPassword_whenMatches_returnsTrue() {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32))
        .thenReturn("secret");

    assertTrue(context.hasFormPassword(request));
  }

  @Test
  void hasFormPassword_whenMismatch_returnsFalse() {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32))
        .thenReturn("wrong");

    assertFalse(context.hasFormPassword(request));
  }

  @Test
  void hasFormPassword_whenUrlEncodedRequestBodyContainsPassword_returnsTrue() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded; charset=UTF-8");
    ToadletContextImpl requestContext = newContext(headers);
    HTTPRequestImpl urlEncodedRequest =
        new HTTPRequestImpl(
            new URI("http://example.com/api/v1/apps/queue-manager/start"),
            new SimpleReadOnlyArrayBucket(
                "formPassword=secret".getBytes(StandardCharsets.US_ASCII)),
            requestContext,
            "POST");

    assertTrue(requestContext.hasFormPassword(urlEncodedRequest));
  }

  @Test
  void getBookmarkManager_whenRequestedAsHandleOrConcrete_returnsConfiguredManager() {
    BookmarkManagerHandle handle = context.getBookmarkManager();
    BookmarkManager concrete = context.getBookmarkManager();

    assertSame(bookmarkManager, handle);
    assertSame(bookmarkManager, concrete);
  }

  @Test
  void getAlertManager_whenRequested_returnsConfiguredAlertSurface() {
    UserAlertSurface alertSurface = context.getAlertManager();

    assertSame(alertManager, alertSurface);
  }

  @Test
  void checkFormPassword_whenMissing_redirectsAndReturnsFalse() throws Exception {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32)).thenReturn("bad");

    boolean result = context.checkFormPassword(request, "/redirect");

    assertFalse(result);
    Map<String, List<String>> headers = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
    assertEquals("302", headers.get("__status").getFirst());
    assertEquals("/redirect", headers.get("location").getFirst());
  }

  @Test
  void handle_whenLegacyGetAccepted_recordsLegacyAdminUsage() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureDispatch(new DispatchTestToadlet(LegacyHttpPaths.CONFIG_PATH, 200));
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.CONFIG_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      LegacyAdminSurfaceUsage usage = usage(CONFIG_SURFACE_ID);
      assertEquals(1L, usage.count());
      assertEquals(1L, usage.fallbackRenderCount());
    }
  }

  @Test
  void handle_whenSlashlessLegacyRequestGetsCanonicalRedirect_recordsLegacyAdminUsage()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configurePermanentRedirect(URI.create(LegacyHttpPaths.CONFIG_PATH));
      Socket socket = new FakeSocket(rawGetRequest("/config"), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(1L, usage(CONFIG_SURFACE_ID).count());
      assertEquals(
          "301",
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8)).get("__status").getFirst());
    }
  }

  @Test
  void handle_whenLegacyRequestGetsNonCanonicalRedirect_doesNotRecordLegacyAdminUsage()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configurePermanentRedirect(URI.create(FirstTimeWizardToadlet.TOADLET_URL));
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.CONFIG_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(0L, usage(CONFIG_SURFACE_ID).count());
      assertEquals(
          "301",
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8)).get("__status").getFirst());
    }
  }

  @Test
  void handle_whenLegacyRequestRedirectsToHelper_recordsOriginalLegacySurface() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      URI helperUri = URI.create(LocalDirectoryToadlet.basePath() + LegacyHttpPaths.CONFIG_PATH);
      configureRedirectDispatch(
          new RedirectingToadlet(LegacyHttpPaths.CONFIG_PATH, helperUri),
          new DispatchTestToadlet(LocalDirectoryToadlet.basePath(), 200));
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.CONFIG_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(1L, usage(CONFIG_SURFACE_ID).count());
    }
  }

  @Test
  void handle_whenPostFormPasswordDenied_doesNotRecordLegacyAdminUsage() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureDispatch(new DispatchTestToadlet(LegacyHttpPaths.CONFIG_PATH, 200));
      Socket socket = new FakeSocket(rawDeniedConfigPostRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(0L, usage(CONFIG_SURFACE_ID).count());
    }
  }

  @Test
  void handle_whenRemovedLegacyGetRequested_redirectsToReplacementAndRecordsEvent()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureQueueManagerReplacementAvailable();
      configureDispatch(new DispatchTestToadlet(QueueToadlet.PATH_DOWNLOADS, 200));
      Socket socket = new FakeSocket(rawDownloadsGetRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      LegacyAdminSurfaceUsage usage = usage(QUEUE_DOWNLOADS_SURFACE_ID);
      assertEquals("303", headers.get("__status").getFirst());
      assertEquals("/apps/queue-manager/", headers.get("location").getFirst());
      assertEquals(0L, usage.count());
      assertEquals(1L, usage.replacementResponseCount());
      assertEquals(0L, usage.blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenWizardGateRedirectsRemovedLegacyGet_honorsWizardRedirect() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configurePermanentRedirect(URI.create(FirstTimeWizardToadlet.TOADLET_URL));
      Socket socket = new FakeSocket(rawDownloadsGetRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      assertEquals("301", headers.get("__status").getFirst());
      assertEquals(FirstTimeWizardToadlet.TOADLET_URL, headers.get("location").getFirst());
      assertEquals(0L, usage(QUEUE_DOWNLOADS_SURFACE_ID).replacementResponseCount());
      assertEquals(0L, usage(QUEUE_DOWNLOADS_SURFACE_ID).blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenWizardGateRedirectsRemovedLegacyPost_honorsWizardRedirect() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configurePermanentRedirect(URI.create(FirstTimeWizardToadlet.TOADLET_URL));
      Socket socket = new FakeSocket(rawDeniedDownloadsPostRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      assertEquals("301", headers.get("__status").getFirst());
      assertEquals(FirstTimeWizardToadlet.TOADLET_URL, headers.get("location").getFirst());
      assertEquals(0L, usage(QUEUE_DOWNLOADS_SURFACE_ID).replacementResponseCount());
      assertEquals(0L, usage(QUEUE_DOWNLOADS_SURFACE_ID).blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenRemovedLegacySlashlessCanonicalRedirect_redirectsToReplacement()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureQueueManagerReplacementAvailable();
      configurePermanentRedirect(URI.create(QueueToadlet.PATH_DOWNLOADS));
      Socket socket = new FakeSocket(rawGetRequest("/downloads"), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      assertEquals("303", headers.get("__status").getFirst());
      assertEquals("/apps/queue-manager/", headers.get("location").getFirst());
      assertEquals(1L, usage(QUEUE_DOWNLOADS_SURFACE_ID).replacementResponseCount());
    }
  }

  @Test
  void handle_whenDiagnosticFallbackSlashlessCanonicalRedirect_preservesFallbackQuery()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureWebShellReplacementAvailable();
      configurePermanentRedirect(URI.create(DiagnosticToadlet.TOADLET_URL));
      Socket socket =
          new FakeSocket(
              rawGetRequest("/diagnostic?legacyFallback=diagnostic-export"), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      assertEquals("301", headers.get("__status").getFirst());
      assertEquals(
          "/diagnostic/?legacyFallback=diagnostic-export", headers.get("location").getFirst());
      assertEquals(1L, usage(DIAGNOSTIC_SURFACE_ID).fallbackRenderCount());
      assertEquals(0L, usage(DIAGNOSTIC_SURFACE_ID).replacementResponseCount());
    }
  }

  @Test
  void handle_whenDiagnosticFallbackSlashlessQueryIsNotExact_redirectsToReplacement()
      throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureWebShellReplacementAvailable();
      configurePermanentRedirect(URI.create(DiagnosticToadlet.TOADLET_URL));
      Socket socket =
          new FakeSocket(
              rawGetRequest("/diagnostic?legacyFallback=diagnostic-export&token=secret"),
              outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      assertEquals("303", headers.get("__status").getFirst());
      assertEquals("/app/node/#diagnostics", headers.get("location").getFirst());
      assertEquals(0L, usage(DIAGNOSTIC_SURFACE_ID).fallbackRenderCount());
      assertEquals(1L, usage(DIAGNOSTIC_SURFACE_ID).replacementResponseCount());
    }
  }

  @Test
  void handle_whenRemovedConfigGetHasNoConcreteToadlet_redirectsBeforeNoToadlet() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureWebShellReplacementAvailable();
      configureNoToadlet();
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.CONFIG_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      LegacyAdminSurfaceUsage usage = usage(CONFIG_SURFACE_ID);
      assertEquals("303", headers.get("__status").getFirst());
      assertEquals("/app/node/#config", headers.get("location").getFirst());
      assertEquals(0L, usage.count());
      assertEquals(1L, usage.replacementResponseCount());
    }
  }

  @Test
  void handle_whenRemovedLegacyPostRequested_blocksMutationAndRecordsEvent() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureQueueManagerReplacementAvailable();
      configureDispatch(new DispatchTestToadlet(QueueToadlet.PATH_DOWNLOADS, 200));
      Socket socket = new FakeSocket(rawDeniedDownloadsPostRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      LegacyAdminSurfaceUsage usage = usage(QUEUE_DOWNLOADS_SURFACE_ID);
      assertEquals("410", headers.get("__status").getFirst());
      assertEquals(0L, usage.count());
      assertEquals(0L, usage.replacementResponseCount());
      assertEquals(1L, usage.blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenRemovedLegacyHeadRequested_redirectsWithoutBody() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureQueueManagerReplacementAvailable();
      configureDispatch(new DispatchTestToadlet(QueueToadlet.PATH_DOWNLOADS, 200));
      Socket socket = new FakeSocket(rawDownloadsHeadRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      String rawResponse = outputStream.toString(StandardCharsets.UTF_8);
      Map<String, List<String>> headers = parseHeaders(rawResponse);
      assertEquals("303", headers.get("__status").getFirst());
      assertEquals("/apps/queue-manager/", headers.get("location").getFirst());
      assertFalse(rawResponse.contains("Legacy page replaced"));
      assertEquals(1L, usage(QUEUE_DOWNLOADS_SURFACE_ID).replacementResponseCount());
    }
  }

  @Test
  void handle_whenStaticAppReplacementUnavailable_rendersLegacyFallback() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureQueueManagerReplacementUnavailable();
      configureDispatch(new DispatchTestToadlet(QueueToadlet.PATH_DOWNLOADS, 200));
      Socket socket = new FakeSocket(rawDownloadsGetRequest(), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      LegacyAdminSurfaceUsage usage = usage(QUEUE_DOWNLOADS_SURFACE_ID);
      assertEquals("200", headers.get("__status").getFirst());
      assertEquals(1L, usage.count());
      assertEquals(1L, usage.fallbackRenderCount());
      assertEquals(0L, usage.replacementResponseCount());
      assertEquals(0L, usage.blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenWebShellReplacementUnavailable_rendersLegacyFallback() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureWebShellReplacementUnavailable();
      configureDispatch(new DispatchTestToadlet(LegacyHttpPaths.FRIENDS_PATH, 200));
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.FRIENDS_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      Map<String, List<String>> headers =
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
      LegacyAdminSurfaceUsage usage = usage(FRIENDS_SURFACE_ID);
      assertEquals("200", headers.get("__status").getFirst());
      assertEquals(1L, usage.count());
      assertEquals(1L, usage.fallbackRenderCount());
      assertEquals(0L, usage.replacementResponseCount());
      assertEquals(0L, usage.blockedMutatingRequestCount());
    }
  }

  @Test
  void handle_whenBrowseRootRequested_doesNotApplyRemovalPolicy() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureDispatch(new DispatchTestToadlet("/", 200));
      Socket socket = new FakeSocket(rawGetRequest("/"), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(
          "200",
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8)).get("__status").getFirst());
      assertEquals(0L, usage(QUEUE_DOWNLOADS_SURFACE_ID).replacementResponseCount());
    }
  }

  @Test
  void handle_whenPendingWizardRequested_doesNotApplyRemovalPolicy() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureDispatch(new DispatchTestToadlet(FirstTimeWizardToadlet.TOADLET_URL, 200));
      Socket socket =
          new FakeSocket(rawGetRequest(FirstTimeWizardToadlet.TOADLET_URL), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(
          "200",
          parseHeaders(outputStream.toString(StandardCharsets.UTF_8)).get("__status").getFirst());
    }
  }

  @Test
  void handle_whenFullAccessDenied_doesNotRecordLegacyAdminUsage() throws Exception {
    try (var _ = clearedLegacyAdminUsage()) {
      configureDispatch(new FullAccessCheckingToadlet(LegacyHttpPaths.CONFIG_PATH));
      Socket socket = new FakeSocket(rawGetRequest(LegacyHttpPaths.CONFIG_PATH), outputStream);

      ToadletContextImpl.handle(socket, newRequestServices());

      assertEquals(0L, usage(CONFIG_SURFACE_ID).count());
    }
  }

  @Test
  void sendReplyHeaders_withoutModifiedTime_setsNoCacheAndCsp() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();

    ReplyHeaders replyHeaders = ReplyHeaders.of(200, "OK", "text/plain", headers);
    ReplyHeaderOptions options = new ReplyHeaderOptions(10, null, true, false, false);
    ToadletContextImpl.sendReplyHeaders(outputStream, replyHeaders, options);

    Map<String, List<String>> parsed = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));

    assertEquals("200", parsed.get("__status").getFirst());
    assertEquals("close", parsed.get("connection").getFirst());
    assertEquals("text/plain", parsed.get("content-type").getFirst());
    assertEquals("10", parsed.get("content-length").getFirst());
    assertEquals("Thu, 01 Jan 1970 00:00:00 GMT", parsed.get("expires").getFirst());
    assertTrue(parsed.get("cache-control").getFirst().contains("no-cache"));
    assertEquals("DENY", parsed.get("x-frame-options").getFirst());
    String csp = parsed.get("content-security-policy").getFirst();
    assertTrue(csp.contains("frame-src 'none'"));
    assertTrue(csp.contains("sha256-RY9OjosvFxocXEmcUqBJ2v1KByDRdUgnGHYSL3Qx/t8="));
    String scriptDirective = getScriptDirective(csp);
    assertFalse(
        scriptDirective.contains("unsafe-inline"),
        "inline scripts must be forbidden when disabled");
  }

  @Test
  void sendReplyHeaders_withModifiedTime_allowsCachingAndScripts() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    Instant modified = Instant.EPOCH;

    ReplyHeaders replyHeaders = ReplyHeaders.of(200, "OK", "text/html", headers);
    ReplyHeaderOptions options = new ReplyHeaderOptions(5, modified, false, true, true);
    ToadletContextImpl.sendReplyHeaders(outputStream, replyHeaders, options);

    Map<String, List<String>> parsed = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));

    assertEquals("keep-alive", parsed.get("connection").getFirst());
    assertEquals("text/html; charset=UTF-8", parsed.get("content-type").getFirst());
    assertTrue(parsed.get("cache-control").getFirst().startsWith("public"));
    Instant lastModified = ToadletContextImpl.parseHTTPDate(parsed.get("last-modified").getFirst());
    assertEquals(modified, lastModified);
    String csp = parsed.get("content-security-policy").getFirst();
    assertTrue(csp.contains("frame-src 'self'"));
    assertTrue(csp.contains("unsafe-inline"));
    assertTrue(csp.contains("unsafe-eval"));
  }

  @Test
  void sendReplyHeaders_whenCalledTwice_throwsIllegalState() throws Exception {
    context.sendReplyHeaders(200, "OK", null, "text/plain", 0);

    assertThrows(
        IllegalStateException.class, () -> context.sendReplyHeaders(200, "OK", null, null, 0));
  }

  @Test
  void writeData_whenClosed_throwsToadletContextClosedException() throws Exception {
    java.lang.reflect.Field closedField = ToadletContextImpl.class.getDeclaredField("closed");
    closedField.setAccessible(true);
    closedField.set(context, true);

    assertThrows(ToadletContextClosedException.class, () -> context.writeData(new byte[] {1, 2}));
  }

  private static boolean invokeShouldDisconnectAfterHandled(
      boolean isHttp10, MultiValueTable<String, String> headers) {
    try {
      java.lang.reflect.Method m =
          ToadletContextImpl.class.getDeclaredMethod(
              "shouldDisconnectAfterHandled", boolean.class, MultiValueTable.class);
      m.setAccessible(true);
      return (boolean) m.invoke(null, isHttp10, headers);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  private static Map<String, List<String>> parseHeaders(String raw) {
    Map<String, List<String>> map = new LinkedHashMap<>();
    List<String> lines = splitLines(raw);
    if (lines.isEmpty()) return map;
    String statusLine = lines.getFirst();
    String[] statusParts = splitOnChar(statusLine, ' ');
    if (statusParts.length >= 2) {
      map.put("__status", List.of(statusParts[1]));
    }
    for (int i = 1; i < lines.size(); i++) {
      String line = lines.get(i);
      if (line.trim().isEmpty()) {
        continue;
      }
      int idx = line.indexOf(':');
      if (idx <= 0) continue;
      String key = line.substring(0, idx).toLowerCase(Locale.ROOT);
      String value = line.substring(idx + 1).trim();
      map.computeIfAbsent(key, _ -> new java.util.ArrayList<>()).add(value);
    }
    return map;
  }

  private static String getScriptDirective(String csp) {
    final String prefix = "script-src";
    for (String part : splitOnChar(csp, ';')) {
      String trimmed = part.trim();
      if (trimmed.startsWith(prefix)) {
        return trimmed;
      }
    }
    return "";
  }

  private static List<String> splitLines(String raw) {
    List<String> lines = new ArrayList<>();
    int start = 0;
    for (int i = 0; i < raw.length(); i++) {
      if (raw.charAt(i) == '\n') {
        int end = i;
        if (end > start && raw.charAt(end - 1) == '\r') {
          end--;
        }
        lines.add(raw.substring(start, end));
        start = i + 1;
      }
    }
    lines.add(raw.substring(start));
    while (!lines.isEmpty() && lines.getLast().isEmpty()) {
      lines.removeLast();
    }
    return lines;
  }

  private static String[] splitOnChar(String value, char delimiter) {
    int segments = 1;
    for (int i = 0; i < value.length(); i++) {
      if (value.charAt(i) == delimiter) {
        segments++;
      }
    }
    String[] parts = new String[segments];
    int start = 0;
    int partIndex = 0;
    for (int i = 0; i < value.length(); i++) {
      if (value.charAt(i) == delimiter) {
        parts[partIndex++] = value.substring(start, i);
        start = i + 1;
      }
    }
    parts[partIndex] = value.substring(start);

    int end = parts.length;
    while (end > 0 && parts[end - 1].isEmpty()) {
      end--;
    }
    return end == parts.length ? parts : java.util.Arrays.copyOf(parts, end);
  }

  private ToadletContextImpl newContext(MultiValueTable<String, String> headers) throws Exception {
    Socket socket = new FakeSocket(outputStream, InetAddress.getLoopbackAddress());
    return new ToadletContextImpl(
        socket, headers, bucketFactory, newRequestServices(), new URI("http://example.com/"), 1L);
  }

  private ToadletRequestServices newRequestServices() {
    return new ToadletRequestServices(container, pageMaker, alertManager, bookmarkManager);
  }

  private void configureQueueManagerReplacementAvailable() {
    org.mockito.Mockito.when(
            container.isAllowedFullAccess(org.mockito.ArgumentMatchers.any(InetAddress.class)))
        .thenReturn(true);
    org.mockito.Mockito.when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    org.mockito.Mockito.when(container.isStaticAppUiAvailable(QUEUE_MANAGER_APP_ID))
        .thenReturn(true);
  }

  private void configureQueueManagerReplacementUnavailable() {
    org.mockito.Mockito.when(
            container.isAllowedFullAccess(org.mockito.ArgumentMatchers.any(InetAddress.class)))
        .thenReturn(true);
    org.mockito.Mockito.when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    org.mockito.Mockito.when(container.isStaticAppUiAvailable(QUEUE_MANAGER_APP_ID))
        .thenReturn(false);
  }

  private void configureWebShellReplacementAvailable() {
    org.mockito.Mockito.when(
            container.isAllowedFullAccess(org.mockito.ArgumentMatchers.any(InetAddress.class)))
        .thenReturn(true);
    org.mockito.Mockito.when(container.primaryUiRoot()).thenReturn(WebShellPaths.SHELL_ROOT);
  }

  private void configureWebShellReplacementUnavailable() {
    org.mockito.Mockito.when(
            container.isAllowedFullAccess(org.mockito.ArgumentMatchers.any(InetAddress.class)))
        .thenReturn(true);
    org.mockito.Mockito.when(container.primaryUiRoot())
        .thenReturn(WebShellPaths.SHELL_ROOT + "off");
  }

  private void configureDispatch(Toadlet toadlet) throws Exception {
    org.mockito.Mockito.when(container.getBucketFactory()).thenReturn(new ArrayBucketFactory());
    org.mockito.Mockito.when(container.allowPosts()).thenReturn(true);
    org.mockito.Mockito.when(container.generateUniqueID()).thenReturn(1L);
    org.mockito.Mockito.when(container.findToadlet(org.mockito.ArgumentMatchers.any(URI.class)))
        .thenReturn(toadlet);
  }

  private void configureNoToadlet() throws Exception {
    org.mockito.Mockito.when(container.getBucketFactory()).thenReturn(new ArrayBucketFactory());
    org.mockito.Mockito.when(container.allowPosts()).thenReturn(true);
    org.mockito.Mockito.when(container.generateUniqueID()).thenReturn(1L);
    org.mockito.Mockito.when(container.findToadlet(org.mockito.ArgumentMatchers.any(URI.class)))
        .thenReturn(null);
  }

  private void configureRedirectDispatch(Toadlet originalToadlet, Toadlet helperToadlet)
      throws Exception {
    org.mockito.Mockito.when(container.getBucketFactory()).thenReturn(new ArrayBucketFactory());
    org.mockito.Mockito.when(container.allowPosts()).thenReturn(true);
    org.mockito.Mockito.when(container.generateUniqueID()).thenReturn(1L);
    org.mockito.Mockito.when(container.findToadlet(org.mockito.ArgumentMatchers.any(URI.class)))
        .thenAnswer(
            invocation -> {
              URI requestedUri = invocation.getArgument(0);
              return requestedUri.getPath().startsWith(helperToadlet.path())
                  ? helperToadlet
                  : originalToadlet;
            });
  }

  private void configurePermanentRedirect(URI newUri) throws Exception {
    org.mockito.Mockito.when(container.getBucketFactory()).thenReturn(new ArrayBucketFactory());
    org.mockito.Mockito.when(container.allowPosts()).thenReturn(true);
    org.mockito.Mockito.when(container.generateUniqueID()).thenReturn(1L);
    org.mockito.Mockito.when(container.findToadlet(org.mockito.ArgumentMatchers.any(URI.class)))
        .thenThrow(new PermanentRedirectException(newUri));
  }

  private static byte[] rawDownloadsGetRequest() {
    return rawGetRequest(QueueToadlet.PATH_DOWNLOADS);
  }

  private static byte[] rawGetRequest(String path) {
    return ("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] rawDownloadsHeadRequest() {
    return ("HEAD " + QueueToadlet.PATH_DOWNLOADS + " HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] rawDeniedDownloadsPostRequest() {
    return ("POST "
            + QueueToadlet.PATH_DOWNLOADS
            + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
            + "application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: "
            + WRONG_FORM_PASSWORD_BODY.length()
            + "\r\n\r\n"
            + WRONG_FORM_PASSWORD_BODY)
        .getBytes(StandardCharsets.US_ASCII);
  }

  private static byte[] rawDeniedConfigPostRequest() {
    return ("POST "
            + LegacyHttpPaths.CONFIG_PATH
            + " HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
            + "application/x-www-form-urlencoded; charset=UTF-8\r\nContent-Length: "
            + WRONG_FORM_PASSWORD_BODY.length()
            + "\r\n\r\n"
            + WRONG_FORM_PASSWORD_BODY)
        .getBytes(StandardCharsets.US_ASCII);
  }

  private static LegacyAdminSurfaceUsage usage(String surfaceId) {
    return LegacyAdminUsageRecorder.defaultRecorder().snapshot().surfaces().stream()
        .filter(surface -> surface.surfaceId().equals(surfaceId))
        .findFirst()
        .orElseThrow();
  }

  private static LegacyAdminUsageScope clearedLegacyAdminUsage() {
    return new LegacyAdminUsageScope();
  }

  private static final class LegacyAdminUsageScope implements AutoCloseable {
    LegacyAdminUsageScope() {
      LegacyAdminUsageRecorder.defaultRecorder().clear();
    }

    @Override
    public void close() {
      LegacyAdminUsageRecorder.defaultRecorder().clear();
    }
  }

  private static class FakeSocket extends Socket {
    private final ByteArrayInputStream is;
    private final ByteArrayOutputStream os;
    private final InetAddress inetAddress;

    FakeSocket(ByteArrayOutputStream os, InetAddress inetAddress) {
      this(new byte[0], os, inetAddress);
    }

    FakeSocket(byte[] input, ByteArrayOutputStream os) {
      this(input, os, InetAddress.getLoopbackAddress());
    }

    FakeSocket(byte[] input, ByteArrayOutputStream os, InetAddress inetAddress) {
      this.is = new ByteArrayInputStream(input);
      this.os = os;
      this.inetAddress = inetAddress;
    }

    @Override
    public InputStream getInputStream() {
      return is;
    }

    @Override
    public ByteArrayOutputStream getOutputStream() {
      return os;
    }

    @Override
    public InetAddress getInetAddress() {
      return inetAddress;
    }

    @Override
    public void close() {
      // no-op for tests
    }
  }

  private static class DispatchTestToadlet extends Toadlet {
    private final String path;
    private final int replyCode;

    DispatchTestToadlet(String path, int replyCode) {
      this.path = path;
      this.replyCode = replyCode;
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      ctx.sendReplyHeaders(replyCode, replyCode == 200 ? "OK" : "Error", null, "text/plain", 0);
    }

    @SuppressWarnings({"UnusedMethod", "unused"})
    public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      handleMethodGET(uri, request, ctx);
    }

    @Override
    public String path() {
      return path;
    }
  }

  private static final class RedirectingToadlet extends Toadlet {
    private final String path;
    private final URI redirectUri;

    RedirectingToadlet(String path, URI redirectUri) {
      this.path = path;
      this.redirectUri = redirectUri;
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
        throws RedirectException {
      throw new RedirectException(redirectUri);
    }

    @Override
    public String path() {
      return path;
    }
  }

  private static final class FullAccessCheckingToadlet extends DispatchTestToadlet {
    FullAccessCheckingToadlet(String path) {
      super(path, 200);
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
        throws ToadletContextClosedException, IOException {
      if (!ctx.isAllowedFullAccess()) {
        ctx.sendReplyHeaders(403, "Forbidden", null, "text/plain", 0);
        return;
      }
      super.handleMethodGET(uri, request, ctx);
    }
  }
}
