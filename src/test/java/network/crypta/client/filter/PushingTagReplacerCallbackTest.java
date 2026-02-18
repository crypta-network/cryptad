package network.crypta.client.filter;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class PushingTagReplacerCallbackTest {

  @Mock private network.crypta.clients.http.FProxyFetchTracker tracker;
  @Mock private ToadletContext ctx;
  @Mock private URIProcessor uriProcessor;

  private SimpleToadletServer container;

  /** No-op ticker to avoid executing queued jobs during tests (deterministic). */
  private static final class NoopTicker implements Ticker {
    @Override
    public void queueTimedJob(Runnable job, long offset) {
      // no-op
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      // no-op
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return null;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      // no-op
    }
  }

  @BeforeEach
  void setUp() {
    // Mock SimpleToadletServer (final class; inline mock-maker enabled in test resources)
    container = mock(SimpleToadletServer.class);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(container.isFProxyWebPushingEnabled()).thenReturn(true);
    // Avoid background activity
    when(container.getTicker()).thenReturn(new NoopTicker());
    // Provide a PushDataManager (mock is fine; BaseUpdatableElement.init will call
    // elementRendered)
    PushDataManager pdm = mock(PushDataManager.class);
    when(container.getPushDataManager()).thenReturn(pdm);

    when(ctx.getContainer()).thenReturn(container);
    when(ctx.getUniqueId()).thenReturn("req-123");

    // Deterministic element id inside ImageElement
    when(tracker.makeRandomElementID()).thenReturn(42);
  }

  @Test
  void getClientSideLocalizationScript_returnsVarWithExpectedKeys() {
    // Arrange
    // Ensure fallback (default language) is loaded so prefix scan is populated
    NodeL10n.getBase().getDefaultLanguageTranslation();

    // Act
    String script = PushingTagReplacerCallback.getClientSideLocalizationScript();

    // Assert
    assertNotNull(script);
    assertTrue(script.startsWith("var l10n={"));
    assertTrue(script.endsWith("};"));
    // Must include known fproxy.push keys with values from en.properties
    assertTrue(script.contains("hide:"), "contains hide key");
    assertTrue(script.contains("show:"), "contains show key");
    assertTrue(script.contains("imageprogress:"), "contains imageprogress key");
    assertTrue(script.contains("pushingCancelled:"), "contains pushingCancelled key");
  }

  @Test
  void processTag_whenJsOrPushDisabled_returnsNull() {
    // Arrange
    // Disable either flag → gate should return null regardless of tag
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(container.isFProxyWebPushingEnabled()).thenReturn(false);
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1234L, ctx);
    ParsedTag head = new ParsedTag("head", Map.of());

    // Act
    String out = cb.processTag(head, uriProcessor);

    // Assert
    assertNull(out);
  }

  @Test
  void processTag_img_withValidKskSrc_returnsImageElementHtml() throws Exception {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 4096L, ctx);
    Map<String, String> attrs = new HashMap<>();
    attrs.put("src", "KSK@foo"); // Valid KSK URI (no keys required)
    ParsedTag img = new ParsedTag("IMG", attrs); // case-insensitive element name

    when(uriProcessor.processURI("KSK@foo", null, false, false)).thenReturn("KSK@foo");
    when(uriProcessor.makeURIAbsolute("KSK@foo")).thenReturn("KSK@foo");

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNotNull(out, "Expected generated ImageElement HTML");
    assertTrue(out.contains("<span"));
    assertTrue(out.contains("jsonly ImageElement"), "includes JS-enabled placeholder");
    assertTrue(out.contains("<noscript>"), "includes noscript fallback");
    assertTrue(out.contains("<img"), "renders original <img> in noscript");
  }

  @Test
  void processTag_img_whenNoSrcAttribute_returnsNull() {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("alt", "x"));

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNull(out);
  }

  @Test
  void processTag_img_whenProcessUriThrowsCommentException_returnsNull() throws Exception {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "KSK@foo"));
    when(uriProcessor.processURI("KSK@foo", null, false, false))
        .thenThrow(new CommentException("bad"));

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNull(out);
  }

  @Test
  void processTag_img_whenMakeUriAbsoluteThrowsURISyntaxException_returnsNull() throws Exception {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "KSK@foo"));
    when(uriProcessor.processURI("KSK@foo", null, false, false)).thenReturn("KSK@foo");
    when(uriProcessor.makeURIAbsolute("KSK@foo")).thenThrow(new URISyntaxException("x", "y"));

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNull(out);
  }

  @Test
  void processTag_img_whenLeadingSlashIsPresent_trimsAndParsesSuccessfully() throws Exception {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "/KSK@foo"));
    when(uriProcessor.processURI("/KSK@foo", null, false, false)).thenReturn("/KSK@foo");
    when(uriProcessor.makeURIAbsolute("/KSK@foo")).thenReturn("/KSK@foo");

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNotNull(out);
    assertTrue(out.contains("jsonly ImageElement"));
  }

  @Test
  void processTag_img_whenFreenetUriIsMalformed_returnsNull() throws Exception {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    // Value missing '@' → FreenetURI throws MalformedURLException which is caught
    ParsedTag img = new ParsedTag("img", Map.of("src", "NOT_A_URI"));
    when(uriProcessor.processURI("NOT_A_URI", null, false, false)).thenReturn("NOT_A_URI");
    when(uriProcessor.makeURIAbsolute("NOT_A_URI")).thenReturn("NOT_A_URI");

    // Act
    String out = cb.processTag(img, uriProcessor);

    // Assert
    assertNull(out);
  }

  @Test
  void processTag_bodyClosing_injectsRequestIdAndL10nScript() {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    List<String> tokens = new ArrayList<>();
    tokens.add("/BODY"); // produces startSlash=true with element name "BODY"
    ParsedTag bodyClose = new ParsedTag(tokens);

    // Act
    String out = cb.processTag(bodyClose, uriProcessor);

    // Assert
    assertNotNull(out);
    assertTrue(out.startsWith("<input id=\"requestId\""), "hidden requestId is injected first");
    assertTrue(out.contains("value=\"req-123\""), "request id value is present");
    assertTrue(out.contains("<script type=\"text/javascript\""), "l10n script injected");
    assertTrue(out.endsWith("</body>"));
  }

  @Test
  void processTag_head_injectsGwtSupport() {
    // Arrange
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag head = new ParsedTag("head", Map.of());

    // Act
    String out = cb.processTag(head, uriProcessor);

    // Assert
    assertNotNull(out);
    assertTrue(out.startsWith("<head><script"));
    assertTrue(out.contains("/static/freenetjs/freenetjs.nocache.js"));
    assertTrue(out.contains("<noscript><style>"));
    assertTrue(out.contains("/static/reset.css"));
  }
}
