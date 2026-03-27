package network.crypta.clients.http.filter;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.filter.CommentException;
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
  @Mock private network.crypta.client.filter.URIProcessor uriProcessor;

  private SimpleToadletServer container;

  private static final class NoopTicker implements Ticker {
    @Override
    public void queueTimedJob(Runnable job, long offset) {
      // Test double: this suite verifies tag generation only and must not execute scheduled work.
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      // Test double: this suite verifies tag generation only and must not execute scheduled work.
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return null;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // Test double: no jobs are queued here, so removal is intentionally a no-op.
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      // Test double: this suite verifies tag generation only and must not execute scheduled work.
    }
  }

  @BeforeEach
  void setUp() {
    container = mock(SimpleToadletServer.class);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(container.isFProxyWebPushingEnabled()).thenReturn(true);
    when(container.getTicker()).thenReturn(new NoopTicker());
    PushDataManager pdm = mock(PushDataManager.class);
    when(container.getPushDataManager()).thenReturn(pdm);

    when(ctx.getContainer()).thenReturn(container);
    when(ctx.getUniqueId()).thenReturn("req-123");
    when(tracker.makeRandomElementID()).thenReturn(42);
  }

  @Test
  void getClientSideLocalizationScript_returnsVarWithExpectedKeys() {
    NodeL10n.getBase().getDefaultLanguageTranslation();

    String script = PushingTagReplacerCallback.getClientSideLocalizationScript();

    assertNotNull(script);
    assertTrue(script.startsWith("var l10n={"));
    assertTrue(script.endsWith("};"));
    assertTrue(script.contains("hide:"), "contains hide key");
    assertTrue(script.contains("show:"), "contains show key");
    assertTrue(script.contains("imageprogress:"), "contains imageprogress key");
    assertTrue(script.contains("pushingCancelled:"), "contains pushingCancelled key");
  }

  @Test
  void processTag_whenJsOrPushDisabled_returnsNull() {
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(container.isFProxyWebPushingEnabled()).thenReturn(false);
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1234L, ctx);
    ParsedTag head = new ParsedTag("head", Map.of());

    String out = cb.processTag(head, uriProcessor);

    assertNull(out);
  }

  @Test
  void processTag_img_withValidKskSrc_returnsImageElementHtml() throws Exception {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 4096L, ctx);
    Map<String, String> attrs = new HashMap<>();
    attrs.put("src", "KSK@foo");
    ParsedTag img = new ParsedTag("IMG", attrs);

    when(uriProcessor.processURI("KSK@foo", null, false, false)).thenReturn("KSK@foo");
    when(uriProcessor.makeURIAbsolute("KSK@foo")).thenReturn("KSK@foo");

    String out = cb.processTag(img, uriProcessor);

    assertNotNull(out, "Expected generated ImageElement HTML");
    assertTrue(out.contains("<span"));
    assertTrue(out.contains("jsonly ImageElement"), "includes JS-enabled placeholder");
    assertTrue(out.contains("<noscript>"), "includes noscript fallback");
    assertTrue(out.contains("<img"), "renders original <img> in noscript");
  }

  @Test
  void processTag_img_whenNoSrcAttribute_returnsNull() {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("alt", "x"));

    String out = cb.processTag(img, uriProcessor);

    assertNull(out);
  }

  @Test
  void processTag_img_whenProcessUriThrowsCommentException_returnsNull() throws Exception {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "KSK@foo"));
    when(uriProcessor.processURI("KSK@foo", null, false, false))
        .thenThrow(new CommentException("bad"));

    String out = cb.processTag(img, uriProcessor);

    assertNull(out);
  }

  @Test
  void processTag_img_whenMakeUriAbsoluteThrowsURISyntaxException_returnsNull() throws Exception {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "KSK@foo"));
    when(uriProcessor.processURI("KSK@foo", null, false, false)).thenReturn("KSK@foo");
    when(uriProcessor.makeURIAbsolute("KSK@foo")).thenThrow(new URISyntaxException("x", "y"));

    String out = cb.processTag(img, uriProcessor);

    assertNull(out);
  }

  @Test
  void processTag_img_whenLeadingSlashIsPresent_trimsAndParsesSuccessfully() throws Exception {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "/KSK@foo"));
    when(uriProcessor.processURI("/KSK@foo", null, false, false)).thenReturn("/KSK@foo");
    when(uriProcessor.makeURIAbsolute("/KSK@foo")).thenReturn("/KSK@foo");

    String out = cb.processTag(img, uriProcessor);

    assertNotNull(out);
    assertTrue(out.contains("jsonly ImageElement"));
  }

  @Test
  void processTag_img_whenFreenetUriIsMalformed_returnsNull() throws Exception {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag img = new ParsedTag("img", Map.of("src", "NOT_A_URI"));
    when(uriProcessor.processURI("NOT_A_URI", null, false, false)).thenReturn("NOT_A_URI");
    when(uriProcessor.makeURIAbsolute("NOT_A_URI")).thenReturn("NOT_A_URI");

    String out = cb.processTag(img, uriProcessor);

    assertNull(out);
  }

  @Test
  void processTag_bodyClosing_injectsRequestIdAndL10nScript() {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    List<String> tokens = new ArrayList<>();
    tokens.add("/BODY");
    ParsedTag bodyClose = new ParsedTag(tokens);

    String out = cb.processTag(bodyClose, uriProcessor);

    assertNotNull(out);
    assertTrue(out.startsWith("<input id=\"requestId\""), "hidden requestId is injected first");
    assertTrue(out.contains("value=\"req-123\""), "request id value is present");
    assertTrue(out.contains("<script type=\"text/javascript\""), "l10n script injected");
    assertTrue(out.endsWith("</body>"));
  }

  @Test
  void processTag_head_injectsGwtSupport() {
    PushingTagReplacerCallback cb = new PushingTagReplacerCallback(tracker, 1L, ctx);
    ParsedTag head = new ParsedTag("head", Map.of());

    String out = cb.processTag(head, uriProcessor);

    assertNotNull(out);
    assertTrue(out.startsWith("<head><script"));
    assertTrue(out.contains("/static/freenetjs/freenetjs.nocache.js"));
    assertTrue(out.contains("<noscript><style>"));
    assertTrue(out.contains("/static/reset.css"));
  }
}
