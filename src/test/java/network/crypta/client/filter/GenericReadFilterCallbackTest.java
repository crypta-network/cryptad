package network.crypta.client.filter;

import static network.crypta.l10n.BaseL10n.LANGUAGE.ENGLISH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Stream;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.BaseL10nTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class GenericReadFilterCallbackTest {

  @Mock private FoundURICallback foundURICallback;
  @Mock private TagReplacerCallback tagReplacerCallback;
  @Mock private LinkFilterExceptionProvider linkFilterExceptionProvider;

  @BeforeAll
  static void setupL10n() {
    // Ensure deterministic error messages during testing
    GenericReadFilterCallback.setBaseL10n(BaseL10nTest.createTestL10n(ENGLISH));
  }

  private GenericReadFilterCallback newCallback(String base) throws URISyntaxException {
    return new GenericReadFilterCallback(
        new URI(base), foundURICallback, tagReplacerCallback, linkFilterExceptionProvider);
  }

  @Test
  void processURI_whenAnchor_expectReturnedAsIs() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    String anchor = "#section_1-~ok?allowed";
    String result = cb.processURI(anchor, null);

    assertEquals(anchor, result);
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("processURI_simpleCases")
  void processURI_whenSimpleCases_expectSanitized(
      String name, String base, String input, String expected, boolean excepted) throws Exception {
    if (excepted) {
      when(linkFilterExceptionProvider.isLinkExcepted(any(URI.class))).thenReturn(true);
    }
    GenericReadFilterCallback cb = newCallback(base);
    String result = cb.processURI(input, null);
    assertEquals(expected, result);
  }

  static Stream<Arguments> processURI_simpleCases() {
    String base = "http://localhost:8888/";
    return Stream.of(
        Arguments.of(
            "bookmark simple",
            base,
            "/?newbookmark=KSK@mykey&desc=My Bookmark",
            "/?newbookmark=KSK@mykey&desc=My+Bookmark",
            false),
        Arguments.of(
            "bookmark active",
            base,
            "/?newbookmark=KSK@mykey&desc=Title&hasAnActivelink=true",
            "/?newbookmark=KSK@mykey&desc=Title&hasAnActivelink=true",
            false),
        Arguments.of("static path", base, "/static/js/app.js?foo=bar", "/static/js/app.js", false),
        Arguments.of(
            "excepted provider", base, "/private/secret?x=1&y=2", "/private/secret?x=1&y=2", true));
  }

  @Test
  void processURI_whenValidFreenetUriInline_expectCallbacksAndRelativePath() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/base/page");

    String input = "KSK@hello";
    String result = cb.processURI(input, null, false, true);

    assertEquals("/KSK@hello", result);

    ArgumentCaptor<FreenetURI> cap = ArgumentCaptor.forClass(FreenetURI.class);
    verify(foundURICallback, times(1)).foundURI(cap.capture());
    assertEquals("KSK@hello", cap.getValue().toString());
    verify(foundURICallback, times(1)).foundURI(cap.getValue(), true);
  }

  @Test
  void processURI_whenOverrideTypeWithCharset_expectTypeParameterEncoded() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    String input = "KSK@doc";
    String result = cb.processURI(input, "text/html; charset=UTF-8");

    assertEquals("/KSK@doc?type=text/html%3b%20charset=UTF-8", result);
  }

  @Test
  void processURI_whenExternalHttp_expectEscapedToExternalLinkToadlet() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    String input = "http://example.com/path?q=a b";
    String result = cb.processURI(input, null);

    assertEquals(
        ExternalLinkToadlet.PATH + "?_CHECKED_HTTP_=http://example.com/path?q=a%20b", result);
  }

  @Test
  void processURI_whenDisallowedProtocol_expectException() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    assertThrows(CommentException.class, () -> cb.processURI("javascript:alert(1)", null));
  }

  @Test
  void processURI_whenInvalidRelative_expectExceptionWithReason() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    CommentException ex =
        assertThrows(CommentException.class, () -> cb.processURI("not/a/freenet/uri", null));
    assertNotNull(ex.getMessage());
  }

  @Test
  void processURI_withForcedAuthority_whenHostMissing_expectPrefixed() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/base/page");

    String result =
        cb.processURI("/KSK@hello", null, "http://forced.example:1234", /* inline= */ false);

    assertEquals("http://forced.example:1234/KSK@hello", result);
  }

  @Test
  void makeURIAbsolute_whenRelative_expectResolvedAgainstBase() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://example.org/dir/page");

    String absolute = cb.makeURIAbsolute("sub/asset.css");
    assertEquals("http://example.org/dir/sub/asset.css", absolute);
  }

  @Test
  void onBaseHref_whenValidFreenetBase_expectUpdatedAndReturned() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    String result = cb.onBaseHref("KSK@site/");
    assertEquals("/KSK@site/", result);

    // subsequent onText should carry the updated base
    cb.onText("text", "p");
    verify(foundURICallback, times(1)).onText("text", "p", new URI("/KSK@site/"));
  }

  @Test
  void onBaseHref_whenExternalAbsolute_expectNull() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    String result = cb.onBaseHref("http://example.com/");
    assertNull(result);
  }

  @Test
  void processForm_whenVariousInputs_expectPolicyApplied() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    // null action -> remove
    assertNull(cb.processForm("GET", null));

    // unsupported method -> remove
    assertNull(cb.processForm("PUT", "/any"));

    // allow /library/
    assertEquals("/library/", cb.processForm("POST", "/library/"));

    // absolute form action -> rejected
    assertThrows(CommentException.class, () -> cb.processForm("GET", "http://example.com/"));

    // plugin action accepted
    assertEquals("/plugins/My.Plugin", cb.processForm("GET", "/plugins/My.Plugin"));

    // traversal attempt rejected
    assertThrows(CommentException.class, () -> cb.processForm("GET", "/plugins/../evil"));
  }

  @Test
  void processTag_whenCallbackPresent_expectDelegated() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    ParsedTag tag = new HTMLFilter.ParsedTag("a", java.util.Collections.emptyMap());
    when(tagReplacerCallback.processTag(tag, cb)).thenReturn("<a>replaced</a>");

    String replacement = cb.processTag(tag);
    assertEquals("<a>replaced</a>", replacement);
  }

  @Test
  void onFinished_whenCallbackPresent_expectEndOfPageNotified() throws Exception {
    GenericReadFilterCallback cb = newCallback("http://localhost:8888/");

    cb.onFinished();
    verify(foundURICallback, times(1)).onFinishedPage();
  }
}
