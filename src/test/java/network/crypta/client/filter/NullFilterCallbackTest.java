package network.crypta.client.filter;

import java.util.HashMap;
import java.util.Map;
import network.crypta.client.filter.HTMLFilter.ParsedTag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NullFilterCallbackTest {

  @Test
  void processURI_whenSimpleCall_expectNull() {
    NullFilterCallback cb = new NullFilterCallback();

    String result1 = cb.processURI("http://example.com", "text/html");
    String result2 = cb.processURI("/relative/path", null);

    assertNull(result1);
    assertNull(result2);
  }

  @ParameterizedTest(name = "noRelative={1}, inline={2}")
  @CsvSource({
    "http://example.com,false,false",
    "/relative,true,false",
    "'data:image/png;base64,abcd',false,true",
    "//schemeless.example,false,true"
  })
  void processURI_withFlags_whenAnyCombination_expectNull(
      String uri, boolean noRelative, boolean inline) throws CommentException {
    NullFilterCallback cb = new NullFilterCallback();
    String result = cb.processURI(uri, null, noRelative, inline);
    assertNull(result);
  }

  @ParameterizedTest(name = "uri={0}, inline={2}")
  @CsvSource({
    "/img.png, https://host.tld:443, false",
    "favicon.ico, https://example.org, true",
    "http://already.absolute, https://ignored.example, false"
  })
  void processURI_withForcedAuthority_whenRelativeOrAbsolute_expectNull(
      String uri, String force, boolean inline) throws CommentException {
    NullFilterCallback cb = new NullFilterCallback();
    String result = cb.processURI(uri, null, force, inline);
    assertNull(result);
  }

  @ParameterizedTest
  @ValueSource(strings = {"https://base.example/", "/relative/base", "", "about:blank"})
  void onBaseHref_whenAnyString_expectNull(String base) {
    NullFilterCallback cb = new NullFilterCallback();
    String result = cb.onBaseHref(base);
    assertNull(result);
  }

  @ParameterizedTest
  @CsvSource({"GET, /submit", "POST, http://example.com/form", "PUT, /ignored", "DELETE, /ignored"})
  void processForm_whenAnyMethodAndAction_expectNull(String method, String action) {
    NullFilterCallback cb = new NullFilterCallback();
    String result = cb.processForm(method, action);
    assertNull(result);
  }

  @Test
  void processTag_whenParsedTagProvided_expectNull() {
    NullFilterCallback cb = new NullFilterCallback();
    Map<String, String> attrs = new HashMap<>();
    attrs.put("id", "x");
    attrs.put("class", "c");
    ParsedTag tag = new ParsedTag("div", attrs);

    String result = cb.processTag(tag);
    assertNull(result);
  }

  @Test
  void onText_whenAnyInput_expectNoException() {
    NullFilterCallback cb = new NullFilterCallback();
    assertDoesNotThrow(() -> cb.onText("hello", "title"));
    assertDoesNotThrow(() -> cb.onText("", null));
  }

  @Test
  void onFinished_whenInvoked_expectNoException() {
    NullFilterCallback cb = new NullFilterCallback();
    assertDoesNotThrow(cb::onFinished);
  }
}
