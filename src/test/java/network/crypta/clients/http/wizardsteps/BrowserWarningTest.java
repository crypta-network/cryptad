package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.regex.Pattern;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S101"})
@ExtendWith(MockitoExtension.class)
class BrowserWarningTest {

  private static final String HEADER_USER_AGENT = "user-agent";
  private static final String PARAM_INCOGNITO = "incognito";
  private static final String INFOBOX_NORMAL = "infobox-normal";
  private static final String FORM_ID_CONTINUE = "continueForm";

  private static final String KEY_PAGE_TITLE = "browserWarningPageTitle";
  private static final String KEY_OLD_FIREFOX = "browserWarningOldFirefox";
  private static final String KEY_OLD_FIREFOX_PRIVACY_MODE =
      "browserWarningOldFirefoxNewerHasPrivacyMode";
  private static final String KEY_OLD_FIREFOX_TABS = "browserWarningFirefoxMightHaveClobberedTabs";
  private static final String KEY_MAYBE_SAFE = "browserWarningMaybeSafe";
  private static final String KEY_MAYBE_SAFE_INCOGNITO = "browserWarningIncognitoMaybeSafe";
  private static final String KEY_SUGGESTION = "browserWarningSuggestion";
  private static final String KEY_SUGGESTION_INCOGNITO = "browserWarningIncognitoSuggestion";
  private static final String KEY_IME_WARNING = "browserImeWarning";
  private static final String KEY_VOICE_WARNING = "browserVoiceRecognitionWarning";

  @Mock HTTPRequest request;
  @Mock PageHelper helper;

  @Test
  void postStep_whenInvoked_expectMisc() {
    BrowserWarning step = new BrowserWarning();

    String next = step.postStep(request);

    assertEquals("MISC", next);
  }

  @Test
  void oldBrowserWarnings_whenNotOldFirefox_expectEmptyList() {
    BrowserWarning step = new BrowserWarning();

    List<String> warnings = step.oldBrowserWarnings(true, false, true);

    assertTrue(warnings.isEmpty());
  }

  @Test
  void oldBrowserWarnings_whenOldFirefoxAndShowTabWarning_expectOldFirefoxAndTabWarning() {
    BrowserWarning step = new BrowserWarning();

    List<String> warnings = step.oldBrowserWarnings(true, true, true);

    assertEquals(
        List.of(WizardL10n.l10n(KEY_OLD_FIREFOX), WizardL10n.l10n(KEY_OLD_FIREFOX_TABS)), warnings);
  }

  @Test
  void oldBrowserWarnings_whenOldFirefoxAndNotIncognito_expectOldFirefoxAndPrivacyModeWarning() {
    BrowserWarning step = new BrowserWarning();

    List<String> warnings = step.oldBrowserWarnings(false, true, false);

    assertEquals(
        List.of(WizardL10n.l10n(KEY_OLD_FIREFOX), WizardL10n.l10n(KEY_OLD_FIREFOX_PRIVACY_MODE)),
        warnings);
  }

  @Test
  void oldBrowserWarnings_whenOldFirefoxAndIncognitoWithoutTabWarning_expectOnlyOldFirefox() {
    BrowserWarning step = new BrowserWarning();

    List<String> warnings = step.oldBrowserWarnings(true, true, false);

    assertEquals(List.of(WizardL10n.l10n(KEY_OLD_FIREFOX)), warnings);
  }

  @Test
  void infoBoxHeaderText_whenIncognito_expectIncognitoShort() {
    BrowserWarning step = new BrowserWarning();

    String header = step.infoBoxHeaderText(true, true);

    assertEquals(WizardL10n.l10n("browserWarningIncognitoShort"), header);
  }

  @Test
  void infoBoxHeaderText_whenRelativelySafeAndNotIncognito_expectRelativelySafeShort() {
    BrowserWarning step = new BrowserWarning();

    String header = step.infoBoxHeaderText(false, true);

    assertEquals(WizardL10n.l10n("browserWarningShortRelativelySafe"), header);
  }

  @Test
  void infoBoxHeaderText_whenNotRelativelySafeAndNotIncognito_expectShort() {
    BrowserWarning step = new BrowserWarning();

    String header = step.infoBoxHeaderText(false, false);

    assertEquals(WizardL10n.l10n("browserWarningShort"), header);
  }

  @Test
  void getStep_whenUserAgentMissingAndIncognito_buildsIncognitoHeaderAndCoreWarnings() {
    BrowserWarning step = new BrowserWarning();

    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(true);
    when(request.getHeader(HEADER_USER_AGENT)).thenReturn(null);

    HTMLNode pageContent = new HTMLNode("div");
    String expectedTitle = WizardL10n.l10n(KEY_PAGE_TITLE);
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox(eq(INFOBOX_NORMAL), anyString(), eq(pageContent), isNull(), eq(false)))
        .thenAnswer(
            invocation -> {
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    HTMLNode formNode = new HTMLNode("form");
    when(helper.addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              parent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper).getPageContent(expectedTitle);
    verify(helper)
        .getInfobox(
            eq(INFOBOX_NORMAL), headerCaptor.capture(), eq(pageContent), isNull(), eq(false));
    verify(helper).addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE));

    String expectedHeader = step.infoBoxHeaderText(true, false);
    assertEquals(expectedHeader, headerCaptor.getValue());

    String html = pageContent.generate();

    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_SUGGESTION_INCOGNITO));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_IME_WARNING));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_VOICE_WARNING));

    assertHtmlHasSubmitInput(html, "back", NodeL10n.getBase().getString("Toadlet.back"));
    assertHtmlHasSubmitInput(html, "next", NodeL10n.getBase().getString("Toadlet.next"));
  }

  @Test
  void getStep_whenFirefox36Incognito_buildsOldFirefoxWarningsAndTabWarning() {
    BrowserWarning step = new BrowserWarning();

    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(true);
    when(request.getHeader(HEADER_USER_AGENT)).thenReturn("Mozilla/5.0 Firefox/3.6.28");

    HTMLNode pageContent = new HTMLNode("div");
    String expectedTitle = WizardL10n.l10n(KEY_PAGE_TITLE);
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox(eq(INFOBOX_NORMAL), anyString(), eq(pageContent), isNull(), eq(false)))
        .thenAnswer(
            invocation -> {
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    HTMLNode formNode = new HTMLNode("form");
    when(helper.addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              parent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper)
        .getInfobox(
            eq(INFOBOX_NORMAL), headerCaptor.capture(), eq(pageContent), isNull(), eq(false));

    String expectedHeader = step.infoBoxHeaderText(true, false);
    assertEquals(expectedHeader, headerCaptor.getValue());

    String html = pageContent.generate();

    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_OLD_FIREFOX));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_OLD_FIREFOX_TABS));

    assertHtmlDoesNotContainEncoded(html, WizardL10n.l10n(KEY_MAYBE_SAFE));
    assertHtmlDoesNotContainEncoded(html, WizardL10n.l10n(KEY_MAYBE_SAFE_INCOGNITO));
  }

  @Test
  void getStep_whenFirefox35IncognitoParamSet_clearsIncognitoAndShowsOldFirefoxPrivacyModeHint() {
    BrowserWarning step = new BrowserWarning();

    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(true);
    when(request.getHeader(HEADER_USER_AGENT)).thenReturn("Mozilla/5.0 Firefox/3.5");

    HTMLNode pageContent = new HTMLNode("div");
    String expectedTitle = WizardL10n.l10n(KEY_PAGE_TITLE);
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox(eq(INFOBOX_NORMAL), anyString(), eq(pageContent), isNull(), eq(false)))
        .thenAnswer(
            invocation -> {
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    when(helper.addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              HTMLNode formNode = new HTMLNode("form");
              parent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper)
        .getInfobox(
            eq(INFOBOX_NORMAL), headerCaptor.capture(), eq(pageContent), isNull(), eq(false));

    String expectedHeader = step.infoBoxHeaderText(false, false);
    assertEquals(expectedHeader, headerCaptor.getValue());

    String html = pageContent.generate();

    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_OLD_FIREFOX));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_OLD_FIREFOX_PRIVACY_MODE));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_SUGGESTION));
  }

  @Test
  void getStep_whenFirefox4IncognitoParamSet_clearsIncognitoAndShowsRelativelySafeText() {
    BrowserWarning step = new BrowserWarning();

    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(true);
    when(request.getHeader(HEADER_USER_AGENT)).thenReturn("Mozilla/5.0 Firefox/4.0");

    HTMLNode pageContent = new HTMLNode("div");
    String expectedTitle = WizardL10n.l10n(KEY_PAGE_TITLE);
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox(eq(INFOBOX_NORMAL), anyString(), eq(pageContent), isNull(), eq(false)))
        .thenAnswer(
            invocation -> {
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    when(helper.addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              HTMLNode formNode = new HTMLNode("form");
              parent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper)
        .getInfobox(
            eq(INFOBOX_NORMAL), headerCaptor.capture(), eq(pageContent), isNull(), eq(false));

    String expectedHeader = step.infoBoxHeaderText(false, true);
    assertEquals(expectedHeader, headerCaptor.getValue());

    String html = pageContent.generate();

    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_MAYBE_SAFE));
    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_SUGGESTION));
    assertHtmlDoesNotContainEncoded(html, WizardL10n.l10n(KEY_OLD_FIREFOX));
  }

  @Test
  void getStep_whenNonFirefoxIncognitoParamSet_preservesIncognitoAndUsesIncognitoHeader() {
    BrowserWarning step = new BrowserWarning();

    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(true);
    when(request.getHeader(HEADER_USER_AGENT)).thenReturn("Mozilla/5.0 Chrome/120.0.0.0");

    HTMLNode pageContent = new HTMLNode("div");
    String expectedTitle = WizardL10n.l10n(KEY_PAGE_TITLE);
    when(helper.getPageContent(expectedTitle)).thenReturn(pageContent);

    HTMLNode infoboxContent = new HTMLNode("div");
    when(helper.getInfobox(eq(INFOBOX_NORMAL), anyString(), eq(pageContent), isNull(), eq(false)))
        .thenAnswer(
            invocation -> {
              pageContent.addChild(infoboxContent);
              return infoboxContent;
            });

    when(helper.addFormChild(any(HTMLNode.class), eq("."), eq(FORM_ID_CONTINUE)))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0, HTMLNode.class);
              HTMLNode formNode = new HTMLNode("form");
              parent.addChild(formNode);
              return formNode;
            });

    step.getStep(request, helper);

    ArgumentCaptor<String> headerCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper)
        .getInfobox(
            eq(INFOBOX_NORMAL), headerCaptor.capture(), eq(pageContent), isNull(), eq(false));

    String expectedHeader = step.infoBoxHeaderText(true, false);
    assertEquals(expectedHeader, headerCaptor.getValue());

    String html = pageContent.generate();

    assertHtmlContainsEncoded(html, WizardL10n.l10n(KEY_SUGGESTION_INCOGNITO));
    assertHtmlDoesNotContainEncoded(html, WizardL10n.l10n(KEY_MAYBE_SAFE));
  }

  private static void assertHtmlContainsEncoded(String html, String text) {
    assertNotNull(html);
    assertNotNull(text);
    assertTrue(
        html.contains(HTMLEncoder.encode(text)),
        () -> "Expected HTML to contain encoded text: " + text);
  }

  private static void assertHtmlDoesNotContainEncoded(String html, String text) {
    assertNotNull(html);
    assertNotNull(text);
    assertFalse(
        html.contains(HTMLEncoder.encode(text)),
        () -> "Expected HTML to not contain encoded text: " + text);
  }

  private static void assertHtmlHasSubmitInput(String html, String name, String value) {
    String encodedValue = HTMLEncoder.encode(value);
    Pattern pattern =
        Pattern.compile(
            "(?s)<input\\b"
                + "(?=[^>]*\\btype=\"submit\")"
                + "(?=[^>]*\\bname=\""
                + Pattern.quote(name)
                + "\")"
                + "(?=[^>]*\\bvalue=\""
                + Pattern.quote(encodedValue)
                + "\")"
                + "[^>]*>");
    assertTrue(pattern.matcher(html).find(), "Missing submit input name=" + name);
  }
}
