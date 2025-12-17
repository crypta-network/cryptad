package network.crypta.clients.http.wizardsteps;

import java.util.ArrayList;
import java.util.List;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Renders a wizard page that warns about browser privacy and usability pitfalls.
 *
 * <p>This {@link Step} inspects request metadata (notably the {@code User-Agent} header and an
 * {@code incognito} request parameter) to tailor the messaging shown to first-time users. The
 * output is purely informational: it builds an infobox, inserts localized warning text, and adds
 * Back/Next controls to continue the wizard flow.
 *
 * <p>Notable behaviors include: Firefox-specific detection for older versions and a special-case
 * warning when Firefox 3.6 is launched in privacy mode, as well as guidance about privacy features
 * and input methods. This class is intentionally stateless; all per-request decisions are derived
 * from the provided {@link HTTPRequest} and do not persist across invocations.
 *
 * <ul>
 *   <li><b>Inputs:</b> {@code User-Agent} header and {@code incognito} parameter.
 *   <li><b>Output:</b> localized HTML content added via {@link PageHelper}.
 *   <li><b>Thread-safety:</b> safe for concurrent use because no mutable state is retained.
 * </ul>
 *
 * @see FirstTimeWizardToadlet
 * @see Step
 */
public class BrowserWarning implements Step {

  /**
   * Result of lightweight Firefox detection for a request.
   *
   * <p>This value type exists only to keep {@link #getStep(HTTPRequest, PageHelper)} readable by
   * grouping related boolean flags returned from {@link #detectFirefox(String, boolean)}.
   */
  private record FirefoxDetection(
      boolean isFirefox, boolean isOldFirefox, boolean showTabWarning, boolean incognito) {}

  /**
   * Creates a new {@link BrowserWarning} step instance.
   *
   * <p>This type is stateless, so construction performs no initialization beyond the default
   * instance setup.
   */
  public BrowserWarning() {
    // Stateless step: all behavior is derived from per-request inputs, so no initialization is
    // required at construction time.
  }

  /**
   * Populates the page with browser warning content for the current request.
   *
   * <p>The rendered content includes a header that reflects whether the user is effectively in
   * private browsing mode, optional warnings for older Firefox versions, and general privacy
   * guidance. The method is idempotent with respect to the provided {@code helper}: calling it
   * multiple times for the same request produces the same content structure and localized strings.
   *
   * @param request HTTP request supplying headers and parameters for browser detection.
   * @param helper wizard page helper used to create HTML nodes and forms.
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    boolean incognito = request.isParameterSet("incognito");
    // Bug 3376: Opening Chrome in incognito mode from command line will open a new non-incognito
    // window if the browser is already open.
    // See http://code.google.com/p/chromium/issues/detail?id=9636
    // This is fixed upstream, but we need to test for fixed versions of Chrome.
    // Bug 5210: Same for Firefox!
    // Note also that Firefox 4 and later are much less vulnerable to CSS link:visited attacks,
    // but are not completely immune, especially if the bad guy can guess the site url. Ideally
    // the user should turn off link:visited styling altogether.
    // See:
    // http://blog.mozilla.com/security/2010/03/31/plugging-the-css-history-leak/
    // http://dbaron.org/mozilla/visited-privacy#limits
    // http://jeremiahgrossman.blogspot.com/2006/08/i-know-where-youve-been.html
    // https://developer.mozilla.org/en/Firefox_4_for_developers
    // https://developer.mozilla.org/en/CSS/Privacy_and_the_%3avisited_selector
    // Future improvement: detect newer Firefox builds and give more precise privacy guidance.
    FirefoxDetection detection = detectFirefox(request.getHeader("user-agent"), incognito);
    incognito = detection.incognito();
    boolean isRelativelySafe = detection.isFirefox() && !detection.isOldFirefox();

    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("browserWarningPageTitle"));

    String infoBoxHeader = infoBoxHeaderText(incognito, isRelativelySafe);
    HTMLNode infoboxContent =
        helper.getInfobox("infobox-normal", infoBoxHeader, contentNode, null, false);

    List<String> oldBrowserWarnings =
        oldBrowserWarnings(incognito, detection.isOldFirefox(), detection.showTabWarning());
    if (!oldBrowserWarnings.isEmpty()) {
      HTMLNode p = infoboxContent.addChild("p");
      p.addChild("#", oldBrowserWarnings.removeFirst());
      oldBrowserWarnings.forEach(s -> p.addChild("#", " " + s));
    }

    if (isRelativelySafe) {
      infoboxContent.addChild(
          "p",
          incognito
              ? WizardL10n.l10n("browserWarningIncognitoMaybeSafe")
              : WizardL10n.l10n("browserWarningMaybeSafe"));
    } else {
      NodeL10n.getBase()
          .addL10nSubstitution(
              infoboxContent,
              incognito
                  ? "FirstTimeWizardToadlet.browserWarningIncognito"
                  : "FirstTimeWizardToadlet.browserWarning",
              new String[] {"bold"},
              new HTMLNode[] {HTMLNode.STRONG});
    }

    if (incognito) {
      infoboxContent.addChild("p", WizardL10n.l10n("browserWarningIncognitoSuggestion"));
    } else {
      infoboxContent.addChild("p", WizardL10n.l10n("browserWarningSuggestion"));
    }
    infoboxContent.addChild("p", WizardL10n.l10n("browserImeWarning"));
    // voice recognition also used for surveillance
    infoboxContent.addChild("p", WizardL10n.l10n("browserVoiceRecognitionWarning"));

    HTMLNode form = helper.addFormChild(infoboxContent.addChild("p"), ".", "continueForm");
    form.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    form.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Detects whether the request appears to come from Firefox and whether additional warnings apply.
   *
   * <p>This method performs a lightweight substring match against the provided {@code User-Agent}
   * string. It recognizes Firefox broadly via {@code "Firefox/"} and treats major versions {@code
   * 0.x} through {@code 3.x} as "old" for the purposes of wizard guidance. A special case applies
   * to Firefox {@code 3.6} when {@code incognito} is requested: the wizard may warn about tab loss,
   * and it preserves the {@code incognito} state only for that case.
   *
   * @param userAgent raw {@code User-Agent} header value; may be {@code null}.
   * @param incognito whether the request asks to use private browsing mode.
   * @return a structured detection result describing Firefox-related warning flags.
   */
  private static FirefoxDetection detectFirefox(String userAgent, boolean incognito) {
    if (userAgent == null) {
      return new FirefoxDetection(false, false, false, incognito);
    }

    boolean isFirefox = userAgent.contains("Firefox/");
    // Firefox 3.6 can destroy tabs, see https://bugs.freenetproject.org/view.php?id=5209
    boolean showTabWarning = userAgent.contains("Firefox/3.6") && incognito;
    if (isFirefox && !showTabWarning) {
      // Versions of Firefox other than 3.6 do not behave properly when going into privacy mode
      // from the command line, so show the warnings about the lack of being in privacy mode.
      incognito = false;
    }

    boolean isOldFirefox =
        userAgent.contains("Firefox/0.")
            || userAgent.contains("Firefox/1.")
            || userAgent.contains("Firefox/2.")
            || userAgent.contains("Firefox/3.");
    return new FirefoxDetection(isFirefox, isOldFirefox, showTabWarning, incognito);
  }

  /**
   * Builds the list of localized warnings that apply to older Firefox versions.
   *
   * <p>The returned list is ordered for presentation: the first element is intended to be the
   * leading sentence, and subsequent elements are appended as follow-on sentences. When {@code
   * isOldFirefox} is {@code false}, this method returns an empty list and does not attempt to infer
   * warnings from other flags.
   *
   * @param incognito whether the wizard believes the user is in private browsing mode.
   * @param isOldFirefox whether the detected browser is an older Firefox major version.
   * @param showTabWarning whether to include the Firefox 3.6 tab-loss warning text.
   * @return an ordered list of localized warning strings; empty when no warning applies.
   */
  public List<String> oldBrowserWarnings(
      boolean incognito, boolean isOldFirefox, boolean showTabWarning) {
    ArrayList<String> oldBrowserWarnings = new ArrayList<>();
    if (isOldFirefox) {
      oldBrowserWarnings.add(WizardL10n.l10n("browserWarningOldFirefox"));
      if (showTabWarning) {
        oldBrowserWarnings.add(WizardL10n.l10n("browserWarningFirefoxMightHaveClobberedTabs"));
      } else if (!incognito) {
        oldBrowserWarnings.add(WizardL10n.l10n("browserWarningOldFirefoxNewerHasPrivacyMode"));
      }
    }
    return oldBrowserWarnings;
  }

  /**
   * Chooses the infobox header text for the browser warning page.
   *
   * <p>If {@code incognito} is {@code true}, the header always uses the incognito-specific short
   * text and {@code isRelativelySafe} is ignored. Otherwise, the selection distinguishes between a
   * "relatively safe" browser configuration and the generic warning case.
   *
   * @param incognito whether the wizard treats the browser as being in private mode.
   * @param isRelativelySafe whether the browser appears to meet the "maybe safe" criteria.
   * @return localized header text appropriate for the current browser state.
   */
  public String infoBoxHeaderText(boolean incognito, boolean isRelativelySafe) {
    if (incognito) {
      return WizardL10n.l10n("browserWarningIncognitoShort");
    }
    if (isRelativelySafe) {
      return WizardL10n.l10n("browserWarningShortRelativelySafe");
    }
    return WizardL10n.l10n("browserWarningShort");
  }

  /**
   * This POST side just continues to the next step.
   *
   * <p>This step does not process form values. Any submitted POST is treated as an acknowledgment
   * of the warning page and advances the wizard to the next logical step.
   *
   * @param request HTTP request for the POST; currently unused by this step.
   * @return the {@link FirstTimeWizardToadlet.WIZARD_STEP} name identifying the next step.
   */
  @Override
  public String postStep(HTTPRequest request) {
    return FirstTimeWizardToadlet.WIZARD_STEP.MISC.name();
  }
}
