package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Wizard step that presents the Opennet choice page.
 *
 * <p>This {@link Step} renders a small form allowing the user to choose how the node connects to
 * the network. The UI offers two mutually exclusive options and provides short localized
 * explanations for each. On submission, the selected value is propagated forward by encoding it
 * into the wizard navigation string used by {@link FirstTimeWizardToadlet}.
 *
 * <p>This type is intentionally stateless: it holds no mutable fields and builds a response solely
 * from the provided {@link PageHelper}. As a result, instances are safe to reuse across requests as
 * long as the surrounding wizard framework does not require per-request state on the step object.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Always renders the same choice form; no request parameters are used for preselection.
 *   <li>Uses localized strings for all user-visible text and button labels.
 *   <li>Encodes the selection as a query parameter named {@code opennet} for the next step.
 * </ul>
 */
public class Opennet implements Step {
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String PARAM_OPENNET = "opennet";

  /**
   * Renders the Opennet choice page into the wizard response.
   *
   * <p>This method builds an infobox containing explanatory text, two radio-button options, and
   * standard wizard navigation buttons. The rendered HTML uses the provided {@link PageHelper} to
   * attach content to the current wizard page; it does not perform any persistence or configuration
   * changes.
   *
   * <p>The {@code request} parameter is accepted to satisfy the {@link Step} interface. This
   * implementation does not read request parameters when rendering the page.
   *
   * @param request The current HTTP request; accepted for interface compatibility and not read.
   * @param helper Helper used to construct the page content and create wizard form elements.
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("opennetChoicePageTitle"));
    HTMLNode infoboxContent =
        helper.getInfobox(
            "infobox-normal", WizardL10n.l10n("opennetChoiceTitle"), contentNode, null, false);

    infoboxContent.addChild("p", WizardL10n.l10n("opennetChoiceIntroduction"));

    HTMLNode form = helper.addFormChild(infoboxContent, ".", "opennetForm", false);

    HTMLNode p = form.addChild("p");
    HTMLNode input =
        p.addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE, "id"},
            new String[] {"radio", PARAM_OPENNET, "false", "opennetFalse"});
    input
        .addChild("label", new String[] {"for"}, new String[] {"opennetFalse"})
        .addChild("b", WizardL10n.l10n("opennetChoiceConnectFriends") + ":");
    p.addChild("br");
    p.addChild("i", WizardL10n.l10n("opennetChoicePro"));
    p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectFriendsPRO") + "¹");
    p.addChild("br");
    p.addChild("i", WizardL10n.l10n("opennetChoiceCon"));
    p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectFriendsCON", "minfriends", "5"));

    p = form.addChild("p");
    input =
        p.addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE, "id"},
            new String[] {"radio", PARAM_OPENNET, "true", "opennetTrue"});
    input
        .addChild("label", new String[] {"for"}, new String[] {"opennetTrue"})
        .addChild("b", WizardL10n.l10n("opennetChoiceConnectStrangers") + ":");
    p.addChild("br");
    p.addChild("i", WizardL10n.l10n("opennetChoicePro"));
    p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectStrangersPRO"));
    p.addChild("br");
    p.addChild("i", WizardL10n.l10n("opennetChoiceCon"));
    p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectStrangersCON"));

    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});

    HTMLNode foot = infoboxContent.addChild("div", "class", "toggleable");
    foot.addChild("i", "¹: " + WizardL10n.l10n("opennetChoiceHowSafeIsCryptaToggle"));
    HTMLNode footHidden = foot.addChild("div", "class", "hidden");
    HTMLNode footList = footHidden.addChild("ol");
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaStupid"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaFriends") + "²");
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaTrustworthy"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaNoSuspect"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaChangeID"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaSSK"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaOS"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaBigPriv"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaDistant"));
    footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaBugs"));
    HTMLNode foot2 = footHidden.addChild("p");
    foot2.addChild("#", "²: " + WizardL10n.l10n("opennetChoiceHowSafeIsCryptaFoot2"));
  }

  /**
   * Handles form submission and returns the next wizard location.
   *
   * <p>This method reads the {@code opennet} form part when present and appends it as a query
   * parameter to the wizard navigation string for {@link
   * FirstTimeWizardToadlet.WIZARD_STEP#SECURITY_NETWORK}. If nothing was selected and the user
   * attempts to proceed, the method returns the token for {@link
   * FirstTimeWizardToadlet.WIZARD_STEP#OPENNET} to redisplay this step.
   *
   * <p>The returned string is part of the wizard's internal navigation protocol; callers typically
   * treat it as opaque and hand it back to the wizard controller.
   *
   * @param request The HTTP request whose multipart form parts may include {@code opennet}.
   * @return Wizard navigation token for the next step, optionally including {@code opennet=...}.
   */
  @Override
  public String postStep(HTTPRequest request) {
    if (request.isPartSet(PARAM_OPENNET)) {
      return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK
          + "&opennet="
          + request.getPartAsStringFailsafe(PARAM_OPENNET, 5);
    } else {
      // Nothing selected when "next" clicked. Display choice again.
      return FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name();
    }
  }
}
