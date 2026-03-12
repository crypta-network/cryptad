package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Renders and processes the First Time Wizard step that configures the node's network threat level.
 *
 * <p>This step presents a small, curated set of {@link SecurityLevels.NETWORK_THREAT_LEVEL network
 * threat levels} based on whether the user is configuring an opennet or a darknet style connection.
 * The UI is intentionally constrained: when opennet is selected, only the lower threat levels are
 * offered; when opennet is not selected, only the higher threat levels are offered. This mirrors
 * the typical setup guidance for those network modes without requiring the user to understand all
 * internal security knobs.
 *
 * <p>Selection is a two-phase flow for the highest-impact choices. If the user chooses {@code HIGH}
 * or {@code MAXIMUM}, the wizard redirects back to the same step with a confirmation prompt that
 * requires explicit acknowledgement before the change is applied.
 *
 * <p><b>Notable behaviors</b>
 *
 * <ul>
 *   <li>Reads the request parameter {@code opennet} to decide which options to display.
 *   <li>Uses the {@code confirm} flag to display a confirmation page for high-impact selections.
 *   <li>Persists the selection via {@link #setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL)}.
 * </ul>
 *
 * @see Step
 * @see SecurityLevels
 */
public class SecurityNetwork implements Step {

  private static final String ATTR_VALUE = "value";
  private static final String INPUT_TAG = "input";
  private static final String INPUT_TYPE_SUBMIT = "submit";
  private static final String PARAM_NETWORK_THREAT_LEVEL = "security-levels.networkThreatLevel";
  private static final String PARAM_NETWORK_THREAT_LEVEL_CONFIRM =
      "security-levels.networkThreatLevel.confirm";
  private static final String PARAM_NETWORK_THREAT_LEVEL_TRY_CONFIRM =
      "security-levels.networkThreatLevel.tryConfirm";

  private final NodeClientCore core;

  /**
   * Creates a wizard step instance bound to a specific {@link NodeClientCore}.
   *
   * <p>The step is stateful only in that it holds a reference to the core; all user selections and
   * navigation state are transported via the {@link HTTPRequest} and the wizard redirect mechanism.
   * The provided core is used to apply the selected {@link SecurityLevels.NETWORK_THREAT_LEVEL} and
   * persist the updated configuration.
   *
   * @param core the node core used to apply and persist the selected security level; must be
   *     non-null
   */
  public SecurityNetwork(NodeClientCore core) {
    this.core = core;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This method renders the HTML content for the step. It selects between the opennet and
   * darknet variants based on the {@code opennet} request parameter and generates one radio-button
   * row per eligible {@link SecurityLevels.NETWORK_THREAT_LEVEL}. When the {@code confirm}
   * parameter is set, it renders a confirmation page for {@code HIGH} and {@code MAXIMUM}
   * selections instead of the normal choice page.
   *
   * @param request the current HTTP request carrying wizard parameters and posted form parts
   * @param helper the page helper used to create forms, infoboxes, and page content nodes
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("networkSecurityPageTitle"));
    String opennetParam = request.getParam("opennet", "false");
    boolean opennet = Fields.stringToBool(opennetParam, false);

    if (request.isParameterSet("confirm")) {
      String networkThreatLevel = request.getParam(PARAM_NETWORK_THREAT_LEVEL);
      SecurityLevels.NETWORK_THREAT_LEVEL newThreatLevel =
          SecurityLevels.parseNetworkThreatLevel(networkThreatLevel);

      HTMLNode infoboxContent =
          helper.getInfobox(
              "infobox-information",
              WizardL10n.l10n("networkThreatLevelConfirmTitle." + newThreatLevel),
              contentNode,
              null,
              false);

      HTMLNode formNode = helper.addFormChild(infoboxContent, ".", "configFormSecLevels");
      formNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"hidden", PARAM_NETWORK_THREAT_LEVEL, networkThreatLevel});
      HTMLNode p = formNode.addChild("p");
      if (newThreatLevel == SecurityLevels.NETWORK_THREAT_LEVEL.MAXIMUM) {
        NodeL10n.getBase()
            .addL10nSubstitution(
                p,
                "SecurityLevels.maximumNetworkThreatLevelWarning",
                new String[] {"bold"},
                new HTMLNode[] {HTMLNode.STRONG});
        p.addChild("#", " ");
        NodeL10n.getBase()
            .addL10nSubstitution(
                p,
                "SecurityLevels.maxSecurityYouNeedFriends",
                new String[] {"bold"},
                new HTMLNode[] {HTMLNode.STRONG});
        formNode
            .addChild("p")
            .addChild(
                INPUT_TAG,
                new String[] {"type", "name", ATTR_VALUE},
                new String[] {"checkbox", PARAM_NETWORK_THREAT_LEVEL_CONFIRM, "off"},
                WizardL10n.l10nSec("maximumNetworkThreatLevelCheckbox"));
      } else {
        NodeL10n.getBase()
            .addL10nSubstitution(
                p,
                "FirstTimeWizardToadlet.highNetworkThreatLevelWarning",
                new String[] {"bold", "addAFriend", "friends"},
                new HTMLNode[] {
                  HTMLNode.STRONG,
                  new HTMLNode("#", NodeL10n.getBase().getString("FProxyToadlet.addFriendTitle")),
                  new HTMLNode("#", NodeL10n.getBase().getString("FProxyToadlet.categoryFriends"))
                });
        HTMLNode checkbox =
            formNode
                .addChild("p")
                .addChild(
                    INPUT_TAG,
                    new String[] {"type", "name", ATTR_VALUE},
                    new String[] {"checkbox", PARAM_NETWORK_THREAT_LEVEL_CONFIRM, "off"});
        NodeL10n.getBase()
            .addL10nSubstitution(
                checkbox,
                "FirstTimeWizardToadlet.highNetworkThreatLevelCheckbox",
                new String[] {"bold", "addAFriend"},
                new HTMLNode[] {
                  HTMLNode.STRONG,
                  new HTMLNode("#", NodeL10n.getBase().getString("FProxyToadlet.addFriendTitle")),
                });
      }
      formNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"hidden", PARAM_NETWORK_THREAT_LEVEL_TRY_CONFIRM, "on"});
      formNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, "return-from-confirm", NodeL10n.getBase().getString("Toadlet.back")
          });
      formNode.addChild(
          INPUT_TAG,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, "next", NodeL10n.getBase().getString("Toadlet.next")});
      return;
    }

    // Add choices and description depending on whether opennet was selected.
    HTMLNode form;
    if (opennet) {
      HTMLNode infoboxContent =
          helper.getInfobox(
              "infobox-normal",
              WizardL10n.l10n("networkThreatLevelHeaderOpennet"),
              contentNode,
              null,
              false);
      infoboxContent.addChild("p", WizardL10n.l10n("networkThreatLevelIntroOpennet"));

      form = helper.addFormChild(infoboxContent, ".", "networkSecurityForm");
      HTMLNode div = form.addChild("div", "class", "opennetDiv");
      for (SecurityLevels.NETWORK_THREAT_LEVEL level :
          SecurityLevels.NETWORK_THREAT_LEVEL.getOpennetValues()) {
        securityLevelChoice(div, level);
      }
    } else {
      HTMLNode infoboxContent =
          helper.getInfobox(
              "infobox-normal",
              WizardL10n.l10n("networkThreatLevelHeaderDarknet"),
              contentNode,
              null,
              false);
      infoboxContent.addChild("p", WizardL10n.l10n("networkThreatLevelIntroDarknet"));

      form = helper.addFormChild(infoboxContent, ".", "networkSecurityForm");
      HTMLNode div = form.addChild("div", "class", "darknetDiv");
      for (SecurityLevels.NETWORK_THREAT_LEVEL level :
          SecurityLevels.NETWORK_THREAT_LEVEL.getDarknetValues()) {
        securityLevelChoice(div, level);
      }
      form.addChild("p")
          .addChild("b", WizardL10n.l10nSec("networkThreatLevel.opennetFriendsWarning"));
    }
    form.addChild(
        INPUT_TAG,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "back", NodeL10n.getBase().getString("Toadlet.back")});
    form.addChild(
        INPUT_TAG,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Adds to the given parent node description and a radio button for the selected security level.
   *
   * @param parent to add content to.
   * @param level to add content about.
   */
  private void securityLevelChoice(HTMLNode parent, SecurityLevels.NETWORK_THREAT_LEVEL level) {
    HTMLNode input =
        parent
            .addChild("p")
            .addChild(
                INPUT_TAG,
                new String[] {"type", "name", ATTR_VALUE, "id"},
                new String[] {
                  "radio",
                  PARAM_NETWORK_THREAT_LEVEL,
                  level.name(),
                  PARAM_NETWORK_THREAT_LEVEL + level.name()
                });
    input
        .addChild(
            "label", new String[] {"for"}, new String[] {PARAM_NETWORK_THREAT_LEVEL + level.name()})
        .addChild("b", WizardL10n.l10nSec("networkThreatLevel.name." + level));
    input.addChild("#", ": ");
    NodeL10n.getBase()
        .addL10nSubstitution(
            input,
            "SecurityLevels.networkThreatLevel.choice." + level,
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
    HTMLNode inner = input.addChild("p").addChild("i");
    NodeL10n.getBase()
        .addL10nSubstitution(
            inner,
            "SecurityLevels.networkThreatLevel.desc." + level,
            new String[] {"bold"},
            new HTMLNode[] {HTMLNode.STRONG});
  }

  /**
   * {@inheritDoc}
   *
   * <p>This method reads the selected threat level from the posted form parts and decides which
   * step should be displayed next. Invalid or missing selections cause the wizard to stay on the
   * current step. Selecting {@code HIGH} or {@code MAXIMUM} triggers an acknowledgement flow; if
   * the user has not checked the confirmation box, the method redirects back to this step to
   * display (or re-display) the confirmation prompt.
   *
   * <p>On successful completion, the new level is persisted by calling {@link
   * #setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL)} and the wizard proceeds to the physical
   * security step.
   *
   * @param request the current HTTP request carrying the selected level and navigation controls
   * @return the next wizard step name to display, suitable for use as a redirect target
   */
  @Override
  public String postStep(HTTPRequest request) {
    String networkThreatLevel = request.getPartAsStringFailsafe(PARAM_NETWORK_THREAT_LEVEL, 128);
    SecurityLevels.NETWORK_THREAT_LEVEL newThreatLevel =
        SecurityLevels.parseNetworkThreatLevel(networkThreatLevel);

    // Used in case of redirect either for retry or confirmation.
    StringBuilder redirectTo =
        new StringBuilder(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name());

    /*If the user didn't select a network security level before clicking continue or the selected
     * security level could not be determined, redirect to the same page.*/
    if (newThreatLevel == null || !request.isPartSet(PARAM_NETWORK_THREAT_LEVEL)) {
      return redirectTo.toString();
    }

    PersistFields persistFields = new PersistFields(request);
    boolean isInPreset = persistFields.isUsingPreset();
    if (request.isPartSet("return-from-confirm")) {
      // User clicked back from a confirmation page
      if (isInPreset) {
        // In a preset, go back a step
        return FirstTimeWizardToadlet.getPreviousStep(
                FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK, persistFields.preset)
            .name();
      }

      // Not in a preset, redisplay level choice.
      return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name();
    }
    if ((newThreatLevel == SecurityLevels.NETWORK_THREAT_LEVEL.MAXIMUM
        || newThreatLevel == SecurityLevels.NETWORK_THREAT_LEVEL.HIGH)) {
      // Make the user aware of the effects of high or maximum network threat if selected.
      // They must check a box acknowledging its effects to proceed.
      boolean confirmationChecked = request.isPartSet(PARAM_NETWORK_THREAT_LEVEL_CONFIRM);
      if (!confirmationChecked) {
        if (request.isPartSet(PARAM_NETWORK_THREAT_LEVEL_TRY_CONFIRM)) {
          // If the user did not check the box and clicked next, redisplay the prompt.
          return confirmationRedirect(redirectTo, networkThreatLevel);
        }
        displayConfirmationBox(redirectTo, networkThreatLevel);
        return redirectTo.toString();
      }
    }
    // The user selected low or normal security, or confirmed high or maximum. Set the configuration
    // and continue to the physical security step.
    setThreatLevel(newThreatLevel);
    return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name();
  }

  private void displayConfirmationBox(StringBuilder redirectTo, String networkThreatLevel) {
    redirectTo
        .append("&confirm=true&security-levels.networkThreatLevel=")
        .append(networkThreatLevel);
  }

  private String confirmationRedirect(StringBuilder redirectTo, String networkThreatLevel) {
    displayConfirmationBox(redirectTo, networkThreatLevel);
    return redirectTo.toString();
  }

  /**
   * Applies the given network threat level to the node and persists the configuration.
   *
   * <p>This is the side-effectful operation for this wizard step: it updates the node's security
   * level and then stores the updated configuration. Callers should only invoke this after the user
   * has made a valid selection and (when required) has completed any confirmation prompts.
   *
   * @param level the new network threat level to set; must be a valid enum value
   */
  public void setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL level) {
    core.getNode().services().securityLevels().setThreatLevel(level);
    core.storeConfig();
  }
}
