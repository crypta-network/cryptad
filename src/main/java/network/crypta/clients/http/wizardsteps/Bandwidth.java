package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Collects bandwidth limit preferences during the First-Time Wizard.
 *
 * <p>This wizard step renders a simple prompt asking whether the user's Internet connection is
 * subject to a monthly transfer cap. The answer determines which follow-up step is presented:
 * either a monthly cap page (when the user indicates a cap) or a rate-based limits page (when the
 * user does not). The UI is rendered as a small HTML form with three submit buttons that post
 * distinct part names, which are then inspected by {@link #postStep(HTTPRequest)}.
 *
 * <p>This class is intentionally stateless and is typically instantiated once per wizard flow. It
 * does not perform I/O beyond adding nodes to the response tree, and it does not persist any
 * settings itself; it only selects the next {@link FirstTimeWizardToadlet.WIZARD_STEP}. The methods
 * are expected to be invoked in the request-handling thread that services the wizard HTTP request.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Render the "cap present?" question and submit controls.
 *   <li>Map the posted button selection to the next wizard step identifier.
 * </ul>
 */
public class Bandwidth implements Step {
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String INPUT_TYPE_SUBMIT = "submit";

  /**
   * Creates a new instance of this wizard step.
   *
   * <p>This type is stateless; constructing it does not allocate external resources and has no side
   * effects. Instances may be safely reused across multiple requests, provided the surrounding
   * wizard wiring does not attach request-scoped state to the instance.
   */
  public Bandwidth() {
    // Intentionally empty: this wizard step is stateless.
  }

  /**
   * Renders the bandwidth-cap question page into the wizard response.
   *
   * <p>This method adds an infobox to the main wizard page content, followed by a form containing
   * submit buttons for "yes", "no", and "back". The buttons are named so that {@link
   * HTTPRequest#isPartSet(String)} can later be used to determine which option the user selected.
   * The method does not interpret any request parameters; it only emits the UI.
   *
   * @param request the HTTP request for this step; used for context only
   * @param helper the page helper used to build the response structure
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("step3Title"));

    HTMLNode bandwidthInfoboxContent =
        helper.getInfobox(
            "infobox-normal", WizardL10n.l10n("bandwidthLimit"), contentNode, null, false);

    bandwidthInfoboxContent.addChild("#", WizardL10n.l10n("bandwidthCapPrompt"));
    HTMLNode bandwidthForm = helper.addFormChild(bandwidthInfoboxContent, ".", "bwForm");
    bandwidthForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "yes", NodeL10n.getBase().getString("Toadlet.yes")});
    bandwidthForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "no", NodeL10n.getBase().getString("Toadlet.no")});
    bandwidthForm
        .addChild("div")
        .addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {INPUT_TYPE_SUBMIT, "back", NodeL10n.getBase().getString("Toadlet.back")});
  }

  /**
   * Determines the next wizard step based on the submitted form selection.
   *
   * <p>The wizard UI posts one of several named parts corresponding to the clicked submit button.
   * This method checks for the presence of the expected part name and returns the next {@link
   * FirstTimeWizardToadlet.WIZARD_STEP} identifier as a string. When the user indicates a monthly
   * cap, the flow transitions to the monthly-cap configuration step; otherwise it transitions to
   * the rate-based configuration step.
   *
   * <p>This method performs no validation beyond checking which button was submitted. The "back"
   * action is handled by the surrounding wizard controller and does not require special handling
   * here.
   *
   * @param request the incoming HTTP request containing posted form parts; must not be {@code null}
   * @return the next wizard step name to navigate to for this submission
   */
  @Override
  public String postStep(HTTPRequest request) {

    // Yes: Set for monthly data limit.
    if (request.isPartSet("yes"))
      return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_MONTHLY.name();

    // No: Set for data rate limit.
    return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE.name();

    // Back: FirstTimeWizardToadlet handles that.
  }
}
