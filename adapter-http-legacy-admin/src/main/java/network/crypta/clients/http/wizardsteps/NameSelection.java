package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Allows the user to choose a node name for Darknet.
 *
 * <p>This wizard step is responsible for rendering a small form that collects a node name and for
 * validating that a non-empty value was provided. When the user submits the form, the value is read
 * from the {@code nname} field and written into the node configuration under {@code node.name}. If
 * the submitted value is blank, the wizard remains on this step so the user can try again.
 *
 * <p>This class does not keep request-scoped state between calls; it only holds a reference to the
 * shared {@link Config} instance. Any concurrency guarantees therefore depend on the thread-safety
 * of the provided configuration implementation. The step performs synchronous configuration writes
 * and emits log messages for observability.
 *
 * <p><b>Responsibilities</b>
 *
 * <ul>
 *   <li>Render the name input control and navigation buttons for the first-time wizard UI.
 *   <li>Validate that the submitted node name is not empty.
 *   <li>Persist the selected name into {@code node.name} for subsequent steps.
 * </ul>
 *
 * @see Step
 * @see FirstTimeWizardToadlet.WIZARD_STEP
 */
public class NameSelection implements Step {
  private static final Logger LOG = LoggerFactory.getLogger(NameSelection.class);
  private static final String INPUT_TAG = "input";

  private final Config config;

  /**
   * Creates a new instance of the name-selection wizard step.
   *
   * <p>The provided {@link Config} is stored and later used to persist the selected node name into
   * {@code node.name} when the user submits the form. The instance itself is lightweight and does
   * not allocate additional resources.
   *
   * @param config configuration handle used to read and update {@code node.name} during wizard
   *     progression; must be non-null and fully initialized.
   */
  public NameSelection(Config config) {
    this.config = config;
  }

  /**
   * Renders the name-selection step into the wizard page.
   *
   * <p>This method adds a short explanation, an input field named {@code nname}, and the standard
   * navigation buttons ({@code back} and {@code next}). The UI is localized via {@link WizardL10n}
   * and {@link NodeL10n}. The generated form is intentionally minimal: the actual validation and
   * persistence happens in {@link #postStep(HTTPRequest)} when the user submits the page.
   *
   * @param request current HTTP request for this wizard step; used only for contextual rendering,
   *     not for mutating state.
   * @param helper page helper used to create HTML nodes and wizard layout elements; must be
   *     non-null and associated with the active wizard session.
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("step2Title"));
    HTMLNode nnameInfoboxContent =
        helper.getInfobox(
            "infobox-normal", WizardL10n.l10n("chooseNodeName"), contentNode, null, false);

    nnameInfoboxContent.addChild("#", WizardL10n.l10n("chooseNodeNameLong"));
    HTMLNode nnameForm = helper.addFormChild(nnameInfoboxContent, ".", "nnameForm");
    nnameForm.addChild(INPUT_TAG, "name", "nname");

    HTMLNode lineBelow = nnameForm.addChild("div");
    lineBelow.addChild(
        INPUT_TAG,
        new String[] {"type", "name", "value"},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    lineBelow.addChild(
        INPUT_TAG,
        new String[] {"type", "name", "value"},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Processes a form submission for the name-selection step.
   *
   * <p>The submitted value is read from the {@code nname} form field (up to 128 characters). If the
   * user provided an empty string, the wizard stays on this step and prompts again. Otherwise, the
   * method writes the chosen value into {@code node.name} and transitions to the datastore sizing
   * step. Configuration write failures are logged and treated as non-fatal for navigation.
   *
   * @param request current HTTP request containing the submitted wizard form parts; the {@code
   *     nname} field is expected to be present as a string.
   * @return the name of the next wizard step to render; returns this step again when the submitted
   *     node name is blank.
   */
  @Override
  public String postStep(HTTPRequest request) {
    String selectedNName = request.getPartAsStringFailsafe("nname", 128);

    // Prompt again when provided with a blank node name.
    if (selectedNName.isEmpty()) {
      return FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name();
    }

    try {
      config.get("node").set("name", selectedNName);
      LOG.info("Configured node.name={}", selectedNName);
    } catch (ConfigException e) {
      LOG.error("Unexpected ConfigException while setting node.name; continuing wizard flow", e);
    }
    return FirstTimeWizardToadlet.WIZARD_STEP.DATASTORE_SIZE.name();
  }
}
