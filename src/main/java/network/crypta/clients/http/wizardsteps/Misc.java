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
 * Renders and handles the "Misc" step of the first-time setup wizard.
 *
 * <p>This step presents operational preferences that are safe to decide early in the setup flow:
 * whether the node should automatically download core updates. The page is rendered as an HTML form
 * with localized labels, and {@link #postStep(HTTPRequest)} persists the selected values into node
 * configuration.
 *
 * <p>The implementation is intentionally side-effect-free during rendering: {@link #getStep} only
 * builds the form structure. State changes happen only when the form is posted.
 *
 * <ul>
 *   <li>Builds localized form controls for core auto-update.
 *   <li>Persists the auto-update preference under {@code node.updater.autoupdate}.
 * </ul>
 *
 * @see Step
 * @see FirstTimeWizardToadlet.WIZARD_STEP
 */
public class Misc implements Step {
  private static final Logger LOG = LoggerFactory.getLogger(Misc.class);

  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";
  private static final String ATTR_VALUE = "value";
  private static final String PARAM_AUTODEPLOY = "autodeploy";

  private final Config config;

  /**
   * Creates a wizard step instance bound to a configuration store.
   *
   * <p>The {@link Config} instance is used to persist the auto-update preference.
   *
   * @param config the configuration root used to persist wizard-selected settings.
   */
  public Misc(Config config) {
    this.config = config;
  }

  /**
   * Builds the HTML form for the "Misc" wizard step and attaches it to the provided page helper.
   *
   * <p>This method creates one infobox section to choose whether core auto-updates should be
   * enabled. The form controls are created with stable {@code name}/{@code id} attributes so {@link
   * #postStep(HTTPRequest)} can read them back. The initial rendering marks auto-update as enabled.
   *
   * @param request the HTTP request that triggered rendering of this wizard step.
   * @param helper the page helper used to build content nodes and forms.
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("stepMiscTitle"));
    HTMLNode form = helper.addFormChild(contentNode, ".", "miscForm");

    HTMLNode miscInfoboxContent =
        helper.getInfobox("infobox-normal", WizardL10n.l10n("autoUpdate"), form, null, false);

    miscInfoboxContent.addChild("p", WizardL10n.l10n("autoUpdateLong"));
    miscInfoboxContent
        .addChild("p")
        .addChild(
            TAG_INPUT,
            new String[] {"type", "checked", "name", ATTR_VALUE, "id"},
            new String[] {"radio", "on", PARAM_AUTODEPLOY, "true", "autodeployTrue"})
        .addChild(
            TAG_LABEL,
            new String[] {"for"},
            new String[] {"autodeployTrue"},
            WizardL10n.l10n("autoUpdateAutodeploy"));
    miscInfoboxContent
        .addChild("p")
        .addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE, "id"},
            new String[] {"radio", PARAM_AUTODEPLOY, "false", "autodeployFalse"})
        .addChild(
            TAG_LABEL,
            new String[] {"for"},
            new String[] {"autodeployFalse"},
            WizardL10n.l10n("autoUpdateNoAutodeploy"));

    miscInfoboxContent.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    miscInfoboxContent.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Applies the user's selections from the "Misc" form and advances the wizard to the next step.
   *
   * <p>The auto-update radio value is parsed as a boolean from the {@code autodeploy} form part,
   * using a small maximum size to bound request processing.
   *
   * @param request the posted HTTP request containing the form parts for this step.
   * @return the enum name of the next wizard step to display after processing.
   */
  @Override
  public String postStep(HTTPRequest request) {
    setAutoUpdate(Boolean.parseBoolean(request.getPartAsStringFailsafe(PARAM_AUTODEPLOY, 10)));
    return FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name();
  }

  /**
   * Persists whether automatic core updates should be enabled for this node.
   *
   * <p>This updates the {@code node.updater.autoupdate} configuration key. The preference controls
   * whether the node is allowed to automatically download update packages; installation is still
   * subject to the platform-specific update workflow. Errors are not expected during normal
   * operation, but are logged defensively if configuration persistence fails.
   *
   * @param enabled {@code true} to enable automatic update downloads; {@code false} to disable.
   */
  public void setAutoUpdate(boolean enabled) {
    try {
      config.get("node.updater").set("autoupdate", enabled);
    } catch (ConfigException e) {
      LOG.error("Unexpected configuration error while updating auto-update setting: {}", e, e);
    }
  }

  /**
   * Legacy compatibility hook for historical wizard presets that toggled UPnP.
   *
   * <p>The plugin runtime has been removed, so this method intentionally performs no work.
   */
  public void setUPnP() {
    // No-op: plugin runtime removed.
  }
}
