package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.DatastoreUtil;

/**
 * Renders and processes the “monthly bandwidth cap” step in the first-time configuration wizard.
 *
 * <p>This step presents a small set of common monthly transfer caps (plus a free-form input) and
 * translates the user’s selection into the node’s underlying up/down bandwidth limits. The UI is
 * intentionally phrased in terms of a monthly total because many ISPs describe limits that way,
 * while the underlying configuration is expressed as sustained rates. On submit, the handler parses
 * the requested cap, converts it to bytes, and delegates to {@link BandwidthManipulator} to persist
 * the computed limits in {@link Config}.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Displays a curated table of caps (plus a custom entry) to guide typical users.
 *   <li>Validates the submitted cap and routes back to this step with a user-facing error when the
 *       value is missing, unparsable, or below the minimum supported limit.
 *   <li>Completes the wizard step only after both download and upload limits are successfully set.
 * </ul>
 *
 * <p>Thread-safety: instances are intended to be used on the request-handling thread for the wizard
 * UI. This class does not maintain mutable shared state beyond delegating to the configuration
 * layer.
 *
 * @see BandwidthManipulator
 * @see Step
 * @see FirstTimeWizardToadlet
 */
public class BandwidthMonthly extends BandwidthManipulator implements Step {

  private static final String L10N_KEY_BANDWIDTH_SELECT = "bandwidthSelect";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String PARAM_CAP_TO = "capTo";
  private static final String TYPE_SUBMIT = "submit";

  private static final long[] caps = {
    (long) Math.ceil(BandwidthLimit.MIN_MONTHLY_LIMIT), 100, 150, 250, 500
  };

  /**
   * Creates a wizard step instance bound to a specific node core and configuration.
   *
   * <p>The created instance is used to render the HTML form for the step and to apply the submitted
   * selection back into the persistent configuration via {@link BandwidthManipulator}. Callers
   * typically construct this once during wizard initialization and reuse it for subsequent HTTP
   * requests for the same node instance.
   *
   * @param core node core used to access services required by the wizard, must be non-null
   * @param config persistent configuration object updated by this step, must be non-null
   */
  public BandwidthMonthly(NodeClientCore core, Config config) {
    super(core, config);
  }

  /**
   * Renders the monthly-cap selection UI for this step.
   *
   * <p>This method adds an informational description, a table of pre-defined caps, and a custom
   * entry field. If the request indicates a previous submission error, it renders a corresponding
   * error message and (when applicable) provides a shortcut to apply the minimum supported cap.
   *
   * <p>This method is side-effecting with respect to the response being built via {@code helper},
   * but it does not persist configuration changes; persistence happens in {@link #postStep}.
   *
   * @param request HTTP request providing query parameters used to display validation errors
   * @param helper page helper used to build the wizard HTML response for the current step
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("bandwidthLimit"));

    // Check for and display any errors.
    final String parseTarget = request.getParam("parseTarget");
    if (request.isParameterSet("parseError")) {
      parseErrorBox(
          contentNode, helper, WizardL10n.l10n("bandwidthCouldNotParse", "limit", parseTarget));
    } else if (request.isParameterSet("tooLow")) {
      HTMLNode errorBox =
          parseErrorBox(
              contentNode,
              helper,
              WizardL10n.l10n(
                  "bandwidthMonthlyLow",
                  new String[] {"requested", "minimum", "useMinimum"},
                  new String[] {
                    parseTarget,
                    String.valueOf(Math.round(BandwidthLimit.MIN_MONTHLY_LIMIT)),
                    WizardL10n.l10n("bandwidthMonthlyUseMinimum")
                  }));

      HTMLNode minimumForm = helper.addFormChild(errorBox, ".", "use-minimum");
      minimumForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"hidden", PARAM_CAP_TO, String.valueOf(BandwidthLimit.MIN_MONTHLY_LIMIT)});
      minimumForm.addChild(
          TAG_INPUT,
          new String[] {"type", ATTR_VALUE},
          new String[] {TYPE_SUBMIT, WizardL10n.l10n("bandwidthMonthlyUseMinimum")});
    }

    // Explain this step's operation.
    HTMLNode infoBox =
        helper.getInfobox(
            "infobox-normal",
            WizardL10n.l10n("bandwidthLimitMonthlyTitle"),
            contentNode,
            null,
            false);
    NodeL10n.getBase()
        .addL10nSubstitution(
            infoBox,
            "FirstTimeWizardToadlet.bandwidthLimitMonthly",
            new String[] {"bold", "coreSettings"},
            new HTMLNode[] {
              HTMLNode.STRONG, new HTMLNode("#", NodeL10n.getBase().getString("ConfigToadlet.node"))
            });

    // Note: We may want to detect the bandwidth limit and hide caps that are unrealistic to reach.
    // The user can always set a custom limit; however, at least one limit should be displayed to
    // demonstrate how to specify the cap.

    // Table header
    HTMLNode table = infoBox.addChild("table");
    HTMLNode headerRow = table.addChild("tr");
    headerRow.addChild("th", WizardL10n.l10n("bandwidthLimitMonthlyTitle"));
    headerRow.addChild("th", WizardL10n.l10n(L10N_KEY_BANDWIDTH_SELECT));

    // Row for each cap
    for (long cap : caps) {
      HTMLNode row = table.addChild("tr");
      // ISPs are likely to list limits in GB instead of GiB, so display GB here.
      row.addChild("td", cap + " GB");
      HTMLNode selectForm = helper.addFormChild(row.addChild("td"), ".", "limit");
      selectForm.addChild(
          TAG_INPUT,
          new String[] {"type", "name", ATTR_VALUE},
          new String[] {"hidden", PARAM_CAP_TO, String.valueOf(cap)});
      selectForm.addChild(
          TAG_INPUT,
          new String[] {"type", ATTR_VALUE},
          new String[] {TYPE_SUBMIT, WizardL10n.l10n(L10N_KEY_BANDWIDTH_SELECT)});
    }

    // Row for custom entry
    HTMLNode customForm = helper.addFormChild(table.addChild("tr"), ".", "custom-form");
    HTMLNode capInput = customForm.addChild("td");
    capInput.addChild(
        TAG_INPUT, new String[] {"type", "name"}, new String[] {"text", PARAM_CAP_TO});
    capInput.addChild("#", " GB");
    customForm
        .addChild("td")
        .addChild(
            TAG_INPUT,
            new String[] {"type", ATTR_VALUE},
            new String[] {TYPE_SUBMIT, WizardL10n.l10n(L10N_KEY_BANDWIDTH_SELECT)});

    // Back / next buttons
    HTMLNode backForm = helper.addFormChild(infoBox, ".", "backForm");
    backForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {TYPE_SUBMIT, "back", NodeL10n.getBase().getString("Toadlet.back")});
  }

  /**
   * Processes a submitted cap value and updates the node’s bandwidth configuration.
   *
   * <p>The handler reads the {@code capTo} form parameter, interprets it as a monthly cap in
   * “GB”-labeled units, and converts it to a byte total using {@link DatastoreUtil#ONE_GIB}. The
   * resulting value is then mapped to upload and download limits via {@link BandwidthLimit} and
   * persisted using {@link #setBandwidthLimit(String, boolean)}. If parsing fails, or if the cap is
   * below the minimum accepted limit, this method returns a redirect target that re-displays the
   * current step with an appropriate error indicator.
   *
   * <p>This method is intended to be called once per form submission; repeating the same submission
   * is effectively idempotent with respect to the resulting stored limit values.
   *
   * @param request HTTP request containing the submitted {@code capTo} parameter for this step
   * @return the next wizard step identifier or a redirect back to this step with error parameters
   */
  @Override
  public String postStep(HTTPRequest request) {
    double gbPerMonth;
    long bytesPerMonth;
    // capTo is specified as floating point GB.
    String capTo = request.getPartAsStringFailsafe(PARAM_CAP_TO, 4096);
    // Target for an error page.
    StringBuilder target =
        new StringBuilder(FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_MONTHLY.name())
            .append("&parseTarget=");
    try {
      gbPerMonth = Double.parseDouble(capTo);
      bytesPerMonth = Math.round(gbPerMonth * DatastoreUtil.ONE_GIB);
    } catch (NumberFormatException _) {
      target.append(URLEncoder.encode(capTo, true));
      target.append("&parseError=true");
      return target.toString();
    }
    BandwidthLimit bandwidth = new BandwidthLimit(bytesPerMonth);

    try {
      setBandwidthLimit(Long.toString(bandwidth.downBytes), false);
      setBandwidthLimit(Long.toString(bandwidth.upBytes), true);
    } catch (InvalidConfigValueException _) {
      target.append(URLEncoder.encode(String.valueOf(gbPerMonth), true));
      target.append("&tooLow=true");
      return target.toString();
    }

    setWizardComplete();

    return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
  }
}
