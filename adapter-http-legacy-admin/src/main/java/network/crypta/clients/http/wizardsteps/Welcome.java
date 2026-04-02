package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.ConfigToadlet;
import network.crypta.clients.http.FirstTimeWizardNewToadlet;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renders the first page of the first-time setup wizard.
 *
 * <p>This {@link Step} produces a simple welcome screen that lets the user choose a wizard preset
 * and adjust the UI language. The GET handler builds a small table with the preset choices (for
 * example {@code Low}, {@code High}, and {@code None}) and a language drop-down that submits on
 * change when JavaScript is available. The POST handler applies the requested language choice to
 * the node configuration and then returns to the same wizard step so the page can be re-rendered in
 * the new locale.
 *
 * <pre>{@code
 * Step step = new Welcome(config);
 * step.getStep(request, helper);
 * }</pre>
 *
 * <p>This implementation keeps no per-request state: it only retains the provided {@link Config}
 * reference and derives all other values from the request and configuration at call time. Any
 * errors while applying the language change are logged and treated as non-fatal so the wizard can
 * continue to render.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> render welcome content, preset choices, and language selection
 *   <li><b>Configuration keys used:</b> {@code fproxy.javascriptEnabled} and {@code node.l10n}
 * </ul>
 *
 * @see FirstTimeWizardToadlet
 * @see FirstTimeWizardNewToadlet
 */
public class Welcome implements Step {
  private static final Logger LOG = LoggerFactory.getLogger(Welcome.class);
  private static final String TAG_INPUT = "input";

  /**
   * Constructs a new welcome step GET handler.
   *
   * <p>The wizard step uses this configuration to read feature flags (for example whether FProxy
   * JavaScript is enabled) and to populate and apply the language selection ({@code node.l10n}).
   * Callers are expected to pass a fully initialized configuration instance.
   *
   * @param config node configuration backing this step; must be non-null and ready for reads/writes
   */
  public Welcome(Config config) {
    this.config = config;
  }

  /**
   * Renders the first page of the wizard into the given content node.
   *
   * <p>This method emits the welcome screen HTML into the page content provided by {@code helper}.
   * It reads the {@code incognito} request parameter and threads that value into the preset forms
   * so later steps can keep the user’s choice. When the configuration indicates that JavaScript is
   * enabled in FProxy, the output includes a small redirect script that forwards to the newer
   * wizard toadlet URL.
   *
   * <p>The method is intended to be safe to call repeatedly for the same request, as it does not
   * mutate any internal state beyond reading from the configuration and request.
   *
   * @param request HTTP request wrapper used to read query and form parameters for this step
   * @param helper page rendering helper used to create nodes and forms for the wizard UI
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("homepageTitle"));
    boolean incognito = request.isParameterSet("incognito");

    boolean fProxyJavascriptEnabled = config.get("fproxy").getBoolean("javascriptEnabled");
    if (fProxyJavascriptEnabled) {
      contentNode
          .addChild("script", "type", "text/javascript")
          .addChild(
              "%",
              "window.location" + ".replace(\"" + FirstTimeWizardNewToadlet.TOADLET_URL + " \");");
    }

    HTMLNode optionsTable = contentNode.addChild("table");
    HTMLNode tableHeader = optionsTable.addChild("tr");
    HTMLNode tableRow = optionsTable.addChild("tr");

    // Low security option
    addSecurityTableCell(tableHeader, tableRow, "Low", helper, incognito);

    // High security option
    addSecurityTableCell(tableHeader, tableRow, "High", helper, incognito);

    // Detailed wizard option
    addSecurityTableCell(tableHeader, tableRow, "None", helper, incognito);

    HTMLNode languageForm = helper.addFormChild(contentNode, ".", "languageForm");
    // Add option dropdown for languages
    Option<?> language = config.get("node").getOption("l10n");
    EnumerableOptionCallback l10nCallback = (EnumerableOptionCallback) language.getCallback();
    HTMLNode dropDown =
        ConfigToadlet.addComboBox(
            language.getValueDisplayString(), l10nCallback, language.getName(), false);
    // Submit automatically upon selection if JavaScript.
    dropDown.addAttribute("onchange", "this.form.submit()");
    languageForm.addChild(dropDown);
    // Otherwise fall back to submit button if no JavaScript
    languageForm.addChild("noscript").addChild(TAG_INPUT, "type", "submit");
  }

  /**
   * Applies changes posted from the welcome page and indicates the next step to render.
   *
   * <p>The welcome page only supports a small set of POST actions, most notably changing the UI
   * language. This implementation reads the desired language value from the {@code l10n} form part,
   * attempts to persist it into {@code node.l10n}, and then returns the wizard step identifier for
   * the welcome step so the page can be re-rendered using the newly selected locale.
   *
   * <p>If the supplied value is invalid or cannot be applied, the method logs the failure and still
   * returns the welcome step. No restart is required for this configuration change.
   *
   * @param request HTTP request wrapper carrying multipart form data for this step submission
   * @return the wizard step name to render next, which is the welcome step identifier
   */
  @Override
  public String postStep(HTTPRequest request) {
    // The user changed their language on the welcome page. Change the language and re-render the
    // page.
    // Presets are handled within FirstTimeWizardToadlet because it can access all steps.
    String desiredLanguage = request.getPartAsStringFailsafe("l10n", 4096);
    try {
      config.get("node").set("l10n", desiredLanguage);
    } catch (InvalidConfigValueException e) {
      LOG.error("Failed to set language to {}.", desiredLanguage, e);
    } catch (NodeNeedRestartException _) {
      // Changing language doesn't require a restart, at least as of version 1385.
      // Doing so would be really annoying as the node would have to start up again
      // which could be very slow.
    }
    return FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.name();
  }

  /**
   * Adds a table cell with information about a given security level and button.
   *
   * <p>This helper writes a header cell (the preset title) and a content cell (description and
   * submit button) to the provided table rows. The preset argument is used as a suffix for the
   * localized message keys and the submitted parameter names.
   *
   * @param header table header row ({@code tr}) to receive the {@code th} cell for this preset
   * @param row table content row ({@code tr}) to receive the {@code td} cell for this preset
   * @param preset suffix used to form localized keys and request parameter names for this preset
   * @param helper page rendering helper used to create a form for the preset selection
   * @param incognito whether the incoming request indicates private/incognito browsing mode
   */
  private void addSecurityTableCell(
      HTMLNode header, HTMLNode row, String preset, PageHelper helper, boolean incognito) {
    header.addChild("th", "width", "33%", WizardL10n.l10n("presetTitle" + preset));
    HTMLNode tableCell = row.addChild("td");
    tableCell.addChild("p", WizardL10n.l10n("preset" + preset));
    HTMLNode centerForm = tableCell.addChild("div", "style", "text-align:center;");
    HTMLNode secForm = helper.addFormChild(centerForm, ".", "SecForm" + preset);
    secForm.addChild(
        TAG_INPUT,
        new String[] {
          "type", "name", "value",
        },
        new String[] {
          "hidden", "incognito", String.valueOf(incognito),
        });
    secForm.addChild(
        TAG_INPUT,
        new String[] {"type", "name", "value"},
        new String[] {"submit", "preset" + preset, WizardL10n.l10n("presetChoose" + preset)});
  }

  private final Config config;
}
