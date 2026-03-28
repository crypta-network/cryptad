package network.crypta.clients.http.wizardsteps;

import java.text.DecimalFormat;
import java.util.Objects;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.URLEncoder;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wizard step that configures rate-based bandwidth limits.
 *
 * <p>This step renders a set of common “connection profile” presets and optionally adds a
 * recommendation derived from the bandwidth indicator when available. It presents these choices as
 * a radio group containing byte-per-second pairs (download/upload) and also provides a custom entry
 * row where the user may type their own limits.
 *
 * <p>A typical interaction is: {@link #getStep(HTTPRequest, PageHelper)} renders the form, the user
 * selects a preset or enters both custom fields, and {@link #postStep(HTTPRequest)} validates and
 * persists the selection via the {@link BandwidthManipulator} helpers. On successful parsing and
 * configuration, the wizard is marked complete and navigation proceeds to the wizard’s completion
 * step. When parsing fails, the step redirects back to itself with query parameters that allow the
 * UI to surface a targeted error message without partially applying limits.
 *
 * <ul>
 *   <li><b>Presets:</b> fixed byte/s values intended as reasonable starting points.
 *   <li><b>Detected recommendation:</b> half of detected down/up limits when available.
 *   <li><b>Custom input:</b> only applied when both custom fields are provided.
 * </ul>
 */
public class BandwidthRate extends BandwidthManipulator implements Step {
  private static final Logger LOG = LoggerFactory.getLogger(BandwidthRate.class);

  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";

  private final WizardBandwidthLimit[] limits;
  private final FirstTimeWizardPort wizardPort;

  /**
   * Creates a new bandwidth-rate wizard step with a fixed set of preset profiles.
   *
   * <p>The preset list is stored on the instance and later rendered by {@link #getStep(HTTPRequest,
   * PageHelper)}. Construction does not apply configuration changes; persistence occurs only after
   * a successful {@link #postStep(HTTPRequest)} submission.
   *
   * @param wizardPort detached wizard runtime used for detected-bandwidth suggestions and the
   *     optional current-bandwidth row
   * @param config node configuration instance that receives the selected bandwidth limits
   */
  public BandwidthRate(FirstTimeWizardPort wizardPort, Config config) {
    super(config);
    this.wizardPort = Objects.requireNonNull(wizardPort, "wizardPort");
    final long KiB = 1024L;
    limits =
        new WizardBandwidthLimit[] {
          // Feedback on typical real-world ratios on slow connections would be helpful.
          // 6Mbps/256kbps - 6Mbps is common in parts of China, as well as being the real value in
          // lots of DSL areas
          new WizardBandwidthLimit(384 * KiB, 16 * KiB, "bandwidthConnection6M", false),
          // 8Mbps/512kbps - UK DSL1 is either 448k up or 832k up
          new WizardBandwidthLimit(512 * KiB, 32 * KiB, "bandwidthConnection8M", false),
          // 12Mbps/1Mbps - typical DSL2
          new WizardBandwidthLimit(768 * KiB, 64 * KiB, "bandwidthConnection12M", false),
          // Typical DSL as of 2024
          new WizardBandwidthLimit(768 * KiB, 160 * KiB, "bandwidthConnectionHalfVDSL", true),
          // 20Mbps/5Mbps - Slow end of VDSL
          new WizardBandwidthLimit(1280 * KiB, 320 * KiB, "bandwidthConnectionVDSL", false),
          // 100Mbps fiber etc.
          new WizardBandwidthLimit(2048 * KiB, 2048 * KiB, "bandwidthConnection100M", false)
        };
  }

  /**
   * Renders the wizard page that allows selecting a bandwidth profile by rate.
   *
   * <p>The page consists of a table of presets, an optional “detected” recommendation, and a custom
   * entry row. Preset and detected entries are emitted as radio options where the value encodes a
   * {@code "<downBytes>/<upBytes>"} pair. The custom row uses the {@code customDown} and {@code
   * customUp} text fields and is only considered valid when both are provided.
   *
   * <p>If the request includes {@code parseError=true}, the page also renders an error box keyed by
   * {@code parseTarget}, allowing {@link #postStep(HTTPRequest)} to redirect back with a specific
   * parsing failure message.
   *
   * @param request incoming request carrying optional error flags and any previous selections
   * @param helper page helper used to build HTML nodes for this wizard step
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {
    FirstTimeWizardSnapshot snapshot = wizardPort.snapshot();
    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("bandwidthLimit"));

    HTMLNode formNode = helper.addFormChild(contentNode, ".", "limit");

    if (request.isParameterSet("parseError")) {
      parseErrorBox(contentNode, helper, request.getParam("parseTarget"));
    }

    HTMLNode infoBox =
        helper.getInfobox(
            "infobox-normal", WizardL10n.l10n("bandwidthLimitRateTitle"), formNode, null, false);
    NodeL10n.getBase()
        .addL10nSubstitution(
            infoBox,
            "FirstTimeWizardToadlet.bandwidthLimitRate",
            new String[] {"bold", "coreSettings"},
            new HTMLNode[] {
              HTMLNode.STRONG, new HTMLNode("#", NodeL10n.getBase().getString("ConfigToadlet.node"))
            });

    // Table header
    HTMLNode table = infoBox.addChild("table");
    HTMLNode headerRow = table.addChild("tr");
    headerRow.addChild("th", WizardL10n.l10n("bandwidthConnectionHeader"));
    headerRow.addChild("th", WizardL10n.l10n("bandwidthDownloadHeader"));
    headerRow.addChild("th", WizardL10n.l10n("bandwidthUploadHeader"));
    headerRow.addChild("th", WizardL10n.l10n("bandwidthSelect"));

    boolean addedDefault = false;

    WizardBandwidthLimit detected = detectedBandwidthLimitOrNull(snapshot);
    if (detected != null) {
      addLimitRow(table, detected, true, true);
      addedDefault = true;
    }

    WizardBandwidthLimit current = currentBandwidthLimitOrNull(snapshot);
    if (current != null) {
      addLimitRow(table, current, false, !addedDefault);
      addedDefault = true;
    }

    for (WizardBandwidthLimit limit : limits) {
      addLimitRow(table, limit, false, !addedDefault);
    }

    // Add the custom option.
    HTMLNode customForm = table.addChild("tr");
    customForm.addChild("td", WizardL10n.l10n("bandwidthCustom"));
    customForm
        .addChild("td")
        .addChild(TAG_INPUT, new String[] {"type", "name"}, new String[] {"text", "customDown"});
    customForm
        .addChild("td")
        .addChild(TAG_INPUT, new String[] {"type", "name"}, new String[] {"text", "customUp"});
    // This is valid if it's filled in. So don't show the selector.
    // JavaScript could auto-select the custom option when fields are filled in.

    infoBox.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
    infoBox.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Handles form submission for the bandwidth-rate step and persists the chosen limits.
   *
   * <p>The handler prefers custom input: when both {@code customDown} and {@code customUp} are
   * present and non-empty, it attempts to parse and apply those values. Otherwise, it expects a
   * preset selection from the {@code bandwidth} radio group and applies the embedded {@code
   * "<downBytes>/<upBytes>"} pair.
   *
   * <p>On any parse failure, this method redirects back to the same step while preserving the
   * message(s) produced by the underlying configuration parser. On success, it marks the wizard
   * complete and returns the completion step identifier.
   *
   * @param request submitted request containing preset selection and/or custom limit fields
   * @return the next wizard step identifier, possibly including parameters for parse-error display
   */
  @Override
  public String postStep(HTTPRequest request) {

    String limitSelected = request.getPartAsStringFailsafe("bandwidth", 100);

    String down = request.getPartAsStringFailsafe("customDown", 20);
    String up = request.getPartAsStringFailsafe("customUp", 20);

    // Try to parse a custom limit first.
    if (!down.isEmpty() && !up.isEmpty()) {
      String failedLimits = attemptSet(up, down);

      if (!failedLimits.isEmpty()) {
        // Some at least one limit failed to parse.
        return "BANDWIDTH_RATE&parseError=true&parseTarget="
            + URLEncoder.encode(failedLimits, true);
      }

      // Success
      setWizardComplete();
      return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
    }

    if (!limitSelected.isEmpty()) {
      int x = limitSelected.indexOf('/');
      if (x != -1) {
        String downString = limitSelected.substring(0, x);
        String upString = limitSelected.substring(x + 1);
        // Pre-defined limit selected.
        String preset = attemptSet(upString, downString);
        if (!preset.isEmpty()) {
          // Error parsing predefined limit.
          // This should not happen, as there are no units to confound the parser.
          LOG.error("Failed to parse pre-defined limit! Please report.");
          return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE
              + "&parseError=true&parseTarget="
              + URLEncoder.encode(preset, true);
        }
      }
    } else {
      LOG.error("No bandwidth limit set!");
      return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE.name();
    }

    setWizardComplete();
    return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
  }

  private WizardBandwidthLimit detectedBandwidthLimitOrNull(FirstTimeWizardSnapshot snapshot) {
    String detectedDownload = snapshot.detectedDownloadLimitKiB();
    String detectedUpload = snapshot.detectedUploadLimitKiB();
    if (detectedDownload.isEmpty() || detectedUpload.isEmpty()) {
      return null;
    }

    try {
      final long kib = 1024L;
      return new WizardBandwidthLimit(
          Long.parseLong(detectedDownload) * kib,
          Long.parseLong(detectedUpload) * kib,
          "bandwidthDetected",
          true);
    } catch (NumberFormatException e) {
      LOG.info("Ignoring malformed detected bandwidth suggestion.", e);
      return null;
    }
  }

  private static WizardBandwidthLimit currentBandwidthLimitOrNull(
      FirstTimeWizardSnapshot snapshot) {
    FirstTimeWizardCurrentBandwidthLimits current = snapshot.currentBandwidthLimits();
    if (current == null) {
      return null;
    }

    return new WizardBandwidthLimit(
        current.downloadBytes(), current.uploadBytes(), "bandwidthCurrent", false);
  }

  /**
   * Attempts to set bandwidth limits.
   *
   * @param up output limit
   * @param down input limit
   * @return a space-separated string of the messages from any exceptions thrown when setting
   *     limits. If both are successful, an empty string.
   */
  private String attemptSet(String up, String down) {
    String failedLimits = "";
    try {
      setBandwidthLimit(down, false);
    } catch (InvalidConfigValueException e) {
      failedLimits = e.getMessage();
    }
    try {
      setBandwidthLimit(up, true);
    } catch (InvalidConfigValueException e) {
      if (!failedLimits.isEmpty()) failedLimits += ' ';
      failedLimits += e.getMessage();
    }
    return failedLimits;
  }

  /**
   * Adds a row to the table for the given limit. Adds a download limit, upload limit, and selection
   * button.
   *
   * @param table Table to add a row to.
   * @param limit Limit to display.
   * @param recommended Whether to mark the limit with (Recommended) next to the select button.
   * @param useMaybeDefault Whether to auto-select this entry when no other default was added.
   */
  private void addLimitRow(
      HTMLNode table, WizardBandwidthLimit limit, boolean recommended, boolean useMaybeDefault) {
    HTMLNode row = table.addChild("tr");
    row.addChild("td", WizardL10n.l10n(limit.descriptionKey()));
    String downColumn =
        SizeUtil.formatSize(limit.downBytes()) + WizardL10n.l10n("bandwidthPerSecond");
    if (limit.downBytes() >= 32 * 1024) {
      downColumn += " (= ";
      if (limit.downBytes() < 256 * 1024)
        downColumn +=
            new DecimalFormat("0.0").format((double) limit.downBytes() * 8 / (1024 * 1024));
      else downColumn += (limit.downBytes() * 8) / (1024 * 1024);
      downColumn += "Mbps)";
    }
    row.addChild("td", downColumn);
    row.addChild(
        "td", SizeUtil.formatSize(limit.upBytes()) + WizardL10n.l10n("bandwidthPerSecond"));

    HTMLNode buttonCell = row.addChild("td");

    HTMLNode radio =
        buttonCell.addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {"radio", "bandwidth", limit.downBytes() + "/" + limit.upBytes()});
    if (recommended || (useMaybeDefault && limit.maybeDefault()))
      radio.addAttribute("checked", "checked");
    if (recommended) {
      buttonCell.addChild("#", WizardL10n.l10n("autodetectedSuggestedLimit"));
    }
  }
}
