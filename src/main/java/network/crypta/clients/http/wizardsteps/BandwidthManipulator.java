package network.crypta.clients.http.wizardsteps;

import java.util.Objects;
import network.crypta.compat.BandwidthIndicator;
import network.crypta.compat.bandwidth.BandwidthDetectionSupport;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.support.HTMLNode;
import network.crypta.support.IllegalValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common helper for bandwidth-related wizard steps.
 *
 * <p>This type centralizes the small pieces of logic that multiple bandwidth wizard pages need:
 * applying user-selected bandwidth limits to the node configuration, rendering a consistent warning
 * infobox when a value cannot be applied, and persisting the “wizard completed” flag. It also
 * contains a static helper for turning raw indicator-reported bit rates into the {@link
 * WizardBandwidthLimit} value object used by the wizard UI.
 *
 * <p>Instances are lightweight and hold a reference to the shared {@link Config} supplied by the
 * surrounding HTTP wizard implementation. This class does not own that object and does not perform
 * any synchronization; callers are expected to invoke it from the same execution context used to
 * render and handle wizard requests.
 *
 * <ul>
 *   <li>Applies an input or output limit string to the {@code node.*BandwidthLimit} option.
 *   <li>Builds a warning infobox for invalid or rejected bandwidth inputs.
 *   <li>Persists {@code fproxy.hasCompletedWizard} at the end of the wizard flow.
 * </ul>
 */
public abstract class BandwidthManipulator {
  private static final Logger LOG = LoggerFactory.getLogger(BandwidthManipulator.class);
  private static final String OUTPUT_BANDWIDTH_LIMIT = "outputBandwidthLimit";
  private static final String INPUT_BANDWIDTH_LIMIT = "inputBandwidthLimit";

  /**
   * Node configuration used to read and update wizard-related options.
   *
   * <p>This is typically the shared configuration for the running node. Updates made through this
   * object may be in-memory only until {@link Config#store()} is called by the caller or by helper
   * methods in this class.
   */
  protected final Config config;

  /**
   * Creates a new helper bound to the given configuration.
   *
   * <p>Subclasses typically call this from their constructors and then use the protected helpers
   * during request handling (rendering pages, validating user input, and persisting wizard state).
   * This constructor performs no I/O and does not persist configuration changes.
   *
   * @param config Configuration handle used to read and update wizard options; must be non-null and
   *     should refer to the node's live configuration.
   */
  protected BandwidthManipulator(Config config) {
    this.config = Objects.requireNonNull(config, "config");
  }

  /**
   * Applies a user-provided bandwidth limit string to the appropriate node configuration option.
   *
   * <p>This updates either {@code node.outputBandwidthLimit} or {@code node.inputBandwidthLimit}
   * based on {@code setOutputLimit}. The provided value is passed to the configuration system for
   * parsing and validation. Callers commonly use this during wizard form submission; persistence is
   * handled elsewhere (either by the wizard flow or by a subsequent {@link Config#store()} call).
   *
   * <p>This method is intended to be idempotent with respect to the effective configuration: if the
   * same value is applied repeatedly, the resulting in-memory option value remains the same.
   *
   * @param limit Bandwidth limit string to apply; may include recognized SI/IEC unit suffixes and
   *     must not include a "/s" rate marker, as parsing is performed by the config option itself.
   * @param setOutputLimit Whether to apply the limit to output (true) or input (false) bandwidth.
   * @throws InvalidConfigValueException If the value is rejected by configuration parsing, such as
   *     being negative, unparsable, or too low to be usable for a running node.
   */
  protected void setBandwidthLimit(String limit, boolean setOutputLimit)
      throws InvalidConfigValueException {
    String limitType = setOutputLimit ? OUTPUT_BANDWIDTH_LIMIT : INPUT_BANDWIDTH_LIMIT;
    try {
      config.get("node").set(limitType, limit);
      LOG.info("The {} has been set to {}", limitType, limit);
    } catch (ConfigException e) {
      if (e instanceof InvalidConfigValueException exception) {
        // Limit was not readable.
        throw exception;
      }
      LOG.error("Should not happen, please report!", e);
    }
  }

  /**
   * Builds a warning infobox describing why a bandwidth value could not be applied.
   *
   * <p>This is a UI helper used by wizard steps to present a consistent warning style when a user
   * enters an invalid value or when the node rejects a configuration update. The returned node is
   * already attached to {@code parent} and includes the provided message in a single paragraph.
   *
   * @param parent Parent HTML node that should receive the warning infobox; must be part of the
   *     page currently being rendered.
   * @param helper Wizard page helper used to create a properly styled infobox; must be non-null and
   *     correspond to the current page context.
   * @param message Human-readable message to display inside the infobox body; should be a single
   *     sentence and must not include raw user secrets.
   * @return The created infobox node that is already attached to {@code parent}.
   */
  protected HTMLNode parseErrorBox(HTMLNode parent, PageHelper helper, String message) {
    HTMLNode infoBox =
        helper.getInfobox(
            "infobox-warning", WizardL10n.l10n("bandwidthErrorSettingTitle"), parent, null, false);

    infoBox.addChild("p", message);

    return infoBox;
  }

  /**
   * Detects upstream and downstream bandwidth limits using the bandwidth indicator.
   *
   * <p>The indicator reports bit rates in bits per second. This method converts those values to
   * bytes per second for use by the wizard UI, logs the raw reported numbers for diagnostics, and
   * rejects values that are clearly invalid (negative or implausibly low). This protects the wizard
   * from presenting misleading “detected” values when the indicator has not yet initialized or
   * cannot provide accurate limits.
   *
   * <p>This method performs no network operations itself; it only queries the provided indicator
   * instance.
   *
   * <pre>{@code
   * WizardBandwidthLimit detected = BandwidthManipulator.detectBandwidthLimits(bwIndicator);
   * }</pre>
   *
   * @param bwIndicator indicator instance used to get upstream and downstream bit rates; may be
   *     null, in which case detection fails as if the indicator is unavailable.
   * @return Detected upstream and downstream bandwidth in bytes per second, suitable for display.
   * @throws WizardBandwidthDetectionUnavailableException If auto-detection is unavailable, or
   *     {@code bwIndicator} is null and detection cannot proceed.
   * @throws IllegalValueException If the indicator reports unavailable rates or values that are
   *     nonsensically low for wizard defaults.
   */
  @SuppressWarnings("unused")
  public static WizardBandwidthLimit detectBandwidthLimits(BandwidthIndicator bwIndicator)
      throws WizardBandwidthDetectionUnavailableException, IllegalValueException {
    try {
      network.crypta.compat.bandwidth.BandwidthLimit detected =
          BandwidthDetectionSupport.detectBandwidthLimits(bwIndicator);
      return new WizardBandwidthLimit(
          detected.downBytes(),
          detected.upBytes(),
          detected.descriptionKey(),
          detected.maybeDefault());
    } catch (network.crypta.compat.bandwidth.BandwidthDetectionUnavailableException e) {
      throw new WizardBandwidthDetectionUnavailableException(e.getMessage(), e);
    }
  }

  /**
   * Marks the HTTP wizard as completed and persists the configuration change.
   *
   * <p>This sets {@code fproxy.hasCompletedWizard} to {@code true} and attempts to store the
   * updated configuration. Failures are logged and do not throw, because the wizard can still
   * complete its HTTP response even if persistence fails; callers may choose to surface additional
   * UI warnings elsewhere.
   */
  protected void setWizardComplete() {
    // Set the wizard completion flag
    try {
      config.get("fproxy").set("hasCompletedWizard", true);
      config.store();
    } catch (ConfigException e) {
      LOG.error("Failed to persist wizard completion flag.", e);
    }
  }
}
