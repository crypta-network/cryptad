package network.crypta.clients.http.wizardsteps;

import network.crypta.compat.BandwidthIndicator;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
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
 * BandwidthLimit} value object used by the wizard UI.
 *
 * <p>Instances are lightweight and hold references to a {@link NodeClientCore} and {@link Config}
 * supplied by the surrounding HTTP wizard implementation. This class does not own those objects and
 * does not perform any synchronization; callers are expected to invoke it from the same execution
 * context used to render and handle wizard requests.
 *
 * <ul>
 *   <li>Applies an input or output limit string to the {@code node.*BandwidthLimit} option.
 *   <li>Builds a warning infobox for invalid or rejected bandwidth inputs.
 *   <li>Optionally displays “current” limits when the node is configured non-default.
 *   <li>Persists {@code fproxy.hasCompletedWizard} at the end of the wizard flow.
 * </ul>
 */
public abstract class BandwidthManipulator {
  private static final Logger LOG = LoggerFactory.getLogger(BandwidthManipulator.class);

  /**
   * Node core used to access the current {@link Node} instance and its configured bandwidth state.
   *
   * <p>This reference is provided by the caller and is treated as non-null. The reference itself is
   * immutable, but the underlying core and node may have state that changes over time as the node
   * runs and configuration is applied.
   */
  protected final NodeClientCore core;

  /**
   * Node configuration used to read and update wizard-related options.
   *
   * <p>This is typically the shared configuration for the running node. Updates made through this
   * object may be in-memory only until {@link Config#store()} is called by the caller or by helper
   * methods in this class.
   */
  protected final Config config;

  /**
   * Creates a new helper bound to the given core and configuration.
   *
   * <p>Subclasses typically call this from their constructors and then use the protected helpers
   * during request handling (rendering pages, validating user input, and persisting wizard state).
   * This constructor performs no I/O and does not persist configuration changes.
   *
   * @param core Node core used to access the current node and its bandwidth limits; must be
   *     non-null for subclasses to function correctly.
   * @param config Configuration handle used to read and update wizard options; must be non-null and
   *     should refer to the node's live configuration.
   */
  protected BandwidthManipulator(NodeClientCore core, Config config) {
    this.config = config;
    this.core = core;
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
   * @see Node#getMinimumBandwidth()
   */
  protected void setBandwidthLimit(String limit, boolean setOutputLimit)
      throws InvalidConfigValueException {
    String limitType = setOutputLimit ? "outputBandwidthLimit" : "inputBandwidthLimit";
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
   * @return The created infobox node which is already attached to {@code parent}.
   */
  protected HTMLNode parseErrorBox(HTMLNode parent, PageHelper helper, String message) {
    HTMLNode infoBox =
        helper.getInfobox(
            "infobox-warning", WizardL10n.l10n("bandwidthErrorSettingTitle"), parent, null, false);

    infoBox.addChild("p", message);

    return infoBox;
  }

  /**
   * Returns the node's currently effective bandwidth limits when they are explicitly configured.
   *
   * <p>This helper is used to populate the wizard UI with a “current settings” row when the node is
   * not using the default bandwidth configuration. If the relevant option is still at its default
   * value, this method returns {@code null} so callers can omit the “current” section.
   *
   * <p>The returned {@link BandwidthLimit} is constructed from the node's current input/output
   * values and is intended for display only; it does not imply that the wizard has validated or
   * re-applied these settings during the current request.
   *
   * @return A {@link BandwidthLimit} describing the node's current limits, or {@code null} when the
   *     wizard should treat the node as using defaults.
   */
  protected BandwidthLimit getCurrentBandwidthLimitsOrNull() {
    if (!config.get("node").getOption("outputBandwidthLimit").isDefault()) {
      return new BandwidthLimit(
          core.getNode().network().inputBandwidthLimit(),
          core.getNode().network().outputBandwidthLimit(),
          "bandwidthCurrent",
          false);
    }
    return null;
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
   * BandwidthLimit detected = BandwidthManipulator.detectBandwidthLimits(bwIndicator);
   * }</pre>
   *
   * @param bwIndicator indicator instance used to obtain upstream and downstream bit rates; may be
   *     null, in which case detection fails as if the indicator is unavailable.
   * @return Detected upstream and downstream bandwidth in bytes per second, suitable for display.
   * @throws BandwidthDetectionUnavailableException If auto-detection is unavailable, or {@code
   *     bwIndicator} is null and detection cannot proceed.
   * @throws IllegalValueException If the indicator reports unavailable rates or values that are
   *     nonsensically low for wizard defaults.
   */
  public static BandwidthLimit detectBandwidthLimits(BandwidthIndicator bwIndicator)
      throws BandwidthDetectionUnavailableException, IllegalValueException {
    if (bwIndicator == null) {
      throw new BandwidthDetectionUnavailableException(
          "The node does not have a bandwidthIndicator.");
    }

    int downstreamBits = bwIndicator.getDownstreamMaxBitRate();
    int upstreamBits = bwIndicator.getUpstreamMaxBitRate();
    LOG.info(
        "bandwidthIndicator reports downstream {} bits/s and upstream {} bits/s.",
        downstreamBits,
        upstreamBits);

    if (downstreamBits < 0 || upstreamBits < 0) {
      throw new IllegalValueException("Reported unavailable.");
    }

    // For readability, in bits.
    final int KiB = 8192;

    if (downstreamBits < 8 * KiB) {
      throw new IllegalValueException(
          "Detected downstream of " + downstreamBits + " bits/s is nonsensically slow, ignoring.");
    }

    if (upstreamBits < KiB) {
      throw new IllegalValueException(
          "Detected upstream of " + upstreamBits + " bits/s is nonsensically slow, ignoring.");
    }

    int downstreamBytes = downstreamBits / 8;
    int upstreamBytes = upstreamBits / 8;

    return new BandwidthLimit(downstreamBytes, upstreamBytes, "bandwidthDetected", false);
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
    // Set wizard completion flag
    try {
      config.get("fproxy").set("hasCompletedWizard", true);
      config.store();
    } catch (ConfigException e) {
      LOG.error("Failed to persist wizard completion flag.", e);
    }
  }
}
