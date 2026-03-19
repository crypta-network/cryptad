package network.crypta.node.runtime;

import java.util.Objects;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.BandwidthManager;
import network.crypta.node.Node;
import network.crypta.node.useralerts.UpgradeConnectionSpeedUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.support.Fields;

/**
 * Bridges the remaining legacy welcome-page POST actions onto the runtime SPI.
 *
 * <p>This adapter keeps the welcome page's last live-daemon action paths in the root module: update
 * arming, delayed shutdown or restart scheduling, and bandwidth-upgrade validation plus alert
 * mutation. {@code WelcomeToadlet} and related HTTP code pass already-parsed form data into this
 * adapter, while the daemon side remains the source of truth for the effects that touch node
 * services, config, and existing user alerts.
 *
 * <p>The adapter intentionally preserves the current semantics instead of generalizing them. It
 * validates the bandwidth fields using the existing rules, updates the existing upgrade alert when
 * present, writes the same config keys, and swallows restart-required exceptions exactly as the
 * legacy welcome toadlet did. The class is package-private because it is an implementation detail
 * behind {@link WelcomeActionPort}; callers should depend on the SPI surface exposed through {@link
 * LegacyRuntimePorts} instead of constructing this adapter directly.
 */
final class LegacyWelcomeActionPort implements WelcomeActionPort {
  /** Small delay that lets the HTTP layer finish its redirect before shutdown or restart begins. */
  private static final long WELCOME_ACTION_DELAY_MILLIS = 1L;

  /** Name of the node sub-configuration that stores the bandwidth-upgrade values. */
  private static final String NODE_CONFIG_PREFIX = "node";

  /** Config key for the welcome-page download-bandwidth upgrade field. */
  private static final String INPUT_BANDWIDTH_LIMIT = "inputBandwidthLimit";

  /** Config key for the welcome-page upload-bandwidth upgrade field. */
  private static final String OUTPUT_BANDWIDTH_LIMIT = "outputBandwidthLimit";

  /** Live daemon node that still owns the underlying welcome-page maintenance behaviors. */
  private final Node node;

  /**
   * Creates a welcome-page action adapter backed by the current daemon runtime.
   *
   * @param node live daemon node that owns the existing welcome-page maintenance actions
   */
  LegacyWelcomeActionPort(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  /** {@inheritDoc} */
  @Override
  public void armNodeUpdate() {
    node.services().nodeUpdater().arm();
  }

  /** {@inheritDoc} */
  @Override
  public void queueShutdownFromWelcome() {
    node.network()
        .ticker()
        .queueTimedJob(() -> node.exit("Shutdown from fproxy"), WELCOME_ACTION_DELAY_MILLIS);
  }

  /** {@inheritDoc} */
  @Override
  public void queueRestartFromWelcome() {
    node.network()
        .ticker()
        .queueTimedJob(() -> node.getNodeStarter().restart(), WELCOME_ACTION_DELAY_MILLIS);
  }

  /** {@inheritDoc} */
  @Override
  public void applyUpgradeConnectionSpeed(String inputBandwidthLimit, String outputBandwidthLimit) {
    Objects.requireNonNull(inputBandwidthLimit, INPUT_BANDWIDTH_LIMIT);
    Objects.requireNonNull(outputBandwidthLimit, OUTPUT_BANDWIDTH_LIMIT);

    UpgradeConnectionSpeedUserAlert upgradeAlert = findUpgradeConnectionSpeedAlert();
    String errorMessage = validateBandwidthLimits(inputBandwidthLimit, outputBandwidthLimit);

    if (errorMessage == null) {
      applyBandwidthLimits(inputBandwidthLimit, outputBandwidthLimit, upgradeAlert);
    } else if (upgradeAlert != null) {
      upgradeAlert.setError(errorMessage);
    }
  }

  /**
   * Finds the existing upgrade-connection-speed alert if the daemon has already published one.
   *
   * <p>The legacy welcome flow mutates a pre-existing {@link UpgradeConnectionSpeedUserAlert}
   * rather than creating a new alert for each submission. Returning {@code null} means no such
   * alert is currently registered, so the caller should preserve the config-side effect without
   * attempting any alert mutation.
   *
   * @return the existing upgrade alert, or {@code null} when the alert is not registered
   */
  private UpgradeConnectionSpeedUserAlert findUpgradeConnectionSpeedAlert() {
    for (UserAlert alert : node.services().clientCore().getAlerts().getAlerts()) {
      if (alert instanceof UpgradeConnectionSpeedUserAlert userAlert) {
        return userAlert;
      }
    }
    return null;
  }

  /**
   * Applies the legacy bandwidth validation rules and combines any resulting error text.
   *
   * <p>The welcome page historically validates upload and download limits independently, then joins
   * both messages into a single human-readable error string. A {@code null} result means both
   * values passed validation and the config writing may proceed. The input strings are expected to
   * be the raw form values already extracted by the HTTP layer.
   *
   * @param inputBandwidthLimit raw download-limit text from the welcome-page submission
   * @param outputBandwidthLimit raw upload-limit text from the welcome-page submission
   * @return a combined validation error message, or {@code null} when both values are valid
   */
  private String validateBandwidthLimits(String inputBandwidthLimit, String outputBandwidthLimit) {
    String errorMessage = null;
    try {
      BandwidthManager.checkOutputBandwidthLimit(Fields.parseInt(outputBandwidthLimit));
    } catch (NumberFormatException _) {
      errorMessage =
          NodeL10n.getBase()
              .getString("UpgradeConnectionSpeedUserAlert.InvalidValue", "type", "upload");
    } catch (InvalidConfigValueException e) {
      errorMessage = e.getMessage();
    }

    try {
      BandwidthManager.checkInputBandwidthLimit(Fields.parseInt(inputBandwidthLimit));
    } catch (NumberFormatException _) {
      errorMessage =
          combineErrorMessage(
              errorMessage,
              NodeL10n.getBase()
                  .getString("UpgradeConnectionSpeedUserAlert.InvalidValue", "type", "download"));
    } catch (InvalidConfigValueException e) {
      errorMessage = combineErrorMessage(errorMessage, e.getMessage());
    }

    return errorMessage;
  }

  /**
   * Joins two validation messages using the legacy single-space separator.
   *
   * @param existing previously accumulated validation message, or {@code null} for none
   * @param newMessage newly generated validation message to append
   * @return {@code newMessage} when no earlier message exists, otherwise both messages joined
   */
  private static String combineErrorMessage(String existing, String newMessage) {
    if (existing == null) {
      return newMessage;
    }
    return existing + " " + newMessage;
  }

  /**
   * Persists validated bandwidth values and updates the existing alert with the legacy semantics.
   *
   * <p>Successful writes mark the existing upgrade alert as upgraded when such an alert is present.
   * Invalid config values are surfaced back into the existing alert, while {@link
   * NodeNeedRestartException} is swallowed so the HTTP flow can preserve the historical "restart
   * later" behavior from the welcome page.
   *
   * @param inputBandwidthLimit validated download-limit text to write into node config
   * @param outputBandwidthLimit validated upload-limit text to write into node config
   * @param upgradeAlert existing upgrade alert to mutate, or {@code null} when none is registered
   */
  private void applyBandwidthLimits(
      String inputBandwidthLimit,
      String outputBandwidthLimit,
      UpgradeConnectionSpeedUserAlert upgradeAlert) {
    try {
      node.getConfig().get(NODE_CONFIG_PREFIX).set(INPUT_BANDWIDTH_LIMIT, inputBandwidthLimit);
      node.getConfig().get(NODE_CONFIG_PREFIX).set(OUTPUT_BANDWIDTH_LIMIT, outputBandwidthLimit);

      if (upgradeAlert != null) {
        upgradeAlert.setUpgraded(true);
      }
    } catch (InvalidConfigValueException e) {
      if (upgradeAlert != null) {
        upgradeAlert.setError(e.getMessage());
      }
    } catch (NodeNeedRestartException _) {
      // The user will restart later if necessary.
    }
  }
}
