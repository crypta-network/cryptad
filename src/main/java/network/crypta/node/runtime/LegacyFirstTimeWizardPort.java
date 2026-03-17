package network.crypta.node.runtime;

import java.io.IOException;
import java.util.Locale;
import java.util.Objects;
import network.crypta.clients.http.wizardsteps.BandwidthDetectionUnavailableException;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.clients.http.wizardsteps.BandwidthManipulator;
import network.crypta.clients.http.wizardsteps.DatastoreSize;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.config.Option;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.support.Fields;
import network.crypta.support.IllegalValueException;
import network.crypta.support.io.DatastoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Implements the page-oriented first-time-wizard SPI on top of the legacy daemon runtime.
 *
 * <p>This adapter stays in the root module because the JavaScript wizard still depends on several
 * daemon-only behaviors that should not leak across the runtime SPI boundary. It reads the current
 * security state, datastore sizing defaults, storage caps, and bandwidth hints directly from the
 * live node, then exposes those values as detached records for the HTTP layer.
 *
 * <p>The writing path preserves the existing wizard completion semantics rather than redesigning
 * them. Config writes and password-related failures that historically stayed daemon-local are still
 * logged here, while runtime validation failures that would make the request report a false success
 * are allowed to abort the submission before the wizard is marked complete.
 *
 * <p>Responsibilities in this adapter are intentionally narrow:
 *
 * <ul>
 *   <li>translate live node state into {@link FirstTimeWizardSnapshot} values,
 *   <li>apply a {@link FirstTimeWizardSubmission} using the legacy ordering of writes, and
 *   <li>keep daemon exceptions, enums, and config internals out of {@code runtime-spi}.
 * </ul>
 */
final class LegacyFirstTimeWizardPort implements FirstTimeWizardPort {
  /** Logger for daemon-local wizard failures that should remain in the root module. */
  private static final Logger LOG = LoggerFactory.getLogger(LegacyFirstTimeWizardPort.class);

  /** Minimum datastore size exposed by this wizard flow, including the required cache overhead. */
  private static final long MIN_STORAGE_LIMIT = NodeStorageSubsystem.MIN_STORE_SIZE * 5 / 4;

  /** Binary kibibyte unit used when converting between daemon byte values and form units. */
  private static final long KIB = 1024L;

  /** Shared message text for unexpected legacy failures that are logged and kept daemon-local. */
  private static final String UNEXPECTED_ERROR_MESSAGE = "Should not happen, please report! {}";

  /** Live node backing the wizard's security, network, storage, and config reads. */
  private final Node node;

  /** Live client core used for autodetection helpers and final config persistence. */
  private final NodeClientCore core;

  /**
   * Creates a daemon-backed adapter for the JavaScript first-time wizard.
   *
   * <p>The adapter keeps stable references to the live {@link Node} and {@link NodeClientCore} so
   * each request can read current runtime values and persist changes through the existing daemon
   * pathways.
   *
   * @param node live daemon node that provides config, security, storage, and network state
   * @param core live node client core used for autodetection and config persistence
   * @throws NullPointerException if either argument is {@code null}
   */
  LegacyFirstTimeWizardPort(Node node, NodeClientCore core) {
    this.node = Objects.requireNonNull(node, "node");
    this.core = Objects.requireNonNull(core, "core");
  }

  /** {@inheritDoc} */
  @Override
  public FirstTimeWizardSnapshot snapshot() {
    Config config = node.getConfig();
    long minStorageLimitBytes = MIN_STORAGE_LIMIT;
    long maxStorageLimitBytes = DatastoreUtil.maxDatastoreSize();
    String[] detectedBandwidthLimits = detectedBandwidthLimits();
    return new FirstTimeWizardSnapshot(
        passwordAlreadySet(),
        initialStorageLimitGiB(config),
        formatGiB(minStorageLimitBytes),
        minStorageLimitBytes,
        formatGiB(maxStorageLimitBytes),
        maxStorageLimitBytes,
        Node.getMinimumBandwidth() / KIB,
        SECONDS.toNanos(1) / KIB,
        String.format(Locale.ENGLISH, "%.2f", BandwidthLimit.MIN_MONTHLY_LIMIT),
        detectedBandwidthLimits[0],
        detectedBandwidthLimits[1]);
  }

  /** {@inheritDoc} */
  @Override
  public void applySubmission(FirstTimeWizardSubmission submission) {
    Objects.requireNonNull(submission, "submission");

    node.services()
        .securityLevels()
        .setThreatLevel(
            submission.knowSomeone() && !submission.connectToStrangers()
                ? NETWORK_THREAT_LEVEL.HIGH
                : NETWORK_THREAT_LEVEL.NORMAL);

    Config config = node.getConfig();
    applyBandwidth(config, submission);
    applyDatastore(config, submission.storageLimitGiB());
    applyPasswordIfRequired(submission);
    markWizardComplete(config);
    core.storeConfig();
  }

  /**
   * Returns whether the live physical-threat policy already implies a configured password.
   *
   * @return {@code true} when the live node currently requires a startup password
   */
  private boolean passwordAlreadySet() {
    return node.services().securityLevels().getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.HIGH;
  }

  /**
   * Computes the initial datastore size shown in the wizard form.
   *
   * <p>The method preserves the legacy precedence order: explicit configured sizes win, otherwise
   * the adapter falls back to datastore autodetection and finally to the historical fixed default.
   *
   * @param config live daemon config used to read existing datastore-related options
   * @return initial datastore size formatted as English-locale GiB text for the form field
   */
  private String initialStorageLimitGiB(Config config) {
    float storage = 100;
    Option<Long> sizeOption = Config.longOption(config.get("node"), "storeSize");
    if (!sizeOption.isDefault()) {
      Option<Long> clientCacheSizeOption = Config.longOption(config.get("node"), "clientCacheSize");
      Option<Long> slashdotCacheSizeOption =
          Config.longOption(config.get("node"), "slashdotCacheSize");
      long totalSize =
          sizeOption.getValue()
              + clientCacheSizeOption.getValue()
              + slashdotCacheSizeOption.getValue();
      storage = (float) totalSize / DatastoreUtil.ONE_GIB;
    } else {
      long autodetectedDatastoreSize = DatastoreUtil.autodetectDatastoreSize(core, config);
      if (autodetectedDatastoreSize > 0) {
        storage = (float) autodetectedDatastoreSize / DatastoreUtil.ONE_GIB;
      }
    }
    return String.format(Locale.ENGLISH, "%.2f", storage);
  }

  /**
   * Detects recommended bandwidth limits for display in the wizard form.
   *
   * <p>Detection failures are expected on some systems. In that case the adapter logs the daemon
   * detail and returns empty strings so the HTTP layer can render the existing unavailable message.
   *
   * @return two-element array containing download then upload suggestions in KiB/s text
   */
  private String[] detectedBandwidthLimits() {
    try {
      BandwidthLimit detected =
          BandwidthManipulator.detectBandwidthLimits(
              node.network().ipDetector().getBandwidthIndicator());
      return new String[] {
        Long.toString(detected.downBytes / 2 / KIB), Long.toString(detected.upBytes / 2 / KIB)
      };
    } catch (BandwidthDetectionUnavailableException | IllegalValueException e) {
      LOG.info(e.getMessage(), e);
      return new String[] {"", ""};
    }
  }

  /**
   * Applies the submission's bandwidth settings through the legacy config keys.
   *
   * <p>Direct per-second limits are written back as KiB-formatted strings. Monthly transfer budgets
   * are converted to the daemon's byte-based bandwidth model first, then stored through the same
   * config pathway. Legacy {@link ConfigException} failures remain daemon-local and are logged.
   *
   * @param config live daemon config receiving the bandwidth writes
   * @param submission detached wizard submission whose bandwidth fields were already validated by
   *     the HTTP layer
   */
  private void applyBandwidth(Config config, FirstTimeWizardSubmission submission) {
    try {
      if (!submission.haveMonthlyLimit()) {
        config.get("node").set("inputBandwidthLimit", submission.downloadLimitKiB() + "KiB");
        config.get("node").set("outputBandwidthLimit", submission.uploadLimitKiB() + "KiB");
        return;
      }

      BandwidthLimit bandwidth =
          new BandwidthLimit(Fields.parseLong(submission.bandwidthMonthlyLimitGiB() + "GiB"));
      config.get("node").set("inputBandwidthLimit", Long.toString(bandwidth.downBytes));
      config.get("node").set("outputBandwidthLimit", Long.toString(bandwidth.upBytes));
    } catch (ConfigException e) {
      LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
    }
  }

  /**
   * Applies the requested datastore size through the existing datastore-sizing helper.
   *
   * <p>Runtime validation failures are allowed to propagate, so the wizard request aborts instead
   * of reporting success after the datastore size was rejected.
   *
   * @param config live daemon config passed into the datastore sizing helper
   * @param storageLimitGiB requested datastore size in GiB text from the wizard form
   */
  private void applyDatastore(Config config, String storageLimitGiB) {
    DatastoreSize.setDatastoreSize(storageLimitGiB + "GiB", config);
  }

  /**
   * Applies the optional startup-password step when the node does not already require one.
   *
   * <p>The method preserves the legacy order of operations: update the physical threat level first,
   * then invoke the master-password change path. Checked daemon failures stay local to this adapter
   * and are logged rather than surfacing new checked exceptions through the SPI.
   *
   * @param submission detached wizard submission containing the password-related choices
   */
  private void applyPasswordIfRequired(FirstTimeWizardSubmission submission) {
    if (passwordAlreadySet()) {
      return;
    }

    try {
      String newPassword;
      if (!submission.setPassword()) {
        node.services().securityLevels().setThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
        newPassword = "";
      } else {
        node.services().securityLevels().setThreatLevel(PHYSICAL_THREAT_LEVEL.HIGH);
        newPassword = submission.password();
      }
      node.storage().changeMasterPassword("", newPassword, true);
    } catch (Node.AlreadySetPasswordException
        | MasterKeysWrongPasswordException
        | MasterKeysFileSizeException
        | IOException e) {
      LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
    }
  }

  /**
   * Marks the JavaScript wizard as completed in FProxy config state.
   *
   * @param config live daemon config receiving the completion marker
   */
  private void markWizardComplete(Config config) {
    try {
      config.get("fproxy").set("hasCompletedWizard", true);
    } catch (ConfigException e) {
      LOG.error(UNEXPECTED_ERROR_MESSAGE, e, e);
    }
  }

  /**
   * Formats a byte value as the English-locale GiB text used by the wizard form.
   *
   * @param sizeBytes datastore-related byte value to render
   * @return GiB string rounded to two decimal places for direct display in the page
   */
  private static String formatGiB(long sizeBytes) {
    return String.format(Locale.ENGLISH, "%.2f", (float) sizeBytes / DatastoreUtil.ONE_GIB);
  }
}
