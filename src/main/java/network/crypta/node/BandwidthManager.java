package network.crypta.node;

import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.compat.BandwidthIndicator;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.UpgradeConnectionSpeedUserAlert;

import static java.util.concurrent.TimeUnit.*;

/**
 * Manages bandwidth configuration checks and user-facing upgrade suggestions.
 *
 * <p>This helper has two responsibilities:
 *
 * <ul>
 *   <li>Periodically inspects auto-detected link capacity and, when it is substantially higher than
 *       the configured limits, raises a {@link UpgradeConnectionSpeedUserAlert} suggesting higher
 *       limits.
 *   <li>Validates input/output bandwidth limit values supplied via configuration, throwing {@link
 *       InvalidConfigValueException} with localized messages when values are unacceptable.
 * </ul>
 *
 * <p>Units: limits are expressed in bytes per second. Auto-detected rates from {@link
 * BandwidthIndicator} are in bits per second and are converted to bytes per second internally.
 */
public class BandwidthManager {

  private static final long DELAY_HOURS = 24;

  private int lastOfferedInputBandwidth;
  private int lastOfferedOutputBandwidth;

  private final Node node;

  /**
   * Creates a manager bound to the given node.
   *
   * @param node owning node used to access configuration, ticker, and auto-detection facilities;
   *     must not be {@code null}
   */
  BandwidthManager(Node node) {
    this.node = node;
  }

  /**
   * Schedules a periodic background check that suggests raising configured bandwidth limits when
   * auto-detected capacity has increased substantially.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>Runs every {@value #DELAY_HOURS} hours on the node ticker.
   *   <li>Checks {@code node.connectionSpeedDetection}; exits early when disabled or when no
   *       indicator is available.
   *   <li>If either downstream or upstream capacity is ≥3× both the current configured limit and
   *       the last offered value, creates an alert proposing conservative new limits.
   * </ul>
   */
  public void start() {
    /* Periodically suggest raising configured limits when auto-detected
     * capacity is far above the current settings and has increased
     * significantly since the last suggestion. */
    node.network()
        .ticker()
        .queueTimedJob(
            new Runnable() {
              @Override
              public void run() {
                try {
                  BandwidthIndicator bandwidthIndicator =
                      node.network().ipDetector().getBandwidthIndicator();
                  if (!node.getConfig().get("node").getBoolean("connectionSpeedDetection")
                      || bandwidthIndicator == null) {
                    return;
                  }

                  // Convert bits/s (indicator) to bytes/s used by configuration.
                  int detectedInputBandwidth = bandwidthIndicator.getDownstreamMaxBitRate() / 8;
                  int detectedOutputBandwidth = bandwidthIndicator.getUpstreamMaxBitRate() / 8;

                  // Current configured limits (bytes/s).
                  int currentInputBandwidth =
                      node.getConfig().get("node").getInt("inputBandwidthLimit");
                  int currentOutputBandwidth =
                      node.getConfig().get("node").getInt("outputBandwidthLimit");

                  // Trigger only on a large step-up (≥3×) vs current and last offer.
                  if ((detectedInputBandwidth > currentInputBandwidth * 3
                          && detectedInputBandwidth > lastOfferedInputBandwidth * 3)
                      || (detectedOutputBandwidth > currentOutputBandwidth * 3
                          && detectedOutputBandwidth > lastOfferedOutputBandwidth * 3)) {
                    // Offer half of the detected rate but never below current limits.
                    lastOfferedInputBandwidth =
                        Math.max(detectedInputBandwidth / 2, currentInputBandwidth);
                    lastOfferedOutputBandwidth =
                        Math.max(detectedOutputBandwidth / 2, currentOutputBandwidth);

                    UpgradeConnectionSpeedUserAlert.createAlert(
                        node,
                        new BandwidthLimit(
                            lastOfferedInputBandwidth, lastOfferedOutputBandwidth, null, false));
                  }
                } finally {
                  // Re-schedule the check after the fixed delay.
                  node.network().ticker().queueTimedJob(this, HOURS.toMillis(DELAY_HOURS));
                }
              }
            },
            HOURS.toMillis(DELAY_HOURS));
  }

  /**
   * Validates an output bandwidth limit.
   *
   * <p>The limit is in bytes per second. It must be positive, not lower than the system minimum
   * returned by {@link Node#getMinimumBandwidth()}, and not so large that per-byte timing
   * resolution underflows (i.e., at most {@code SECONDS.toNanos(1)} bytes/s so that {@code 1e9 /
   * limit ≥ 1 ns}).
   *
   * @param obwLimit output bandwidth limit in bytes per second
   * @throws InvalidConfigValueException if the value is non-positive, below the minimum, or exceeds
   *     the upper bound implied by nanos-per-byte timing
   */
  public static void checkOutputBandwidthLimit(int obwLimit) throws InvalidConfigValueException {
    if (obwLimit <= 0) {
      throw new InvalidConfigValueException(
          NodeL10n.getBase().getString("Node.bwlimitMustBePositive"));
    }

    if (obwLimit < Node.getMinimumBandwidth()) {
      throw lowBandwidthLimit(obwLimit);
    }

    // Bound so nanos-per-byte remains ≥ 1 (see outputThrottle: 1e9 / limit).
    if (obwLimit > SECONDS.toNanos(1)) {
      throw new InvalidConfigValueException(
          NodeL10n.getBase()
              .getString(
                  "Node.outputBwlimitMustBeLessThan", "max", Long.toString(SECONDS.toNanos(1))));
    }
  }

  /**
   * Validates an input bandwidth limit.
   *
   * <p>The limit is in bytes per second. A value of {@code -1} means the input limit is derived
   * from the configured output limit. Otherwise, the value must be greater than {@code 1} and not
   * lower than the system minimum returned by {@link Node#getMinimumBandwidth()}.
   *
   * @param ibwLimit input bandwidth limit in bytes per second, or {@code -1} to auto-derive from
   *     the output limit
   * @throws InvalidConfigValueException if the value is not {@code -1} and is non-positive or below
   *     the minimum
   */
  public static void checkInputBandwidthLimit(int ibwLimit) throws InvalidConfigValueException {
    if (ibwLimit == -1) { // Reserved value: derive from the output limit.
      return;
    }

    if (ibwLimit <= 1) {
      throw new InvalidConfigValueException(
          NodeL10n.getBase().getString("Node.bandwidthLimitMustBePositiveOrMinusOne"));
    }

    if (ibwLimit < Node.getMinimumBandwidth()) {
      throw lowBandwidthLimit(ibwLimit);
    }
  }

  /**
   * Returns an exception with an explanation that the given bandwidth limit is too low.
   *
   * <p>See the Node.bandwidthMinimum localization string.
   *
   * @param limit Bandwidth limit in bytes.
   */
  private static InvalidConfigValueException lowBandwidthLimit(int limit) {
    return new InvalidConfigValueException(
        NodeL10n.getBase()
            .getString(
                "Node.bandwidthMinimum",
                new String[] {"limit", "minimum"},
                new String[] {
                  Integer.toString(limit), Integer.toString(Node.getMinimumBandwidth())
                }));
  }
}
