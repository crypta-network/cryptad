package network.crypta.compat.bandwidth;

import network.crypta.compat.BandwidthIndicator;
import network.crypta.support.IllegalValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runtime-neutral helpers for converting detected link rates into wizard-compatible bandwidth
 * limits.
 *
 * <p>This class owns the small amount of policy that turns a runtime-provided {@link
 * BandwidthIndicator} estimate into the leaf-safe {@link BandwidthLimit} value object used by
 * first-run configuration flows. Callers use it when they want the historical “detected bandwidth”
 * behavior without depending on the legacy HTTP wizard package. The implementation deliberately
 * keeps the same thresholds, units, and failure messages as the previous wizard-local code, so
 * setup defaults remain stable during the ongoing decoupling work.
 *
 * <p>The helper is stateless and thread-safe. It performs a single synchronous read from the
 * supplied indicator, logs the raw bit-per-second values for diagnostics, rejects obviously invalid
 * measurements, and returns a new immutable result. It does not cache, persist, or probe the
 * network on its own.
 */
public final class BandwidthDetectionSupport {

  private static final Logger LOG =
      LoggerFactory.getLogger("network.crypta.clients.http.wizardsteps.BandwidthManipulator");

  private BandwidthDetectionSupport() {
    throw new AssertionError("No instances");
  }

  /**
   * Detects upstream and downstream bandwidth limits using the bandwidth indicator.
   *
   * <p>The supplied indicator reports transfer rates in bits per second. This method preserves the
   * legacy wizard behavior by logging the raw numbers, validating them against the same
   * availability and plausibility thresholds, and converting accepted values to bytes per second
   * for downstream consumers. The returned limit always uses the historical {@code
   * "bandwidthDetected"} description key and never marks the result as a default preset.
   *
   * <p>This method does not hide malformed or unavailable input behind fallback values. Callers are
   * expected to treat the checked and validation exceptions as a signal to continue with manual
   * bandwidth configuration instead of auto-detection.
   *
   * @param bwIndicator indicator instance used to get downstream and upstream maximum rates in bits
   *     per second; may be {@code null} when the current runtime cannot provide bandwidth estimates
   * @return immutable download and upload limits expressed in bytes per second for setup and alert
   *     flows
   * @throws BandwidthDetectionUnavailableException if automatic detection cannot start because no
   *     indicator is available in the current runtime context
   * @throws IllegalValueException if the indicator reports unavailable, negative, or implausibly
   *     low transfer rates, that should not be shown as detected defaults
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
}
