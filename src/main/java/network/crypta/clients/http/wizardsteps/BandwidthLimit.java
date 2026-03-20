package network.crypta.clients.http.wizardsteps;

import network.crypta.support.io.DatastoreUtil;

/**
 * Represents a simple, immutable bandwidth limit pair used by the HTTP setup wizard.
 *
 * <p>This type models the two rate caps the node enforces for network traffic: an upload limit and
 * a download limit, each expressed as a number of bytes per second. In the wizard, instances are
 * used to present fixed presets (with a translation key) as well as to derive a reasonable split
 * from a single user-provided monthly budget. The computed split is intentionally asymmetric: as
 * the overall budget grows, download receives a larger share than upload.
 *
 * <p>Instances are pure data holders with no internal synchronization. They are safe to share
 * between threads as long as the surrounding wizard model treats them as read-only (the fields are
 * final). The constructors perform the full calculation up front; no further state changes occur
 * after construction.
 *
 * <ul>
 *   <li><b>Presets:</b> Use {@link #BandwidthLimit(long, long, String, boolean)} to provide
 *       explicit per-second caps and a UI description key.
 *   <li><b>Derived:</b> Use {@link #fromMonthlyBudget(long, long)} to derive per-second caps from a
 *       monthly budget while respecting an explicit minimum bandwidth.
 * </ul>
 */
@SuppressWarnings("ClassCanBeRecord")
public class BandwidthLimit {

  /**
   * Number of seconds in a fixed 30-day month, used to convert between monthly and per-second
   * limits.
   *
   * <p>The wizard uses a fixed month length for deterministic calculations and consistent UI. This
   * intentionally ignores varying calendar months; callers should treat derived limits as heuristic
   * guidance rather than an accounting guarantee.
   */
  public static final double SECONDS_PER_MONTH = 2592000d;

  /**
   * Download rate limit, expressed as bytes per second.
   *
   * <p>This value is intended to be applied as a steady-state cap by the node's bandwidth limiter.
   * It is computed by {@link #fromMonthlyBudget(long, long)} from a monthly budget and otherwise
   * provided directly by callers constructing presets.
   */
  public final long downBytes;

  /**
   * Upload rate limit, expressed as bytes per second.
   *
   * <p>This value is intended to be applied as a steady-state cap by the node's bandwidth limiter.
   * In derived configurations it may be smaller than {@link #downBytes} to reduce latency impact
   * from saturated uplinks.
   */
  public final long upBytes;

  /**
   * Translation key used by the wizard UI to describe this limit selection.
   *
   * <p>For preset values this typically points at a localized string resource. For derived limits,
   * the current implementation sets a simple English label; callers that require localization
   * should prefer providing their own key via the explicit constructor.
   */
  public final String descriptionKey;

  /**
   * Indicates whether this instance is a plausible default choice in the wizard UI.
   *
   * <p>The wizard uses this flag to hint which entry to preselect when presenting multiple presets.
   * It does not affect runtime enforcement of bandwidth limits and has no side effects.
   */
  public final boolean maybeDefault;

  /**
   * Creates a bandwidth limit with explicit per-direction rate caps.
   *
   * <p>This constructor is used for wizard presets where the caller already knows the desired
   * upload and download caps (in bytes per second) and wants to attach a description key and a UI
   * default hint. The values are stored as-is; no normalization or validation is performed here.
   *
   * @param downBytes download rate cap in bytes per second, typically {@code >= 0} for presets
   * @param upBytes upload rate cap in bytes per second, typically {@code >= 0} for presets
   * @param descriptionKey translation key or label used to describe this selection in the UI
   * @param maybeDefault whether the wizard may treat this instance as a default choice
   */
  public BandwidthLimit(long downBytes, long upBytes, String descriptionKey, boolean maybeDefault) {
    this.downBytes = downBytes;
    this.upBytes = upBytes;
    this.descriptionKey = descriptionKey;
    this.maybeDefault = maybeDefault;
  }

  /**
   * Calculates the minimum monthly transfer budget implied by a per-direction minimum rate.
   *
   * <p>The returned value assumes both download and upload are pinned to {@code minBytesPerSecond}
   * for a fixed 30-day month and converts the total to GiB.
   *
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second
   * @return minimum monthly transfer budget in GiB implied by the provided minimum rate
   */
  public static double minimumMonthlyLimitGiB(long minBytesPerSecond) {
    return 2d * minBytesPerSecond * SECONDS_PER_MONTH / DatastoreUtil.ONE_GIB;
  }

  /**
   * Calculates per-direction rate caps from a monthly transfer budget.
   *
   * <p>The implementation derives a bytes-per-second budget by dividing {@code bytesPerMonth} by a
   * fixed 30-day month ({@link #SECONDS_PER_MONTH}). It then reserves at least the provided minimum
   * rate for both upload and download and splits any remaining budget asymmetrically, favoring
   * download as the total budget increases. The computed values are rounded up to whole bytes per
   * second.
   *
   * @param bytesPerMonth monthly total transfer budget in bytes, used to derive per-second caps
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second
   * @return derived upload and download limits for the wizard
   */
  public static BandwidthLimit fromMonthlyBudget(long bytesPerMonth, long minBytesPerSecond) {
    /*
     * Fraction of the total limit used for download. Asymptotically from 0.5 at the minimum cap to 0.8.
     *
     * Q: Why do we do this? It does not work, since download cannot be larger than upload
     *  for any long amount of time.
     * A: Upload is limited because maxing it out increases latency... http://bufferbloat.net/
     *  And fred (line most layered P2Ps) deals very poorly with high-latency links
     *
     * This 50/50 split is consistent with the assumption in the definition of minCap that the upload and
     * download limits are equal.
     */
    double bytesPerSecond = bytesPerMonth / SECONDS_PER_MONTH;
    double bwinc = bytesPerSecond - 2 * minBytesPerSecond; // min for up and min for down
    double asymptoticDlFraction = 4. / 5.;
    double dllimit = minBytesPerSecond + (bwinc * asymptoticDlFraction);
    double ullimit = minBytesPerSecond + (bwinc * (1 - asymptoticDlFraction));
    return new BandwidthLimit(
        (long) Math.ceil(dllimit), (long) Math.ceil(ullimit), "Monthly bandwidth limit", false);
  }
}
