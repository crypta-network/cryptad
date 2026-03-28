package network.crypta.compat.bandwidth;

/**
 * Represents a simple, immutable bandwidth limit pair used by setup and alerting flows.
 *
 * <p>This type models the two rate caps the node enforces for network traffic: an upload limit and
 * a download limit, each expressed as a number of bytes per second. Instances are used to present
 * fixed presets (with a translation key) as well as to derive a reasonable split from a single
 * user-provided monthly budget. The computed split is intentionally asymmetric: as the overall
 * budget grows, download receives a larger share than upload.
 *
 * <p>Instances are pure data holders with no internal synchronization. They are safe to share
 * between threads as long as the surrounding model treats them as read-only. Construction performs
 * the full calculation up front; no further state changes occur after construction.
 *
 * @param downBytes download rate cap in bytes per second as consumed by configuration and UI code
 * @param upBytes upload rate cap in bytes per second as consumed by configuration and UI code
 * @param descriptionKey translation key or stable label describing the source or preset choice
 * @param maybeDefault whether callers may treat this value as a plausible default selection in
 *     interactive setup flows
 */
public record BandwidthLimit(
    long downBytes, long upBytes, String descriptionKey, boolean maybeDefault) {

  /** Size of one gibibyte (GiB) in bytes. */
  private static final double ONE_GIB = 1024d * 1024d * 1024d;

  /**
   * Number of seconds in a fixed 30-day month, used to convert between monthly and per-second
   * limits.
   */
  public static final double SECONDS_PER_MONTH = 2592000d;

  /**
   * Calculates the minimum monthly transfer budget implied by a per-direction minimum rate.
   *
   * <p>This helper preserves the historical wizard calculation used to validate monthly-bandwidth
   * caps. The result assumes a fixed 30-day month and allocates the same minimum rate to both
   * upload and download, so the returned total already includes both directions.
   *
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second that the node
   *     should reserve for both upload and download traffic
   * @return minimum monthly transfer budget in GiB implied by applying the provided minimum rate to
   *     both transfer directions for a fixed 30-day month
   */
  public static double minimumMonthlyLimitGiB(long minBytesPerSecond) {
    return 2d * minBytesPerSecond * SECONDS_PER_MONTH / ONE_GIB;
  }

  /**
   * Calculates per-direction rate caps from a monthly transfer budget.
   *
   * <p>The returned split intentionally becomes download-heavy as the monthly allowance increases,
   * while still honoring the same minimum upload and download floor in both directions. The
   * calculation keeps the historical asymptotic 80/20 bias and uses {@link Math#ceil(double)} so
   * neither direction is rounded below its computed target.
   *
   * @param bytesPerMonth monthly total transfer budget in bytes across both upload and download
   *     traffic
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second that must remain
   *     available regardless of the monthly budget
   * @return immutable upload and download rate limits derived from the provided monthly budget and
   *     the preserved historical asymmetry rule
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
