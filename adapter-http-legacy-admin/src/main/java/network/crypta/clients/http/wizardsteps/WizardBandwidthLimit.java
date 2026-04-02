package network.crypta.clients.http.wizardsteps;

/**
 * Compatibility shim that preserves the historical HTTP wizard bandwidth-limit type while
 * delegating the underlying value-object logic to {@code foundation-compat}.
 *
 * <p>This record exists so the legacy wizard pages can continue to exchange a small, local
 * bandwidth-limit type while the actual sizing and monthly-budget math lives in the extracted leaf
 * module. It mirrors the old HTTP-package shape closely enough for existing rendering and form
 * logic, but the helper methods simply delegate to the shared {@link
 * network.crypta.compat.bandwidth.BandwidthLimit} implementation and adapt the result back into the
 * wizard-local type.
 *
 * <p>Instances are immutable and thread-safe. They carry only display and configuration values used
 * by the wizard UI: download and upload rates in bytes per second, a human-facing description key,
 * and a hint about whether the value can be auto-selected.
 *
 * @param downBytes download rate cap in bytes per second for the wizard UI and form submissions
 * @param upBytes upload rate cap in bytes per second for the wizard UI and form submissions
 * @param descriptionKey translation key or label used to describe this selection in the UI
 * @param maybeDefault whether the wizard may treat this instance as a default choice when no more
 *     specific recommendation is available
 */
public record WizardBandwidthLimit(
    long downBytes, long upBytes, String descriptionKey, boolean maybeDefault) {

  /**
   * Number of seconds in a fixed 30-day month, used to convert between monthly and per-second
   * limits.
   */
  public static final double SECONDS_PER_MONTH =
      network.crypta.compat.bandwidth.BandwidthLimit.SECONDS_PER_MONTH;

  /**
   * Calculates the minimum monthly transfer budget implied by a per-direction minimum rate.
   *
   * <p>This is a compatibility delegate for the shared leaf-owned helper. It preserves the wizard's
   * historical interpretation of monthly limits: a fixed 30-day month with the minimum rate applied
   * to both upload and download directions.
   *
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second used for both
   *     upload and download traffic
   * @return minimum monthly transfer budget in GiB implied by the provided minimum rate across both
   *     transfer directions
   */
  public static double minimumMonthlyLimitGiB(long minBytesPerSecond) {
    return network.crypta.compat.bandwidth.BandwidthLimit.minimumMonthlyLimitGiB(minBytesPerSecond);
  }

  /**
   * Calculates per-direction rate caps from a monthly transfer budget.
   *
   * <p>This delegates the actual split calculation to the extracted leaf helper and adapts the
   * result back into the HTTP wizard record. Callers therefore keep the same legacy API while the
   * underlying math, labels, and asymmetry rules stay centralized in one place.
   *
   * @param bytesPerMonth monthly total transfer budget in bytes across upload and download traffic
   * @param minBytesPerSecond minimum per-direction bandwidth in bytes per second that must be
   *     preserved in the resulting limit
   * @return derived upload and download limits wrapped in the wizard-local compatibility record
   */
  public static WizardBandwidthLimit fromMonthlyBudget(long bytesPerMonth, long minBytesPerSecond) {
    network.crypta.compat.bandwidth.BandwidthLimit limit =
        network.crypta.compat.bandwidth.BandwidthLimit.fromMonthlyBudget(
            bytesPerMonth, minBytesPerSecond);
    return new WizardBandwidthLimit(
        limit.downBytes(), limit.upBytes(), limit.descriptionKey(), limit.maybeDefault());
  }
}
