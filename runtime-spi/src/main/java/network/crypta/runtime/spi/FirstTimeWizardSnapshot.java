package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Captures one detached view of the legacy JavaScript first-time wizard page state.
 *
 * <p>The HTTP wizard uses this record to populate the initial form, re-render invalid submissions,
 * and validate user input without reaching back into live daemon objects. All string values are
 * expected to be ready for direct reuse in HTML form fields, including locale-stable decimal
 * formatting for GiB values and empty strings when a bandwidth suggestion is unavailable.
 *
 * <p>The record carries both rounded display strings and exact byte bounds for datastore size. That
 * split preserves the existing UI while letting the HTTP layer validate submissions against the
 * live daemon's true limits instead of reparsing rounded text. Instances are immutable and safe to
 * pass across request-handling layers.
 *
 * @param passwordAlreadySet whether the current physical-threat policy already implies that a
 *     startup password is configured
 * @param initialStorageLimitGiB initial datastore size suggestion, formatted as GiB text for the
 *     storage form field
 * @param minStorageLimitGiB minimum datastore size accepted by the page, formatted as GiB text for
 *     display and error messages
 * @param minStorageLimitBytes minimum datastore size accepted by the page, expressed in exact bytes
 *     for validation
 * @param maxStorageLimitGiB maximum datastore size accepted by the page, formatted as GiB text for
 *     display and error messages
 * @param maxStorageLimitBytes maximum datastore size accepted by the page, expressed in exact bytes
 *     for validation
 * @param minBandwidthKiB minimum direct download or upload limit accepted by the page, in KiB/s
 * @param maxUploadLimitKiB maximum direct upload limit accepted by the page, in KiB/s
 * @param minBandwidthMonthlyLimitGiB minimum monthly transfer budget accepted by the page,
 *     formatted as GiB text
 * @param detectedDownloadLimitKiB recommended direct download limit in KiB/s text or an empty
 *     string when automatic detection is unavailable
 * @param detectedUploadLimitKiB recommended direct upload limit in KiB/s text or an empty string
 *     when automatic detection is unavailable
 * @param autodetectedStorageLimitBytes autodetected datastore suggestion in exact bytes, or {@code
 *     -1} when the legacy datastore page should fall back to its fixed-size defaults
 */
public record FirstTimeWizardSnapshot(
    boolean passwordAlreadySet,
    String initialStorageLimitGiB,
    String minStorageLimitGiB,
    long minStorageLimitBytes,
    String maxStorageLimitGiB,
    long maxStorageLimitBytes,
    long minBandwidthKiB,
    long maxUploadLimitKiB,
    String minBandwidthMonthlyLimitGiB,
    String detectedDownloadLimitKiB,
    String detectedUploadLimitKiB,
    long autodetectedStorageLimitBytes) {
  /**
   * Creates an immutable first-time-wizard snapshot.
   *
   * <p>The constructor preserves the detached values exactly as supplied. It enforces only the
   * nullability contract for string-backed form values and display bounds; it does not normalize
   * units, trim whitespace, or reinterpret empty strings.
   *
   * @throws NullPointerException if any string-backed field is {@code null}
   */
  public FirstTimeWizardSnapshot {
    Objects.requireNonNull(initialStorageLimitGiB, "initialStorageLimitGiB");
    Objects.requireNonNull(minStorageLimitGiB, "minStorageLimitGiB");
    Objects.requireNonNull(maxStorageLimitGiB, "maxStorageLimitGiB");
    Objects.requireNonNull(minBandwidthMonthlyLimitGiB, "minBandwidthMonthlyLimitGiB");
    Objects.requireNonNull(detectedDownloadLimitKiB, "detectedDownloadLimitKiB");
    Objects.requireNonNull(detectedUploadLimitKiB, "detectedUploadLimitKiB");
  }
}
