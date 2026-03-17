package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents one detached submission from the legacy JavaScript first-time wizard page.
 *
 * <p>This record intentionally mirrors the existing page model instead of introducing a broader
 * onboarding domain type. The HTTP layer still performs request parsing, checkbox handling, and
 * user-facing validation. The runtime adapter receives the detached result and maps it onto the
 * legacy daemon writes that complete wizard setup.
 *
 * <p>String fields preserve the raw form values after HTTP extraction. That lets the page
 * round-trip user input unchanged when validation fails, while still allowing the runtime adapter
 * to apply the same units and parsing rules used by the legacy wizard flow.
 *
 * @param knowSomeone whether the user reports knowing an existing trusted Crypta operator
 * @param connectToStrangers whether the user still opts into connecting to untrusted peers
 * @param haveMonthlyLimit whether the submission uses a monthly transfer budget instead of direct
 *     per-second limits
 * @param downloadLimitKiB requested direct download limit, preserved as KiB/s text from the form
 * @param uploadLimitKiB requested direct upload limit, preserved as KiB/s text from the form
 * @param bandwidthMonthlyLimitGiB requested monthly transfer budget, preserved as GiB text from the
 *     form
 * @param storageLimitGiB requested datastore size, preserved as GiB text from the form
 * @param setPassword whether the user chose to configure a startup password during wizard
 *     completion
 * @param password requested password text, which may be empty when password setup is disabled
 */
public record FirstTimeWizardSubmission(
    boolean knowSomeone,
    boolean connectToStrangers,
    boolean haveMonthlyLimit,
    String downloadLimitKiB,
    String uploadLimitKiB,
    String bandwidthMonthlyLimitGiB,
    String storageLimitGiB,
    boolean setPassword,
    String password) {
  /**
   * Creates an immutable first-time-wizard submission.
   *
   * <p>The constructor preserves the HTTP layer's detached values exactly as provided. It validates
   * only that string-backed fields are non-null, leaving parsing, range checking, and empty-string
   * semantics to the surrounding wizard workflow.
   *
   * @throws NullPointerException if any string-backed field is {@code null}
   */
  public FirstTimeWizardSubmission {
    Objects.requireNonNull(downloadLimitKiB, "downloadLimitKiB");
    Objects.requireNonNull(uploadLimitKiB, "uploadLimitKiB");
    Objects.requireNonNull(bandwidthMonthlyLimitGiB, "bandwidthMonthlyLimitGiB");
    Objects.requireNonNull(storageLimitGiB, "storageLimitGiB");
    Objects.requireNonNull(password, "password");
  }
}
