package network.crypta.runtime.spi;

/**
 * Exposes the detached runtime surface that the JavaScript first-time wizard still needs.
 *
 * <p>This SPI is intentionally page-shaped instead of domain-pure. The HTTP layer already owns the
 * wizard route, template model, localization keys, and request-local validation flow. What remains
 * here is the smallest stable boundary that keeps live daemon types out of the page code while
 * still preserving the existing onboarding behavior.
 *
 * <p>Implementations are responsible for:
 *
 * <ul>
 *   <li>reading current defaults and limits from the live node,
 *   <li>formatting detached values so the legacy form can round-trip them unchanged, and
 *   <li>applying a validated submission to the daemon using the existing save semantics.
 * </ul>
 *
 * @see FirstTimeWizardSnapshot
 * @see FirstTimeWizardSubmission
 */
public interface FirstTimeWizardPort {
  /**
   * Returns a detached snapshot of the current first-time-wizard page state.
   *
   * <p>Callers typically request a fresh snapshot for each HTTP render so the page reflects the
   * current datastore bounds, password state, and bandwidth suggestions. The returned record is
   * immutable and contains only detached values that can be safely passed into templates and form
   * validation logic.
   *
   * @return immutable snapshot containing the defaults, bounds, and suggested values used by the
   *     current wizard page render
   */
  FirstTimeWizardSnapshot snapshot();

  /**
   * Applies one detached first-time-wizard form submission to the live daemon.
   *
   * <p>Implementations preserve the current legacy page behavior: threat-level changes, bandwidth
   * and datastore configuration writes, optional master-password mutation, wizard completion, and
   * config persistence all remain inside the daemon root module. The submission is expected to have
   * passed the HTTP layer's request validation already, but implementations may still reject it if
   * live daemon constraints changed between rendering and submission.
   *
   * @param submission detached form submission reflecting the legacy wizard page semantics and raw
   *     form field values
   * @throws NullPointerException if {@code submission} is {@code null}
   */
  void applySubmission(FirstTimeWizardSubmission submission);
}
