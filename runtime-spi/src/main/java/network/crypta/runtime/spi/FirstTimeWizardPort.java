package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the detached runtime surface that the first-time wizard flows still need.
 *
 * <p>This SPI is intentionally page-shaped instead of domain-pure. The HTTP layer already owns the
 * wizard route, template model, localization keys, and request-local validation flow. What remains
 * here is the smallest stable boundary that keeps live daemon types out of the page code while
 * still preserving the existing onboarding behavior for both the JavaScript wizard and the legacy
 * multipage security path.
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
   * Returns whether the live node currently has Opennet enabled.
   *
   * @return {@code true} when the running node currently participates in Opennet
   */
  boolean isOpennetEnabled();

  /**
   * Returns the detached security snapshot needed by the legacy multipage wizard security steps.
   *
   * @return immutable snapshot of current threat levels, database status, and password-file
   *     metadata
   */
  SecurityLevelsSnapshot securitySnapshot();

  /**
   * Applies a new detached network threat level using the legacy first-time-wizard semantics.
   *
   * @param level new detached network threat level
   */
  void setNetworkThreatLevel(SecurityNetworkThreatLevel level);

  /**
   * Applies a new detached physical threat level using the legacy first-time-wizard semantics.
   *
   * @param level new detached physical threat level
   */
  void setPhysicalThreatLevel(SecurityPhysicalThreatLevel level);

  /**
   * Changes the master password protecting client material using the first-time-wizard storage
   * path.
   *
   * @param oldPassword previous password, possibly empty
   * @param newPassword new password to set, possibly empty
   * @return detached mutation outcome preserving the legacy wizard distinctions
   * @throws IOException if a filesystem error occurs while reading or writing password material
   */
  MasterPasswordMutationStatus changeMasterPassword(String oldPassword, String newPassword)
      throws IOException;

  /**
   * Sets or unlocks the master password protecting client material using the first-time-wizard
   * storage path.
   *
   * @param password password to set or use for unlocking
   * @return detached mutation outcome preserving the legacy wizard distinctions
   * @throws IOException if a filesystem error occurs while reading or writing password material
   */
  MasterPasswordMutationStatus setMasterPassword(String password) throws IOException;

  /**
   * Deletes the master-password file using the first-time-wizard deletion path.
   *
   * @throws IOException if the file cannot be deleted
   */
  void deleteMasterPasswordFile() throws IOException;

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
