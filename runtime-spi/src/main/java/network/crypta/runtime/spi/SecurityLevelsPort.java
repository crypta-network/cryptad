package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the small legacy security-levels admin-page runtime surface without daemon-only types.
 *
 * <p>This port is intentionally page-oriented rather than a general security domain model. It keeps
 * the remaining live daemon interactions for the `/seclevels/` admin page behind one narrow SPI:
 * current threat-level reads, the existing network-level confirmation-warning builder, threat-level
 * mutations, and master-password-file operations.
 */
public interface SecurityLevelsPort {
  /**
   * Returns a detached snapshot of the current legacy security-levels page state.
   *
   * @return immutable snapshot of current threat levels, database status, and password-file
   *     metadata
   */
  SecurityLevelsSnapshot snapshot();

  /**
   * Returns the legacy confirmation warning HTML for a prospective network-level change.
   *
   * <p>Implementations may return {@code null} when no confirmation UI is required for the
   * requested transition.
   *
   * @param newLevel requested detached network threat level
   * @param checkboxName checkbox name that the rendered HTML should use for confirmation
   * @return rendered warning HTML, or {@code null} when no warning is required
   */
  String networkThreatLevelConfirmWarningHtml(
      SecurityNetworkThreatLevel newLevel, String checkboxName);

  /**
   * Applies a new detached network threat level.
   *
   * @param newLevel new detached network threat level
   */
  void setNetworkThreatLevel(SecurityNetworkThreatLevel newLevel);

  /**
   * Applies a new detached physical threat level.
   *
   * @param newLevel new detached physical threat level
   */
  void setPhysicalThreatLevel(SecurityPhysicalThreatLevel newLevel);

  /**
   * Changes the master password protecting client material.
   *
   * @param oldPassword previous password, possibly empty
   * @param newPassword new password to set, possibly empty
   * @return detached mutation outcome preserving the legacy admin-page distinctions
   * @throws IOException if a filesystem error occurs while reading or writing password material
   */
  MasterPasswordMutationStatus changeMasterPassword(String oldPassword, String newPassword)
      throws IOException;

  /**
   * Sets or unlocks the master password protecting client material.
   *
   * @param password password to set or use for unlocking
   * @return detached mutation outcome preserving the legacy admin-page distinctions
   * @throws IOException if a filesystem error occurs while reading or writing password material
   */
  MasterPasswordMutationStatus setMasterPassword(String password) throws IOException;

  /**
   * Deletes the master-password file using the runtime's existing deletion path.
   *
   * @throws IOException if the file cannot be deleted
   */
  void deleteMasterPasswordFile() throws IOException;
}
