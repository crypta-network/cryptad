package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * A detached snapshot of the legacy security-levels page state.
 *
 * <p>This record carries only the small set of runtime values that the legacy `/seclevels/` page
 * still needs to render forms and error pages: current network and physical threat levels, whether
 * the client database is active, and the current master-password file metadata.
 *
 * @param networkThreatLevel current detached network threat level
 * @param physicalThreatLevel current detached physical threat level
 * @param hasDatabase whether the node currently has an active client database
 * @param masterPasswordFileExists whether the master-password file currently exists on disk
 * @param masterPasswordFilePath path to the master-password file, or an empty string when
 *     unavailable
 */
public record SecurityLevelsSnapshot(
    SecurityNetworkThreatLevel networkThreatLevel,
    SecurityPhysicalThreatLevel physicalThreatLevel,
    boolean hasDatabase,
    boolean masterPasswordFileExists,
    String masterPasswordFilePath) {
  /**
   * Creates an immutable security-levels snapshot.
   *
   * @throws NullPointerException if a required enum or path value is {@code null}
   */
  public SecurityLevelsSnapshot {
    Objects.requireNonNull(networkThreatLevel, "networkThreatLevel");
    Objects.requireNonNull(physicalThreatLevel, "physicalThreatLevel");
    Objects.requireNonNull(masterPasswordFilePath, "masterPasswordFilePath");
  }
}
