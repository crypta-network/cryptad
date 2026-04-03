package network.crypta.platform.api.security;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;

/**
 * Read-only security-level endpoint family for Platform API v1.
 *
 * <p>The handler exposes the detached security-level page snapshot as JSON without bringing the
 * legacy mutation or confirmation-warning flows into the first platform API surface.
 */
public final class SecurityLevelsApiHandler {
  /** Detached runtime port that supplies security-level snapshots for the API layer. */
  private final SecurityLevelsPort securityLevelsPort;

  /**
   * Creates a security-level API handler backed by the supplied runtime port.
   *
   * @param securityLevelsPort detached runtime security-level port
   */
  public SecurityLevelsApiHandler(SecurityLevelsPort securityLevelsPort) {
    this.securityLevelsPort = Objects.requireNonNull(securityLevelsPort, "securityLevelsPort");
  }

  /**
   * Returns the current detached security-level snapshot as a JSON-compatible object.
   *
   * @return JSON-compatible security-level snapshot
   */
  public Map<String, Object> snapshot() {
    SecurityLevelsSnapshot snapshot = securityLevelsPort.snapshot();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("networkThreatLevel", snapshot.networkThreatLevel().name());
    json.put("physicalThreatLevel", snapshot.physicalThreatLevel().name());
    json.put("hasDatabase", snapshot.hasDatabase());
    json.put("masterPasswordFileExists", snapshot.masterPasswordFileExists());
    json.put("masterPasswordFilePath", snapshot.masterPasswordFilePath());
    return json;
  }
}
