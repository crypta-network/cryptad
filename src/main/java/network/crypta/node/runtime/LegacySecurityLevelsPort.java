package network.crypta.node.runtime;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;

/**
 * Bridges legacy daemon security-levels behavior into the detached runtime SPI.
 *
 * <p>This adapter keeps all daemon-only threat-level enums, password-mutation exceptions, storage
 * calls, and HTML warning generation inside the root module while exposing only SPI-local enums,
 * snapshots, and status values to higher layers.
 */
public final class LegacySecurityLevelsPort implements SecurityLevelsPort {
  /** Parameter name used when validating detached threat-level arguments. */
  private static final String NEW_LEVEL_ARGUMENT = "newLevel";

  /**
   * Live daemon node that still owns security-level state, warning rendering, and master-password
   * storage operations.
   */
  private final Node node;

  /**
   * Creates a security-levels runtime adapter backed by the current daemon node.
   *
   * @param node live daemon node that owns security-level and storage state
   */
  public LegacySecurityLevelsPort(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  @Override
  public SecurityLevelsSnapshot snapshot() {
    File masterKeysFile = node.storage().getMasterKeysFile();
    return new SecurityLevelsSnapshot(
        mapNetworkThreatLevel(node.services().securityLevels().getNetworkThreatLevel()),
        mapPhysicalThreatLevel(node.services().securityLevels().getPhysicalThreatLevel()),
        node.hasDatabase(),
        masterKeysFile != null && masterKeysFile.exists(),
        masterKeysFile == null ? "" : masterKeysFile.getPath());
  }

  @Override
  public String networkThreatLevelConfirmWarningHtml(
      SecurityNetworkThreatLevel newLevel, String checkboxName) {
    Objects.requireNonNull(checkboxName, "checkboxName");
    HTMLNode warning =
        node.services()
            .securityLevels()
            .getConfirmWarning(
                mapNetworkThreatLevel(Objects.requireNonNull(newLevel, NEW_LEVEL_ARGUMENT)),
                checkboxName);
    return warning == null ? null : warning.generate();
  }

  @Override
  public void setNetworkThreatLevel(SecurityNetworkThreatLevel newLevel) {
    node.services()
        .securityLevels()
        .setThreatLevel(
            mapNetworkThreatLevel(Objects.requireNonNull(newLevel, NEW_LEVEL_ARGUMENT)));
  }

  @Override
  public void setPhysicalThreatLevel(SecurityPhysicalThreatLevel newLevel) {
    node.services()
        .securityLevels()
        .setThreatLevel(
            mapPhysicalThreatLevel(Objects.requireNonNull(newLevel, NEW_LEVEL_ARGUMENT)));
  }

  @Override
  public MasterPasswordMutationStatus changeMasterPassword(String oldPassword, String newPassword)
      throws IOException {
    try {
      node.storage()
          .changeMasterPassword(
              Objects.requireNonNull(oldPassword, "oldPassword"),
              Objects.requireNonNull(newPassword, "newPassword"),
              false);
      return MasterPasswordMutationStatus.SUCCESS;
    } catch (MasterKeysWrongPasswordException _) {
      return MasterPasswordMutationStatus.WRONG_PASSWORD;
    } catch (Node.AlreadySetPasswordException _) {
      return MasterPasswordMutationStatus.ALREADY_SET;
    } catch (MasterKeysFileSizeException _) {
      return MasterPasswordMutationStatus.CORRUPTED_FILE;
    }
  }

  @Override
  public MasterPasswordMutationStatus setMasterPassword(String password) throws IOException {
    try {
      node.storage().setMasterPassword(Objects.requireNonNull(password, "password"), false);
      return MasterPasswordMutationStatus.SUCCESS;
    } catch (MasterKeysWrongPasswordException _) {
      return MasterPasswordMutationStatus.WRONG_PASSWORD;
    } catch (Node.AlreadySetPasswordException _) {
      return MasterPasswordMutationStatus.ALREADY_SET;
    } catch (MasterKeysFileSizeException _) {
      return MasterPasswordMutationStatus.CORRUPTED_FILE;
    }
  }

  @Override
  public void deleteMasterPasswordFile() throws IOException {
    node.storage().killMasterKeysFile();
  }

  /**
   * Converts a daemon network threat level into the detached SPI enum used by HTTP callers.
   *
   * @param level daemon network threat level read from the live security-levels service
   * @return detached network threat level with the same legacy enum name
   */
  private static SecurityNetworkThreatLevel mapNetworkThreatLevel(NETWORK_THREAT_LEVEL level) {
    return switch (level) {
      case LOW -> SecurityNetworkThreatLevel.LOW;
      case NORMAL -> SecurityNetworkThreatLevel.NORMAL;
      case HIGH -> SecurityNetworkThreatLevel.HIGH;
      case MAXIMUM -> SecurityNetworkThreatLevel.MAXIMUM;
    };
  }

  /**
   * Converts a detached network threat level back into the daemon enum expected by the node.
   *
   * @param level detached network threat level supplied through the runtime SPI
   * @return daemon network threat level with the same legacy enum name
   */
  private static NETWORK_THREAT_LEVEL mapNetworkThreatLevel(SecurityNetworkThreatLevel level) {
    return switch (level) {
      case LOW -> NETWORK_THREAT_LEVEL.LOW;
      case NORMAL -> NETWORK_THREAT_LEVEL.NORMAL;
      case HIGH -> NETWORK_THREAT_LEVEL.HIGH;
      case MAXIMUM -> NETWORK_THREAT_LEVEL.MAXIMUM;
    };
  }

  /**
   * Converts a daemon physical threat level into the detached SPI enum used by HTTP callers.
   *
   * @param level daemon physical threat level read from the live security-levels service
   * @return detached physical threat level with the same legacy enum name
   */
  private static SecurityPhysicalThreatLevel mapPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL level) {
    return switch (level) {
      case LOW -> SecurityPhysicalThreatLevel.LOW;
      case NORMAL -> SecurityPhysicalThreatLevel.NORMAL;
      case HIGH -> SecurityPhysicalThreatLevel.HIGH;
      case MAXIMUM -> SecurityPhysicalThreatLevel.MAXIMUM;
    };
  }

  /**
   * Converts a detached physical threat level back into the daemon enum expected by the node.
   *
   * @param level detached physical threat level supplied through the runtime SPI
   * @return daemon physical threat level with the same legacy enum name
   */
  private static PHYSICAL_THREAT_LEVEL mapPhysicalThreatLevel(SecurityPhysicalThreatLevel level) {
    return switch (level) {
      case LOW -> PHYSICAL_THREAT_LEVEL.LOW;
      case NORMAL -> PHYSICAL_THREAT_LEVEL.NORMAL;
      case HIGH -> PHYSICAL_THREAT_LEVEL.HIGH;
      case MAXIMUM -> PHYSICAL_THREAT_LEVEL.MAXIMUM;
    };
  }
}
