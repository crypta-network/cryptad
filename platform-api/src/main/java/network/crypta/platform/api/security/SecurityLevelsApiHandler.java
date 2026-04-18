package network.crypta.platform.api.security;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;

/**
 * Security-level endpoint family for Platform API v1.
 *
 * <p>The handler exposes the detached security-level snapshot as JSON and adds narrowly scoped
 * threat-level mutations. Legacy confirmation-warning HTML and master-password flows remain on the
 * fallback page for this phase.
 */
public final class SecurityLevelsApiHandler {
  private static final String FIELD_OPERATION = "operation";
  private static final String FIELD_CONFIRMATION_REQUIRED = "confirmationRequired";
  private static final String FIELD_PHYSICAL_THREAT_LEVEL = "physicalThreatLevel";
  private static final String FIELD_WARNING_HTML = "warningHtml";
  private static final String OPERATION_SET_PHYSICAL_THREAT_LEVEL = "set_physical_threat_level";
  private static final String PARAMETER_CONFIRMED = "confirmed";
  private static final String PARAMETER_NEW_LEVEL = "newLevel";

  /** Detached runtime port that supplies security-level snapshots for the API layer. */
  private final SecurityLevelsPort securityLevelsPort;

  /** Detached config port used to persist accepted threat-level changes. */
  private final ConfigPort configPort;

  /**
   * Detached wizard port reused for the legacy physical-security path that reopens the database
   * after leaving MAXIMUM.
   */
  private final FirstTimeWizardPort firstTimeWizardPort;

  /**
   * Creates a security-level API handler backed by the supplied runtime port.
   *
   * @param securityLevelsPort detached runtime security-level port
   * @param configPort detached runtime config port used for persistence
   * @param firstTimeWizardPort detached wizard port reused for MAXIMUM exit semantics
   */
  public SecurityLevelsApiHandler(
      SecurityLevelsPort securityLevelsPort,
      ConfigPort configPort,
      FirstTimeWizardPort firstTimeWizardPort) {
    this.securityLevelsPort = Objects.requireNonNull(securityLevelsPort, "securityLevelsPort");
    this.configPort = Objects.requireNonNull(configPort, "configPort");
    this.firstTimeWizardPort = Objects.requireNonNull(firstTimeWizardPort, "firstTimeWizardPort");
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
    json.put(FIELD_PHYSICAL_THREAT_LEVEL, snapshot.physicalThreatLevel().name());
    json.put("hasDatabase", snapshot.hasDatabase());
    json.put("masterPasswordFileExists", snapshot.masterPasswordFileExists());
    json.put("masterPasswordFilePath", snapshot.masterPasswordFilePath());
    return json;
  }

  /**
   * Returns the current legacy confirmation warning for a prospective network-level change.
   *
   * <p>This keeps the legacy warning generation on the runtime side while letting shell clients
   * preflight a change before sending the mutating request.
   *
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible warning snapshot for the requested network level
   */
  public Map<String, Object> networkThreatLevelWarning(Map<String, List<String>> queryParameters) {
    SecurityNetworkThreatLevel newLevel =
        PlatformApiParameters.requireEnum(
            queryParameters, PARAMETER_NEW_LEVEL, SecurityNetworkThreatLevel.class);
    String warningHtml =
        securityLevelsPort.networkThreatLevelConfirmWarningHtml(newLevel, PARAMETER_CONFIRMED);

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(3);
    response.put(PARAMETER_NEW_LEVEL, newLevel.name());
    response.put(FIELD_CONFIRMATION_REQUIRED, warningHtml != null);
    response.put(FIELD_WARNING_HTML, warningHtml == null ? "" : warningHtml);
    return response;
  }

  /**
   * Applies a new network threat level and persists the updated config.
   *
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation summary
   */
  public Map<String, Object> setNetworkThreatLevel(Map<String, List<String>> queryParameters) {
    SecurityNetworkThreatLevel newLevel =
        PlatformApiParameters.requireEnum(
            queryParameters, PARAMETER_NEW_LEVEL, SecurityNetworkThreatLevel.class);
    boolean confirmed = readConfirmationFlag(queryParameters);
    String warningHtml =
        securityLevelsPort.networkThreatLevelConfirmWarningHtml(newLevel, PARAMETER_CONFIRMED);
    if (warningHtml != null && !confirmed) {
      throw new PlatformApiException(
          409,
          "network_threat_level_confirmation_required",
          "This network threat-level change requires server-side confirmation. Retry after"
              + " acknowledging the warning in the Web Shell or use the legacy security page.");
    }

    securityLevelsPort.setNetworkThreatLevel(newLevel);
    configPort.persist();

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, "set_network_threat_level");
    response.put("networkThreatLevel", newLevel.name());
    return response;
  }

  /**
   * Applies a new physical threat level and persists the updated config.
   *
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation summary
   */
  public Map<String, Object> setPhysicalThreatLevel(Map<String, List<String>> queryParameters) {
    SecurityLevelsSnapshot snapshot = securityLevelsPort.snapshot();
    SecurityPhysicalThreatLevel newLevel =
        PlatformApiParameters.requireEnum(
            queryParameters, PARAMETER_NEW_LEVEL, SecurityPhysicalThreatLevel.class);
    boolean confirmed = readConfirmationFlag(queryParameters);
    SecurityPhysicalThreatLevel currentLevel = snapshot.physicalThreatLevel();
    if (newLevel == currentLevel) {
      LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
      response.put(FIELD_OPERATION, OPERATION_SET_PHYSICAL_THREAT_LEVEL);
      response.put(FIELD_PHYSICAL_THREAT_LEVEL, newLevel.name());
      return response;
    }
    if (newLevel == SecurityPhysicalThreatLevel.HIGH
        || (currentLevel == SecurityPhysicalThreatLevel.HIGH
            && (newLevel == SecurityPhysicalThreatLevel.LOW
                || newLevel == SecurityPhysicalThreatLevel.NORMAL))) {
      throw new PlatformApiException(
          409,
          "physical_threat_level_password_required",
          "Changing to or from physical HIGH still requires the legacy password flow."
              + " Use the legacy security page for this transition.");
    }
    if (currentLevel == SecurityPhysicalThreatLevel.MAXIMUM) {
      firstTimeWizardPort.setPhysicalThreatLevel(newLevel);

      LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
      response.put(FIELD_OPERATION, OPERATION_SET_PHYSICAL_THREAT_LEVEL);
      response.put(FIELD_PHYSICAL_THREAT_LEVEL, newLevel.name());
      return response;
    }
    if (newLevel == SecurityPhysicalThreatLevel.MAXIMUM) {
      if (snapshot.hasDatabase() && !confirmed) {
        throw new PlatformApiException(
            409,
            "physical_threat_level_confirmation_required",
            "Changing the physical threat level to MAXIMUM can delete queued work. Retry after"
                + " acknowledging the confirmation.");
      }
      try {
        securityLevelsPort.deleteMasterPasswordFile();
      } catch (IOException _) {
        throw new PlatformApiException(
            409,
            "physical_threat_level_master_password_cleanup_failed",
            "Cannot switch to physical MAXIMUM because the master-password file could not be"
                + " removed. Use the legacy security page for recovery.");
      }
    }

    securityLevelsPort.setPhysicalThreatLevel(newLevel);
    configPort.persist();

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, OPERATION_SET_PHYSICAL_THREAT_LEVEL);
    response.put(FIELD_PHYSICAL_THREAT_LEVEL, newLevel.name());
    return response;
  }

  private static boolean readConfirmationFlag(Map<String, List<String>> queryParameters) {
    List<String> values = queryParameters.get(PARAMETER_CONFIRMED);
    if (values == null || values.isEmpty()) {
      return false;
    }
    boolean anyTruthy = false;
    for (String raw : values) {
      if (raw == null || isConfirmedCheckboxValue(raw)) {
        anyTruthy = true;
      } else if (!"false".equalsIgnoreCase(raw)) {
        throw new PlatformApiException(
            400,
            "invalid_query_parameter",
            "Query parameter '"
                + PARAMETER_CONFIRMED
                + "' must be a legacy checkbox value or one of 'true' or 'false'.");
      }
    }
    return anyTruthy;
  }

  private static boolean isConfirmedCheckboxValue(String raw) {
    return raw.isBlank()
        || "true".equalsIgnoreCase(raw)
        || "on".equalsIgnoreCase(raw)
        || "off".equalsIgnoreCase(raw)
        || PARAMETER_CONFIRMED.equals(raw);
  }
}
