package network.crypta.platform.api.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.ConfigSection;
import network.crypta.runtime.spi.ConfigSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class SecurityLevelsApiHandlerTest {
  @Test
  void networkThreatLevelWarning_whenWarningRequired_expectWarningPayload() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.networkWarningHtml = "<p>Needs confirmation</p>";
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, new RecordingConfigPort(), new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.networkThreatLevelWarning(Map.of("newLevel", List.of("LOW")));

    assertEquals("LOW", response.get("newLevel"));
    assertEquals(Boolean.TRUE, response.get("confirmationRequired"));
    assertEquals("<p>Needs confirmation</p>", response.get("warningHtml"));
  }

  @Test
  void setNetworkThreatLevel_whenValidLevelProvided_expectMutationAndPersist() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setNetworkThreatLevel(Map.of("newLevel", List.of("HIGH")));

    assertEquals(SecurityNetworkThreatLevel.HIGH, securityLevelsPort.lastNetworkThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("set_network_threat_level", response.get("operation"));
    assertEquals("HIGH", response.get("networkThreatLevel"));
  }

  @Test
  void setNetworkThreatLevel_whenConfirmationRequiredWithoutAcknowledgement_expectConflict() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.networkWarningHtml = "<p>Needs confirmation</p>";
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("LOW"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setNetworkThreatLevel(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("network_threat_level_confirmation_required", exception.errorCode());
    assertEquals(0, configPort.persistCalls);
  }

  @Test
  void setNetworkThreatLevel_whenConfirmationAcknowledged_expectMutationAndPersist() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.networkWarningHtml = "<p>Needs confirmation</p>";
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setNetworkThreatLevel(
            Map.of("newLevel", List.of("LOW"), "confirmed", List.of("true")));

    assertEquals(SecurityNetworkThreatLevel.LOW, securityLevelsPort.lastNetworkThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("LOW", response.get("networkThreatLevel"));
  }

  @Test
  void setNetworkThreatLevel_whenConfirmationPostedAsCheckbox_expectMutationAndPersist() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.networkWarningHtml = "<p>Needs confirmation</p>";
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setNetworkThreatLevel(
            Map.of("newLevel", List.of("LOW"), "confirmed", List.of("on")));

    assertEquals(SecurityNetworkThreatLevel.LOW, securityLevelsPort.lastNetworkThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("LOW", response.get("networkThreatLevel"));
  }

  @Test
  void
      setNetworkThreatLevel_whenConfirmationPostedAsLegacyCheckboxValue_expectMutationAndPersist() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.networkWarningHtml = "<p>Needs confirmation</p>";
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setNetworkThreatLevel(
            Map.of("newLevel", List.of("LOW"), "confirmed", List.of("off")));

    assertEquals(SecurityNetworkThreatLevel.LOW, securityLevelsPort.lastNetworkThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("LOW", response.get("networkThreatLevel"));
  }

  @Test
  void setPhysicalThreatLevel_whenValidLevelProvided_expectMutationAndPersist() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setPhysicalThreatLevel(Map.of("newLevel", List.of("MAXIMUM")));

    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, securityLevelsPort.lastPhysicalThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("set_physical_threat_level", response.get("operation"));
    assertEquals("MAXIMUM", response.get("physicalThreatLevel"));
  }

  @Test
  void setPhysicalThreatLevel_whenSettingMaximum_expectDeletesMasterPasswordFile() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    handler.setPhysicalThreatLevel(Map.of("newLevel", List.of("MAXIMUM")));

    assertEquals(1, securityLevelsPort.deleteMasterPasswordFileCalls);
    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, securityLevelsPort.lastPhysicalThreatLevel);
    assertEquals(1, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenMaximumNeedsConfirmation_expectConflict() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.hasDatabase = true;
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("MAXIMUM"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setPhysicalThreatLevel(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("physical_threat_level_confirmation_required", exception.errorCode());
    assertEquals(0, securityLevelsPort.deleteMasterPasswordFileCalls);
    assertEquals(0, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenMaximumConfirmed_expectDeletesMasterPasswordFile() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.hasDatabase = true;
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    handler.setPhysicalThreatLevel(
        Map.of("newLevel", List.of("MAXIMUM"), "confirmed", List.of("true")));

    assertEquals(1, securityLevelsPort.deleteMasterPasswordFileCalls);
    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, securityLevelsPort.lastPhysicalThreatLevel);
    assertEquals(1, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenMaximumCleanupFails_expectConflict() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.deleteMasterPasswordFileException = new IOException("boom");
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("MAXIMUM"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setPhysicalThreatLevel(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("physical_threat_level_master_password_cleanup_failed", exception.errorCode());
    assertEquals(0, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenTransitionRequiresPasswordFlow_expectConflict() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.currentPhysicalThreatLevel = SecurityPhysicalThreatLevel.NORMAL;
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("HIGH"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setPhysicalThreatLevel(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("physical_threat_level_password_required", exception.errorCode());
    assertEquals(0, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenDowngradingFromHigh_expectConflict() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.currentPhysicalThreatLevel = SecurityPhysicalThreatLevel.HIGH;
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("NORMAL"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setPhysicalThreatLevel(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("physical_threat_level_password_required", exception.errorCode());
    assertEquals(0, configPort.persistCalls);
  }

  @Test
  void setPhysicalThreatLevel_whenDowngradingFromHighToMaximum_expectMaximumApplied() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.currentPhysicalThreatLevel = SecurityPhysicalThreatLevel.HIGH;
    securityLevelsPort.hasDatabase = true;
    RecordingConfigPort configPort = new RecordingConfigPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            securityLevelsPort, configPort, new RecordingFirstTimeWizardPort());

    Map<String, Object> response =
        handler.setPhysicalThreatLevel(
            Map.of("newLevel", List.of("MAXIMUM"), "confirmed", List.of("true")));

    assertEquals(1, securityLevelsPort.deleteMasterPasswordFileCalls);
    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, securityLevelsPort.lastPhysicalThreatLevel);
    assertEquals(1, configPort.persistCalls);
    assertEquals("set_physical_threat_level", response.get("operation"));
    assertEquals("MAXIMUM", response.get("physicalThreatLevel"));
  }

  @Test
  void setNetworkThreatLevel_whenLevelInvalid_expectInvalidQueryException() {
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(
            new RecordingSecurityLevelsPort(),
            new RecordingConfigPort(),
            new RecordingFirstTimeWizardPort());
    Map<String, List<String>> queryParameters = Map.of("newLevel", List.of("BOGUS"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.setNetworkThreatLevel(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void setPhysicalThreatLevel_whenLeavingMaximum_expectWizardSemantics() {
    RecordingSecurityLevelsPort securityLevelsPort = new RecordingSecurityLevelsPort();
    securityLevelsPort.currentPhysicalThreatLevel = SecurityPhysicalThreatLevel.MAXIMUM;
    RecordingConfigPort configPort = new RecordingConfigPort();
    RecordingFirstTimeWizardPort firstTimeWizardPort = new RecordingFirstTimeWizardPort();
    SecurityLevelsApiHandler handler =
        new SecurityLevelsApiHandler(securityLevelsPort, configPort, firstTimeWizardPort);

    Map<String, Object> response =
        handler.setPhysicalThreatLevel(Map.of("newLevel", List.of("NORMAL")));

    assertEquals(SecurityPhysicalThreatLevel.NORMAL, firstTimeWizardPort.lastPhysicalThreatLevel);
    assertNull(securityLevelsPort.lastPhysicalThreatLevel);
    assertEquals(0, configPort.persistCalls);
    assertEquals("set_physical_threat_level", response.get("operation"));
    assertEquals("NORMAL", response.get("physicalThreatLevel"));
  }

  private static final class RecordingSecurityLevelsPort implements SecurityLevelsPort {
    private String networkWarningHtml;
    private final SecurityNetworkThreatLevel currentNetworkThreatLevel =
        SecurityNetworkThreatLevel.NORMAL;
    private SecurityPhysicalThreatLevel currentPhysicalThreatLevel =
        SecurityPhysicalThreatLevel.NORMAL;
    private boolean hasDatabase;
    private IOException deleteMasterPasswordFileException;
    private int deleteMasterPasswordFileCalls;
    private SecurityNetworkThreatLevel lastNetworkThreatLevel;
    private SecurityPhysicalThreatLevel lastPhysicalThreatLevel;

    @Override
    public SecurityLevelsSnapshot snapshot() {
      return new SecurityLevelsSnapshot(
          currentNetworkThreatLevel, currentPhysicalThreatLevel, hasDatabase, false, "");
    }

    @Override
    public String networkThreatLevelConfirmWarningHtml(
        SecurityNetworkThreatLevel newLevel, String checkboxName) {
      return networkWarningHtml;
    }

    @Override
    public void setNetworkThreatLevel(SecurityNetworkThreatLevel newLevel) {
      lastNetworkThreatLevel = newLevel;
    }

    @Override
    public void setPhysicalThreatLevel(SecurityPhysicalThreatLevel newLevel) {
      lastPhysicalThreatLevel = newLevel;
    }

    @Override
    public network.crypta.runtime.spi.MasterPasswordMutationStatus changeMasterPassword(
        String oldPassword, String newPassword) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.runtime.spi.MasterPasswordMutationStatus setMasterPassword(
        String password) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteMasterPasswordFile() throws IOException {
      deleteMasterPasswordFileCalls++;
      if (deleteMasterPasswordFileException != null) {
        throw deleteMasterPasswordFileException;
      }
    }
  }

  private static final class RecordingConfigPort implements ConfigPort {
    private int persistCalls;

    @Override
    public ConfigSnapshot export(Set<ConfigSection> sections) {
      return ConfigSnapshot.empty();
    }

    @Override
    public void applyOverrides(Map<String, String> overrides) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void persist() {
      persistCalls++;
    }
  }

  private static final class RecordingFirstTimeWizardPort implements FirstTimeWizardPort {
    private SecurityPhysicalThreatLevel lastPhysicalThreatLevel;

    @Override
    public FirstTimeWizardSnapshot snapshot() {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean isOpennetEnabled() {
      throw new UnsupportedOperationException();
    }

    @Override
    public SecurityLevelsSnapshot securitySnapshot() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNetworkThreatLevel(SecurityNetworkThreatLevel level) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setPhysicalThreatLevel(SecurityPhysicalThreatLevel level) {
      lastPhysicalThreatLevel = level;
    }

    @Override
    public network.crypta.runtime.spi.MasterPasswordMutationStatus changeMasterPassword(
        String oldPassword, String newPassword) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.runtime.spi.MasterPasswordMutationStatus setMasterPassword(
        String password) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteMasterPasswordFile() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void applySubmission(FirstTimeWizardSubmission submission) {
      throw new UnsupportedOperationException();
    }
  }
}
