package network.crypta.platform.api.wizard;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class FirstTimeWizardApiHandlerTest {
  @Test
  void snapshot_whenRequested_expectDetachedWizardJson() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);

    Map<String, Object> response = handler.snapshot();

    assertEquals(Boolean.TRUE, response.get("passwordAlreadySet"));
    assertEquals(Boolean.TRUE, response.get("opennetEnabled"));
    assertEquals("HIGH", response.get("currentNetworkThreatLevel"));
    assertEquals("HIGH", response.get("currentPhysicalThreatLevel"));
    assertEquals("2.50", response.get("initialStorageLimitGiB"));
    assertEquals("49.44", response.get("minBandwidthMonthlyLimitGiB"));
    @SuppressWarnings("unchecked")
    Map<String, Object> currentBandwidthLimits =
        (Map<String, Object>) response.get("currentBandwidthLimits");
    assertEquals(4096L, currentBandwidthLimits.get("downloadBytes"));
    assertEquals(1024L, currentBandwidthLimits.get("uploadBytes"));
  }

  @Test
  void apply_whenValidSubmissionProvided_expectDelegatesDetachedSubmission() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    wizardPort.passwordAlreadySet = false;
    wizardPort.securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.NORMAL,
            SecurityPhysicalThreatLevel.NORMAL,
            false,
            false,
            "");
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);

    Map<String, Object> response =
        handler.apply(
            orderedParameters(
                Map.entry("knowSomeone", List.of("on")),
                Map.entry("downloadLimitKiB", List.of("20000")),
                Map.entry("uploadLimitKiB", List.of("10000")),
                Map.entry("storageLimitGiB", List.of("2")),
                Map.entry("setPassword", List.of("true")),
                Map.entry("password", List.of("secret"))));

    assertEquals(
        new FirstTimeWizardSubmission(
            true, false, false, "20000", "10000", "", "2", true, "secret"),
        wizardPort.lastSubmission);
    assertEquals("apply_submission", response.get("operation"));
    assertEquals(Boolean.TRUE, response.get("wizardApplied"));
  }

  @Test
  void apply_whenPreserveBandwidthRequested_expectDelegatesPreserveBandwidthSubmission() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    wizardPort.passwordAlreadySet = false;
    wizardPort.securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.NORMAL,
            SecurityPhysicalThreatLevel.NORMAL,
            false,
            false,
            "");
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);

    Map<String, Object> response =
        handler.apply(
            orderedParameters(
                Map.entry("preserveBandwidthSettings", List.of("on")),
                Map.entry("storageLimitGiB", List.of("2")),
                Map.entry("setPassword", List.of("true")),
                Map.entry("password", List.of("secret"))));

    assertEquals(
        new FirstTimeWizardSubmission(false, false, false, true, "", "", "", "2", true, "secret"),
        wizardPort.lastSubmission);
    assertEquals("apply_submission", response.get("operation"));
    assertEquals(Boolean.TRUE, response.get("wizardApplied"));
  }

  @Test
  void apply_whenPreserveBandwidthRequestedWithoutCurrentBandwidthRow_expectDelegatesSubmission() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    wizardPort.passwordAlreadySet = false;
    wizardPort.currentBandwidthLimits = null;
    wizardPort.securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.NORMAL,
            SecurityPhysicalThreatLevel.NORMAL,
            false,
            false,
            "");
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);

    Map<String, Object> response =
        handler.apply(
            orderedParameters(
                Map.entry("preserveBandwidthSettings", List.of("on")),
                Map.entry("storageLimitGiB", List.of("2"))));

    assertEquals(
        new FirstTimeWizardSubmission(false, false, false, true, "", "", "", "2", false, ""),
        wizardPort.lastSubmission);
    assertEquals("apply_submission", response.get("operation"));
    assertEquals(Boolean.TRUE, response.get("wizardApplied"));
  }

  @Test
  void apply_whenCurrentSecurityStateIsLowOrMaximumWithoutPreserveFlags_expectConflictException() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    wizardPort.passwordAlreadySet = false;
    wizardPort.securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.MAXIMUM, SecurityPhysicalThreatLevel.LOW, false, false, "");
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);
    Map<String, List<String>> queryParameters =
        orderedParameters(
            Map.entry("downloadLimitKiB", List.of("20000")),
            Map.entry("uploadLimitKiB", List.of("10000")),
            Map.entry("storageLimitGiB", List.of("2")));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.apply(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("wizard_current_security_unsupported", exception.errorCode());
    assertNull(wizardPort.lastSubmission);
  }

  @Test
  void apply_whenCurrentSecurityStateIsLowOrMaximumWithPreserveFlags_expectDelegatesSubmission() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    wizardPort.passwordAlreadySet = false;
    wizardPort.securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.MAXIMUM, SecurityPhysicalThreatLevel.LOW, false, false, "");
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);

    Map<String, Object> response =
        handler.apply(
            orderedParameters(
                Map.entry("preserveCurrentNetworkThreatLevel", List.of("on")),
                Map.entry("preserveCurrentPhysicalThreatLevel", List.of("on")),
                Map.entry("downloadLimitKiB", List.of("20000")),
                Map.entry("uploadLimitKiB", List.of("10000")),
                Map.entry("storageLimitGiB", List.of("2"))));

    assertEquals(
        new FirstTimeWizardSubmission(
            false, false, false, false, true, true, "20000", "10000", "", "2", false, ""),
        wizardPort.lastSubmission);
    assertEquals("apply_submission", response.get("operation"));
    assertEquals(Boolean.TRUE, response.get("wizardApplied"));
  }

  @Test
  void apply_whenPasswordAlreadySetAndWizardPasswordRequested_expectConflictException() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);
    Map<String, List<String>> queryParameters =
        orderedParameters(
            Map.entry("downloadLimitKiB", List.of("20000")),
            Map.entry("uploadLimitKiB", List.of("10000")),
            Map.entry("storageLimitGiB", List.of("2")),
            Map.entry("setPassword", List.of("true")),
            Map.entry("password", List.of("secret")));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.apply(queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("wizard_password_already_set", exception.errorCode());
    assertNull(wizardPort.lastSubmission);
  }

  @Test
  void apply_whenStorageLimitBelowMinimum_expectInvalidQueryException() {
    RecordingFirstTimeWizardPort wizardPort = new RecordingFirstTimeWizardPort();
    FirstTimeWizardApiHandler handler = new FirstTimeWizardApiHandler(wizardPort);
    Map<String, List<String>> queryParameters =
        orderedParameters(
            Map.entry("downloadLimitKiB", List.of("20000")),
            Map.entry("uploadLimitKiB", List.of("10000")),
            Map.entry("storageLimitGiB", List.of("0.50")));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.apply(queryParameters));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @SafeVarargs
  private static Map<String, List<String>> orderedParameters(
      Map.Entry<String, List<String>>... entries) {
    LinkedHashMap<String, List<String>> parameters = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, List<String>> entry : entries) {
      parameters.put(entry.getKey(), entry.getValue());
    }
    return parameters;
  }

  private static final class RecordingFirstTimeWizardPort implements FirstTimeWizardPort {
    private boolean passwordAlreadySet = true;
    private FirstTimeWizardCurrentBandwidthLimits currentBandwidthLimits =
        new FirstTimeWizardCurrentBandwidthLimits(4096L, 1024L);
    private SecurityLevelsSnapshot securitySnapshot =
        new SecurityLevelsSnapshot(
            SecurityNetworkThreatLevel.HIGH, SecurityPhysicalThreatLevel.HIGH, false, false, "");
    private FirstTimeWizardSubmission lastSubmission;

    @Override
    public FirstTimeWizardSnapshot snapshot() {
      return new FirstTimeWizardSnapshot(
          passwordAlreadySet,
          "2.50",
          "1.25",
          network.crypta.support.Fields.parseLong("1.25GiB"),
          "10.00",
          network.crypta.support.Fields.parseLong("10GiB"),
          network.crypta.support.Fields.parseLong("12GiB"),
          10,
          976562,
          "49.44",
          "2048",
          "1024",
          currentBandwidthLimits,
          -1L);
    }

    @Override
    public boolean isOpennetEnabled() {
      return true;
    }

    @Override
    public SecurityLevelsSnapshot securitySnapshot() {
      return securitySnapshot;
    }

    @Override
    public void setNetworkThreatLevel(network.crypta.runtime.spi.SecurityNetworkThreatLevel level) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setPhysicalThreatLevel(
        network.crypta.runtime.spi.SecurityPhysicalThreatLevel level) {
      throw new UnsupportedOperationException();
    }

    @Override
    public MasterPasswordMutationStatus changeMasterPassword(
        String oldPassword, String newPassword) {
      throw new UnsupportedOperationException();
    }

    @Override
    public MasterPasswordMutationStatus setMasterPassword(String password) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void deleteMasterPasswordFile() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void applySubmission(FirstTimeWizardSubmission submission) {
      lastSubmission = submission;
    }
  }
}
