package network.crypta.platform.api.updates;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreSupportLifecycleStatus;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class UpdatesApiHandlerTest {
  @Test
  void coreSnapshot_whenUpdaterAvailable_expectAvailabilityFlags() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    coreUpdateActionPort.downloadAvailable = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.coreSnapshot();

    assertEquals(true, response.get("available"));
    assertEquals(true, response.get("downloadAllowed"));
    assertFalse(response.containsKey("supportLifecycle"));
  }

  @Test
  void coreSnapshot_whenUpdaterAvailableWithoutSelectableUpdate_expectDownloadDisallowed() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.coreSnapshot();

    assertEquals(true, response.get("available"));
    assertEquals(false, response.get("downloadAllowed"));
    assertFalse(response.containsKey("supportLifecycle"));
  }

  @Test
  void supportLifecycleSnapshot_whenRuntimeHasRevokedBuild_expectRedactedSecurityGuidance() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.lifecycleSnapshot = lifecycleSnapshot(false);
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.supportLifecycleSnapshot();

    assertEquals(true, response.get("known"));
    assertEquals(false, response.get("stale"));
    assertEquals("revoked", response.get("runningStatus"));
    assertEquals(1300, response.get("requiredReplacementBuild"));
    assertEquals("Install only the authenticated replacement.", response.get("recoveryGuidance"));
    assertEquals(List.of("CRYPTA-2026-001"), response.get("advisoryIds"));
    assertEquals("sha256:" + "a".repeat(64), response.get("descriptorDigest"));
    String rendered = response.toString();
    org.junit.jupiter.api.Assertions.assertFalse(rendered.contains("USK@"));
    org.junit.jupiter.api.Assertions.assertFalse(rendered.contains("Authorization"));
    org.junit.jupiter.api.Assertions.assertFalse(rendered.contains("/work/"));
  }

  @Test
  void supportLifecycleSnapshot_whenDescriptorIsStale_expectStaleNotReportedAsUnknown() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.lifecycleSnapshot = lifecycleSnapshot(true);
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.supportLifecycleSnapshot();

    assertEquals(true, response.get("known"));
    assertEquals(true, response.get("stale"));
    assertEquals("revoked", response.get("runningStatus"));
  }

  @Test
  void startCoreDownload_whenUpdaterUnavailable_expectConflictException() {
    UpdatesApiHandler handler = new UpdatesApiHandler(new RecordingCoreUpdateActionPort());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, handler::startCoreDownload);

    assertEquals(409, exception.statusCode());
    assertEquals("updater_unavailable", exception.errorCode());
  }

  @Test
  void startCoreDownload_whenUpdaterAvailable_expectDelegatesAndReturnsSummary() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    coreUpdateActionPort.downloadAvailable = true;
    coreUpdateActionPort.startResult = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.startCoreDownload();

    assertEquals(1, coreUpdateActionPort.startCalls);
    assertEquals("start_core_download", response.get("operation"));
    assertEquals(Boolean.TRUE, response.get("downloadTriggered"));
  }

  @Test
  void startCoreDownload_whenStartReturnsFalse_expectConflictException() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    coreUpdateActionPort.downloadAvailable = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, handler::startCoreDownload);

    assertEquals(409, exception.statusCode());
    assertEquals("core_download_not_started", exception.errorCode());
  }

  @Test
  void startCoreDownload_whenSelectableUpdateMissing_expectConflictException() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, handler::startCoreDownload);

    assertEquals(409, exception.statusCode());
    assertEquals("core_update_unavailable", exception.errorCode());
  }

  private static final class RecordingCoreUpdateActionPort implements CoreUpdateActionPort {
    private boolean available;
    private boolean downloadAvailable;
    private boolean startResult;
    private int startCalls;
    private CoreSupportLifecycleSnapshot lifecycleSnapshot =
        CoreSupportLifecycleSnapshot.unknown(1200, List.of("lifecycle_unknown"));

    @Override
    public CoreSupportLifecycleSnapshot supportLifecycleSnapshot() {
      return lifecycleSnapshot;
    }

    @Override
    public boolean isCoreUpdaterAvailable() {
      return available;
    }

    @Override
    public boolean isCoreDownloadAvailable() {
      return downloadAvailable;
    }

    @Override
    public boolean startCoreDownloadFromUi() {
      startCalls++;
      return startResult;
    }

    @Override
    public Optional<Path> resolveDownloadedInstaller(String rawPath) {
      return Optional.empty();
    }
  }

  private static CoreSupportLifecycleSnapshot lifecycleSnapshot(boolean stale) {
    return new CoreSupportLifecycleSnapshot(
        true,
        stale,
        new CoreSupportLifecycleSnapshot.RunningBuild(
            1200,
            CoreSupportLifecycleStatus.REVOKED,
            "2026-07-01T00:00:00Z",
            "2026-06-01T00:00:00Z",
            "2026-12-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
            1300,
            "Install only the authenticated replacement.",
            List.of("CRYPTA-2026-001"),
            List.of("critical-release-defect")),
        new CoreSupportLifecycleSnapshot.Recommendation(1300, 1300, true),
        new CoreSupportLifecycleSnapshot.DescriptorVerification(
            7L, "sha256:" + "a".repeat(64), "2026-07-01T00:05:00Z"),
        stale ? List.of("lifecycle_descriptor_stale") : List.of("build_revoked"));
  }
}
