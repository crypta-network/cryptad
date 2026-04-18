package network.crypta.platform.api.updates;

import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    assertEquals(Map.of("available", true, "downloadAllowed", true), response);
  }

  @Test
  void coreSnapshot_whenUpdaterAvailableWithoutSelectableUpdate_expectDownloadDisallowed() {
    RecordingCoreUpdateActionPort coreUpdateActionPort = new RecordingCoreUpdateActionPort();
    coreUpdateActionPort.available = true;
    UpdatesApiHandler handler = new UpdatesApiHandler(coreUpdateActionPort);

    Map<String, Object> response = handler.coreSnapshot();

    assertEquals(Map.of("available", true, "downloadAllowed", false), response);
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
}
