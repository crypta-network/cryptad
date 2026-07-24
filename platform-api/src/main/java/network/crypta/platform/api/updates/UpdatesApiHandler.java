package network.crypta.platform.api.updates;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreUpdateActionPort;

/**
 * Core-update control-plane endpoints for Platform API v1.
 *
 * <p>This handler is the transport-neutral bridge between the Platform API router and the daemon's
 * detached updater SPI. It deliberately exposes only the smallest updater surface that the shell
 * can use safely in Phase 3: one read-only snapshot that answers whether updater actions are wired
 * and currently actionable, plus one mutation that mirrors the legacy "download from UI" control.
 *
 * <p>The class does not attempt to model installer launching, package-store handoff, progress
 * rendering, or platform-specific recovery guidance. Those concerns still belong to the legacy HTTP
 * updater pages and their runtime adapters. Callers should therefore treat this handler as a
 * control-plane surface for availability and download triggering, not as a complete updater domain
 * API.
 *
 * <ul>
 *   <li>Reads are side-effect free and report only stable JSON fields.
 *   <li>Mutations fail fast when the updater cannot actually honor the request.
 *   <li>Legacy installer and store flows remain available as fallback/debug paths.
 * </ul>
 */
public final class UpdatesApiHandler {
  private static final String FIELD_OPERATION = "operation";

  /**
   * Detached runtime port that exposes the remaining updater actions needed by the control plane.
   */
  private final CoreUpdateActionPort coreUpdateActionPort;

  /**
   * Creates an updater API handler backed by the supplied runtime port.
   *
   * <p>The supplied port stays responsible for all daemon-bound updater decisions, including
   * whether the updater service is present, whether a manual download is currently meaningful, and
   * whether a requested UI-triggered download actually started. This handler only translates those
   * outcomes into stable Platform API responses.
   *
   * @param coreUpdateActionPort detached updater action port used for availability checks and
   *     UI-triggered download start
   * @throws NullPointerException if {@code coreUpdateActionPort} is {@code null}
   */
  public UpdatesApiHandler(CoreUpdateActionPort coreUpdateActionPort) {
    this.coreUpdateActionPort =
        Objects.requireNonNull(coreUpdateActionPort, "coreUpdateActionPort");
  }

  /**
   * Returns the current updater availability snapshot.
   *
   * <p>The response intentionally separates service presence from action readiness. {@code
   * available} reports whether the legacy core-updater integration exists at all in the current
   * runtime, while {@code downloadAllowed} narrows that to the smaller condition required for the
   * shell-native "trigger download" button. Callers should not infer installer readiness or update
   * progress from this snapshot alone.
   *
   * @return JSON-compatible updater snapshot containing stable booleans for updater presence and
   *     current manual-download readiness
   */
  public Map<String, Object> coreSnapshot() {
    boolean available = coreUpdateActionPort.isCoreUpdaterAvailable();
    boolean downloadAllowed = available && coreUpdateActionPort.isCoreDownloadAvailable();
    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put("available", available);
    response.put("downloadAllowed", downloadAllowed);
    return response;
  }

  /**
   * Returns the redacted last-known-good Stable 1.0 support-lifecycle projection.
   *
   * <p>Unknown and stale states remain explicit; this handler does not infer support from normal
   * updater availability or advertise raw descriptor bytes and update-key URIs.
   *
   * @return JSON-compatible local lifecycle snapshot containing only public release metadata
   */
  public Map<String, Object> supportLifecycleSnapshot() {
    CoreSupportLifecycleSnapshot snapshot = coreUpdateActionPort.supportLifecycleSnapshot();
    return (snapshot == null
            ? CoreSupportLifecycleSnapshot.unknown(
                -1, List.of("lifecycle_runtime_snapshot_unavailable"))
            : snapshot)
        .toJsonValue();
  }

  /**
   * Starts the current core-package download through the detached updater port.
   *
   * <p>This method preserves the legacy updater semantics that the shell can rely on: it refuses to
   * report success when the updater service is absent, when no selectable package is currently
   * downloadable, or when a race causes the underlying download start request to become a no-op.
   * Callers should treat a successful response as "the daemon accepted the download start request
   * now", not as proof that the package already finished downloading.
   *
   * @return JSON-compatible mutation summary describing the accepted download trigger
   * @throws PlatformApiException if the updater service is absent, no downloadable package is
   *     currently selected, or the runtime declines to start the download
   */
  public Map<String, Object> startCoreDownload() {
    if (!coreUpdateActionPort.isCoreUpdaterAvailable()) {
      throw new PlatformApiException(
          409, "updater_unavailable", "Core updater is not currently available.");
    }
    if (!coreUpdateActionPort.isCoreDownloadAvailable()) {
      throw new PlatformApiException(
          409, "core_update_unavailable", "No selectable core update is currently available.");
    }

    if (!coreUpdateActionPort.startCoreDownloadFromUi()) {
      throw new PlatformApiException(
          409,
          "core_download_not_started",
          "The core download could not be started. Refresh updater state and retry.");
    }

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, "start_core_download");
    response.put("downloadTriggered", true);
    return response;
  }
}
