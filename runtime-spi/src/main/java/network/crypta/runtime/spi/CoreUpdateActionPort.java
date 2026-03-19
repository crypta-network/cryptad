package network.crypta.runtime.spi;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Exposes the last daemon-backed updater actions still needed by the legacy core-update toadlet.
 *
 * <p>This SPI is intentionally small. Implementations answer whether a live core updater is
 * currently wired, start the same UI-triggered download flow that the legacy admin page expects,
 * and validate installer paths that come back from form submissions. The interface keeps those
 * live-daemon checks behind the runtime boundary while avoiding direct exposure of {@code Node},
 * updater services, or daemon-specific transport and config classes.
 *
 * <p>{@code CoreActionToadlet} continues to own request parsing, redirects, result pages, {@code
 * AppEnv} checks, and OS-specific installer or store-launching behavior. Callers typically fetch
 * the port from {@link RuntimePorts}, check availability for one request, and then invoke either a
 * download trigger or installer-path validation step.
 *
 * @see RuntimePorts#coreUpdateAction()
 */
public interface CoreUpdateActionPort {
  /**
   * Returns whether the package-based core updater is currently available.
   *
   * <p>Callers use this to preserve the legacy redirect behavior when the updater is disabled,
   * still starting up, or otherwise unavailable for the current node runtime. The result is a
   * point-in-time availability check rather than a reservation of updater resources, so callers
   * should expect a later action to remain best-effort.
   *
   * @return {@code true} when the core updater can currently accept UI-triggered actions; {@code
   *     false} when the updater service is absent or unavailable
   */
  boolean isCoreUpdaterAvailable();

  /**
   * Starts the current core-package download from the updater UI.
   *
   * <p>Implementations preserve the daemon-side selection and in-progress checks used by the legacy
   * updater flow. Callers are expected to check {@link #isCoreUpdaterAvailable()} before invoking
   * this method and to treat the call as a trigger, not as a completion signal. Follow-up status,
   * redirects, or operator-visible errors still come from the HTTP layer and the updater itself.
   */
  void startCoreDownloadFromUi();

  /**
   * Resolves one raw installer path to a canonical downloaded-installer path when it stays within
   * the legacy core-updater download area.
   *
   * <p>Implementations preserve the existing {@code <nodeDir>/updates/core} containment check and
   * return an empty result for blank, invalid, or out-of-tree inputs. The returned path is
   * canonical, detached from daemon-only file-wrapper types, and suitable for later launcher or
   * installer handling in the HTTP layer. The method validates location only; callers still handle
   * later file existence or execution failures through the normal installation flow.
   *
   * @param rawPath raw installer path string read from the HTTP request body or query data
   * @return canonical installer path when accepted; otherwise {@link Optional#empty()} for blank,
   *     malformed, or out-of-tree input
   */
  Optional<Path> resolveDownloadedInstaller(String rawPath);
}
