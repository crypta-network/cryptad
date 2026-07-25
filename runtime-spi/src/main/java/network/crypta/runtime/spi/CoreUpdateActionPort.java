package network.crypta.runtime.spi;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Exposes the last daemon-backed updater actions still needed by the legacy core-update toadlet.
 *
 * <p>This SPI is intentionally small. Implementations answer whether a live core updater is
 * currently wired, start the same UI-triggered download flow that the legacy admin page expects,
 * and run installer actions for paths that come back from form submissions. The interface keeps
 * those live-daemon checks behind the runtime boundary while avoiding direct exposure of {@code
 * Node}, updater services, or daemon-specific transport and config classes.
 *
 * <p>{@code CoreActionToadlet} continues to own request parsing, redirects, result pages, {@code
 * AppEnv} checks, and OS-specific installer or store-launching behavior. Callers typically fetch
 * the port from {@link RuntimePorts}, check availability for one request, and then invoke either a
 * download trigger, guarded installer action, or exact store-target validation step.
 *
 * @see RuntimePorts#coreUpdateAction()
 */
public interface CoreUpdateActionPort {
  /**
   * Performs one caller-owned action with a currently authorized downloaded installer.
   *
   * <p>The runtime invokes this action only after validating the submitted path and retains its
   * updater-selection and lifecycle authorization until the action returns. Implementations must
   * not return the installer path for later use. Callers should perform only the bounded launch
   * operation inside the callback and render responses after it returns.
   *
   * @param <T> action result returned to the caller after authorization is released
   */
  @FunctionalInterface
  interface InstallerAction<T> {
    /**
     * Executes the bounded installer launch operation.
     *
     * @param installer canonical installer path retained under runtime authorization
     * @return non-null launch outcome for later response rendering
     */
    T execute(Path installer);
  }

  /**
   * Returns the last locally verified Stable 1.0 build-support lifecycle snapshot.
   *
   * <p>The default keeps older or partial runtime adapters fail-closed: it reports unknown rather
   * than inferring support from the current build or ordinary update availability. Full daemon
   * adapters should override this method with their persisted last-known-good lifecycle view.
   *
   * @return public-safe lifecycle snapshot suitable for Platform API and operator diagnostics
   */
  default CoreSupportLifecycleSnapshot supportLifecycleSnapshot() {
    return CoreSupportLifecycleSnapshot.unknown(-1, java.util.List.of("lifecycle_unavailable"));
  }

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
   * Returns whether a selectable core update is currently available for UI-triggered download.
   *
   * <p>This is narrower than {@link #isCoreUpdaterAvailable()}: the updater service may be wired
   * and ready while no newer package currently matches the running platform or release gate.
   * Callers use this to decide whether a download action should be offered for the current request.
   *
   * @return {@code true} when the updater currently has a newer selectable core package; {@code
   *     false} when no UI-downloadable package is presently available
   */
  boolean isCoreDownloadAvailable();

  /**
   * Starts the current core-package download from the updater UI.
   *
   * <p>Implementations preserve the daemon-side selection and in-progress checks used by the legacy
   * updater flow. Callers may invoke this method directly for one download request, so the updater
   * lookup and the download trigger uses the same daemon snapshot instead of being split across two
   * separate calls. The method remains a trigger rather than a completion signal; follow-up status,
   * redirects, or operator-visible errors still come from the HTTP layer and the updater itself.
   */
  boolean startCoreDownloadFromUi();

  /**
   * Validates a submitted package-store handoff against the daemon's current update selection.
   *
   * <p>The default is fail-closed so partial runtime adapters cannot authorize a client-supplied
   * store target. Full daemon adapters must require an exact match for the selected package kind,
   * derived package identifier, and public store URL, and must recheck the selected build's
   * lifecycle revocation state at submission time.
   *
   * @param kind package-store kind submitted by the updater form
   * @param id package identifier submitted by the updater form, or an empty string when absent
   * @param url public store URL submitted by the updater form, or an empty string when absent
   * @return {@code true} only when the submitted target is still the exact selectable, non-revoked
   *     daemon update target
   */
  default boolean isCurrentStoreTarget(String kind, String id, String url) {
    return false;
  }

  /**
   * Executes an installer action while the submitted package remains the authorized selection.
   *
   * <p>Implementations preserve the existing {@code <nodeDir>/updates/core} containment check and
   * return an empty result for blank, invalid, out-of-tree, superseded, lifecycle-revoked, or
   * update-key-invalidated inputs. Selection, updater-scope, and lifecycle authorization must
   * remain held through {@link InstallerAction#execute(Path)} so a concurrently revoked or
   * superseded package cannot be launched through a detached path.
   *
   * @param rawPath raw installer path string read from the HTTP request body or query data
   * @param action bounded launch action to invoke with the canonical authorized installer
   * @param <T> non-null launch outcome type
   * @return action outcome when the package stayed authorized through launch; otherwise {@link
   *     Optional#empty()}
   */
  <T> Optional<T> withDownloadedInstaller(String rawPath, InstallerAction<T> action);
}
