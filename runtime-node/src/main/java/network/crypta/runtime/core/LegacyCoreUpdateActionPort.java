package network.crypta.runtime.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import network.crypta.node.Node;
import network.crypta.node.Version;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.updater.CoreUpdater;
import network.crypta.runtime.updater.NodeUpdateManager;

/**
 * Adapts the core-update action SPI to the legacy daemon runtime.
 *
 * <p>This adapter bridges {@link CoreUpdateActionPort} back to the current daemon implementation
 * without letting HTTP-layer code depend on {@link Node}, {@link NodeUpdateManager}, or {@link
 * CoreUpdater}. It preserves the legacy behavior that matters to the admin shell: availability
 * depends on whether a live core updater service is wired, UI download requests delegate to {@code
 * startDownloadFromUI()}, and installer actions accept only canonical paths beneath the node's
 * {@code updates/core} directory.
 *
 * <p>The adapter does not choose how to launch installers, open stores, or interpret HTTP results.
 * Those operator-visible choices remain inside the toadlet, while the supplied installer action
 * executes before the daemon releases its selection and lifecycle authorization.
 */
final class LegacyCoreUpdateActionPort implements CoreUpdateActionPort {
  private static final String CORE_UPDATE_DIRECTORY = "updates/core";

  private final Node node;

  /**
   * Creates an adapter bound to one live node instance.
   *
   * <p>The adapter resolves updater availability from the node services layer each time a caller
   * asks for it, so it follows current daemon wiring instead of caching updater objects across
   * requests.
   *
   * @param node live node that owns updater services and the node-directory layout
   */
  LegacyCoreUpdateActionPort(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  @Override
  public boolean isCoreUpdaterAvailable() {
    return getCoreUpdater().isPresent();
  }

  @Override
  public boolean isCoreDownloadAvailable() {
    return getCoreUpdater().map(CoreUpdater::isUiDownloadAvailable).orElse(false);
  }

  @Override
  public boolean startCoreDownloadFromUi() {
    return getCoreUpdater().map(CoreUpdater::startDownloadFromUI).orElse(false);
  }

  @Override
  public boolean isCurrentStoreTarget(String kind, String id, String url) {
    return getCoreUpdater()
        .map(updater -> updater.isCurrentStoreTarget(kind, id, url))
        .orElse(false);
  }

  @Override
  public CoreSupportLifecycleSnapshot supportLifecycleSnapshot() {
    NodeUpdateManager manager = node.services().nodeUpdater();
    return manager == null
        ? CoreSupportLifecycleSnapshot.unknown(
            Version.currentBuildNumber(), List.of("lifecycle_updater_unavailable"))
        : manager.supportLifecycleSnapshot();
  }

  @Override
  public <T> Optional<T> withDownloadedInstaller(String rawPath, InstallerAction<T> action) {
    Objects.requireNonNull(action, "action");
    if (rawPath == null || rawPath.isBlank()) {
      return Optional.empty();
    }

    try {
      File base = new File(node.getNodeDir(), CORE_UPDATE_DIRECTORY).getCanonicalFile();
      File candidate = new File(rawPath).getCanonicalFile();
      Path candidatePath = candidate.toPath();
      if (!candidatePath.startsWith(base.toPath())) {
        return Optional.empty();
      }
      return getCoreUpdater()
          .flatMap(
              updater ->
                  updater.withDownloadedInstaller(
                      candidate, installer -> action.execute(installer.toPath())));
    } catch (IOException _) {
      return Optional.empty();
    }
  }

  private Optional<CoreUpdater> getCoreUpdater() {
    NodeUpdateManager nodeUpdateManager = node.services().nodeUpdater();
    return nodeUpdateManager == null
        ? Optional.empty()
        : Optional.ofNullable(nodeUpdateManager.getCoreUpdater());
  }
}
