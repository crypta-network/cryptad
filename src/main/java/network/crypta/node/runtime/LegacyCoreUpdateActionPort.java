package network.crypta.node.runtime;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import network.crypta.node.Node;
import network.crypta.node.updater.CoreUpdater;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.runtime.spi.CoreUpdateActionPort;

/**
 * Adapts the core-update action SPI to the legacy daemon runtime.
 *
 * <p>This adapter bridges {@link CoreUpdateActionPort} back to the current daemon implementation
 * without letting HTTP-layer code depend on {@link Node}, {@link NodeUpdateManager}, or {@link
 * CoreUpdater}. It preserves the legacy behavior that matters to the admin shell: availability
 * depends on whether a live core updater service is wired, UI download requests delegate to {@code
 * startDownloadFromUI()}, and installer validation accepts only canonical paths beneath the node's
 * {@code updates/core} directory.
 *
 * <p>The adapter does not launch installers, open stores, or interpret HTTP results. Those
 * operator-visible choices remain inside the toadlet, which means this class stays focused on
 * daemon lookups and filesystem containment checks.
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
  public void startCoreDownloadFromUi() {
    getCoreUpdater().ifPresent(CoreUpdater::startDownloadFromUI);
  }

  @Override
  public Optional<Path> resolveDownloadedInstaller(String rawPath) {
    if (rawPath == null || rawPath.isBlank()) {
      return Optional.empty();
    }

    try {
      File base = new File(node.getNodeDir(), CORE_UPDATE_DIRECTORY).getCanonicalFile();
      File candidate = new File(rawPath).getCanonicalFile();
      Path candidatePath = candidate.toPath();
      return candidatePath.startsWith(base.toPath())
          ? Optional.of(candidatePath)
          : Optional.empty();
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
