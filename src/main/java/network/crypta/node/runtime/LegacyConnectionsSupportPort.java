package network.crypta.node.runtime;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.runtime.spi.ConnectionsInstallerSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.support.io.FileUtil;

/**
 * Adapts the remaining connections-page support helpers behind the runtime SPI.
 *
 * <p>This bridge is intentionally narrow and transitional. It keeps the legacy add-friend installer
 * lookups, opennet-enabled check, and peer-offer file traversal inside the daemon root module while
 * exposing only JDK-only values to the HTTP connections-family toadlets.
 */
final class LegacyConnectionsSupportPort implements ConnectionsSupportPort {
  private final Node node;

  LegacyConnectionsSupportPort(Node node) {
    this.node = Objects.requireNonNull(node);
  }

  @Override
  public ConnectionsInstallerSnapshot windowsInstaller() {
    NodeUpdateManager nodeUpdater = node.services().nodeUpdater();
    return new ConnectionsInstallerSnapshot(
        NodeFile.INSTALLER_WINDOWS.getFilename(),
        nodeUpdater.getInstallerWindows(),
        nodeUpdater.getInstallerWindowsURI().toString());
  }

  @Override
  public ConnectionsInstallerSnapshot nonWindowsInstaller() {
    NodeUpdateManager nodeUpdater = node.services().nodeUpdater();
    return new ConnectionsInstallerSnapshot(
        NodeFile.INSTALLER_NON_WINDOWS.getFilename(),
        nodeUpdater.getInstallerNonWindows(),
        nodeUpdater.getInstallerNonWindowsURI().toString());
  }

  @Override
  public boolean isOpennetEnabled() {
    return node.network().isOpennetEnabled();
  }

  @Override
  public String readPeerOfferReferencesText() throws IOException {
    File[] files = node.runDir().file("peers-offers").listFiles();
    if (files == null || files.length == 0) {
      return "";
    }

    StringBuilder peerOfferReferencesText = new StringBuilder();
    for (File file : files) {
      if (file.isFile() && file.getName().endsWith(".fref")) {
        peerOfferReferencesText.append(FileUtil.readUTF(file));
      }
    }
    return peerOfferReferencesText.toString();
  }
}
