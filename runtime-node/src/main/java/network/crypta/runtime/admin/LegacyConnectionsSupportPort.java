package network.crypta.runtime.admin;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;
import network.crypta.runtime.spi.ConnectionsInstallerSnapshot;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.updater.NodeUpdateManager;
import network.crypta.support.io.FileUtil;

/**
 * Adapts the remaining connections-page support helpers behind the runtime SPI.
 *
 * <p>This bridge is intentionally narrow and transitional. It keeps the legacy add-friend installer
 * lookups, opennet-enabled check, peer-offer file traversal, and noderef text loading inside the
 * daemon root module while exposing only JDK-only values to the HTTP connections-family toadlets.
 */
final class LegacyConnectionsSupportPort implements ConnectionsSupportPort {
  private final Node node;
  private final HighLevelSimpleClient peerReferenceClient;

  LegacyConnectionsSupportPort(Node node, HighLevelSimpleClient peerReferenceClient) {
    this.node = Objects.requireNonNull(node);
    this.peerReferenceClient = Objects.requireNonNull(peerReferenceClient);
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

  @Override
  public StringBuilder readPeerReferenceText(String locationText) throws IOException {
    try {
      FreenetURI freenetURI = new FreenetURI(locationText);
      return readFromFreenetUriOrUrl(freenetURI, locationText);
    } catch (MalformedURLException _) {
      return readFromUrl(locationText);
    }
  }

  private StringBuilder readFromFreenetUriOrUrl(FreenetURI freenetURI, String locationText)
      throws IOException {
    try {
      return PeerReferenceTextLoader.readFromFreenetUri(freenetURI, peerReferenceClient);
    } catch (FetchException _) {
      return readFromUrl(locationText);
    }
  }

  private static StringBuilder readFromUrl(String locationText) throws IOException {
    return PeerReferenceTextLoader.readFromUrl(buildUrl(locationText));
  }

  private static URL buildUrl(String locationText) throws MalformedURLException {
    try {
      return URI.create(locationText).toURL();
    } catch (IllegalArgumentException e) {
      MalformedURLException malformedURLException = new MalformedURLException(e.getMessage());
      malformedURLException.initCause(e);
      throw malformedURLException;
    }
  }
}
