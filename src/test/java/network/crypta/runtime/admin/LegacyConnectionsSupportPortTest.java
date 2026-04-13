package network.crypta.runtime.admin;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.peers.reference.PeerReferenceTextLoader;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.runtime.spi.ConnectionsInstallerSnapshot;
import network.crypta.runtime.updater.NodeUpdateManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyConnectionsSupportPortTest {

  @Mock private Node node;
  @Mock private NodeServicesSubsystem services;
  @Mock private NodeUpdateManager nodeUpdater;
  @Mock private HighLevelSimpleClient peerReferenceClient;

  @TempDir private Path tempDir;

  private LegacyConnectionsSupportPort port;

  @BeforeEach
  void setUp() {
    lenient().when(node.services()).thenReturn(services);
    lenient().when(services.nodeUpdater()).thenReturn(nodeUpdater);
    port = new LegacyConnectionsSupportPort(node, peerReferenceClient);
  }

  @Test
  void windowsInstaller_whenQueried_returnsFilenameLocalFileAndFallbackSourceText()
      throws Exception {
    File installer =
        Files.createFile(tempDir.resolve("freenet-latest-installer-windows.exe")).toFile();
    FreenetURI installerUri = new FreenetURI("CHK", "win");
    when(nodeUpdater.getInstallerWindows()).thenReturn(installer);
    when(nodeUpdater.getInstallerWindowsURI()).thenReturn(installerUri);

    ConnectionsInstallerSnapshot snapshot = port.windowsInstaller();

    assertEquals(NodeFile.INSTALLER_WINDOWS.getFilename(), snapshot.filename());
    assertSame(installer, snapshot.localFile());
    assertEquals(installerUri.toString(), snapshot.sourceUriText());
  }

  @Test
  void nonWindowsInstaller_whenLocalFileMissing_returnsFallbackSnapshot() {
    FreenetURI installerUri = new FreenetURI("CHK", "unix");
    when(nodeUpdater.getInstallerNonWindows()).thenReturn(null);
    when(nodeUpdater.getInstallerNonWindowsURI()).thenReturn(installerUri);

    ConnectionsInstallerSnapshot snapshot = port.nonWindowsInstaller();

    assertEquals(NodeFile.INSTALLER_NON_WINDOWS.getFilename(), snapshot.filename());
    assertNull(snapshot.localFile());
    assertEquals(installerUri.toString(), snapshot.sourceUriText());
  }

  @Test
  void isOpennetEnabled_whenQueried_delegatesToNetworkSubsystem() {
    NodeNetworkSubsystem network = org.mockito.Mockito.mock(NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.isOpennetEnabled()).thenReturn(true).thenReturn(false);

    assertTrue(port.isOpennetEnabled());
    assertFalse(port.isOpennetEnabled());
  }

  @Test
  void readPeerOfferReferencesText_whenPeersOffersDirectoryMissingOrEmpty_returnsEmptyString()
      throws Exception {
    stubRunDir();

    assertEquals("", port.readPeerOfferReferencesText());

    Files.createDirectories(tempDir.resolve("peers-offers"));

    assertEquals("", port.readPeerOfferReferencesText());
  }

  @Test
  void readPeerOfferReferencesText_whenFrefFilesPresent_readsAndConcatenatesMatchesOnly()
      throws Exception {
    stubRunDir();
    Path peersOffersDir = Files.createDirectories(tempDir.resolve("peers-offers"));
    Files.writeString(
        peersOffersDir.resolve("offer-a.fref"),
        "identity=alpha\nlastGoodVersion=1\nEnd\n",
        StandardCharsets.UTF_8);
    Files.writeString(
        peersOffersDir.resolve("ignored.txt"),
        "identity=ignored\nlastGoodVersion=9\nEnd\n",
        StandardCharsets.UTF_8);
    Files.writeString(
        peersOffersDir.resolve("offer-b.fref"),
        "identity=beta\nlastGoodVersion=2\nEnd\n",
        StandardCharsets.UTF_8);

    String actual = port.readPeerOfferReferencesText();

    File[] encounteredFiles = peersOffersDir.toFile().listFiles();
    assertNotNull(encounteredFiles);
    StringBuilder expected = new StringBuilder();
    for (File file : encounteredFiles) {
      if (file.isFile() && file.getName().endsWith(".fref")) {
        expected.append(Files.readString(file.toPath(), StandardCharsets.UTF_8));
      }
    }

    assertEquals(expected.toString(), actual);
    assertFalse(actual.contains("ignored"));
  }

  @Test
  void readPeerReferenceText_whenFreenetUriLoadSucceeds_returnsFreenetText() throws Exception {
    FreenetURI uri = new FreenetURI("KSK@peer-reference");
    StringBuilder expected = new StringBuilder();
    expected.append("freenet-line-1\n").append("freenet-line-2\n");

    try (MockedStatic<PeerReferenceTextLoader> mocked = mockStatic(PeerReferenceTextLoader.class)) {
      mocked
          .when(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, peerReferenceClient))
          .thenReturn(expected);

      StringBuilder actual = port.readPeerReferenceText(uri.toString());

      assertSame(expected, actual);
      mocked.verify(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, peerReferenceClient));
      mocked.verifyNoMoreInteractions();
    }
  }

  @Test
  void readPeerReferenceText_whenFreenetFetchFails_fallsBackToUrlLoader() throws Exception {
    String locationText = "https://example.invalid/KSK@peer-reference";
    FreenetURI uri = new FreenetURI(locationText);
    URL url = URI.create(locationText).toURL();
    StringBuilder expected = new StringBuilder();
    expected.append("url-line-1\n").append("url-line-2\n");

    try (MockedStatic<PeerReferenceTextLoader> mocked = mockStatic(PeerReferenceTextLoader.class)) {
      mocked
          .when(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, peerReferenceClient))
          .thenThrow(new FetchException(FetchExceptionMode.DATA_NOT_FOUND));
      mocked.when(() -> PeerReferenceTextLoader.readFromUrl(url)).thenReturn(expected);

      StringBuilder actual = port.readPeerReferenceText(locationText);

      assertSame(expected, actual);
      mocked.verify(() -> PeerReferenceTextLoader.readFromFreenetUri(uri, peerReferenceClient));
      mocked.verify(() -> PeerReferenceTextLoader.readFromUrl(url));
      mocked.verifyNoMoreInteractions();
    }
  }

  @Test
  void readPeerReferenceText_whenFreenetUriParsingFails_fallsBackToUrlLoader() throws Exception {
    URL url = tempDir.resolve("peer-reference.txt").toUri().toURL();
    StringBuilder expected = new StringBuilder();
    expected.append("url-line-1\n").append("url-line-2\n");

    try (MockedStatic<PeerReferenceTextLoader> mocked = mockStatic(PeerReferenceTextLoader.class)) {
      mocked.when(() -> PeerReferenceTextLoader.readFromUrl(url)).thenReturn(expected);

      StringBuilder actual = port.readPeerReferenceText(url.toExternalForm());

      assertSame(expected, actual);
      mocked.verify(() -> PeerReferenceTextLoader.readFromUrl(url));
      mocked.verifyNoMoreInteractions();
    }
  }

  @Test
  void readPeerReferenceText_whenUrlReadFails_propagatesIOException() throws Exception {
    URL url = tempDir.resolve("peer-reference.txt").toUri().toURL();

    try (MockedStatic<PeerReferenceTextLoader> mocked = mockStatic(PeerReferenceTextLoader.class)) {
      mocked
          .when(() -> PeerReferenceTextLoader.readFromUrl(url))
          .thenThrow(new IOException("boom"));

      IOException exception =
          assertThrows(IOException.class, () -> port.readPeerReferenceText(url.toExternalForm()));

      assertEquals("boom", exception.getMessage());
      mocked.verify(() -> PeerReferenceTextLoader.readFromUrl(url));
      mocked.verifyNoMoreInteractions();
    }
  }

  private void stubRunDir() throws Exception {
    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    when(node.runDir()).thenReturn(runDir);
  }
}
