package network.crypta.node.runtime;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyConnectionsSupportPortTest {

  @Mock private Node node;

  @TempDir private Path tempDir;

  private LegacyConnectionsSupportPort port;

  @BeforeEach
  void setUp() {
    port = new LegacyConnectionsSupportPort(node);
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

  private void stubRunDir() throws Exception {
    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    when(node.runDir()).thenReturn(runDir);
  }
}
