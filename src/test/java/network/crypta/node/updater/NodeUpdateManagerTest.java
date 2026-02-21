package network.crypta.node.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.Config;
import network.crypta.io.comm.Message;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeFile;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerMessenger;
import network.crypta.node.PeerNode;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.Version;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class NodeUpdateManagerTest {

  @TempDir Path tempDir;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock NodeClientCore nodeCore;
  @Mock UserAlertManager alerts;
  @Mock PeerManager peerManager;
  @Mock PeerMessenger peerMessenger;
  @Mock NodeStats nodeStats;

  private NodeUpdateManager manager;

  @BeforeEach
  void setUp() throws Exception {
    // Prepare filesystem roots used by NodeFile helpers and RevocationChecker
    File persistentTmpDir = tempDir.resolve("persistTmp").toFile();
    assertTrue(persistentTmpDir.mkdirs() || persistentTmpDir.exists());

    File runDir = tempDir.resolve("run").toFile();
    assertTrue(runDir.mkdirs() || runDir.exists());
    ProgramDirectory runProgramDir = new ProgramDirectory();
    runProgramDir.move(runDir.getAbsolutePath());

    // Wire minimal node surface for the manager
    when(node.services().clientCore()).thenReturn(nodeCore);
    when(nodeCore.getPersistentTempDir()).thenReturn(persistentTmpDir);
    when(nodeCore.getAlerts()).thenReturn(alerts);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.messenger()).thenReturn(peerMessenger);
    when(node.network().stats()).thenReturn(nodeStats);

    // Provide values read when building announcements
    when(nodeStats.getNodeAveragePingTime()).thenReturn(100.0);
    when(nodeStats.getBwlimitDelayTime()).thenReturn(5.0);

    // NodeFile lookups for installers use runDir()
    when(node.runDir()).thenReturn(runProgramDir);

    // Minimal fetch context for RevocationChecker construction
    HighLevelSimpleClient hlsc = Mockito.mock(HighLevelSimpleClient.class);
    FetchContext fctx = getFetchContext();
    when(nodeCore.makeClient(Mockito.anyShort(), Mockito.anyBoolean(), Mockito.anyBoolean()))
        .thenReturn(hlsc);
    when(hlsc.getFetchContext()).thenReturn(fctx);
    ClientContext clientContext = Mockito.mock(ClientContext.class);
    when(nodeCore.getClientContext()).thenReturn(clientContext);

    manager = new NodeUpdateManager(node, new Config());
  }

  private static @NotNull FetchContext getFetchContext() {
    SimpleEventProducer ep = new SimpleEventProducer();
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(Long.MAX_VALUE, Long.MAX_VALUE, 1024 * 1024)
            .archiveLimits(1, 1, 1, false)
            .retryLimits(0, 0, 0)
            .splitfileLimits(true, 1, 1)
            .behavior(true, false, false)
            .clientOptions(ep, false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  @Test
  void isEnabled_initiallyFalse_thenStartCoreUpdater_true() {
    // Arrange + Act
    // Assert initial state
    assertFalse(manager.isEnabled());

    // Act: start core updater explicitly without going through enable(true)
    manager.startCoreUpdater();

    // Assert
    assertTrue(manager.isEnabled());
    assertNotNull(manager.getCoreUpdater());
  }

  // CHK preference path requires CoreUpdater state; fallback is exercised below.

  @Test
  void addChangelogLinks_withoutCoreCHKs_expectFallbackToSSKLinks() {
    // Arrange: coreUpdater stays null → fallback paths
    HTMLNode root = new HTMLNode("div");
    long version = 7L;
    String changelogSsk =
        manager.getChangelogURI().setSuggestedEdition(version).sskForUSK().toASCIIString();
    String devSsk =
        manager.getDeveloperChangelogURI().setSuggestedEdition(version).sskForUSK().toASCIIString();

    // Act
    manager.addChangelogLinks(version, root);

    // Assert: two anchors with SSK hrefs
    long anchorCount = root.getChildren().stream().filter(n -> "a".equals(n.getName())).count();
    assertEquals(2, anchorCount);
    HTMLNode first =
        root.getChildren().stream().filter(n -> "a".equals(n.getName())).findFirst().orElseThrow();
    HTMLNode last =
        root.getChildren().stream()
            .filter(n -> "a".equals(n.getName()))
            .reduce((_, b) -> b)
            .orElseThrow();
    assertEquals('/' + changelogSsk + "?type=text/plain", first.getAttributes().get("href"));
    assertEquals('/' + devSsk + "?type=text/plain", last.getAttributes().get("href"));
  }

  @Test
  void setURI_whenDifferentAndCoreUpdaterPresent_expectNoException_andUriUpdated() {
    // Arrange
    FreenetURI newUri = manager.getURI().setDocName("newdoc");

    // Act
    manager.setURI(newUri);

    // Assert: the update URI reflects the new docname and current build
    assertEquals(
        newUri.setSuggestedEdition(Version.currentBuildNumber()).toString(false, false),
        manager.getURI().toString(false, false));
  }

  @Test
  void getInstallerFiles_whenMissingOrPresent_expectNullOrFile() throws Exception {
    // Arrange: ensure a clean state
    File winFile = NodeFile.INSTALLER_WINDOWS.getFile(node);
    Files.deleteIfExists(winFile.toPath());
    File nonWinFile = NodeFile.INSTALLER_NON_WINDOWS.getFile(node);
    Files.deleteIfExists(nonWinFile.toPath());

    // Act + Assert: missing → null
    assertNull(manager.getInstallerWindows());
    assertNull(manager.getInstallerNonWindows());

    // Create non-empty files and assert non-null
    try (FileOutputStream fos = new FileOutputStream(winFile)) {
      fos.write(1);
    }
    try (FileOutputStream fos = new FileOutputStream(nonWinFile)) {
      fos.write(1);
    }

    assertNotNull(manager.getInstallerWindows());
    assertNotNull(manager.getInstallerNonWindows());
  }

  @Test
  void blow_whenCalled_expectHasBeenBlownTrue_andBroadcast() {
    // Act
    manager.blow("revoked", false);

    // Assert state
    assertTrue(manager.isBlown());

    // Announcement broadcasted via PeerManager
    verify(peerMessenger, times(1))
        .localBroadcast(
            any(Message.class),
            eq(true),
            eq(true),
            same(manager.getByteCounter()),
            eq(NodeUpdateManager.TRANSITION_VERSION),
            eq(Integer.MAX_VALUE));

    // A user alert should be registered
    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);
    verify(alerts, times(1)).register(alertCaptor.capture());
    assertNotNull(alertCaptor.getValue());
  }

  @Test
  void maybeSendUOMAnnounce_whenNothingToAnnounce_expectNoSend() {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    when(peer.getNodeName()).thenReturn("Cryptad");
    when(peer.getBuildNumber()).thenReturn(Version.currentBuildNumber());
    // Do not call blow() or broadcastUOMAnnounces(), so nothing should be sent.

    // Act
    manager.maybeSendUOMAnnounce(peer);

    // Assert
    verifyNoInteractions(peer);
  }

  // --- helpers (none) ---
}
