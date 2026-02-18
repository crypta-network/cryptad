package network.crypta.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerPersistenceTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeNetworkSubsystem network;
  @Mock private PeerManager peerManager;
  @Mock private Ticker ticker;

  @Test
  void scheduleInitialWrite_whenCalled_queuesImmediateJob() {
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    PeerPersistence persistence = new PeerPersistence(node, peerManager);

    persistence.scheduleInitialWrite();

    verify(ticker).queueTimedJob(any(Runnable.class), eq(0L));
  }

  @Test
  void writePeersUrgent_whenDarknetMarked_rotatesAndWrites(@TempDir Path tempDir)
      throws IOException {
    Path darknetFile = tempDir.resolve("darknet.peers");
    Files.writeString(darknetFile, "", StandardCharsets.UTF_8);

    PeerPersistence persistence = new PeerPersistence(node, peerManager);

    NodeCrypto crypto = org.mockito.Mockito.mock(NodeCrypto.class);
    persistence.tryReadPeers(darknetFile.toString(), crypto, null, false, false);

    DarknetPeerNode darknetPeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    SimpleFieldSet newFieldSet = simpleFieldSet("new-peer");
    when(darknetPeer.exportDiskFieldSet()).thenReturn(newFieldSet);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {darknetPeer});

    network.crypta.support.PriorityAwareExecutor executor =
        org.mockito.Mockito.mock(network.crypta.support.PriorityAwareExecutor.class);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);

    persistence.writePeers(false);
    persistence.writePeersUrgent(false);

    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).execute(runnableCaptor.capture());
    runnableCaptor.getValue().run();

    Path backupFile = tempDir.resolve("darknet.peers.bak");
    assertAll(
        () ->
            assertEquals(
                newFieldSet.toOrderedString(),
                Files.readString(darknetFile, StandardCharsets.UTF_8)),
        () -> assertTrue(Files.exists(backupFile)),
        () -> assertEquals("", Files.readString(backupFile, StandardCharsets.UTF_8)));
  }

  @Test
  void flushOnShutdown_whenCalled_writesDarknetAndOpennetWithoutRotation(@TempDir Path tempDir)
      throws IOException {
    Path darknetFile = tempDir.resolve("darknet.peers");
    Path opennetFile = tempDir.resolve("opennet.peers");
    Path darknetBackup = tempDir.resolve("darknet.peers.bak");
    Path opennetBackup = tempDir.resolve("opennet.peers.bak");
    Files.writeString(darknetFile, "", StandardCharsets.UTF_8);
    Files.writeString(opennetFile, "", StandardCharsets.UTF_8);
    Files.writeString(darknetBackup, "keep-darknet\n", StandardCharsets.UTF_8);
    Files.writeString(opennetBackup, "keep-opennet\n", StandardCharsets.UTF_8);

    PeerPersistence persistence = new PeerPersistence(node, peerManager);
    NodeCrypto crypto = org.mockito.Mockito.mock(NodeCrypto.class);
    persistence.tryReadPeers(darknetFile.toString(), crypto, null, false, false);
    persistence.tryReadPeers(opennetFile.toString(), crypto, null, true, false);

    DarknetPeerNode darknetPeer = org.mockito.Mockito.mock(DarknetPeerNode.class);
    OpennetPeerNode opennetPeer = org.mockito.Mockito.mock(OpennetPeerNode.class);
    SimpleFieldSet darknetFieldSet = simpleFieldSet("darknet");
    SimpleFieldSet opennetFieldSet = simpleFieldSet("opennet");
    when(darknetPeer.exportDiskFieldSet()).thenReturn(darknetFieldSet);
    when(opennetPeer.exportDiskFieldSet()).thenReturn(opennetFieldSet);
    when(peerManager.myPeers()).thenReturn(new PeerNode[] {darknetPeer, opennetPeer});

    OpennetManager opennetManager = org.mockito.Mockito.mock(OpennetManager.class);
    Path oldOpennetFile = tempDir.resolve("old-opennet.peers");
    when(opennetManager.getOldPeersFilename()).thenReturn(oldOpennetFile.toString());
    when(opennetManager.getOldPeers()).thenReturn(new OpennetPeerNode[] {opennetPeer});
    when(node.network().opennet()).thenReturn(opennetManager);

    persistence.flushOnShutdown();

    assertAll(
        () ->
            assertEquals(
                darknetFieldSet.toOrderedString(),
                Files.readString(darknetFile, StandardCharsets.UTF_8)),
        () ->
            assertEquals(
                opennetFieldSet.toOrderedString(),
                Files.readString(opennetFile, StandardCharsets.UTF_8)),
        () ->
            assertEquals(
                opennetFieldSet.toOrderedString(),
                Files.readString(oldOpennetFile, StandardCharsets.UTF_8)),
        () ->
            assertEquals("keep-darknet\n", Files.readString(darknetBackup, StandardCharsets.UTF_8)),
        () ->
            assertEquals(
                "keep-opennet\n", Files.readString(opennetBackup, StandardCharsets.UTF_8)));
  }

  @Test
  void flushOnShutdown_whenOldOpennetPeersArrayIsEmpty_writesEmptyOldOpennetFile(
      @TempDir Path tempDir) {
    when(node.network()).thenReturn(network);

    OpennetManager opennetManager = org.mockito.Mockito.mock(OpennetManager.class);
    Path oldOpennetFile = tempDir.resolve("old-opennet.peers");
    when(opennetManager.getOldPeersFilename()).thenReturn(oldOpennetFile.toString());
    when(opennetManager.getOldPeers()).thenReturn(new OpennetPeerNode[0]);
    when(network.opennet()).thenReturn(opennetManager);

    PeerPersistence persistence = new PeerPersistence(node, peerManager);

    persistence.flushOnShutdown();

    assertAll(
        () -> assertTrue(Files.exists(oldOpennetFile)),
        () -> assertEquals("", Files.readString(oldOpennetFile, StandardCharsets.UTF_8)));
  }

  @Test
  void tryReadPeers_whenOldOpennetPeers_addsOldOpennetNode(@TempDir Path tempDir) throws Exception {
    Path opennetFile = tempDir.resolve("opennet.peers");
    SimpleFieldSet peerFieldSet = simpleFieldSet("peer");
    Files.writeString(opennetFile, peerFieldSet.toOrderedString(), StandardCharsets.UTF_8);

    PeerPersistence persistence = new PeerPersistence(node, peerManager);
    NodeCrypto crypto = org.mockito.Mockito.mock(NodeCrypto.class);

    OpennetManager opennetManager = org.mockito.Mockito.mock(OpennetManager.class);
    OpennetPeerNode opennetPeer = org.mockito.Mockito.mock(OpennetPeerNode.class);
    PeerPersistence spyPersistence = org.mockito.Mockito.spy(persistence);
    org.mockito.Mockito.doReturn(opennetPeer)
        .when(spyPersistence)
        .createPeerNode(any(SimpleFieldSet.class), eq(crypto), eq(opennetManager));

    spyPersistence.tryReadPeers(opennetFile.toString(), crypto, opennetManager, true, true);

    verify(opennetManager).addOldOpennetNode(opennetPeer);
  }

  @Test
  void tryReadPeers_whenPeerParseFails_createsBrokenCopy(@TempDir Path tempDir) throws Exception {
    Path opennetFile = tempDir.resolve("opennet.peers");
    SimpleFieldSet peerFieldSet = simpleFieldSet("peer");
    String peerContent = peerFieldSet.toOrderedString();
    Files.writeString(opennetFile, peerContent, StandardCharsets.UTF_8);

    PeerPersistence persistence = new PeerPersistence(node, peerManager);
    NodeCrypto crypto = org.mockito.Mockito.mock(NodeCrypto.class);

    OpennetManager opennetManager = org.mockito.Mockito.mock(OpennetManager.class);
    PeerPersistence spyPersistence = org.mockito.Mockito.spy(persistence);
    org.mockito.Mockito.doThrow(new network.crypta.io.comm.PeerParseException("bad"))
        .when(spyPersistence)
        .createPeerNode(any(SimpleFieldSet.class), eq(crypto), eq(opennetManager));

    spyPersistence.tryReadPeers(opennetFile.toString(), crypto, opennetManager, true, false);

    Path brokenFile = tempDir.resolve("opennet.peers.broken");
    assertAll(
        () -> assertTrue(Files.exists(brokenFile)),
        () -> assertEquals(peerContent, Files.readString(brokenFile, StandardCharsets.UTF_8)));
  }

  private static SimpleFieldSet simpleFieldSet(String name) {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("myName", name);
    return fieldSet;
  }
}
