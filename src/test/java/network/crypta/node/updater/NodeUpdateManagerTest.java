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
import network.crypta.config.PersistentConfig;
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
import network.crypta.support.SimpleFieldSet;
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
  private Config config;
  private static final String DEFAULT_FETCHED_SCOPE =
      "USK@" + NodeUpdateManager.UPDATE_URI + "/info/0";

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

    config = new Config();
    manager = new NodeUpdateManager(node, config);
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
  void updateUriCallback_whenGivenPublicKeyOnly_expectExpandedToUskInfoUri() throws Exception {
    // Arrange
    NodeUpdateManager.UpdateURICallback callback = manager.new UpdateURICallback();

    // Act
    callback.set(NodeUpdateManager.UPDATE_URI);

    // Assert
    String expected =
        "USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + Version.currentBuildNumber();
    assertEquals(expected, manager.getURI().toString(false, false));
  }

  @Test
  void revocationUriCallback_whenGivenPublicKeyOnly_expectExpandedToSskRevokedUri()
      throws Exception {
    // Arrange
    NodeUpdateManager.UpdateRevocationURICallback callback =
        manager.new UpdateRevocationURICallback();

    // Act
    callback.set(NodeUpdateManager.REVOCATION_URI);

    // Assert
    String expected = "SSK@" + NodeUpdateManager.REVOCATION_URI + "/revoked";
    assertEquals(expected, manager.getRevocationURI().toString(false, false));
  }

  @Test
  void uriCallbacks_get_expectPublicKeyOnly() {
    // Arrange
    NodeUpdateManager.UpdateURICallback updateCallback = manager.new UpdateURICallback();
    NodeUpdateManager.UpdateRevocationURICallback revocationCallback =
        manager.new UpdateRevocationURICallback();

    // Act + Assert
    assertEquals(NodeUpdateManager.UPDATE_URI, updateCallback.get());
    assertEquals(NodeUpdateManager.REVOCATION_URI, revocationCallback.get());
  }

  @Test
  void revocationUriCallback_get_whenCustomDocName_expectFullUriPreserved() throws Exception {
    // Arrange
    NodeUpdateManager.UpdateRevocationURICallback revocationCallback =
        manager.new UpdateRevocationURICallback();
    String customUri = "SSK@" + NodeUpdateManager.REVOCATION_URI + "/custom-revocation-doc";

    // Act
    manager.setRevocationURI(new FreenetURI(customUri));

    // Assert
    assertEquals(customUri, revocationCallback.get());
  }

  @Test
  void updateUriCallback_get_whenCustomDocName_expectFullUriPreserved() throws Exception {
    // Arrange
    NodeUpdateManager.UpdateURICallback updateCallback = manager.new UpdateURICallback();
    String customUri =
        "USK@"
            + NodeUpdateManager.UPDATE_URI
            + "/custom-update-doc/"
            + Version.currentBuildNumber();

    // Act
    manager.setURI(new FreenetURI(customUri));

    // Assert
    assertEquals(customUri, updateCallback.get());
  }

  @Test
  void constructor_whenLegacyFullUrisPersisted_expectAcceptedAndCanonicalizedToBareKeys()
      throws Exception {
    // Arrange
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.putSingle("node.updater.URI", "USK@" + NodeUpdateManager.UPDATE_URI + "/jar/1481");
    persisted.putSingle(
        "node.updater.revocationURI", "SSK@" + NodeUpdateManager.REVOCATION_URI + "/revoked");
    PersistentConfig persistedConfig = new PersistentConfig(persisted);

    // Act
    NodeUpdateManager migrated = new NodeUpdateManager(node, persistedConfig);

    // Assert: updater URI uses the current build and default info docname
    String expectedUpdate =
        "USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + Version.currentBuildNumber();
    assertEquals(expectedUpdate, migrated.getURI().toString(false, false));
    assertEquals(
        "SSK@" + NodeUpdateManager.REVOCATION_URI + "/revoked",
        migrated.getRevocationURI().toString(false, false));

    // Assert: persisted option values are canonical bare keys after migration
    assertEquals(
        NodeUpdateManager.UPDATE_URI, persistedConfig.get("node.updater").getString("URI"));
    assertEquals(
        NodeUpdateManager.REVOCATION_URI,
        persistedConfig.get("node.updater").getString("revocationURI"));
  }

  @Test
  void constructor_whenCustomRevocationUriPersisted_expectCustomValuePreserved() throws Exception {
    // Arrange
    String customUri = "SSK@" + NodeUpdateManager.REVOCATION_URI + "/custom-revocation-doc";
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.putSingle("node.updater.URI", NodeUpdateManager.UPDATE_URI);
    persisted.putSingle("node.updater.revocationURI", customUri);
    PersistentConfig persistedConfig = new PersistentConfig(persisted);

    // Act
    NodeUpdateManager custom = new NodeUpdateManager(node, persistedConfig);

    // Assert
    assertEquals(customUri, custom.getRevocationURI().toString(false, false));
    assertEquals(customUri, persistedConfig.get("node.updater").getString("revocationURI"));
  }

  @Test
  void constructor_whenCustomUpdateUriPersisted_expectCustomValuePreserved() throws Exception {
    // Arrange
    String customUri =
        "USK@"
            + NodeUpdateManager.UPDATE_URI
            + "/custom-update-doc/"
            + Version.currentBuildNumber();
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.putSingle("node.updater.URI", customUri);
    persisted.putSingle("node.updater.revocationURI", NodeUpdateManager.REVOCATION_URI);
    PersistentConfig persistedConfig = new PersistentConfig(persisted);

    // Act
    NodeUpdateManager custom = new NodeUpdateManager(node, persistedConfig);

    // Assert
    assertEquals(customUri, custom.getURI().toString(false, false));
    assertEquals(customUri, persistedConfig.get("node.updater").getString("URI"));

    // The core updater should subscribe to the configured custom docname channel.
    custom.startCoreUpdater();
    assertEquals("custom-update-doc", custom.getCoreUpdater().getUpdateKey().getDocName());
  }

  @Test
  void
      startCoreUpdater_whenMatchingPersistedEditionHigherThanCurrent_expectSubscribeSeedFromEdition()
          throws Exception {
    // Arrange
    int seededEdition = Version.currentBuildNumber() + 7;
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.put("node.updater.lastKnownGoodFetchedEdition", seededEdition);
    persisted.putSingle(
        "node.updater.lastKnownGoodFetchedEditionKey", NodeUpdateManager.UPDATE_URI);
    PersistentConfig persistedConfig = new PersistentConfig(persisted);
    NodeUpdateManager seeded = new NodeUpdateManager(node, persistedConfig);

    // Act
    seeded.startCoreUpdater();

    // Assert
    assertEquals(seededEdition - 1, seeded.getCoreUpdater().getUpdateKey().getSuggestedEdition());
  }

  @Test
  void startCoreUpdater_whenMatchingPersistedEditionLowerThanCurrent_expectSubscribeSeedAtCurrent()
      throws Exception {
    // Arrange
    int seededEdition = Version.currentBuildNumber() - 7;
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.put("node.updater.lastKnownGoodFetchedEdition", seededEdition);
    persisted.putSingle(
        "node.updater.lastKnownGoodFetchedEditionKey", NodeUpdateManager.UPDATE_URI);
    PersistentConfig persistedConfig = new PersistentConfig(persisted);
    NodeUpdateManager seeded = new NodeUpdateManager(node, persistedConfig);

    // Act
    seeded.startCoreUpdater();

    // Assert
    assertEquals(
        Version.currentBuildNumber(), seeded.getCoreUpdater().getUpdateKey().getSuggestedEdition());
  }

  @Test
  void startCoreUpdater_whenMatchingPersistedEditionOneAboveCurrent_expectSubscribeSeedAtCurrent()
      throws Exception {
    // Arrange
    int seededEdition = Version.currentBuildNumber() + 1;
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.put("node.updater.lastKnownGoodFetchedEdition", seededEdition);
    persisted.putSingle(
        "node.updater.lastKnownGoodFetchedEditionKey", NodeUpdateManager.UPDATE_URI);
    PersistentConfig persistedConfig = new PersistentConfig(persisted);
    NodeUpdateManager seeded = new NodeUpdateManager(node, persistedConfig);

    // Act
    seeded.startCoreUpdater();

    // Assert
    assertEquals(
        Version.currentBuildNumber(), seeded.getCoreUpdater().getUpdateKey().getSuggestedEdition());
  }

  @Test
  void constructor_whenPersistedEditionKeyMismatched_expectEditionResetAndKeyCanonicalized()
      throws Exception {
    // Arrange
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.put("node.updater.lastKnownGoodFetchedEdition", Version.currentBuildNumber() + 12);
    persisted.putSingle(
        "node.updater.lastKnownGoodFetchedEditionKey",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,AQACAAE");
    PersistentConfig persistedConfig = new PersistentConfig(persisted);

    // Act
    new NodeUpdateManager(node, persistedConfig);

    // Assert
    assertEquals(-1, persistedConfig.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        DEFAULT_FETCHED_SCOPE,
        persistedConfig.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void constructor_whenLegacyBareHintAndCustomUpdateScope_expectEditionResetAndSeedAtCurrent()
      throws Exception {
    // Arrange
    int seededEdition = Version.currentBuildNumber() + 12;
    String customDoc = "custom-update-doc";
    PersistentConfig persistedConfig =
        createLegacyBareHintPersistedConfigForCustomScope(seededEdition, customDoc);

    // Act
    NodeUpdateManager migrated = new NodeUpdateManager(node, persistedConfig);
    migrated.startCoreUpdater();

    // Assert
    assertEquals(-1, persistedConfig.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        "USK@" + NodeUpdateManager.UPDATE_URI + "/" + customDoc + "/0",
        persistedConfig.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
    assertEquals(
        Version.currentBuildNumber(),
        migrated.getCoreUpdater().getUpdateKey().getSuggestedEdition());
  }

  @Test
  void setURI_whenPublicKeyChanges_expectPersistedFetchedEditionReset() throws Exception {
    // Arrange
    int knownEdition = Version.currentBuildNumber() + 5;
    manager.recordSuccessfulCoreInfoFetch(
        manager.getCoreInfoURI().setSuggestedEdition(knownEdition), knownEdition);
    String alternateKey = "v" + NodeUpdateManager.UPDATE_URI.substring(1);
    FreenetURI changedKeyUri =
        new FreenetURI("USK@" + alternateKey + "/info/" + Version.currentBuildNumber());

    // Act
    manager.setURI(changedKeyUri);

    // Assert
    assertEquals(-1, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        "USK@" + alternateKey + "/info/0",
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void setURI_whenDocNameChangesOnSameKey_expectPersistedFetchedEditionReset() throws Exception {
    // Arrange
    int knownEdition = Version.currentBuildNumber() + 5;
    manager.recordSuccessfulCoreInfoFetch(
        manager.getCoreInfoURI().setSuggestedEdition(knownEdition), knownEdition);
    String customDoc = "custom-info";
    FreenetURI changedDocUri =
        new FreenetURI(
            "USK@"
                + NodeUpdateManager.UPDATE_URI
                + "/"
                + customDoc
                + "/"
                + Version.currentBuildNumber());

    // Act
    manager.setURI(changedDocUri);

    // Assert
    assertEquals(-1, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        "USK@" + NodeUpdateManager.UPDATE_URI + "/" + customDoc + "/0",
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void recordSuccessfulCoreInfoFetch_whenMatchingKey_expectPersistedHintUpdated() {
    // Arrange
    int knownEdition = Version.currentBuildNumber() + 4;

    // Act
    manager.recordSuccessfulCoreInfoFetch(
        manager.getCoreInfoURI().setSuggestedEdition(knownEdition), knownEdition);

    // Assert
    assertEquals(knownEdition, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        DEFAULT_FETCHED_SCOPE,
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void recordSuccessfulCoreInfoFetch_whenMatchingSskForUsk_expectPersistedHintUpdated() {
    // Arrange
    int knownEdition = Version.currentBuildNumber() + 6;
    FreenetURI fetchedSskUri =
        manager.getCoreInfoURI().setSuggestedEdition(knownEdition).sskForUSK();

    // Act
    manager.recordSuccessfulCoreInfoFetch(fetchedSskUri, knownEdition);

    // Assert
    assertEquals(knownEdition, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        DEFAULT_FETCHED_SCOPE,
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void recordSuccessfulCoreInfoFetch_whenDifferentKey_expectPersistedHintUnchanged()
      throws Exception {
    // Arrange
    String alternateKey = "v" + NodeUpdateManager.UPDATE_URI.substring(1);
    FreenetURI changedKeyUri =
        new FreenetURI("USK@" + alternateKey + "/info/" + Version.currentBuildNumber());

    // Act
    manager.recordSuccessfulCoreInfoFetch(changedKeyUri, Version.currentBuildNumber() + 4);

    // Assert
    assertEquals(-1, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        DEFAULT_FETCHED_SCOPE,
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
  }

  @Test
  void recordSuccessfulCoreInfoFetch_whenSameKeyDifferentDoc_expectPersistedHintUnchanged()
      throws Exception {
    // Arrange
    String customDoc = "custom-info";
    FreenetURI changedDocUri =
        new FreenetURI(
            "USK@"
                + NodeUpdateManager.UPDATE_URI
                + "/"
                + customDoc
                + "/"
                + Version.currentBuildNumber());
    manager.setURI(changedDocUri);
    int fetchedEdition = Version.currentBuildNumber() + 4;
    FreenetURI staleDocUri =
        new FreenetURI("USK@" + NodeUpdateManager.UPDATE_URI + "/info/" + fetchedEdition);

    // Act
    manager.recordSuccessfulCoreInfoFetch(staleDocUri, fetchedEdition);

    // Assert
    assertEquals(-1, config.get("node.updater").getInt("lastKnownGoodFetchedEdition"));
    assertEquals(
        "USK@" + NodeUpdateManager.UPDATE_URI + "/" + customDoc + "/0",
        config.get("node.updater").getString("lastKnownGoodFetchedEditionKey"));
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

  private static PersistentConfig createLegacyBareHintPersistedConfigForCustomScope(
      int seededEdition, String customDoc) {
    String customUri =
        "USK@"
            + NodeUpdateManager.UPDATE_URI
            + "/"
            + customDoc
            + "/"
            + Version.currentBuildNumber();
    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.putSingle("node.updater.URI", customUri);
    persisted.put("node.updater.lastKnownGoodFetchedEdition", seededEdition);
    persisted.putSingle(
        "node.updater.lastKnownGoodFetchedEditionKey", NodeUpdateManager.UPDATE_URI);
    return new PersistentConfig(persisted);
  }
}
