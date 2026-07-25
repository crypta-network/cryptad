package network.crypta.runtime.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.Config;
import network.crypta.config.PersistentConfig;
import network.crypta.fs.AppEnv;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeFile;
import network.crypta.node.NodeStats;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerMessenger;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTransport;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.Version;
import network.crypta.runtime.alerts.RevocationKeyFoundUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.io.ArrayBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
  @Mock ClientContext clientContext;
  @Mock UserAlertManager alerts;
  @Mock PeerManager peerManager;
  @Mock PeerMessenger peerMessenger;
  @Mock NodeStats nodeStats;
  @Mock Ticker ticker;

  private NodeUpdateManager manager;
  private Config config;
  private static final String DEFAULT_FETCHED_SCOPE =
      "USK@" + NodeUpdateManager.UPDATE_URI + "/info/0";
  private static final String VALID_TEST_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";

  private static final String SUPPORT_LIFECYCLE_IDENTITY_DIGEST =
      "sha256:b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7";
  private static final String SUPPORT_LIFECYCLE_STATE_PATH =
      "updates/core/support-lifecycle-last-known-good.json";

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
    when(node.network().ticker()).thenReturn(ticker);
    when(peerManager.messenger()).thenReturn(peerMessenger);
    when(node.network().stats()).thenReturn(nodeStats);

    // Provide values read when building announcements
    when(nodeStats.getNodeAveragePingTime()).thenReturn(100.0);
    when(nodeStats.getBwlimitDelayTime()).thenReturn(5.0);

    // NodeFile lookups for installers use runDir()
    when(node.runDir()).thenReturn(runProgramDir);
    File nodeDir = tempDir.resolve("node").toFile();
    assertTrue(nodeDir.mkdirs() || nodeDir.exists());
    ProgramDirectory nodeProgramDir = new ProgramDirectory();
    nodeProgramDir.move(nodeDir.getAbsolutePath());
    when(node.nodeDir()).thenReturn(nodeProgramDir);

    // Minimal fetch context for RevocationChecker construction
    HighLevelSimpleClient hlsc = mock(HighLevelSimpleClient.class);
    FetchContext fctx = getFetchContext();
    when(nodeCore.makeClient(anyShort(), anyBoolean(), anyBoolean())).thenReturn(hlsc);
    when(hlsc.getFetchContext()).thenReturn(fctx);
    when(nodeCore.getClientContext()).thenReturn(clientContext);

    config = new Config();
    manager = new NodeUpdateManager(node, config);
  }

  @Test
  void supportLifecycleTrustBinding_whenUsingCanonicalUpdateKey_expectPinnedOpaqueScope() {
    CoreSupportLifecycleParser.TrustBinding binding = manager.supportLifecycleTrustBinding();

    assertEquals("support-lifecycle", manager.getSupportLifecycleURI().getDocName());
    assertEquals(SUPPORT_LIFECYCLE_IDENTITY_DIGEST, binding.updateKeyIdentityDigest());
    assertEquals(
        SUPPORT_LIFECYCLE_IDENTITY_DIGEST + "/support-lifecycle/0", binding.updateKeyScope());
    assertEquals("support-lifecycle", binding.updateKeyDocName());
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

  private void setCoreUpdater(CoreUpdater updater) throws Exception {
    Field coreUpdaterField = NodeUpdateManager.class.getDeclaredField("coreUpdater");
    coreUpdaterField.setAccessible(true);
    coreUpdaterField.set(manager, updater);
  }

  private void setSupportLifecycleUpdater(CoreSupportLifecycleUpdater updater) throws Exception {
    Field updaterField = NodeUpdateManager.class.getDeclaredField("supportLifecycleUpdater");
    updaterField.setAccessible(true);
    updaterField.set(manager, updater);
  }

  private CoreSupportLifecycleUpdater getSupportLifecycleUpdater() throws Exception {
    return getSupportLifecycleUpdater(manager);
  }

  private static CoreSupportLifecycleUpdater getSupportLifecycleUpdater(NodeUpdateManager target)
      throws Exception {
    Field updaterField = NodeUpdateManager.class.getDeclaredField("supportLifecycleUpdater");
    updaterField.setAccessible(true);
    return (CoreSupportLifecycleUpdater) updaterField.get(target);
  }

  private CoreSupportLifecycleState getSupportLifecycleState() throws Exception {
    return getSupportLifecycleState(manager);
  }

  private static CoreSupportLifecycleState getSupportLifecycleState(NodeUpdateManager target)
      throws Exception {
    Field stateField = NodeUpdateManager.class.getDeclaredField("supportLifecycleState");
    stateField.setAccessible(true);
    return (CoreSupportLifecycleState) stateField.get(target);
  }

  private RevocationKeyFoundUserAlert getRevocationAlert() throws Exception {
    return getRevocationAlert(manager);
  }

  private static RevocationKeyFoundUserAlert getRevocationAlert(NodeUpdateManager target)
      throws Exception {
    Field alertField = NodeUpdateManager.class.getDeclaredField("revocationAlert");
    alertField.setAccessible(true);
    return (RevocationKeyFoundUserAlert) alertField.get(target);
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

  @Test
  void enable_whenPackageUpdatesAreDisabled_expectLifecycleSubscriberRemainsActive()
      throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.enable(true);
    CoreSupportLifecycleUpdater lifecycleUpdater = getSupportLifecycleUpdater();

    manager.enable(false);

    assertFalse(manager.isEnabled());
    assertNull(manager.getCoreUpdater());
    assertSame(lifecycleUpdater, getSupportLifecycleUpdater());
    assertTrue(lifecycleUpdater.isFetchingEnabled());
  }

  @Test
  void enable_whenPackageUpdatesStartDisabled_expectLifecycleSubscriberStarts() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);

    manager.enable(false);

    CoreSupportLifecycleUpdater lifecycleUpdater = getSupportLifecycleUpdater();
    assertFalse(manager.isEnabled());
    assertNotNull(lifecycleUpdater);
    assertTrue(lifecycleUpdater.isFetchingEnabled());
    verify(uskManager).subscribe(any(), same(lifecycleUpdater), eq(true), same(lifecycleUpdater));
  }

  @Test
  void enable_whenCalledRepeatedly_expectLifecycleSubscriberIsNotDuplicated() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.enable(false);
    CoreSupportLifecycleUpdater lifecycleUpdater = getSupportLifecycleUpdater();

    manager.enable(true);
    manager.enable(true);

    assertSame(lifecycleUpdater, getSupportLifecycleUpdater());
    verify(uskManager).subscribe(any(), same(lifecycleUpdater), eq(true), same(lifecycleUpdater));
  }

  @Test
  void enable_whenUpdateKeyIsBlown_expectLifecycleSubscriberRemainsStopped() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.enable(false);
    assertNotNull(getSupportLifecycleUpdater());

    manager.blow("revoked", false);
    manager.enable(false);

    assertNull(getSupportLifecycleUpdater());
    assertTrue(manager.isUpdateKeyCompromised());
  }

  @Test
  void start_whenRestartRestoresCompromise_expectUpdateSubscribersStoppedAndRevocationRearmed()
      throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.blow("authenticated update-key compromise", false);
    clearInvocations(alerts, clientContext, uskManager);
    NodeUpdateManager restarted = new NodeUpdateManager(node, new Config());
    RevocationKeyFoundUserAlert restoredAlert = getRevocationAlert(restarted);

    restarted.start();
    restarted.startCoreUpdater();
    restarted.startSupportLifecycleUpdater();

    assertNotNull(restoredAlert);
    assertTrue(restarted.isBlown());
    assertTrue(restarted.isUpdateKeyCompromised());
    assertFalse(restarted.isEnabled());
    assertNull(restarted.getCoreUpdater());
    assertNull(getSupportLifecycleUpdater(restarted));
    verify(alerts).register(same(restoredAlert));
    verifyNoInteractions(uskManager);
    ArgumentCaptor<ClientGetter> getterCaptor = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext).start(getterCaptor.capture());
    assertEquals(restarted.getRevocationURI(), getterCaptor.getValue().getURI());
  }

  @Test
  void start_whenPersistedCompromiseMarkerIsMalformed_expectFailClosedAlertAndNoUpdaters()
      throws Exception {
    Path descriptor = tempDir.resolve("node").resolve(SUPPORT_LIFECYCLE_STATE_PATH);
    Files.createDirectories(tempDir.resolve("node/updates/core"));
    Files.writeString(trustInvalidationMarker(descriptor), "malformed");
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    NodeUpdateManager restarted = new NodeUpdateManager(node, new Config());
    RevocationKeyFoundUserAlert restoredAlert = getRevocationAlert(restarted);

    restarted.start();

    assertNotNull(restoredAlert);
    assertTrue(restarted.isBlown());
    assertTrue(restarted.isUpdateKeyCompromised());
    assertFalse(restarted.supportLifecycleSnapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidation_marker_invalid"),
        restarted.supportLifecycleSnapshot().warnings());
    assertNull(restarted.getCoreUpdater());
    assertNull(getSupportLifecycleUpdater(restarted));
    verify(alerts).register(same(restoredAlert));
    verifyNoInteractions(uskManager);
    ArgumentCaptor<ClientGetter> getterCaptor = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext).start(getterCaptor.capture());
    assertEquals(restarted.getRevocationURI(), getterCaptor.getValue().getURI());
  }

  @Test
  void blow_whenRestartedCheckerRecoversCertificate_expectRevocationUomRearmed() throws Exception {
    manager.blow("authenticated update-key compromise", false);
    clearInvocations(peerMessenger);
    NodeUpdateManager restarted = new NodeUpdateManager(node, new Config());
    FetchResult result = mock(FetchResult.class);
    when(result.asByteArray()).thenReturn("revoked".getBytes(StandardCharsets.UTF_8));
    when(result.getMimeType()).thenReturn("text/plain");
    PeerNode newlyConnectedPeer = mock(PeerNode.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(newlyConnectedPeer.getNodeName()).thenReturn("Cryptad");
    when(newlyConnectedPeer.getBuildNumber()).thenReturn(Version.currentBuildNumber());
    when(newlyConnectedPeer.transport()).thenReturn(transport);

    restarted
        .getRevocationChecker()
        .onSuccess(result, null, new ArrayBucket("blob".getBytes(StandardCharsets.UTF_8)));
    restarted.maybeSendUOMAnnounce(newlyConnectedPeer);

    assertTrue(restarted.getRevocationChecker().hasBlown());
    verify(peerMessenger)
        .localBroadcast(
            any(Message.class),
            eq(true),
            eq(true),
            same(restarted.getByteCounter()),
            eq(NodeUpdateManager.TRANSITION_VERSION),
            eq(Integer.MAX_VALUE));
    ArgumentCaptor<Message> announcement = ArgumentCaptor.forClass(Message.class);
    verify(transport).sendAsync(announcement.capture(), isNull(), same(restarted.getByteCounter()));
    assertTrue(announcement.getValue().getBoolean(DMT.HAVE_REVOCATION_KEY));
  }

  @Test
  void blow_whenUpdateKeyIsCompromised_expectLifecycleTrustInvalidated() throws Exception {
    CoreSupportLifecycleState lifecycleState = getSupportLifecycleState();
    lifecycleState.accept(lifecycleDescriptorForRunningBuild(), 1);
    Path persisted = tempDir.resolve("node").resolve(SUPPORT_LIFECYCLE_STATE_PATH);
    assertTrue(manager.supportLifecycleSnapshot().known());
    assertTrue(Files.isRegularFile(persisted));

    manager.blow("revoked", false);

    assertFalse(manager.supportLifecycleSnapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidated"), manager.supportLifecycleSnapshot().warnings());
    assertFalse(Files.exists(persisted));
    assertTrue(Files.isRegularFile(trustInvalidationMarker(persisted)));
  }

  @Test
  void constructor_whenNodeDirectoryRootIsSymbolicLink_expectLifecycleStateUsesPinnedTarget()
      throws Exception {
    Path realNode = Files.createDirectory(tempDir.resolve("real-node"));
    Path configuredNode = tempDir.resolve("configured-node");
    Files.createSymbolicLink(configuredNode, realNode);
    ProgramDirectory nodeProgramDir = new ProgramDirectory();
    nodeProgramDir.move(configuredNode.toString());
    when(node.nodeDir()).thenReturn(nodeProgramDir);
    NodeUpdateManager symlinked = new NodeUpdateManager(node, new Config());
    CoreSupportLifecycleState lifecycleState = getSupportLifecycleState(symlinked);
    Path persisted = realNode.resolve(SUPPORT_LIFECYCLE_STATE_PATH);

    lifecycleState.accept(lifecycleDescriptorForRunningBuild(), 1);
    assertTrue(Files.isRegularFile(persisted));
    assertTrue(symlinked.supportLifecycleSnapshot().known());

    symlinked.blow("authenticated update-key compromise", false);

    assertFalse(Files.exists(persisted));
    assertTrue(Files.isRegularFile(trustInvalidationMarker(persisted)));
    assertTrue(
        Files.isRegularFile(
            realNode.resolve(NodeUpdateManager.UPDATE_KEY_TRUST_INVALIDATION_FILE)));
    assertTrue(symlinked.isUpdateKeyCompromised());
  }

  @Test
  void blow_whenUpdateKeyIsCompromised_expectSubscribersStoppedBeforeTrustPersistence()
      throws Exception {
    Path descriptor = tempDir.resolve("node").resolve(SUPPORT_LIFECYCLE_STATE_PATH);
    Path marker = trustInvalidationMarker(descriptor);
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    CoreSupportLifecycleUpdater lifecycleUpdater = mock(CoreSupportLifecycleUpdater.class);
    AtomicInteger preparedSubscribers = new AtomicInteger();
    AtomicInteger stoppedSubscribers = new AtomicInteger();
    setCoreUpdater(coreUpdater);
    setSupportLifecycleUpdater(lifecycleUpdater);
    doAnswer(
            _ -> {
              assertTrue(manager.isBlown());
              assertTrue(manager.isUpdateKeyCompromised());
              assertFalse(Files.exists(marker));
              preparedSubscribers.incrementAndGet();
              return null;
            })
        .when(coreUpdater)
        .preKill();
    doAnswer(
            _ -> {
              assertTrue(manager.isBlown());
              assertTrue(manager.isUpdateKeyCompromised());
              assertFalse(Files.exists(marker));
              preparedSubscribers.incrementAndGet();
              return null;
            })
        .when(lifecycleUpdater)
        .preKill();
    doAnswer(
            _ -> {
              assertFalse(Files.exists(marker));
              stoppedSubscribers.incrementAndGet();
              return null;
            })
        .when(coreUpdater)
        .kill();
    doAnswer(
            _ -> {
              assertFalse(Files.exists(marker));
              stoppedSubscribers.incrementAndGet();
              return null;
            })
        .when(lifecycleUpdater)
        .kill();

    manager.blow("authenticated update-key compromise", false);

    assertEquals(2, preparedSubscribers.get());
    assertEquals(2, stoppedSubscribers.get());
    verify(coreUpdater).kill();
    verify(lifecycleUpdater).kill();
    assertTrue(Files.isRegularFile(marker));
  }

  @Test
  void blow_whenCompromiseMarkersCannotPersist_expectRetryRestoresDurableRestartLatch()
      throws Exception {
    Path descriptor = tempDir.resolve("node").resolve(SUPPORT_LIFECYCLE_STATE_PATH);
    Path siblingMarker = trustInvalidationMarker(descriptor);
    Path fallbackMarker =
        tempDir.resolve("node").resolve(NodeUpdateManager.UPDATE_KEY_TRUST_INVALIDATION_FILE);
    Files.createDirectories(siblingMarker);
    Files.createDirectory(fallbackMarker);

    manager.blow("authenticated update-key compromise", false);

    assertTrue(manager.isBlown());
    assertTrue(manager.isUpdateKeyCompromised());
    assertFalse(manager.supportLifecycleSnapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidation_persistence_failed"),
        manager.supportLifecycleSnapshot().warnings());
    ArgumentCaptor<Runnable> retry = ArgumentCaptor.forClass(Runnable.class);
    verify(ticker).queueTimedJob(retry.capture(), eq(TimeUnit.SECONDS.toMillis(1)));

    Files.delete(siblingMarker);
    Files.delete(fallbackMarker);
    retry.getValue().run();
    NodeUpdateManager restarted = new NodeUpdateManager(node, new Config());

    assertTrue(Files.isRegularFile(siblingMarker));
    assertTrue(Files.isRegularFile(fallbackMarker));
    assertEquals(
        List.of("lifecycle_trust_invalidated"), manager.supportLifecycleSnapshot().warnings());
    assertTrue(restarted.isBlown());
    assertTrue(restarted.isUpdateKeyCompromised());
    assertFalse(restarted.supportLifecycleSnapshot().known());
    verify(ticker, times(1)).queueTimedJob(any(Runnable.class), eq(TimeUnit.SECONDS.toMillis(1)));
  }

  @Test
  void blow_whenLocalFailurePrecedesCompromise_expectLifecycleTrustInvalidatedOnlyByCompromise()
      throws Exception {
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.enable(false);
    CoreSupportLifecycleUpdater lifecycleUpdater = getSupportLifecycleUpdater();
    CoreSupportLifecycleState lifecycleState = getSupportLifecycleState();
    lifecycleState.accept(lifecycleDescriptorForRunningBuild(), 1);
    Path persisted = tempDir.resolve("node").resolve(SUPPORT_LIFECYCLE_STATE_PATH);

    manager.blow("local updater failure", true);

    assertTrue(manager.supportLifecycleSnapshot().known());
    assertTrue(Files.isRegularFile(persisted));
    assertFalse(manager.isUpdateKeyCompromised());
    assertSame(lifecycleUpdater, getSupportLifecycleUpdater());
    assertFalse(lifecycleUpdater.isFetchingBlockedByManagerState());

    manager.blow("later authenticated compromise", false);

    assertFalse(manager.supportLifecycleSnapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidated"), manager.supportLifecycleSnapshot().warnings());
    assertFalse(Files.exists(persisted));
    assertTrue(Files.isRegularFile(trustInvalidationMarker(persisted)));
    assertTrue(manager.isUpdateKeyCompromised());
    assertNull(getSupportLifecycleUpdater());
    assertTrue(lifecycleUpdater.isFetchingBlockedByManagerState());
  }

  @Test
  void blow_whenLocalAlertRegistrationRacesWithCompromise_expectOnlyCompromiseAlertRemains()
      throws Exception {
    Set<UserAlert> registeredAlerts = ConcurrentHashMap.newKeySet();
    AtomicInteger registrationCalls = new AtomicInteger();
    CountDownLatch firstRegistrationEntered = new CountDownLatch(1);
    CountDownLatch releaseFirstRegistration = new CountDownLatch(1);
    CountDownLatch authenticatedRegistrationEntered = new CountDownLatch(1);
    doAnswer(
            invocation -> {
              UserAlert alert = invocation.getArgument(0);
              int call = registrationCalls.incrementAndGet();
              if (call == 1) {
                firstRegistrationEntered.countDown();
                assertTrue(releaseFirstRegistration.await(5, TimeUnit.SECONDS));
              } else {
                authenticatedRegistrationEntered.countDown();
              }
              registeredAlerts.add(alert);
              return null;
            })
        .when(alerts)
        .register(any(UserAlert.class));
    doAnswer(
            invocation -> {
              UserAlert alert = invocation.getArgument(0);
              registeredAlerts.remove(alert);
              return null;
            })
        .when(alerts)
        .unregister(any(UserAlert.class));

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      try {
        Future<?> localFailure = executor.submit(() -> manager.blow("local updater failure", true));
        assertTrue(firstRegistrationEntered.await(5, TimeUnit.SECONDS));
        Future<?> authenticatedCompromise =
            executor.submit(() -> manager.blow("authenticated update-key compromise", false));

        assertFalse(authenticatedRegistrationEntered.await(1, TimeUnit.SECONDS));
        releaseFirstRegistration.countDown();
        localFailure.get(5, TimeUnit.SECONDS);
        authenticatedCompromise.get(5, TimeUnit.SECONDS);

        assertTrue(manager.isUpdateKeyCompromised());
        assertEquals(1, registeredAlerts.size());
        assertTrue(registeredAlerts.contains(getRevocationAlert()));
      } finally {
        releaseFirstRegistration.countDown();
        executor.shutdownNow();
      }
    }
  }

  @Test
  void hasNewCorePackage_whenUpdaterCallBlocks_expectManagerMonitorReleased() throws Exception {
    // Arrange
    CoreUpdater coreUpdater = mock(CoreUpdater.class);
    CountDownLatch enteredUpdater = new CountDownLatch(1);
    CountDownLatch releaseUpdater = new CountDownLatch(1);
    when(coreUpdater.canUpdateNow())
        .thenAnswer(
            _ -> {
              enteredUpdater.countDown();
              assertTrue(releaseUpdater.await(5, TimeUnit.SECONDS));
              return true;
            });
    setCoreUpdater(coreUpdater);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      try {
        // Act
        Future<Boolean> hasNewCorePackage = executor.submit(manager::hasNewCorePackage);
        assertTrue(enteredUpdater.await(5, TimeUnit.SECONDS));
        Future<Boolean> autoUpdateAllowed = executor.submit(manager::isAutoUpdateAllowed);

        // Assert
        assertFalse(autoUpdateAllowed.get(1, TimeUnit.SECONDS));
        releaseUpdater.countDown();
        assertTrue(hasNewCorePackage.get(5, TimeUnit.SECONDS));
      } finally {
        releaseUpdater.countDown();
        executor.shutdownNow();
      }
    }
  }

  private static byte[] lifecycleDescriptorForRunningBuild() throws Exception {
    Map<String, Object> descriptor =
        JsonMini.parseObject(
            Files.readString(
                Path.of(
                    "tools/release-certification/fixtures/stable-lifecycle/"
                        + "runtime-descriptor-v1.json"),
                StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) descriptor.get("entries")).getFirst();
    String build = Integer.toString(Version.currentBuildNumber());
    String runtimeRevision = Version.gitRevision();
    String sourceCommit = "a".repeat(40);
    if (runtimeRevision.matches("[0-9a-f]{7,40}")) {
      sourceCommit = runtimeRevision + "0".repeat(40 - runtimeRevision.length());
    }
    entry.put("releaseId", "stable-1.0-build-" + build);
    entry.put("buildVersion", build);
    entry.put("tag", "v" + build);
    entry.put("sourceCommit", sourceCommit);
    descriptor.put("currentStableBuild", build);
    descriptor.put("minimumSupportedBuild", build);
    descriptor.put("minimumSecuritySupportedBuild", build);
    descriptor.put("recommendedBuild", build);
    descriptor.remove("descriptorDigest");
    descriptor.put("descriptorDigest", CoreSupportLifecycleParser.semanticDigest(descriptor));
    return CoreSupportLifecycleParser.canonicalJson(descriptor).getBytes(StandardCharsets.UTF_8);
  }

  private static Path trustInvalidationMarker(Path persistedDescriptor) {
    return persistedDescriptor.resolveSibling(
        persistedDescriptor.getFileName() + ".trust-invalidated");
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
  void setURI_whenScopeChanges_expectHasNewCorePackageReset() {
    // Arrange
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.startCoreUpdater();
    CoreUpdater updater = manager.getCoreUpdater();
    assertNotNull(updater);
    String descriptorJson =
        """
          {
            "version": "%d",
            "packages": {}
          }
        """
            .formatted(Version.currentBuildNumber() + 5);
    FetchResult descriptor =
        FetchResult.create(
            new ClientMetadata("application/json"),
            new ArrayBucket(descriptorJson.getBytes(StandardCharsets.UTF_8)));

    // Act + Assert precondition: descriptor marks a new version available.
    updater.maybeParseManifest(descriptor, Version.currentBuildNumber() + 5);
    assertTrue(manager.hasNewCorePackage());

    // Act: switch to a different update scope (docname/channel).
    manager.setURI(manager.getURI().setDocName("alternate-info"));

    // Assert: stale descriptor state from previous scope must not leak.
    assertFalse(manager.hasNewCorePackage());
  }

  @Test
  void setURI_whenPackageDownloadInProgress_expectActiveDownloadCancelled() throws Exception {
    // Arrange
    USKManager uskManager = mock(USKManager.class);
    when(nodeCore.getUskManager()).thenReturn(uskManager);
    manager.startCoreUpdater();
    CoreUpdater updater = manager.getCoreUpdater();
    assertNotNull(updater);

    String arch = new AppEnv().detectEnvironment().getArch();
    String descriptorJson =
        """
          {
            "version": "%d",
            "packages": {
              "%s.deb": { "chk": "%s" }
            }
          }
        """
            .formatted(Version.currentBuildNumber() + 9, arch, VALID_TEST_CHK);
    FetchResult descriptor =
        FetchResult.create(
            new ClientMetadata("application/json"),
            new ArrayBucket(descriptorJson.getBytes(StandardCharsets.UTF_8)));

    updater.maybeParseManifest(descriptor, Version.currentBuildNumber() + 9);
    updater.startDownloadFromUI();

    ArgumentCaptor<ClientGetter> getterCaptor = ArgumentCaptor.forClass(ClientGetter.class);
    verify(clientContext, times(1)).start(getterCaptor.capture());
    ClientGetter inFlightGetter = getterCaptor.getValue();
    assertFalse(inFlightGetter.isCancelled());

    // Act
    manager.setURI(manager.getURI().setDocName("alternate-info"));

    // Assert
    assertTrue(inFlightGetter.isCancelled());
  }

  @Test
  void maybeParseManifest_whenAutoUpdateEnabledAndVersionNotInteger_expectNoAutoDownload()
      throws Exception {
    // Arrange
    manager.startCoreUpdater();
    manager.setAutoUpdateAllowed(true);
    CoreUpdater updater = manager.getCoreUpdater();
    assertNotNull(updater);
    String arch = new AppEnv().detectEnvironment().getArch();
    String descriptorJson =
        """
          {
            "version": "1.2.3+build123",
            "packages": {
              "%s.deb": { "chk": "%s" }
            }
          }
        """
            .formatted(arch, VALID_TEST_CHK);
    FetchResult descriptor =
        FetchResult.create(
            new ClientMetadata("application/json"),
            new ArrayBucket(descriptorJson.getBytes(StandardCharsets.UTF_8)));

    // Act
    updater.maybeParseManifest(descriptor, Version.currentBuildNumber() + 9);

    // Assert
    assertFalse(manager.hasNewCorePackage());
    verify(clientContext, times(0)).start(any(ClientGetter.class));
  }

  @Test
  void maybeParseManifest_whenAutoUpdateEnabledAndVersionNewer_expectAutoDownloadStarted()
      throws Exception {
    // Arrange
    manager.startCoreUpdater();
    manager.setAutoUpdateAllowed(true);
    CoreUpdater updater = manager.getCoreUpdater();
    assertNotNull(updater);
    String arch = new AppEnv().detectEnvironment().getArch();
    String descriptorJson =
        """
          {
            "version": "%d",
            "packages": {
              "%s.deb": { "chk": "%s" }
            }
          }
        """
            .formatted(Version.currentBuildNumber() + 9, arch, VALID_TEST_CHK);
    FetchResult descriptor =
        FetchResult.create(
            new ClientMetadata("application/json"),
            new ArrayBucket(descriptorJson.getBytes(StandardCharsets.UTF_8)));

    // Act
    updater.maybeParseManifest(descriptor, Version.currentBuildNumber() + 9);

    // Assert
    verify(clientContext, times(1)).start(any(ClientGetter.class));
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
    PeerNode peer = mock(PeerNode.class);
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
