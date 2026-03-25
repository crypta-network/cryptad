package network.crypta.node;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.config.PersistentConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.NodeSSK;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.core.LegacyRuntimePorts;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.endpoints.NodeClientPersistence;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class NodeClientCoreTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private SecurityLevels securityLevels;
  @Mock private SimpleToadletServer toadlets;
  @Mock private RequestStarterGroup requestStarters;
  @Mock private ClientRequestScheduler schedulerBulk;
  @Mock private ClientRequestScheduler schedulerRt;
  @Mock private RandomSource rng;
  @Mock private NodeClientPersistence persistence;
  @Mock private ClientLayerPersister clientLayerPersister;
  @Mock private ClientContext clientContext;
  @Mock private TempBucketFactory tempBucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private DatastoreChecker storeChecker;
  @Mock private UserAlertManager alerts;
  @Mock private PersistentConfig config;
  @Mock private PriorityAwareExecutor executor;
  @Mock private IPDetectorManager ipDetectorManager;

  @TempDir Path tempDir; // base dir for downloads and test files

  private NodeClientCore core;
  private RuntimePorts runtimePorts;
  private NodeClientCoreTransfers transfers;
  private USKManager uskManager;
  private File nodeDir;
  private File coreTempDir;
  private File persistentTempDir;

  @BeforeEach
  void setUp() throws Exception {
    // Create a mock that calls real methods without running the heavy constructor
    core =
        Mockito.mock(
            NodeClientCore.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));

    // Inject required collaborators/fields via reflection to avoid full Node/Config bootstrapping
    setField(core, "random", rng);
    setField(core, "node", node);
    setField(core, "persistence", persistence);
    setField(core, "clientLayerPersister", clientLayerPersister);
    setField(core, "clientContext", clientContext);
    setField(core, "tempBucketFactory", tempBucketFactory);
    setField(core, "persistentTempBucketFactory", persistentTempBucketFactory);
    setField(core, "storeChecker", storeChecker);
    setField(core, "alerts", alerts);
    setField(core, "formPassword", "form-password");
    NodeServicesSubsystem services = Mockito.mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(node.getConfig()).thenReturn(config);
    when(node.network().executor()).thenReturn(executor);

    setField(core, "downloadsDir", tempDir.toFile());
    setField(core, "transferPolicy", new NodeClientCoreTransferPolicy(node, tempDir.toFile()));
    nodeDir = tempDir.resolve("node").toFile();
    coreTempDir = tempDir.resolve("temp").toFile();
    persistentTempDir = tempDir.resolve("persistent").toFile();
    Files.createDirectories(coreTempDir.toPath());
    Files.createDirectories(persistentTempDir.toPath());
    Files.createDirectories(nodeDir.toPath());
    setField(core, "tempDir", coreTempDir);
    setField(core, "persistentTempDir", persistentTempDir);

    ClientEndpoints endpoints = new ClientEndpoints(Mockito.mock(FCPServer.class), null, toadlets);
    setField(core, "endpoints", endpoints);
    setField(core, "requestStarters", requestStarters);
    transfers = Mockito.mock(NodeClientCoreTransfers.class);
    uskManager = Mockito.mock(USKManager.class);
    setField(core, "transfers", transfers);
    setField(core, "uskManager", uskManager);
    runtimePorts = new LegacyRuntimePorts(node, core);
    setField(core, "runtimePorts", runtimePorts);
    NodeIPDetector nodeIpDetector = Mockito.mock(NodeIPDetector.class);
    setField(nodeIpDetector, NodeIPDetector.class, "ipDetectorManager", ipDetectorManager);
    when(node.network().ipDetector()).thenReturn(nodeIpDetector);
    when(node.getNodeDir()).thenReturn(nodeDir);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(256L);

    // sensible default unless a test overrides
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
  }

  @Test
  void makeUID_whenRandomReturnsMinusOneFirst_expectSkipsAndReturnsNonMinusOne() {
    when(rng.nextLong()).thenReturn(-1L, 1234L);
    long uid = core.makeUID();
    assertNotEquals(-1L, uid);
    assertEquals(1234L, uid);
  }

  @Test
  void isDownloadDisabled_whenNoAllowedDirs_expectTrue() {
    core.setDownloadAllowedDirs(new String[] {});
    assertTrue(core.isDownloadDisabled());

    // Also verify that with no allowed dirs, a path is rejected
    File f = tempDir.resolve("file.bin").toFile();
    assertFalse(core.allowDownloadTo(f));
  }

  @Test
  void allowDownloadTo_whenPhysicalLevelMaximum_expectFalseRegardlessOfDirs() {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.MAXIMUM);
    core.setDownloadAllowedDirs(new String[] {"all"});
    File f = tempDir.resolve("any.bin").toFile();
    assertFalse(core.allowDownloadTo(f));
  }

  @Test
  void allowDownloadTo_whenDownloadsDirIncluded_expectTrueInsideDownloadsFalseOutside()
      throws Exception {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
    core.setDownloadAllowedDirs(new String[] {"downloads"});

    Path insideDir = tempDir.resolve("sub");
    Files.createDirectories(insideDir);
    Path inside = insideDir.resolve("inside.dat");
    Path outsideDir = Files.createTempDirectory("outside-");
    File outside = outsideDir.resolve("out.dat").toFile();

    assertTrue(core.allowDownloadTo(inside.toFile()));
    assertFalse(core.allowDownloadTo(outside));
  }

  @Test
  void allowDownloadTo_whenExplicitDirAllowed_expectTrueForSubpathsOnly() throws Exception {
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(PHYSICAL_THREAT_LEVEL.NORMAL);
    Path allowed = tempDir.resolve("allowed");
    Files.createDirectories(allowed);
    core.setDownloadAllowedDirs(new String[] {allowed.toFile().getAbsolutePath()});

    File inSub = allowed.resolve("deep/nested/file.dat").toFile();
    Path other = Files.createTempDirectory("other-");
    File notAllowed = other.resolve("na.bin").toFile();

    assertTrue(core.allowDownloadTo(inSub));
    assertFalse(core.allowDownloadTo(notAllowed));
  }

  @Test
  void setDownloadAllowedDirs_whenAllAndExplicitDirs_expectInternalStateReflectedByGetters() {
    Path a = tempDir.resolve("A");
    Path b = tempDir.resolve("B");
    core.setDownloadAllowedDirs(
        new String[] {a.toFile().getAbsolutePath(), b.toFile().getAbsolutePath()});
    File[] dirs = core.getAllowedDownloadDirs();
    // Order is preserved for concrete paths; "downloads" and "all" are not part of this array
    assertArrayEquals(new File[] {a.toFile(), b.toFile()}, dirs);
  }

  @Test
  void allowUploadFrom_whenAllEnabled_expectTrueForAnyPath() {
    core.setUploadAllowedDirs(new String[] {"all"});
    File anywhere = tempDir.resolve("..").resolve("anywhere.txt").normalize().toFile();
    assertTrue(core.allowUploadFrom(anywhere));
  }

  @Test
  void allowUploadFrom_whenSpecificDirEnabled_expectOnlyThatDirAccepted() throws Exception {
    Path up = tempDir.resolve("uploads");
    Files.createDirectories(up);
    core.setUploadAllowedDirs(new String[] {up.toFile().getAbsolutePath()});

    File inside = up.resolve("ok.bin").toFile();
    Path other = Files.createTempDirectory("not-up-");
    File outside = other.resolve("nope.bin").toFile();

    assertTrue(core.allowUploadFrom(inside));
    assertFalse(core.allowUploadFrom(outside));
  }

  @Test
  void queueOfferedKey_whenSSKAndRealTime_expectDelegatedToAppropriateScheduler() {
    NodeSSK key =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE], new byte[NodeSSK.E_H_DOCNAME_SIZE], (byte) 1);

    when(requestStarters.getScheduler(true, false, true)).thenReturn(schedulerRt);

    core.queueOfferedKey(key, true);

    verify(schedulerRt, times(1)).queueOfferedKey(key, true);
  }

  @Test
  void dequeueOfferedKey_whenSSK_expectBothBulkAndRealtimeSchedulersNotified() {
    NodeSSK key =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE], new byte[NodeSSK.E_H_DOCNAME_SIZE], (byte) 1);

    when(requestStarters.getScheduler(true, false, false)).thenReturn(schedulerBulk);
    when(requestStarters.getScheduler(true, false, true)).thenReturn(schedulerRt);

    core.dequeueOfferedKey(key);

    verify(schedulerBulk, times(1)).dequeueOfferedKey(key);
    verify(schedulerRt, times(1)).dequeueOfferedKey(key);
  }

  @Test
  void linkFilterProvider_and_fproxyFlags_and_bookmarks_areDelegatedToToadletContainer() {
    BookmarkManager bm = Mockito.mock(BookmarkManager.class);
    when(toadlets.getBookmarks()).thenReturn(bm);
    when(toadlets.getBookmarkURIs()).thenReturn(new network.crypta.keys.FreenetURI[0]);
    when(toadlets.isAdvancedModeEnabled()).thenReturn(true);
    when(toadlets.isFProxyJavascriptEnabled()).thenReturn(true);

    assertSame(toadlets, core.getEndpoints().getToadletContainer());
    assertSame(bm, core.getEndpoints().getToadletContainer().getBookmarks());
    assertEquals(0, core.getEndpoints().getToadletContainer().getBookmarkURIs().length);
    assertTrue(core.isAdvancedModeEnabled());
    assertTrue(core.isFProxyJavascriptEnabled());
  }

  @Test
  void fproxySetterGetter_and_myName_delegations_work() {
    FProxyToadlet fproxy = Mockito.mock(FProxyToadlet.class);
    core.getEndpoints().setFProxy(fproxy);
    assertSame(fproxy, core.getEndpoints().getFProxy());

    when(node.getMyName()).thenReturn("MyNode");
    assertEquals("MyNode", core.getMyName());
  }

  @Test
  void getters_whenCollaboratorsInjected_expectVerbatimReferencesReturned() {
    assertSame(runtimePorts, core.getRuntimePorts());
    assertEquals(tempDir.toFile(), core.getDownloadsDir());
    assertEquals(persistentTempDir, core.getPersistentTempDir());
    assertEquals(coreTempDir, core.getTempDir());
    assertSame(uskManager, core.getUskManager());
    assertSame(transfers, core.getTransfers());
    assertSame(requestStarters, core.getRequestStarters());
    assertEquals("form-password", core.getFormPassword());
    assertSame(tempBucketFactory, core.getTempBucketFactory());
    assertSame(persistentTempBucketFactory, core.getPersistentTempBucketFactory());
    assertSame(clientLayerPersister, core.getClientLayerPersister());
    assertSame(node, core.getNode());
    assertSame(rng, core.getRandom());
    assertSame(alerts, core.getAlerts());
    assertSame(storeChecker, core.getStoreChecker());
    assertSame(clientContext, core.getClientContext());
  }

  @Test
  void countQueuedRequests_whenRequestStartersProvideCount_expectDelegatedCount() {
    when(requestStarters.countQueuedRequests()).thenReturn(42L);

    long queued = core.countQueuedRequests();

    assertEquals(42L, queued);
  }

  @Test
  void persistThrottlesToFieldSet_whenRequestStartersProvideSnapshot_expectSameSnapshot() {
    SimpleFieldSet snapshot = new SimpleFieldSet(true);
    when(requestStarters.persistToFieldSet()).thenReturn(snapshot);

    SimpleFieldSet persisted = core.persistThrottlesToFieldSet();

    assertSame(snapshot, persisted);
  }

  @Test
  void wantKey_whenRealtimeSchedulerWantsKey_expectReturnsTrueWithoutCheckingBulk() {
    NodeSSK key =
        new NodeSSK(
            new byte[NodeSSK.PUBKEY_HASH_SIZE], new byte[NodeSSK.E_H_DOCNAME_SIZE], (byte) 2);
    when(clientContext.getFetchScheduler(true, true)).thenReturn(schedulerRt);
    when(schedulerRt.wantKey(key)).thenReturn(true);

    boolean wanted = core.wantKey(key);

    assertTrue(wanted);
    verify(clientContext).getFetchScheduler(true, true);
    verify(clientContext, never()).getFetchScheduler(true, false);
  }

  @Test
  void wantKey_whenBulkSchedulerWantsKey_expectFallsBackAfterRealtimeMiss() {
    network.crypta.keys.Key key = Mockito.mock(network.crypta.keys.Key.class);
    when(clientContext.getFetchScheduler(false, true)).thenReturn(schedulerRt);
    when(clientContext.getFetchScheduler(false, false)).thenReturn(schedulerBulk);
    when(schedulerRt.wantKey(key)).thenReturn(false);
    when(schedulerBulk.wantKey(key)).thenReturn(true);

    boolean wanted = core.wantKey(key);

    assertTrue(wanted);
    verify(clientContext).getFetchScheduler(false, true);
    verify(clientContext).getFetchScheduler(false, false);
  }

  @Test
  void updatePersistentRAFSpaceLimit_whenPersistentFactoryPresent_expectAddsRamAllowance()
      throws Exception {
    when(persistence.hasPersistentRafFactory()).thenReturn(true);
    setField(core, "minDiskFreeLongTerm", 1024L);

    core.updatePersistentRAFSpaceLimit();

    verify(persistence).updateMinDiskSpace(1280L);
  }

  @Test
  void updatePersistentRAFSpaceLimit_whenPersistentFactoryMissing_expectNoUpdate()
      throws Exception {
    when(persistence.hasPersistentRafFactory()).thenReturn(false);
    setField(core, "minDiskFreeLongTerm", 1024L);

    core.updatePersistentRAFSpaceLimit();

    verify(persistence, never()).updateMinDiskSpace(anyLong());
  }

  @Test
  void setupMasterSecret_whenPersistentSecretAbsent_expectConfiguresContextAndStorage() {
    MasterSecret secret = new MasterSecret();
    when(clientContext.getPersistentMasterSecret()).thenReturn(null);

    core.setupMasterSecret(secret);

    verify(clientContext).setPersistentMasterSecret(secret);
    verify(persistentTempBucketFactory).setMasterSecret(secret);
    verify(persistence).setPersistentRafMasterSecret(secret);
  }

  @Test
  void setupMasterSecret_whenPersistentSecretAlreadyPresent_expectDoesNotOverwriteContextSecret() {
    MasterSecret existingSecret = new MasterSecret();
    MasterSecret newSecret = new MasterSecret();
    when(clientContext.getPersistentMasterSecret()).thenReturn(existingSecret);

    core.setupMasterSecret(newSecret);

    verify(clientContext, never()).setPersistentMasterSecret(any());
    verify(persistentTempBucketFactory).setMasterSecret(newSecret);
    verify(persistence).setPersistentRafMasterSecret(newSecret);
  }

  @Test
  void storeConfig_whenInvoked_expectDelegatesToNodeConfig() {
    core.storeConfig();

    verify(config).store();
  }

  @Test
  void lateInitDatabase_whenStorageLoads_expectReturnsTrueAndLoadsPersistentRequests()
      throws Exception {
    ClientEndpoints endpoints = Mockito.mock(ClientEndpoints.class);
    DatabaseKey databaseKey = new DatabaseKey(new byte[32]);
    setField(core, "endpoints", endpoints);

    boolean initialized = core.lateInitDatabase(databaseKey);

    assertTrue(initialized);
    verify(clientLayerPersister)
        .setFilesAndLoad(
            same(nodeDir),
            eq("client.dat"),
            eq(false),
            eq(false),
            same(databaseKey),
            same(requestStarters));
    verify(endpoints).loadPersistentRequestsIfNeeded();
  }

  @Test
  void lateInitDatabase_whenMasterKeyWrong_expectReturnsFalseAndSkipsPersistentRequestLoad()
      throws Exception {
    ClientEndpoints endpoints = Mockito.mock(ClientEndpoints.class);
    DatabaseKey databaseKey = new DatabaseKey(new byte[32]);
    setField(core, "endpoints", endpoints);
    doThrow(new MasterKeysWrongPasswordException())
        .when(clientLayerPersister)
        .setFilesAndLoad(any(), anyString(), anyBoolean(), anyBoolean(), same(databaseKey), any());

    boolean initialized = core.lateInitDatabase(databaseKey);

    assertFalse(initialized);
    verify(endpoints, never()).loadPersistentRequestsIfNeeded();
  }

  @Test
  void loadedDatabase_whenPersisterHasLoaded_expectTrue() {
    when(clientLayerPersister.hasLoaded()).thenReturn(true);

    boolean loaded = core.loadedDatabase();

    assertTrue(loaded);
  }

  @Test
  void killedDatabase_whenPersisterIsUnavailable_expectTrue() {
    when(clientLayerPersister.isKilledOrNotLoaded()).thenReturn(true);

    boolean killed = core.killedDatabase();

    assertTrue(killed);
  }

  @Test
  void getPersistentRequests_whenPersistenceProvidesSnapshot_expectSameArray() {
    ClientRequest[] requests = new ClientRequest[] {Mockito.mock(ClientRequest.class)};
    when(persistence.getPersistentRequests()).thenReturn(requests);

    ClientRequest[] persisted = core.getPersistentRequests();

    assertSame(requests, persisted);
  }

  @Test
  void start_whenDatabaseKeyPresent_expectStartsServicesAndFinishesStorage() throws Exception {
    ClientEndpoints endpoints = Mockito.mock(ClientEndpoints.class);
    DatabaseKey databaseKey = new DatabaseKey(new byte[32]);
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
    setField(core, "endpoints", endpoints);
    when(node.storage().getDatabaseKey()).thenReturn(databaseKey);

    core.start();

    verify(persistence).startThrottle();
    verify(requestStarters).start();
    verify(storeChecker).start();
    verify(endpoints).maybeStart();
    verify(ipDetectorManager).start();
    verify(executor).execute(runnableCaptor.capture(), eq("Startup completion thread"));
    PrioRunnable startupTask = assertInstanceOf(PrioRunnable.class, runnableCaptor.getValue());
    assertEquals(
        network.crypta.support.io.NativeThread.PriorityLevel.LOW_PRIORITY.value,
        startupTask.getPriority());

    startupTask.run();

    verify(persistentTempBucketFactory).completedInit();
    verify(endpoints).unregisterStartupAlert(alerts);
    assertTrue((Boolean) getField(core, "finishedInitStorage"));
    assertFalse((Boolean) getField(core, "finishingInitStorage"));
  }

  // --- helpers ---
  private static void setField(Object target, String name, Object value) throws Exception {
    setField(target, NodeClientCore.class, name, value);
  }

  private static void setField(Object target, Class<?> declaringClass, String name, Object value)
      throws Exception {
    Field f = declaringClass.getDeclaredField(name);
    f.setAccessible(true);
    f.set(target, value);
  }

  private static Object getField(Object target, String name) throws Exception {
    Field f = NodeClientCore.class.getDeclaredField(name);
    f.setAccessible(true);
    return f.get(target);
  }
}
