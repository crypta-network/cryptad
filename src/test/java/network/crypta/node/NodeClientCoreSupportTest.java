package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import network.crypta.client.ArchiveManager;
import network.crypta.client.async.SimpleHealingQueue;
import network.crypta.config.SubConfig;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.fs.AppDirs;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.keys.BlockEncodeParams;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKEncodeException;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.useralerts.DatastoreTooSmallAlert;
import network.crypta.node.useralerts.DiskSpaceUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeClientCoreSupportTest {

  private static final String SERVICE_MODE_PROPERTY = "cryptad.service.mode";
  private static final String CFG_KEY = "cfgKey";
  private static final String DEFAULT_VALUE = "defaultValue";
  private static final String SHORT_DESC = "shortDesc";
  private static final String LONG_DESC = "longDesc";
  private static final String MOVE_ERR = "moveErr";
  private static final String CHK_SAMPLE = "hello-chk";
  private static final byte[] SSK_SAMPLE_BYTES = "ssk-data".getBytes(StandardCharsets.UTF_8);
  private static final String SSK_DOC_NAME = "doc";
  private static final String START_TITLE = "Start";
  private static final String START_LONG = "Long";
  private static final String START_SHORT = "Short";

  @TempDir Path tempDir;

  private String originalServiceMode;
  private boolean serviceModeTouched;

  @AfterEach
  void restoreServiceModeProperty() {
    if (!serviceModeTouched) {
      return;
    }
    if (originalServiceMode == null) {
      System.clearProperty(SERVICE_MODE_PROPERTY);
    } else {
      System.setProperty(SERVICE_MODE_PROPERTY, originalServiceMode);
    }
    serviceModeTouched = false;
    originalServiceMode = null;
  }

  @Test
  void resolveDefaultCacheDir_whenServiceModeUser_returnsAppDirsCacheDir() {
    setServiceModeProperty("user");
    Resolved resolved = new AppDirs().resolve();

    File cacheDir = NodeClientCoreSupport.resolveDefaultCacheDir();

    assertEquals(resolved.getCacheDir().toFile(), cacheDir);
  }

  @Test
  void resolveDefaultDataDir_whenServiceModeUser_returnsAppDirsDataDir() {
    setServiceModeProperty("user");
    Resolved resolved = new AppDirs().resolve();

    File dataDir = NodeClientCoreSupport.resolveDefaultDataDir();

    assertEquals(resolved.getDataDir().toFile(), dataDir);
  }

  @Test
  void resolveDefaultCacheDir_whenServiceModeService_returnsServiceDirsCacheDir() {
    setServiceModeProperty("service");
    Resolved resolved = new ServiceDirs().resolve();

    File cacheDir = NodeClientCoreSupport.resolveDefaultCacheDir();

    assertEquals(resolved.getCacheDir().toFile(), cacheDir);
  }

  @Test
  void resolveDefaultDataDir_whenServiceModeService_returnsServiceDirsDataDir() {
    setServiceModeProperty("service");
    Resolved resolved = new ServiceDirs().resolve();

    File dataDir = NodeClientCoreSupport.resolveDefaultDataDir();

    assertEquals(resolved.getDataDir().toFile(), dataDir);
  }

  @Test
  void setupProgramDirFile_whenMoveErrMsgProvided_returnsResolvedDir() throws Exception {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SubConfig installConfig = mock(SubConfig.class);
    ProgramDirectory programDirectory = new ProgramDirectory();
    programDirectory.move(tempDir.toString());

    when(node.setupProgramDir(
            installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, MOVE_ERR))
        .thenReturn(programDirectory);

    File resolved =
        NodeClientCoreSupport.setupProgramDirFile(
            node, installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, MOVE_ERR);

    assertEquals(tempDir.toFile(), resolved);
    verify(node)
        .setupProgramDir(installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, MOVE_ERR);
  }

  @Test
  void setupProgramDirFile_whenMoveErrMsgOmitted_returnsResolvedDir() throws Exception {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SubConfig installConfig = mock(SubConfig.class);
    ProgramDirectory programDirectory = new ProgramDirectory();
    programDirectory.move(tempDir.toString());

    when(node.setupProgramDir(installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, null))
        .thenReturn(programDirectory);

    File resolved =
        NodeClientCoreSupport.setupProgramDirFile(
            node, installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC);

    assertEquals(tempDir.toFile(), resolved);
    verify(node)
        .setupProgramDir(installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, null);
  }

  @Test
  void setupProgramDirFile_whenNodeThrows_throwsNodeInitException() throws Exception {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SubConfig installConfig = mock(SubConfig.class);
    NodeInitException exception = new NodeInitException(NodeInitException.EXIT_BAD_DIR, "bad dir");

    when(node.setupProgramDir(installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC, null))
        .thenThrow(exception);

    NodeInitException thrown =
        assertThrows(
            NodeInitException.class,
            () ->
                NodeClientCoreSupport.setupProgramDirFile(
                    node, installConfig, CFG_KEY, DEFAULT_VALUE, SHORT_DESC, LONG_DESC));

    assertEquals(exception, thrown);
  }

  @Test
  void createClientContextResources_whenCalled_returnsArchiveAndHealingQueue() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);

    ClientContextResources resources =
        NodeClientCoreSupport.createClientContextResources(
            node, tempBucketFactory, 5, 10L, 15L, 20, 3);

    assertNotNull(resources);
    assertInstanceOf(ArchiveManager.class, resources.getArchiveManager());
    assertInstanceOf(SimpleHealingQueue.class, resources.getHealingQueue());
  }

  @Test
  void buildClientChkBlock_whenUsingEncodedBlock_returnsEquivalentBlock() throws Exception {
    ClientCHKBlock original = encodeSampleChkBlock(CHK_SAMPLE);

    ClientKeyBlock rebuilt =
        NodeClientCoreSupport.buildClientChkBlock(original.getBlock(), original.getClientKey());

    assertInstanceOf(ClientCHKBlock.class, rebuilt);
    assertEquals(original, rebuilt);
  }

  @Test
  void buildClientChkBlock_whenKeyMismatch_throwsChkVerifyException() throws Exception {
    ClientCHKBlock original = encodeSampleChkBlock(CHK_SAMPLE);
    ClientCHKBlock other = encodeSampleChkBlock("other-chk");
    ClientCHK wrongKey = other.getClientKey();

    assertThrows(
        CHKVerifyException.class,
        () -> NodeClientCoreSupport.buildClientChkBlock(original.getBlock(), wrongKey));
  }

  @Test
  void buildClientChkBlock_whenUsingRawData_returnsEquivalentBlock() throws Exception {
    ClientCHKBlock original = encodeSampleChkBlock(CHK_SAMPLE);
    CHKBlock raw = original.getBlock();

    ClientKeyBlock rebuilt =
        NodeClientCoreSupport.buildClientChkBlock(
            raw.getData(), raw.getHeaders(), original.getClientKey());

    assertEquals(original, rebuilt);
  }

  @Test
  void buildClientSskBlock_whenBlockMatchesKey_returnsEquivalentBlock() throws Exception {
    ClientSSKBlock original = encodeSampleSskBlock(42L);

    ClientKeyBlock rebuilt =
        NodeClientCoreSupport.buildClientSskBlock(
            (SSKBlock) original.getBlock(), original.getClientKey());

    assertInstanceOf(ClientSSKBlock.class, rebuilt);
    assertEquals(original, rebuilt);
  }

  @Test
  void buildClientSskBlock_whenKeyMismatch_throwsSskVerifyException() throws Exception {
    ClientSSKBlock original = encodeSampleSskBlock(42L);
    ClientSSKBlock other = encodeSampleSskBlock(43L);

    assertThrows(
        SSKVerifyException.class,
        () ->
            NodeClientCoreSupport.buildClientSskBlock(
                (SSKBlock) original.getBlock(), other.getClientKey()));
  }

  @Test
  void deleteFile_whenFileExists_removesFile() throws IOException {
    Path filePath = tempDir.resolve("delete-me.txt");
    Files.writeString(filePath, "data");

    NodeClientCoreSupport.deleteFile(filePath.toFile());

    assertFalse(Files.exists(filePath));
  }

  @Test
  void deleteFile_whenMissing_throwsIOException() {
    File missing = tempDir.resolve("missing.txt").toFile();

    assertThrows(IOException.class, () -> NodeClientCoreSupport.deleteFile(missing));
  }

  @Test
  void checkRecentlyFailed_whenRoutingReportsFailure_returnsWakeup() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peers = mock(PeerManager.class);
    PeerRoutingSelector routingSelector = mock(PeerRoutingSelector.class);
    Key key = mock(Key.class);
    short maxHtl = 7;
    short decremented = 6;
    long wakeup = 12345L;
    boolean realTime = true;

    when(node.maxHTL()).thenReturn(maxHtl);
    when(node.routing().decrementHTL(null, maxHtl)).thenReturn(decremented);
    when(node.network().peers()).thenReturn(peers);
    when(peers.routingSelector()).thenReturn(routingSelector);
    when(key.toNormalizedDouble()).thenReturn(0.25);
    when(node.network().enableNewLoadManagement(realTime)).thenReturn(true);

    doAnswer(
            invocation -> {
              PeerRoutingSelectionParams params = invocation.getArgument(0);
              params.recentlyFailed().fail(wakeup);
              return null;
            })
        .when(routingSelector)
        .closerPeer(any(PeerRoutingSelectionParams.class));

    long result = NodeClientCoreSupport.checkRecentlyFailed(node, key, realTime);

    assertEquals(wakeup, result);
    verify(node.routing()).decrementHTL(null, maxHtl);
    verify(node.network()).enableNewLoadManagement(realTime);
  }

  @Test
  void checkRecentlyFailed_whenNoFailure_returnsMinusOne() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PeerManager peers = mock(PeerManager.class);
    PeerRoutingSelector routingSelector = mock(PeerRoutingSelector.class);
    Key key = mock(Key.class);
    short maxHtl = 5;
    short decremented = 4;
    boolean realTime = false;

    when(node.maxHTL()).thenReturn(maxHtl);
    when(node.routing().decrementHTL(null, maxHtl)).thenReturn(decremented);
    when(node.network().peers()).thenReturn(peers);
    when(peers.routingSelector()).thenReturn(routingSelector);
    when(key.toNormalizedDouble()).thenReturn(0.7);
    when(node.network().enableNewLoadManagement(realTime)).thenReturn(false);

    when(routingSelector.closerPeer(any(PeerRoutingSelectionParams.class))).thenReturn(null);

    long result = NodeClientCoreSupport.checkRecentlyFailed(node, key, realTime);

    assertEquals(-1L, result);
    verify(node.routing()).decrementHTL(null, maxHtl);
  }

  @Test
  void createStartingUpAlert_whenCalled_populatesAlertFields() {
    UserAlert alert =
        NodeClientCoreSupport.createStartingUpAlert("Title", "Long text", "Short text");

    assertInstanceOf(SimpleUserAlert.class, alert);
    assertEquals("Title", alert.getTitle());
    assertEquals("Long text", alert.getText());
    assertEquals("Short text", alert.getShortText());
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
    assertTrue(alert.userCanDismiss());
  }

  @Test
  void registerFProxyAlerts_whenPersistenceKilled_registersAlertsAndIsValid() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    File persistentTemp = tempDir.resolve("temp").toFile();
    File userDir = tempDir.resolve("user").toFile();

    when(core.getNode()).thenReturn(node);
    when(core.getPersistentTempDir()).thenReturn(persistentTemp);
    when(core.killedDatabase()).thenReturn(true);
    when(node.getUserDir()).thenReturn(userDir);
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(false);

    UserAlert startingUp =
        NodeClientCoreSupport.createStartingUpAlert(START_TITLE, START_LONG, START_SHORT);

    UserAlert persistenceAlert = capturePersistenceAlert(alerts, core, startingUp);

    assertFalse(persistenceAlert.userCanDismiss());
    assertEquals(UserAlert.CRITICAL_ERROR, persistenceAlert.getPriorityClass());
    assertTrue(persistenceAlert.isValid());
  }

  @Test
  void registerFProxyAlerts_whenDatabaseNotKilled_persistenceAlertInvalid() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    when(core.getNode()).thenReturn(node);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.killedDatabase()).thenReturn(false);
    when(node.getUserDir()).thenReturn(tempDir.toFile());

    UserAlert startingUp =
        NodeClientCoreSupport.createStartingUpAlert(START_TITLE, START_LONG, START_SHORT);

    UserAlert persistenceAlert = capturePersistenceAlert(alerts, core, startingUp);

    assertFalse(persistenceAlert.isValid());
  }

  @Test
  void registerFProxyAlerts_whenAwaitingPassword_persistenceAlertInvalid() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    when(core.getNode()).thenReturn(node);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.killedDatabase()).thenReturn(true);
    when(node.getUserDir()).thenReturn(tempDir.toFile());
    when(node.awaitingPassword()).thenReturn(true);

    UserAlert startingUp =
        NodeClientCoreSupport.createStartingUpAlert(START_TITLE, START_LONG, START_SHORT);

    UserAlert persistenceAlert = capturePersistenceAlert(alerts, core, startingUp);

    assertFalse(persistenceAlert.isValid());
  }

  @Test
  void registerFProxyAlerts_whenStopping_persistenceAlertInvalid() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);

    when(core.getNode()).thenReturn(node);
    when(core.getPersistentTempDir()).thenReturn(tempDir.toFile());
    when(core.killedDatabase()).thenReturn(true);
    when(node.getUserDir()).thenReturn(tempDir.toFile());
    when(node.awaitingPassword()).thenReturn(false);
    when(node.isStopping()).thenReturn(true);

    UserAlert startingUp =
        NodeClientCoreSupport.createStartingUpAlert(START_TITLE, START_LONG, START_SHORT);

    UserAlert persistenceAlert = capturePersistenceAlert(alerts, core, startingUp);

    assertFalse(persistenceAlert.isValid());
  }

  @Test
  void registerStorageAlerts_whenCalled_registersDiskAndDatastoreAlerts() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    NodeClientCore core = mock(NodeClientCore.class);

    NodeClientCoreSupport.registerStorageAlerts(alerts, core);

    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);
    verify(alerts, org.mockito.Mockito.times(2)).register(captor.capture());
    List<UserAlert> registered = captor.getAllValues();

    assertInstanceOf(DiskSpaceUserAlert.class, registered.get(0));
    assertInstanceOf(DatastoreTooSmallAlert.class, registered.get(1));
  }

  private void setServiceModeProperty(String value) {
    if (!serviceModeTouched) {
      originalServiceMode = System.getProperty(SERVICE_MODE_PROPERTY);
      serviceModeTouched = true;
    }
    if (value == null) {
      System.clearProperty(SERVICE_MODE_PROPERTY);
    } else {
      System.setProperty(SERVICE_MODE_PROPERTY, value);
    }
  }

  private UserAlert capturePersistenceAlert(
      UserAlertManager alerts, NodeClientCore core, UserAlert startingUp) {
    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);
    InOrder order = inOrder(alerts);

    NodeClientCoreSupport.registerFProxyAlerts(alerts, core, startingUp);

    order.verify(alerts).register(startingUp);
    order.verify(alerts).register(captor.capture());
    return captor.getValue();
  }

  private ClientCHKBlock encodeSampleChkBlock(String content) throws CHKEncodeException {
    byte[] data = content.getBytes(StandardCharsets.UTF_8);
    return ClientCHKBlock.encode(
        data, false, true, (short) -1, data.length, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
  }

  private ClientSSKBlock encodeSampleSskBlock(long seed)
      throws SSKEncodeException, IOException, InvalidCompressionCodecException {
    DummyRandomSource random = new DummyRandomSource(seed);
    InsertableClientSSK key = InsertableClientSSK.createRandom(random, SSK_DOC_NAME);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(SSK_SAMPLE_BYTES);
    return key.encode(
        new BlockEncodeParams(
            bucket,
            false,
            true,
            (short) -1,
            bucket.size(),
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
  }
}
