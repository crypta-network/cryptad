package network.crypta.clients.fcp.bridge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.ClientPutDirExecution;
import network.crypta.clients.fcp.ClientPutDirExecutionSpec;
import network.crypta.clients.fcp.ClientPutExecution;
import network.crypta.clients.fcp.ClientPutExecutionSpec;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.ClientRequestParams;
import network.crypta.clients.fcp.DefaultFcpInsertContextHandle;
import network.crypta.clients.fcp.FcpCompatibilityAnalysis;
import network.crypta.clients.fcp.FcpCompatibilityMode;
import network.crypta.clients.fcp.FcpInsertBehaviorOptions;
import network.crypta.clients.fcp.FcpInsertCallback;
import network.crypta.clients.fcp.FcpInsertContextHandle;
import network.crypta.clients.fcp.FcpInsertContextLimits;
import network.crypta.clients.fcp.FcpInsertOptions;
import network.crypta.clients.fcp.FcpInsertTuningOptions;
import network.crypta.clients.fcp.FcpRequestRuntimeContext;
import network.crypta.clients.fcp.PersistentPutDirEntrySnapshot;
import network.crypta.crypt.CryptoResumeContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.DelayedFreeRandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpInsertRuntimeSupportTest {
  private static final String MIME_TEXT_PLAIN = "text/plain";
  private static final String DISK_FILE_NAME = "disk.dat";
  private static final String TARGET_NAME = "target";
  private static final String REDIRECT_FILE_NAME = "redirect.bin";
  private static final String VALID_CHK =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,"
          + "PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String WRAPPED_FILE_NAME = "wrapped.dat";
  private static final String DEFAULT_NAME = "index.html";
  private static final Supplier<ClientPutDir> CLIENT_PUT_DIR_FACTORY = clientPutDirFactory();
  private static final VarHandle MANIFEST_ELEMENTS_HANDLE = manifestElementsHandle();

  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private TransferAccessPort transferAccess;
  @Mock private BucketFactory bucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RandomAccessBucket bucket;

  @TempDir Path tempDir;

  @Test
  void defaultPersistentInsertContextHandle_whenRequested_returnsDetachedCopyOfClientDefaults() {
    InsertContext defaultInsertContext = mock(InsertContext.class);
    when(defaultInsertContext.isGetCHKOnly()).thenReturn(true);
    when(defaultInsertContext.isDontCompress()).thenReturn(true);
    when(defaultInsertContext.getMaxInsertRetries()).thenReturn(9);
    when(defaultInsertContext.getConsecutiveRNFsCountAsSuccess()).thenReturn(4);
    when(defaultInsertContext.getSplitfileSegmentDataBlocks()).thenReturn(10);
    when(defaultInsertContext.getSplitfileSegmentCheckBlocks()).thenReturn(11);
    when(defaultInsertContext.isCanWriteClientCache()).thenReturn(true);
    when(defaultInsertContext.getCompressorDescriptor()).thenReturn("GZIP");
    when(defaultInsertContext.isForkOnCacheable()).thenReturn(true);
    when(defaultInsertContext.getExtraInsertsSingleBlock()).thenReturn(2);
    when(defaultInsertContext.getExtraInsertsSplitfileHeaderBlock()).thenReturn(3);
    when(defaultInsertContext.getCompatibilityMode())
        .thenReturn(InsertContext.CompatibilityMode.COMPAT_1468);
    when(defaultInsertContext.isLocalRequestOnly()).thenReturn(true);
    when(defaultInsertContext.isEarlyEncode()).thenReturn(true);
    when(defaultInsertContext.isIgnoreUSKDatehints()).thenReturn(true);
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getDefaultPersistentInsertContext()).thenReturn(defaultInsertContext);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    FcpInsertContextHandle actual = support.defaultPersistentInsertContextHandle();

    assertTrue(actual.getCHKOnly());
    assertTrue(actual.isDontCompress());
    assertSame(FcpCompatibilityMode.COMPAT_1468, actual.getCompatibilityMode());
    verify(clientContext).getDefaultPersistentInsertContext();
  }

  @Test
  void transferAccess_whenRequested_returnsSupplierValue() {
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    assertSame(transferAccess, support.transferAccess());
  }

  @Test
  void compatibilityModeValue_whenMappedBetweenBridgeAndRuntime_preservesCodes() {
    assertSame(
        FcpCompatibilityMode.COMPAT_1468,
        CoreFcpInsertRuntimeSupport.toCompatibilityMode(
            InsertContext.CompatibilityMode.COMPAT_1468));
    assertSame(
        InsertContext.CompatibilityMode.COMPAT_1468,
        CoreFcpInsertRuntimeSupport.toRuntimeCompatibilityMode(FcpCompatibilityMode.COMPAT_1468));
    assertSame(FcpCompatibilityMode.COMPAT_1468, FcpCompatibilityMode.COMPAT_CURRENT.intern());
    assertSame(
        InsertContext.CompatibilityMode.COMPAT_1468,
        CoreFcpInsertRuntimeSupport.toRuntimeCompatibilityMode(
            FcpCompatibilityMode.COMPAT_CURRENT));
  }

  @Test
  void compatibilityAnalysis_whenRoundTrippedThroughBridge_preservesRuntimeEncoding()
      throws Exception {
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] cryptoKey = new byte[32];
    cryptoKey[0] = 7;
    cryptoKey[31] = 42;
    analyser.merge(
        InsertContext.CompatibilityMode.COMPAT_1250,
        InsertContext.CompatibilityMode.COMPAT_1468,
        cryptoKey,
        false,
        true);

    FcpCompatibilityAnalysis bridgeAnalysis =
        CoreFcpInsertRuntimeSupport.toCompatibilityAnalysis(analyser);

    assertSame(FcpCompatibilityMode.COMPAT_1250, bridgeAnalysis.min());
    assertSame(FcpCompatibilityMode.COMPAT_1468, bridgeAnalysis.max());
    assertArrayEquals(cryptoKey, bridgeAnalysis.getCryptoKey());
    assertFalse(bridgeAnalysis.dontCompress());
    assertTrue(bridgeAnalysis.definitive());

    byte[] runtimeBytes = serialize(analyser);
    byte[] bridgeBytes = serialize(bridgeAnalysis);
    assertArrayEquals(runtimeBytes, bridgeBytes);

    CompatibilityAnalyser roundTripped =
        CoreFcpInsertRuntimeSupport.toRuntimeCompatibilityAnalyser(bridgeAnalysis);
    assertArrayEquals(runtimeBytes, serialize(roundTripped));
  }

  @Test
  void compatibilityAnalysis_whenReadFromSerializedRuntime_preservesValues() throws Exception {
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] cryptoKey = new byte[32];
    cryptoKey[3] = 9;
    analyser.merge(
        InsertContext.CompatibilityMode.COMPAT_1255,
        InsertContext.CompatibilityMode.COMPAT_1416,
        cryptoKey,
        true,
        false);

    FcpCompatibilityAnalysis read =
        new FcpCompatibilityAnalysis(
            new java.io.DataInputStream(new ByteArrayInputStream(serialize(analyser))));

    assertSame(FcpCompatibilityMode.COMPAT_1255, read.min());
    assertSame(FcpCompatibilityMode.COMPAT_1416, read.max());
    assertArrayEquals(cryptoKey, read.getCryptoKey());
    assertTrue(read.dontCompress());
    assertFalse(read.definitive());
  }

  @Test
  void legacyInsertContextBridge_whenRoundTripped_preservesDetachedValues() throws Exception {
    SimpleEventProducer eventProducer = new SimpleEventProducer();
    FcpInsertContextHandle handle =
        new DefaultFcpInsertContextHandle(
            eventProducer,
            new FcpInsertContextLimits(4, 10, 11),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(true, true, true, 9, true, false, true),
                new FcpInsertTuningOptions(
                    true, true, "GZIP", 2, 3, FcpCompatibilityMode.COMPAT_1468),
                null));

    Object legacyContext = CoreFcpInsertRuntimeSupport.legacyInsertContextForSerialization(handle);
    FcpInsertContextHandle restored =
        CoreFcpInsertRuntimeSupport.wrapLegacyInsertContext(legacyContext);

    assertInstanceOf(InsertContext.class, legacyContext);
    assertSame(eventProducer, restored.eventProducer());
    assertTrue(restored.getCHKOnly());
    assertTrue(restored.isDontCompress());
    assertEquals(9, restored.getMaxInsertRetries());
    assertEquals(4, restored.getConsecutiveRnfsCountAsSuccess());
    assertEquals(10, restored.getSplitfileSegmentDataBlocks());
    assertEquals(11, restored.getSplitfileSegmentCheckBlocks());
    assertTrue(restored.canWriteClientCache());
    assertEquals("GZIP", restored.getCompressorDescriptor());
    assertTrue(restored.forkOnCacheable());
    assertEquals(2, restored.getExtraInsertsSingleBlock());
    assertEquals(3, restored.getExtraInsertsSplitfileHeaderBlock());
    assertSame(FcpCompatibilityMode.COMPAT_1468, restored.getCompatibilityMode());
    assertTrue(restored.localRequestOnly());
    assertTrue(restored.earlyEncode());
    assertTrue(restored.ignoreUSKDatehints());
  }

  @Test
  void bucketFactory_whenPersistenceFlagProvided_returnsClientContextFactory() {
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getBucketFactory(true)).thenReturn(bucketFactory);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    BucketFactory actual = support.bucketFactory(true);

    assertSame(bucketFactory, actual);
    verify(clientContext).getBucketFactory(true);
  }

  @Test
  void createRedirectMetadataBucket_whenRedirectRequested_returnsNewMetadataBucket()
      throws Exception {
    ClientMetadata metadata = new ClientMetadata(MIME_TEXT_PLAIN);
    FreenetURI redirectTarget = new FreenetURI(VALID_CHK);
    RandomAccessBucket redirectBucket = new NullBucket();
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getBucketFactory(true)).thenReturn(bucketFactory);
    when(bucketFactory.makeBucket(-1)).thenReturn(redirectBucket);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    RandomAccessBucket actual =
        support.createRedirectMetadataBucket(metadata, redirectTarget, true);

    assertSame(redirectBucket, actual);
    verify(clientContext).getBucketFactory(true);
  }

  @Test
  void allocatePersistentUploadBucket_whenDatabaseKilled_throwsPersistenceDisabledException() {
    when(core.killedDatabase()).thenReturn(true);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    //noinspection resource
    assertThrows(
        PersistenceDisabledException.class, () -> support.allocatePersistentUploadBucket(64L));
    verifyNoInteractions(persistentTempBucketFactory);
  }

  @Test
  void allocatePersistentUploadBucket_whenDatabaseAvailable_returnsPersistentBucket()
      throws Exception {
    when(core.killedDatabase()).thenReturn(false);
    when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);
    when(persistentTempBucketFactory.makeBucket(128L)).thenReturn(bucket);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    RandomAccessBucket actual = support.allocatePersistentUploadBucket(128L);

    assertSame(bucket, actual);
    //noinspection resource
    verify(persistentTempBucketFactory).makeBucket(128L);
  }

  @Test
  void persistentPutDirEntries_whenManifestContainsDiskDirectAndRedirect_snapshotsDetachedEntries()
      throws Exception {
    Path diskFilePath = Files.createFile(tempDir.resolve(DISK_FILE_NAME));
    FileBucket diskBucket = new FileBucket(diskFilePath.toFile(), false, false, false, false);
    ManifestElement diskElement =
        new ManifestElement(DISK_FILE_NAME, diskBucket, MIME_TEXT_PLAIN, 4);
    ManifestElement directElement =
        new ManifestElement("nested.bin", new NullBucket(8), "application/octet-stream", 8);
    FreenetURI redirectUri = new FreenetURI("CHK", TARGET_NAME);
    ManifestElement redirectElement = new ManifestElement(REDIRECT_FILE_NAME, redirectUri, null);

    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(DISK_FILE_NAME, diskElement);
    Map<String, Object> subdir = new LinkedHashMap<>();
    subdir.put("nested.bin", directElement);
    manifest.put("subdir", subdir);
    manifest.put(REDIRECT_FILE_NAME, redirectElement);

    ClientPutDirExecution execution = newDirectoryExecution(manifest);

    List<PersistentPutDirEntrySnapshot> entries = execution.persistentPutDirEntries();

    assertEquals(3, entries.size());
    assertEquals(
        new PersistentPutDirEntrySnapshot(
            DISK_FILE_NAME,
            network.crypta.clients.fcp.ClientPutBase.UploadFrom.DISK,
            4,
            diskFilePath.toFile().getPath(),
            MIME_TEXT_PLAIN,
            null),
        entries.getFirst());
    assertEquals(
        new PersistentPutDirEntrySnapshot(
            "subdir/nested.bin",
            network.crypta.clients.fcp.ClientPutBase.UploadFrom.DIRECT,
            8,
            null,
            "application/octet-stream",
            null),
        entries.get(1));
    assertEquals(
        new PersistentPutDirEntrySnapshot(
            REDIRECT_FILE_NAME,
            network.crypta.clients.fcp.ClientPutBase.UploadFrom.REDIRECT,
            -1,
            null,
            null,
            redirectUri),
        entries.get(2));
  }

  @Test
  void persistentPutDirEntries_whenBucketWrappedInDelayedFree_usesUnderlyingFileBucket()
      throws Exception {
    Path wrappedFilePath = Files.createFile(tempDir.resolve(WRAPPED_FILE_NAME));
    FileBucket underlyingBucket =
        new FileBucket(wrappedFilePath.toFile(), false, false, false, false);
    PersistentFileTracker tracker = mock(PersistentFileTracker.class);
    when(tracker.commitID()).thenReturn(1L);
    DelayedFreeRandomAccessBucket wrapped =
        new DelayedFreeRandomAccessBucket(tracker, underlyingBucket);
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put(WRAPPED_FILE_NAME, new ManifestElement(WRAPPED_FILE_NAME, wrapped, null, 12));

    List<PersistentPutDirEntrySnapshot> entries =
        newDirectoryExecution(manifest).persistentPutDirEntries();

    assertEquals(1, entries.size());
    PersistentPutDirEntrySnapshot entry = entries.getFirst();
    assertSame(network.crypta.clients.fcp.ClientPutBase.UploadFrom.DISK, entry.uploadFrom());
    assertEquals(wrappedFilePath.toFile().getPath(), entry.filename());
  }

  @Test
  void persistentPutDirEntries_whenBucketTypeUnknown_throwsIllegalStateException()
      throws Exception {
    Map<String, Object> manifest = new LinkedHashMap<>();
    manifest.put("unknown.bin", new ManifestElement("unknown.bin", bucket, null, 2));

    ClientPutDirExecution execution = newDirectoryExecution(manifest);

    assertThrows(IllegalStateException.class, execution::persistentPutDirEntries);
  }

  @Test
  void directoryExecution_whenSerialized_doesNotCaptureEnclosingRuntimeSupport() throws Exception {
    ClientPutDirExecutionSpec executionSpec =
        new ClientPutDirExecutionSpec(
            newSerializableClientPutDir(),
            new ClientRequestParams(
                new FreenetURI("CHK", TARGET_NAME),
                "put-dir",
                0,
                (short) 1,
                Persistence.REBOOT,
                false,
                null,
                false),
            mock(FcpInsertContextHandle.class, withSettings().serializable()),
            DEFAULT_NAME,
            null);
    ManifestPutter putter = mock(ManifestPutter.class, withSettings().serializable());

    ClientPutDirExecution execution = instantiateDirectoryExecution(executionSpec, putter);

    byte[] serialized = serialize(execution);

    assertTrue(serialized.length > 0);
  }

  @Test
  void singleFileExecution_whenLegacyPutterSerialized_keepsSerializableCallbackAdapter()
      throws Exception {
    FcpInsertCallback callback = mock(FcpInsertCallback.class, withSettings().serializable());
    RequestClient requestClient = mock(RequestClient.class, withSettings().serializable());
    RandomAccessBucket uploadBucket = mock(RandomAccessBucket.class, withSettings().serializable());
    when(callback.getRequestClient()).thenReturn(requestClient);
    ClientPutExecutionSpec executionSpec =
        new ClientPutExecutionSpec(
            callback,
            new ClientRequestParams(
                new FreenetURI("CHK", TARGET_NAME),
                "put-file",
                0,
                (short) 1,
                Persistence.REBOOT,
                false,
                null,
                false),
            new DefaultFcpInsertContextHandle(
                new SimpleEventProducer(),
                new FcpInsertContextLimits(4, 10, 11),
                new FcpInsertOptions(
                    new FcpInsertBehaviorOptions(true, true, true, 9, true, false, true),
                    new FcpInsertTuningOptions(
                        true, true, "GZIP", 2, 3, FcpCompatibilityMode.COMPAT_1468),
                    null)),
            uploadBucket,
            new ClientMetadata(MIME_TEXT_PLAIN),
            false,
            new ClientPutExecutionSpec.ExecutionOptions(DEFAULT_NAME, false, null, -1));
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    ClientPutExecution execution = support.createSingleFileExecution(executionSpec);
    Object legacyPutter = execution.legacySerializableRequester();
    byte[] serialized = serialize(legacyPutter);

    assertInstanceOf(ClientPutter.class, legacyPutter);
    assertTrue(serialized.length > 0);
  }

  @Test
  void insertCallbackAdapter_onResume_preservesCryptoResumeContext() throws Exception {
    FcpInsertCallback callback = mock(FcpInsertCallback.class);
    ClientPutCallback adapter = instantiateInsertCallbackAdapter(callback);
    MasterSecret secret = mock(MasterSecret.class);
    when(clientContext.getPersistentMasterSecret()).thenReturn(secret);

    adapter.onResume(clientContext);

    ArgumentCaptor<FcpRequestRuntimeContext> captor =
        ArgumentCaptor.forClass(FcpRequestRuntimeContext.class);
    verify(callback).onResume(captor.capture());
    FcpRequestRuntimeContext requestContext = captor.getValue();
    CryptoResumeContext cryptoContext = assertInstanceOf(CryptoResumeContext.class, requestContext);
    assertSame(secret, cryptoContext.getPersistentMasterSecret());
    assertSame(clientContext, requestContext.persistentRequestRuntimeContext());
  }

  private static ClientPutDirExecution instantiateDirectoryExecution(
      ClientPutDirExecutionSpec executionSpec, ManifestPutter putter)
      throws InvalidObjectException {
    ClientPutDirExecution execution =
        CoreFcpInsertRuntimeSupport.wrapLegacyDirectoryExecution(putter, executionSpec);
    Class<?> executionClass = execution.getClass();
    assertTrue(Modifier.isStatic(executionClass.getModifiers()));
    return execution;
  }

  private static ClientPutDirExecution newDirectoryExecution(Map<String, Object> manifest)
      throws InvalidObjectException {
    ClientPutDir request = newSerializableClientPutDir();
    setManifestElements(request, manifest);
    ClientPutDirExecutionSpec executionSpec =
        new ClientPutDirExecutionSpec(
            request,
            new ClientRequestParams(
                new FreenetURI("CHK", TARGET_NAME),
                "put-dir",
                0,
                (short) 1,
                Persistence.REBOOT,
                false,
                null,
                false),
            mock(FcpInsertContextHandle.class, withSettings().serializable()),
            DEFAULT_NAME,
            null);
    return instantiateDirectoryExecution(
        executionSpec, mock(ManifestPutter.class, withSettings().serializable()));
  }

  private static ClientPutDir newSerializableClientPutDir() {
    return CLIENT_PUT_DIR_FACTORY.get();
  }

  private static void setManifestElements(ClientPutDir request, Map<String, Object> manifest) {
    MANIFEST_ELEMENTS_HANDLE.set(request, manifest);
  }

  private static byte[] serialize(Object value) throws IOException {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(value);
      objectOutput.flush();
      return output.toByteArray();
    }
  }

  private static ClientPutCallback instantiateInsertCallbackAdapter(FcpInsertCallback callback) {
    try {
      Class<?> adapterClass =
          Class.forName(
              "network.crypta.clients.fcp.bridge.CoreFcpInsertRuntimeSupport$CoreInsertCallbackAdapter");
      MethodHandle constructor =
          MethodHandles.privateLookupIn(adapterClass, MethodHandles.lookup())
              .findConstructor(
                  adapterClass, MethodType.methodType(void.class, FcpInsertCallback.class));
      return (ClientPutCallback) constructor.invoke(callback);
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Throwable t) {
      throw new IllegalStateException(t);
    }
  }

  private static byte[] serialize(CompatibilityAnalyser analyser) throws IOException {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output)) {
      analyser.writeTo(dataOutput);
      dataOutput.flush();
      return output.toByteArray();
    }
  }

  private static byte[] serialize(FcpCompatibilityAnalysis analysis) throws IOException {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output)) {
      analysis.writeTo(dataOutput);
      dataOutput.flush();
      return output.toByteArray();
    }
  }

  private static VarHandle manifestElementsHandle() {
    try {
      return MethodHandles.privateLookupIn(ClientPutDir.class, MethodHandles.lookup())
          .findVarHandle(ClientPutDir.class, "manifestElements", Map.class);
    } catch (IllegalAccessException | NoSuchFieldException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static Supplier<ClientPutDir> clientPutDirFactory() {
    try {
      MethodHandle constructor =
          MethodHandles.privateLookupIn(ClientPutDir.class, MethodHandles.lookup())
              .findConstructor(ClientPutDir.class, MethodType.methodType(void.class));
      return () -> instantiateClientPutDir(constructor);
    } catch (IllegalAccessException | NoSuchMethodException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  private static ClientPutDir instantiateClientPutDir(MethodHandle constructor) {
    try {
      return (ClientPutDir) constructor.invoke();
    } catch (RuntimeException | Error e) {
      throw e;
    } catch (Throwable t) {
      throw new IllegalStateException(t);
    }
  }
}
