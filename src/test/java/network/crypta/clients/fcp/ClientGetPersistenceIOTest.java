package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.CompatibilityAnalyser;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.USKManager;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.config.Config;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientContextResources;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetPersistenceIOTest {

  @Test
  void openChecksummed_whenChecksumReturnsStream_readsPayload()
      throws IOException, ChecksumFailedException, StorageFormatException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream payloadBuffer = new ByteArrayOutputStream();
    try (DataOutputStream payloadOut = new DataOutputStream(payloadBuffer)) {
      payloadOut.writeInt(42);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payloadBuffer.toByteArray()));

    DataInputStream result =
        ClientGetPersistenceIO.openChecksummed(input, context, checker, 65536L);

    assertEquals(42, result.readInt());
    verify(checker).checksumReaderWithLength(input, context.tempBucketFactory, 65536);
  }

  @Test
  void readFetchContextOrDefault_whenValidData_returnsRestoredContext()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    FetchContext expected = buildFetchContext();
    byte[] payload = serializeFetchContext(expected);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payload));

    FetchContext restored =
        ClientGetPersistenceIO.readFetchContextOrDefault(input, context, checker);

    assertArrayEquals(payload, serializeFetchContext(restored));
  }

  @Test
  void readFetchContextOrDefault_whenChecksumFails_returnsDefault()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    FetchContext fallback = context.getDefaultPersistentFetchContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenThrow(new ChecksumFailedException());

    FetchContext restored =
        ClientGetPersistenceIO.readFetchContextOrDefault(input, context, checker);

    assertArrayEquals(serializeFetchContext(fallback), serializeFetchContext(restored));
  }

  @Test
  void readInitialMetadata_whenMarkerFalse_returnsNull()
      throws IOException, StorageFormatException, ResumeFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(data)) {
      out.writeBoolean(false);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(data.toByteArray()));

    Bucket result = ClientGetPersistenceIO.readInitialMetadata(input, context, checker);

    assertNull(result);
    verifyNoInteractions(checker);
  }

  @Test
  void readInitialMetadata_whenChecksumFails_throwsStorageFormatException()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(data)) {
      out.writeBoolean(true);
    }
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(data.toByteArray()));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenThrow(new ChecksumFailedException());

    StorageFormatException error =
        assertThrows(
            StorageFormatException.class,
            () -> ClientGetPersistenceIO.readInitialMetadata(input, context, checker));

    assertEquals(ChecksumFailedException.class, error.getCause().getClass());
  }

  @Test
  void restoreCompletedDirectBucketOrNull_whenRestoreSucceeds_returnsBucket()
      throws ResumeFailedException, IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    Bucket expectedBucket = mock(Bucket.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(new byte[0]));

    try (MockedStatic<BucketTools> bucketTools = mockStatic(BucketTools.class)) {
      bucketTools
          .when(
              () ->
                  BucketTools.restoreFrom(
                      any(DataInputStream.class),
                      eq(context.persistentFG),
                      eq(context.getPersistentFileTracker()),
                      eq(context.getPersistentMasterSecret())))
          .thenReturn(expectedBucket);

      Bucket restored =
          ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(input, context, checker);

      assertEquals(expectedBucket, restored);
    }
  }

  @Test
  void restoreCompletedDirectBucketOrNull_whenChecksumFails_returnsNull()
      throws ResumeFailedException, IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenThrow(new ChecksumFailedException());

    Bucket restored =
        ClientGetPersistenceIO.restoreCompletedDirectBucketOrNull(input, context, checker);

    assertNull(restored);
  }

  @Test
  void restoreFailureMessageOrNull_whenValidMessage_returnsMessage()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(true, null, "req-1", RequestIdentifier.RequestType.GET);
    long expectedLength = 123L;
    String expectedType = "text/plain";
    byte[] payload =
        serializeFailureMessage(
            FetchException.FetchExceptionMode.DATA_NOT_FOUND, "missing", false, null);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payload));

    GetFailedMessage restored =
        ClientGetPersistenceIO.restoreFailureMessageOrNull(
            input, reqID, expectedLength, expectedType, context, checker);

    assertNotNull(restored);
    assertEquals(FetchException.FetchExceptionMode.DATA_NOT_FOUND, restored.failureMode);
    assertEquals(reqID.identifier, restored.requestIdentifier);
    assertEquals(reqID.globalQueue, restored.global);
    assertEquals(expectedLength, restored.expectedDataLength);
    assertEquals(expectedType, restored.expectedMimeType);
  }

  @Test
  void restoreFailureMessageOrNull_whenRedirectProvided_readsRedirect()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(true, null, "req-redirect", RequestIdentifier.RequestType.GET);
    String redirectUri =
        "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
    byte[] payload =
        serializeFailureMessage(
            FetchException.FetchExceptionMode.INTERNAL_ERROR, "boom", true, redirectUri);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payload));

    GetFailedMessage restored =
        ClientGetPersistenceIO.restoreFailureMessageOrNull(
            input, reqID, -1L, null, context, checker);

    assertNotNull(restored);
    assertEquals("boom", restored.extraDescription);
    assertTrue(restored.finalizedExpected);
    assertNotNull(restored.redirectURI);
    assertEquals(redirectUri, restored.redirectURI.toString());
  }

  @Test
  void restoreFailureMessageOrNull_whenInvalidPayload_returnsNull()
      throws IOException, ChecksumFailedException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    RequestIdentifier reqID =
        new RequestIdentifier(false, "client", "req-2", RequestIdentifier.RequestType.GET);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));
    byte[] payload = serializeInvalidFailureMessage();

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payload));

    GetFailedMessage restored =
        ClientGetPersistenceIO.restoreFailureMessageOrNull(
            input, reqID, -1L, null, context, checker);

    assertNull(restored);
  }

  @Test
  void restoreInProgressState_whenResumeReturnsTrue_readsTransientFields()
      throws IOException, ChecksumFailedException, StorageFormatException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetter getter = mock(ClientGetter.class);
    ClientGet request = newRequestWithState("req-1", false);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    byte[] payload = serializeTransientProgress(42L, "text/plain");
    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenReturn(new ByteArrayInputStream(payload));
    when(getter.resumeFromTrivialProgress(any(DataInputStream.class), eq(context)))
        .thenReturn(true);

    ClientGetPersistenceIO.restoreInProgressState(input, context, checker, getter, request);

    verify(getter).resumeFromTrivialProgress(any(DataInputStream.class), eq(context));
    assertEquals(42L, request.state().getFoundDataLength());
    assertEquals("text/plain", request.state().getFoundDataMimeType());
  }

  @Test
  void restoreInProgressState_whenChecksumFails_skipsResume()
      throws IOException, ChecksumFailedException, StorageFormatException {
    ClientContext context = newClientContext();
    ChecksumChecker checker = mock(ChecksumChecker.class);
    ClientGetter getter = mock(ClientGetter.class);
    ClientGet request = mock(ClientGet.class);
    DataInputStream input = new DataInputStream(new ByteArrayInputStream(new byte[0]));

    when(checker.checksumReaderWithLength(input, context.tempBucketFactory, 65536))
        .thenThrow(new ChecksumFailedException());

    ClientGetPersistenceIO.restoreInProgressState(input, context, checker, getter, request);

    verifyNoInteractions(getter, request);
  }

  private static ClientContext newClientContext() {
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    PriorityAwareExecutor mainExecutor = mock(PriorityAwareExecutor.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    Ticker ticker = mock(Ticker.class);
    RandomSource strongRandom = mock(RandomSource.class);
    SecureRandom fastWeakRandom = new SecureRandom();
    MasterSecret transientSecret = mock(MasterSecret.class);
    MasterSecret persistentSecret = mock(MasterSecret.class);
    PersistentTempBucketFactory persistentBucketFactory = mock(PersistentTempBucketFactory.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    PersistentFileTracker persistentFileTracker = mock(PersistentFileTracker.class);
    FilenameGenerator fg = mock(FilenameGenerator.class);
    FilenameGenerator persistentFG = mock(FilenameGenerator.class);
    FileRandomAccessBufferFactory fileRAFTransient = mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent = mock(FileRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory tempRAF = mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAF = mock(LockableRandomAccessBufferFactory.class);
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    HealingQueue healingQueue = mock(HealingQueue.class);
    USKManager uskManager = mock(USKManager.class);
    RealCompressor compressor = mock(RealCompressor.class);
    DatastoreChecker datastoreChecker = mock(DatastoreChecker.class);
    PersistentRequestRoot persistentRoot = mock(PersistentRequestRoot.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        mock(LinkFilterExceptionProvider.class);

    FetchContext defaultFetchContext = buildFetchContext();
    InsertContext defaultInsertContext = buildInsertContext();

    ClientContext context =
        new ClientContext(
            1L,
            new ClientContextRuntime(
                jobRunner,
                mainExecutor,
                memoryLimitedJobRunner,
                ticker,
                strongRandom,
                fastWeakRandom,
                transientSecret),
            new ClientContextStorageFactories(
                persistentBucketFactory,
                tempBucketFactory,
                persistentFileTracker,
                fg,
                persistentFG,
                fileRAFTransient,
                fileRAFPersistent),
            new ClientContextRafFactories(tempRAF, persistentRAF),
            new ClientContextServices(
                new ClientContextResources(archiveManager, healingQueue),
                uskManager,
                compressor,
                datastoreChecker,
                persistentRoot,
                linkFilterExceptionProvider),
            new ClientContextDefaults(defaultFetchContext, defaultInsertContext, new Config()));

    context.setPersistentMasterSecret(persistentSecret);
    return context;
  }

  private static FetchContext buildFetchContext() {
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(1024L, 2048L, 4096)
            .archiveLimits(2, 3, 1, false)
            .retryLimits(1, 1, 0)
            .splitfileLimits(true, 16, 16)
            .behavior(true, false, true)
            .clientOptions(new SimpleEventProducer(), false, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static InsertContext buildInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(1, 0)
            .splitfileSegmentLimits(16, 16)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static ClientGet newRequestWithState(String identifier, boolean global) {
    ClientGet request =
        mock(ClientGet.class, Mockito.withSettings().defaultAnswer(Mockito.CALLS_REAL_METHODS));
    setField(request, ClientRequest.class, "identifier", identifier);
    setField(request, ClientRequest.class, "global", global);
    setField(request, ClientGet.class, "state", new ClientGetState(request));
    setField(request, ClientGet.class, "persistenceLock", new ClientGet().persistenceLock());
    return request;
  }

  private static byte[] serializeTransientProgress(long length, String mimeType)
      throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeLong(length);
      if (mimeType != null) {
        out.writeBoolean(true);
        out.writeUTF(mimeType);
      } else {
        out.writeBoolean(false);
      }
      new CompatibilityAnalyser().writeTo(out);
      ClientGetGetterFactory.writeExpectedHashes(out, null);
    }
    return buffer.toByteArray();
  }

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, Class<?> owner, String fieldName, Object value) {
    try {
      Field field = owner.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      LinkageError error = new LinkageError("Failed to set field: " + fieldName);
      error.initCause(e);
      throw error;
    }
  }

  private static byte[] serializeFetchContext(FetchContext context) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      context.writeTo(out);
    }
    return buffer.toByteArray();
  }

  private static byte[] serializeFailureMessage(
      FetchException.FetchExceptionMode mode,
      String description,
      boolean finalizedExpected,
      String redirectUri)
      throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeInt(GetFailedMessage.VERSION);
      out.writeInt(mode.code);
      writePossiblyNull(out, description);
      out.writeBoolean(finalizedExpected);
      writePossiblyNull(out, redirectUri);
    }
    return buffer.toByteArray();
  }

  private static byte[] serializeInvalidFailureMessage() throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(buffer)) {
      out.writeInt(GetFailedMessage.VERSION + 1);
      out.writeInt(FetchException.FetchExceptionMode.DATA_NOT_FOUND.code);
      writePossiblyNull(out, "bad");
      out.writeBoolean(false);
      writePossiblyNull(out, null);
    }
    return buffer.toByteArray();
  }

  private static void writePossiblyNull(DataOutputStream out, String value) throws IOException {
    if (value == null) {
      out.writeBoolean(false);
    } else {
      out.writeBoolean(true);
      out.writeUTF(value);
    }
  }
}
