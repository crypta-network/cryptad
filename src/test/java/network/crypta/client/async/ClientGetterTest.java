package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.ClientContextResources;
import network.crypta.node.RequestClient;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetterTest {

  // Minimal in-memory RandomAccessBucket for deterministic tests
  private static final class InMemoryBucket implements RandomAccessBucket {
    private final String name;
    private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private boolean readOnly;

    InMemoryBucket(String name) {
      this.name = name;
    }

    byte[] toByteArray() {
      return baos.toByteArray();
    }

    @Override
    public OutputStream getOutputStream() {
      if (readOnly) throw new IllegalStateException("Bucket is read-only");
      return baos;
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      return getOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(baos.toByteArray());
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public long size() {
      return baos.size();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public void setReadOnly() {
      readOnly = true;
    }

    @Override
    public void free() {
      baos.reset();
    }

    @Override
    public RandomAccessBucket createShadow() {
      return null; // not needed in tests
    }

    @Override
    public void onResume(ClientContext context) {
      // no-op for tests
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      throw new UnsupportedOperationException("Not needed in tests");
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("Not needed in tests");
    }
  }

  // Simple direct executor/ticker used by DummyJobRunner in ClientContext
  private static final class DirectExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      job.run();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      job.run();
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }

  private static final class DirectTicker implements Ticker {
    private final PriorityAwareExecutor executor = new DirectExecutor();

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      job.run();
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      job.run();
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return executor;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      runner.run();
    }
  }

  private static ClientContext minimalContext(
      ClientLayerPersister jobRunner,
      LinkFilterExceptionProvider linkFilterExceptionProvider,
      FetchContext defaultPF,
      InsertContext defaultPI,
      USKManager uskManager) {
    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            new DirectExecutor(),
            Mockito.mock(MemoryLimitedJobRunner.class),
            new DirectTicker(),
            Mockito.mock(RandomSource.class),
            new Random(123),
            Mockito.mock(MasterSecret.class)),
        new ClientContextStorageFactories(
            Mockito.mock(PersistentTempBucketFactory.class),
            Mockito.mock(TempBucketFactory.class),
            Mockito.mock(PersistentFileTracker.class),
            Mockito.mock(FilenameGenerator.class),
            Mockito.mock(FilenameGenerator.class),
            Mockito.mock(FileRandomAccessBufferFactory.class),
            Mockito.mock(FileRandomAccessBufferFactory.class)),
        new ClientContextRafFactories(
            Mockito.mock(LockableRandomAccessBufferFactory.class),
            Mockito.mock(LockableRandomAccessBufferFactory.class)),
        new ClientContextServices(
            new ClientContextResources(
                Mockito.mock(ArchiveManager.class), Mockito.mock(HealingQueue.class)),
            uskManager,
            Mockito.mock(RealCompressor.class),
            Mockito.mock(DatastoreChecker.class),
            Mockito.mock(PersistentRequestRoot.class),
            linkFilterExceptionProvider),
        new ClientContextDefaults(defaultPF, defaultPI, Mockito.mock(Config.class)));
  }

  private static FetchContext newFetchContext(boolean filter) {
    // Use reasonable small limits; values are not critical for these tests.
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(16 * 1024, 16 * 1024, 4096)
            .archiveLimits(4, 0, 2, false)
            .retryLimits(1, 1, 0)
            .splitfileLimits(true, 0, 0)
            .behavior(true, false, filter)
            .clientOptions(new SimpleEventProducer(), true, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  @Mock private ClientGetCallback callback;

  @Mock private ClientLayerPersister jobRunner;

  @Mock private LinkFilterExceptionProvider linkFilterExceptionProvider;

  @Mock private USKManager uskManager;

  private ClientGetter newGetter(
      FreenetURI uri, FetchContext fctx, Bucket returnBucket, String forceCompatibleExt) {
    when(callback.getRequestClient())
        .thenReturn(
            new RequestClient() {
              @Override
              public boolean persistent() {
                return false; // transient for these tests
              }

              @Override
              public boolean realTimeFlag() {
                return false;
              }
            });

    return new ClientGetter(
        new ClientGetterRequest(callback, uri, fctx, (short) 1),
        new ClientGetterOptions(returnBucket, null, false, null, forceCompatibleExt));
  }

  private ClientContext newContext(FetchContext fctx, InsertContext ictx) {
    return minimalContext(jobRunner, linkFilterExceptionProvider, fctx, ictx, uskManager);
  }

  @Test
  void onSuccess_streamGeneratorHappyPath_writesBucketAndCallsCallback() throws Exception {
    // Arrange
    FetchContext fctx = newFetchContext(false);
    ClientContext ctx = newContext(fctx, newInsertContext());
    FreenetURI uri = new FreenetURI("KSK", "test");
    InMemoryBucket bucket = new InMemoryBucket("ret");
    ClientGetter getter = newGetter(uri, fctx, bucket, null);
    ClientMetadata meta = new ClientMetadata("text/plain");

    StreamGenerator generator = Mockito.mock(StreamGenerator.class);
    byte[] payload = "hello world".getBytes(StandardCharsets.UTF_8);
    doAnswer(
            inv -> {
              OutputStream os = inv.getArgument(0, OutputStream.class);
              os.write(payload);
              os.flush();
              // Important: close to signal EOF to the worker reading the pipe
              os.close();
              return null;
            })
        .when(generator)
        .writeTo(any(OutputStream.class), any(ClientContext.class));
    // Do not stub size(); ClientGetter does not use it on this path.

    // Act
    getter.onSuccess(generator, meta, null, null, ctx);

    // Assert
    ArgumentCaptor<FetchResult> cap = ArgumentCaptor.forClass(FetchResult.class);
    verify(callback, times(1)).onSuccess(cap.capture(), eq(getter));
    FetchResult res = cap.getValue();
    assertEquals("text/plain", res.getMetadata().getMIMEType());
    assertEquals(payload.length, res.size());
    try (Bucket b = res.asBucket()) {
      assertArrayEquals(payload, ((InMemoryBucket) b).toByteArray());
    }
    // Finished state observable via isFinished()
    assertTrue(getter.isFinished());
  }

  @Test
  void onSuccess_whenIncompatibleExtensionWithFilter_triggersFailure() {
    // Arrange
    FetchContext fctx = newFetchContext(true);
    ClientContext ctx = newContext(fctx, newInsertContext());
    FreenetURI uri = new FreenetURI("KSK", "test");
    InMemoryBucket bucket = new InMemoryBucket("ret");
    ClientGetter getter = newGetter(uri, fctx, bucket, "jpg");
    ClientMetadata meta = new ClientMetadata("text/plain"); // not compatible with .jpg

    // Act
    getter.onSuccess(Mockito.mock(StreamGenerator.class), meta, null, null, ctx);

    // Assert
    ArgumentCaptor<FetchException> exc = ArgumentCaptor.forClass(FetchException.class);
    verify(callback, times(1)).onFailure(exc.capture());
    assertEquals(FetchExceptionMode.MIME_INCOMPATIBLE_WITH_EXTENSION, exc.getValue().mode);
    verify(callback, never()).onSuccess(any(FetchResult.class), any(ClientGetter.class));
  }

  @Test
  void onSuccess_whenStreamGeneratorThrows_propagatesAsBucketErrorFailure() throws Exception {
    // Arrange
    FetchContext fctx = newFetchContext(false);
    ClientContext ctx = newContext(fctx, newInsertContext());
    FreenetURI uri = new FreenetURI("KSK", "test");
    InMemoryBucket bucket = new InMemoryBucket("ret");
    ClientGetter getter = newGetter(uri, fctx, bucket, null);
    ClientMetadata meta = new ClientMetadata("text/plain");

    StreamGenerator generator = Mockito.mock(StreamGenerator.class);
    doAnswer(
            _ -> {
              throw new IOException("boom");
            })
        .when(generator)
        .writeTo(any(OutputStream.class), any(ClientContext.class));
    // Do not stub size(); unused in this path.

    // Act
    getter.onSuccess(generator, meta, null, null, ctx);

    // Assert
    ArgumentCaptor<FetchException> exc = ArgumentCaptor.forClass(FetchException.class);
    verify(callback, times(1)).onFailure(exc.capture());
    assertEquals(FetchExceptionMode.BUCKET_ERROR, exc.getValue().mode);
  }

  @Test
  void onSuccess_fileTruncationHappyPath_movesFileAndCallsCallback(@TempDir File tmpDir)
      throws Exception {
    // Arrange
    FetchContext fctx = newFetchContext(false);
    ClientContext ctx = newContext(fctx, newInsertContext());
    FreenetURI uri = new FreenetURI("KSK", "filetest");
    File completion = new File(tmpDir, "final.dat");
    // Ensure target does not yet exist
    if (completion.exists()) {
      // defensive; shouldn't happen
      assertTrue(completion.delete());
    }
    Bucket returnBucket = new FileBucket(completion, false, true, false, false);
    ClientGetter getter = newGetter(uri, fctx, returnBucket, null);
    ClientMetadata meta = new ClientMetadata("text/plain");

    File temp = new File(tmpDir, "tempfile.dat");
    try (FileOutputStream fos = new FileOutputStream(temp)) {
      fos.write("0123456789".getBytes(StandardCharsets.UTF_8)); // 10 bytes
    }
    long targetLength = 5L;

    // Act
    getter.onSuccess(temp, targetLength, meta, null, ctx);

    // Assert
    ArgumentCaptor<FetchResult> cap = ArgumentCaptor.forClass(FetchResult.class);
    verify(callback, times(1)).onSuccess(cap.capture(), eq(getter));
    FetchResult res = cap.getValue();
    assertEquals(targetLength, res.size());
    assertEquals("text/plain", res.getMetadata().getMIMEType());
    try (Bucket b = res.asBucket()) {
      assertEquals(completion.getAbsolutePath(), ((FileBucket) b).getFile().getPath());
    }
  }

  @Test
  void writeTrivialProgress_whenNoSplitFileFetcher_returnsFalseAndWritesFlag() throws Exception {
    FetchContext fctx = newFetchContext(false);
    ClientGetter getter =
        newGetter(new FreenetURI("KSK", "t"), fctx, new InMemoryBucket("ret"), null);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    boolean ok = getter.writeTrivialProgress(dos);
    dos.flush();

    assertFalse(ok);
    byte[] bytes = baos.toByteArray();
    // writeBoolean(false) writes a single 0 byte
    assertEquals(1, bytes.length);
    assertEquals(0, bytes[0]);
  }

  @Test
  void resumeFromTrivialProgress_whenFlagFalse_returnsFalse() throws Exception {
    FetchContext fctx = newFetchContext(false);
    ClientContext ctx = newContext(fctx, newInsertContext());
    ClientGetter getter =
        newGetter(new FreenetURI("KSK", "t"), fctx, new InMemoryBucket("ret"), null);
    byte[] data = new byte[] {0}; // boolean false
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

    boolean resumed = getter.resumeFromTrivialProgress(dis, ctx);
    assertFalse(resumed);
  }

  @Test
  void simple_accessors_canRestartAndGetURIAndCompletionFileBehaviors() {
    FetchContext fctx = newFetchContext(false);
    InMemoryBucket bucket = new InMemoryBucket("ret");
    FreenetURI uri = new FreenetURI("KSK", "accessors");
    ClientGetter getter = newGetter(uri, fctx, bucket, null);

    // canRestart is true when no state is active
    assertTrue(getter.canRestart());
    // getURI returns the original
    assertEquals(uri, getter.getURI());
    // completion file is null for non-FileBucket
    assertNull(getter.getCompletionFile());
  }

  // no helper methods
}
