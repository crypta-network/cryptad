package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.ClientContextResources;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class InsertCompressorTest {

  @Mock private RealCompressor rc;

  private PriorityAwareExecutor inlineExecutor;
  private BucketFactory arrayBucketFactory;

  @BeforeEach
  void setUp() {
    inlineExecutor = new InlineExecutor();
    arrayBucketFactory = new ArrayBucketFactory();
  }

  // Helper executor that runs tasks inline for determinism
  private static final class InlineExecutor implements PriorityAwareExecutor {
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

  // Minimal Test Inserter that records callbacks without performing full scheduling logic
  private static final class TestInserter extends SingleFileInserter {
    CompressionOutput lastOutput;
    ClientContext lastContext;
    COMPRESSOR_TYPE lastStartType;

    TestInserter(
        InsertBlock block, InsertContext ctx, boolean persistent, PutCompletionCallback cb) {
      super(
          new SingleFileInserterParams()
              .withParent(null)
              .withCallback(cb)
              .withBlock(block)
              .withMetadata(false)
              .withCtx(ctx)
              .withExecutionOptions(
                  new InsertExecutionOptions(false, false, null, null, (byte) 0, false))
              .withToken(new Object())
              .withFreeData(false)
              .withTargetFilename(null)
              .withForSplitfile(false)
              .withPersistent(persistent)
              .withOrigDataLength(0L)
              .withOrigCompressedDataLength(0L)
              .withOrigHashes(null)
              .withMetadataThreshold(0L));
    }

    @Override
    public void onStartCompression(COMPRESSOR_TYPE ctype, ClientContext context) {
      lastStartType = ctype;
    }

    @Override
    void onCompressed(CompressionOutput output, ClientContext context) {
      lastOutput = output;
      lastContext = context;
    }
  }

  private static ClientContext makeContext(
      RealCompressor rc,
      PriorityAwareExecutor mainExec,
      ClientLayerPersister jobRunner,
      Config config) {
    // Provide minimal but valid defaults for required ctor parameters; most are unused in tests
    return new ClientContext(
        /*bootID*/ 1L,
        new ClientContextRuntime(jobRunner, mainExec, null, null, null, new Random(0), null),
        new ClientContextStorageFactories(null, null, null, null, null, null, null),
        new ClientContextRafFactories(null, null),
        new ClientContextServices(
            new ClientContextResources(null, null), null, rc, null, null, null),
        new ClientContextDefaults(
            new network.crypta.client.FetchContext(
                FetchContextOptions.builder()
                    .limits(0L, 0L, 0)
                    .archiveLimits(1, 0, 0, false)
                    .retryLimits(0, 0, 0)
                    .splitfileLimits(false, 0, 0)
                    .behavior(false, false, false)
                    .clientOptions(new SimpleEventProducer(), true, false)
                    .filterOverrides(null, null, null)
                    .build()),
            new InsertContext(
                InsertContextOptions.builder()
                    .retryLimits(0, 0)
                    .splitfileSegmentLimits(128, 128)
                    .clientOptions(new SimpleEventProducer(), false, false, false)
                    .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
                    .redundancy(0, 0)
                    .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
                    .build()),
            config));
  }

  private static InsertContext makeInsertCtx(String compressorDescriptor) {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(128, 128)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(compressorDescriptor)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static RandomAccessBucket makeData(byte[] bytes) throws IOException {
    ArrayBucket b = new ArrayBucket();
    try (OutputStream os = b.getOutputStream()) {
      os.write(bytes);
    }
    return b;
  }

  private static Config makeConfigWithNode() {
    Config cfg = new Config();
    cfg.createSubConfig("node");
    return cfg;
  }

  @Test
  void init_whenCalledTwice_enqueuesOnlyOnce() throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);

    InsertContext insertCtx = makeInsertCtx("GZIP");
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter =
        new TestInserter(block, insertCtx, /*persistent*/ false, mock(PutCompletionCallback.class));
    RandomAccessBucket data = makeData("hello world".getBytes(StandardCharsets.UTF_8));
    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            data,
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ false,
            /*generateHashes*/ 0L,
            cfg);

    // Act
    compressor.init(ctx);
    compressor.init(ctx); // second call should be ignored

    // Assert
    verify(rc, times(1)).enqueueNewJob(compressor);
    verifyNoMoreInteractions(rc);
  }

  @Test
  void start_whenCalled_enqueuesJob() throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);
    InsertContext insertCtx = makeInsertCtx("GZIP");
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter =
        new TestInserter(block, insertCtx, false, mock(PutCompletionCallback.class));
    RandomAccessBucket data = makeData("abc".getBytes(StandardCharsets.UTF_8));

    // Act
    InsertCompressor.start(
        ctx,
        inserter,
        data,
        CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
        arrayBucketFactory,
        /*persistent*/ false,
        /*generateHashes*/ 0L);

    // Assert
    verify(rc, times(1)).enqueueNewJob(org.mockito.ArgumentMatchers.any(InsertCompressor.class));
  }

  @Test
  void tryCompress_nonPersistent_success_callsOnCompressed_andHashes_whenRequested()
      throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);
    InsertContext insertCtx = makeInsertCtx("GZIP");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ false, cb);

    // Use easily compressible data larger than one block threshold before compression
    byte[] big = new byte[80_000];
    Arrays.fill(big, (byte) 'A');
    RandomAccessBucket origData = makeData(big);

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            origData,
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ false,
            /*generateHashes*/ HashType.SHA256.bitmask,
            cfg);

    // Act
    compressor.tryCompress(ctx);

    // Assert
    assertNotNull(inserter.lastOutput, "onCompressed should have been called");
    assertSame(ctx, inserter.lastContext);
    assertEquals(COMPRESSOR_TYPE.GZIP, inserter.lastOutput.bestCodec());
    HashResult[] hashes = inserter.lastOutput.hashes();
    assertNotNull(hashes, "hashes should be present when generateHashes != 0");
  }

  @Test
  void tryCompress_persistent_success_schedulesPersistentJobs_andCallsOnCompressed()
      throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    // Execute queued persistent jobs immediately for determinism
    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(makeContext(rc, new InlineExecutor(), jobRunner, cfg));
              return null;
            })
        .when(jobRunner)
        .queue(
            org.mockito.ArgumentMatchers.any(PersistentJob.class),
            org.mockito.ArgumentMatchers.anyInt());

    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);
    InsertContext insertCtx = makeInsertCtx("GZIP");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ true, cb);

    byte[] content = new byte[70_000];
    for (int i = 0; i < content.length; i++) content[i] = (byte) ('0' + (i % 10));
    RandomAccessBucket origData = makeData(content);

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            origData,
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ true,
            /*generateHashes*/ 0L,
            cfg);

    // Act
    compressor.tryCompress(ctx);

    // Assert
    assertNotNull(
        inserter.lastOutput, "onCompressed should have been invoked via persistent queue");
    assertEquals(COMPRESSOR_TYPE.GZIP, inserter.lastOutput.bestCodec());
    verify(jobRunner, times(2))
        .queue(
            org.mockito.ArgumentMatchers.any(PersistentJob.class),
            org.mockito.ArgumentMatchers.anyInt());
  }

  @Test
  void tryCompress_invalidDescriptor_callsFail_nonPersistent() throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);

    // Descriptor with an unknown codec should trigger InvalidCompressionCodecException -> fail()
    InsertContext insertCtx = makeInsertCtx("DOES_NOT_EXIST");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ false, cb);

    RandomAccessBucket origData = makeData("data".getBytes(StandardCharsets.UTF_8));

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            origData,
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ false,
            /*generateHashes*/ 0L,
            cfg);

    // Act
    compressor.tryCompress(ctx);

    // Assert: onFailure should be called with INTERNAL_ERROR (from
    // InvalidCompressionCodecException)
    verify(cb, times(1))
        .onFailure(
            org.mockito.ArgumentMatchers.argThat(
                e -> e.getMode() == InsertExceptionMode.INTERNAL_ERROR),
            org.mockito.ArgumentMatchers.same(inserter),
            org.mockito.ArgumentMatchers.same(ctx));
  }

  @Test
  void tryCompress_ratioCheckFails_thenUsesNextCodec_andHashesCaptured() throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    // Configure node options to force early ratio check and a very high minimum percentage
    SubConfig node = cfg.get("node");
    // Register options so getLong/getInt return configured values
    node.register(
        "amountOfDataToCheckCompressionRatio",
        32768L,
        new Option.Meta(0, false, false, "", ""),
        null,
        true);
    node.register(
        "minimumCompressionPercentage",
        100,
        new Option.Meta(0, false, false, "", ""),
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 100;
          }

          @Override
          public void set(Integer val) {
            // Test stub: this option is not mutated in these tests; setter should not be called.
            throw new UnsupportedOperationException("Not used in tests");
          }
        },
        false);

    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);

    // Two codecs: GZIP first will fail ratio check -> proceed to BZIP2
    InsertContext insertCtx = makeInsertCtx("GZIP,BZIP2");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ false, cb);

    // Use moderately large patterned data; ratio requirement is 100% so GZIP will fail the check
    byte[] input = new byte[90_000];
    for (int i = 0; i < input.length; i++) input[i] = (byte) (i % 251);
    RandomAccessBucket origData = makeData(input);

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            origData,
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ false,
            /*generateHashes*/ HashType.SHA256.bitmask,
            cfg);

    // Act
    compressor.tryCompress(ctx);

    // Assert: compression attempted and hashes were captured even when ratio check aborted
    assertNotNull(inserter.lastOutput);
    assertNotNull(inserter.lastOutput.hashes(), "hashes must be captured when ratio check fails");
    // Ensure the onStartCompression was invoked at least once
    assertNotNull(inserter.lastStartType);
  }

  @Test
  void onFailure_nonPersistent_callsCallbackDirectly() {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);
    InsertContext insertCtx = makeInsertCtx("GZIP");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ false, cb);

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            new ArrayBucket(),
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ false,
            /*generateHashes*/ 0L,
            cfg);

    InsertException ie = new InsertException(InsertExceptionMode.CANCELLED);

    // Act
    compressor.onFailure(ie, null, ctx);

    // Assert
    verify(cb, times(1)).onFailure(ie, inserter, ctx);
  }

  @Test
  void onFailure_persistent_queuesCallback() throws Exception {
    // Arrange
    Config cfg = makeConfigWithNode();
    ClientLayerPersister jobRunner = mock(ClientLayerPersister.class);
    // Immediately run queued jobs for determinism
    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(makeContext(rc, new InlineExecutor(), jobRunner, cfg));
              return null;
            })
        .when(jobRunner)
        .queue(
            org.mockito.ArgumentMatchers.any(PersistentJob.class),
            org.mockito.ArgumentMatchers.anyInt());

    ClientContext ctx = makeContext(rc, inlineExecutor, jobRunner, cfg);
    InsertContext insertCtx = makeInsertCtx("GZIP");
    PutCompletionCallback cb = mock(PutCompletionCallback.class);
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    TestInserter inserter = new TestInserter(block, insertCtx, /*persistent*/ true, cb);

    InsertCompressor compressor =
        new InsertCompressor(
            inserter,
            new ArrayBucket(),
            CHKBlock.MAX_COMPRESSED_DATA_LENGTH,
            arrayBucketFactory,
            /*persistent*/ true,
            /*generateHashes*/ 0L,
            cfg);

    InsertException ie = new InsertException(InsertExceptionMode.CANCELLED);

    // Act
    compressor.onFailure(ie, null, ctx);

    // Assert
    verify(jobRunner, times(1))
        .queue(
            org.mockito.ArgumentMatchers.any(PersistentJob.class),
            org.mockito.ArgumentMatchers.anyInt());
    verify(cb, times(1))
        .onFailure(
            org.mockito.ArgumentMatchers.same(ie),
            org.mockito.ArgumentMatchers.same(inserter),
            org.mockito.ArgumentMatchers.any(ClientContext.class));
  }
}
