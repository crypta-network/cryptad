package network.crypta.client.async;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.events.StartedCompressionEvent;
import network.crypta.keys.FreenetURI;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ArrayBucket;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SingleFileInserterTest {

  @Mock private PutCompletionCallback cb;

  private InsertContext insertCtx;

  // Simple executor that runs tasks inline for determinism
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

  private PriorityAwareExecutor inlineExecutor;

  @BeforeEach
  void setUp() {
    inlineExecutor = new InlineExecutor();
    insertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(0, 0)
                .splitfileSegmentLimits(128, 128)
                .clientOptions(new SimpleEventProducer(), false, false, false)
                .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
                .redundancy(0, 0)
                .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
                .build());
  }

  // Helper for constructing a SingleFileInserter instance used by the
  // onStartCompression test. Returns the configured inserter (sfi).
  private static SingleFileInserter buildSfiForStartCompression(
      BaseClientPutter parentAndCb, PutCompletionCallback cb, InsertContext ctx) {
    InsertBlock block = new InsertBlock(new ArrayBucket(), null, FreenetURI.EMPTY_CHK_URI);
    InsertExecutionOptions execOptions =
        new InsertExecutionOptions(false, false, null, null, (byte) 0, false);
    SingleFileInserterParams params =
        new SingleFileInserterParams()
            .withParent(parentAndCb)
            .withCallback(cb)
            .withBlock(block)
            .withMetadata(false)
            .withCtx(ctx)
            .withExecutionOptions(execOptions)
            .withToken(new Object())
            .withFreeData(false)
            .withTargetFilename(null)
            .withForSplitfile(false)
            .withPersistent(false)
            .withOrigDataLength(0L)
            .withOrigCompressedDataLength(0L)
            .withOrigHashes(null)
            .withMetadataThreshold(0L);
    return new SingleFileInserter(params);
  }

  private static RandomAccessBucket makeData(byte[] bytes) throws Exception {
    ArrayBucket b = new ArrayBucket();
    try (OutputStream os = b.getOutputStream()) {
      os.write(bytes);
    }
    return b;
  }

  private static ClientContext mockContextWithInlineExecution(PriorityAwareExecutor executor) {
    ClientContext context = mock(ClientContext.class);
    // Use lenient stubbing so tests that don't exercise this path don't fail strictness checks
    Mockito.lenient().when(context.getMainExecutor()).thenReturn(executor);
    return context;
  }

  @Test
  void onCompressed_whenUnknownKeyType_expectCallbackFailure() throws Exception {
    // Arrange
    RandomAccessBucket data = makeData("hello".getBytes(StandardCharsets.UTF_8));
    InsertBlock block =
        new InsertBlock(data, null, new FreenetURI("ABC", null, (byte[]) null, null, null));
    InsertExecutionOptions execOptions =
        new InsertExecutionOptions(false, false, null, null, (byte) 0, false);
    SingleFileInserterParams params =
        new SingleFileInserterParams()
            .withParent(mock(BaseClientPutter.class))
            .withCallback(cb)
            .withBlock(block)
            .withMetadata(false)
            .withCtx(insertCtx)
            .withExecutionOptions(execOptions)
            .withToken(new Object())
            .withFreeData(false)
            .withTargetFilename(null)
            .withForSplitfile(false)
            .withPersistent(false)
            .withOrigDataLength(0L)
            .withOrigCompressedDataLength(0L)
            .withOrigHashes(null)
            .withMetadataThreshold(0L);
    SingleFileInserter sfi = new SingleFileInserter(params);

    ClientContext context = mockContextWithInlineExecution(inlineExecutor);
    CompressionOutput output = new CompressionOutput(block.getData(), null, null);

    // Act
    sfi.onCompressed(output, context);

    // Assert
    verify(cb, times(1))
        .onFailure(
            argThat(e -> e.getMode() == InsertExceptionMode.INVALID_URI), same(sfi), same(context));
    assertFalse(sfi.started());
    assertFalse(sfi.cancelled());
  }

  @Test
  void onCompressed_whenFitsInOneBlockWithoutMetadata_schedulesSingleBlock_andNotifies()
      throws Exception {
    // Arrange: CHK with tiny data, no metadata, no archive type
    RandomAccessBucket data = makeData("tiny".getBytes(StandardCharsets.UTF_8));
    InsertBlock block =
        new InsertBlock(data, null, new FreenetURI("CHK", null, (byte[]) null, null, null));

    // Configure insert context to avoid scheduler path and synchronous behavior
    insertCtx.setGetCHKOnly(
        true); // so SingleBlockInserter.schedule() doesn't register with schedulers
    insertCtx.setEarlyEncode(false); // avoid encode path that needs RandomSource

    SingleFileInserter sfi =
        new SingleFileInserter(
            new SingleFileInserterParams()
                .withParent(mock(BaseClientPutter.class))
                .withCallback(cb)
                .withBlock(block)
                .withMetadata(false)
                .withCtx(insertCtx)
                .withExecutionOptions(
                    new InsertExecutionOptions(false, false, null, null, (byte) 0, false))
                .withToken(new Object())
                .withFreeData(false)
                .withTargetFilename(null)
                .withForSplitfile(false)
                .withPersistent(false)
                .withOrigDataLength(0L)
                .withOrigCompressedDataLength(0L)
                .withOrigHashes(null)
                .withMetadataThreshold(0L));

    ClientContext context = mockContextWithInlineExecution(inlineExecutor);
    CompressionOutput output = new CompressionOutput(block.getData(), null, null);

    // Act
    sfi.onCompressed(output, context);

    // Assert: transitioned to a SingleBlockInserter, block set finished, and underlying SBI
    // succeeded
    verify(cb, times(1)).onTransition(same(sfi), any(ClientPutState.class), same(context));
    verify(cb, times(1)).onBlockSetFinished(same(sfi), same(context));
    // Success will be reported by the SingleBlockInserter created above
    verify(cb, times(1)).onSuccess(any(ClientPutState.class), same(context));
    assertTrue(sfi.started());
  }

  @Test
  void cancel_whenCalled_marksCancelled_andNotifiesCancelled_andFreesData() throws Exception {
    // Arrange
    RandomAccessBucket data = makeData("abcdef".getBytes(StandardCharsets.UTF_8));
    InsertBlock block = new InsertBlock(data, null, FreenetURI.EMPTY_CHK_URI);
    SingleFileInserter sfi =
        new SingleFileInserter(
            new SingleFileInserterParams()
                .withParent(mock(BaseClientPutter.class))
                .withCallback(cb)
                .withBlock(block)
                .withMetadata(false)
                .withCtx(insertCtx)
                .withExecutionOptions(
                    new InsertExecutionOptions(false, false, null, null, (byte) 0, false))
                .withToken(new Object())
                .withFreeData(true)
                .withTargetFilename(null)
                .withForSplitfile(false)
                .withPersistent(false)
                .withOrigDataLength(0L)
                .withOrigCompressedDataLength(0L)
                .withOrigHashes(null)
                .withMetadataThreshold(0L));

    ClientContext context = mockContextWithInlineExecution(inlineExecutor);

    // Act
    sfi.cancel(context);

    // Assert
    verify(cb, times(1))
        .onFailure(
            argThat(e -> e.getMode() == InsertExceptionMode.CANCELLED), same(sfi), same(context));
    assertTrue(sfi.cancelled());
    // Data should be freed on the block when freeData=true
    assertNull(block.getData());
  }

  @Test
  void onStartCompression_whenParentIsCallback_emitsStartedCompressionEvent() {
    // Arrange: use a single mock instance as both parent and callback to satisfy (parent == cb)
    BaseClientPutter parentAndCb =
        mock(
            BaseClientPutter.class,
            Mockito.withSettings().extraInterfaces(PutCompletionCallback.class));
    PutCompletionCallback sameCb = (PutCompletionCallback) parentAndCb;

    // Use a mocked event producer to verify the event emission
    ClientEventProducer producer = mock(ClientEventProducer.class);
    insertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(0, 0)
                .splitfileSegmentLimits(128, 128)
                .clientOptions(producer, false, false, false)
                .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
                .redundancy(0, 0)
                .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
                .build());

    SingleFileInserter sfi = buildSfiForStartCompression(parentAndCb, sameCb, insertCtx);

    ClientContext context = mockContextWithInlineExecution(inlineExecutor);

    // Act
    sfi.onStartCompression(COMPRESSOR_TYPE.GZIP, context);

    // Assert: producer called with a StartedCompressionEvent
    verify(producer, times(1))
        .produceEvent(argThat(StartedCompressionEvent.class::isInstance), same(context));
  }

  @Test
  void onResume_whenNotStartedOrCancelled_queuesCompression_andCallsCallbackOnResume()
      throws Exception {
    // Arrange: small CHK so tryCompress() will not compress and will queue a job invoking
    // onCompressed
    RandomAccessBucket data = makeData("xyz".getBytes(StandardCharsets.UTF_8));
    InsertBlock block =
        new InsertBlock(data, null, new FreenetURI("CHK", null, (byte[]) null, null, null));
    insertCtx.setGetCHKOnly(true); // downstream schedule avoids real schedulers

    SingleFileInserter sfi =
        new SingleFileInserter(
            new SingleFileInserterParams()
                .withParent(mock(BaseClientPutter.class))
                .withCallback(cb)
                .withBlock(block)
                .withMetadata(false)
                .withCtx(insertCtx)
                .withExecutionOptions(
                    new InsertExecutionOptions(false, false, null, null, (byte) 0, false))
                .withToken(new Object())
                .withFreeData(false)
                .withTargetFilename(null)
                .withForSplitfile(false)
                .withPersistent(false)
                .withOrigDataLength(0L)
                .withOrigCompressedDataLength(0L)
                .withOrigHashes(null)
                .withMetadataThreshold(0L));

    ClientContext context = mock(ClientContext.class);
    Mockito.lenient().when(context.getMainExecutor()).thenReturn(inlineExecutor);
    // When queueNormalOrDrop is called, invoke the job immediately
    PersistentJobRunner runner = mock(PersistentJobRunner.class);
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0);
              job.run(context);
              return null;
            })
        .when(runner)
        .queueNormalOrDrop(any(PersistentJob.class));
    Mockito.lenient().when(context.getJobRunner(ArgumentMatchers.anyBoolean())).thenReturn(runner);

    // Act
    sfi.onResume(context);

    // Assert: callback notified of resume; job queued once
    verify(cb, times(1)).onResume(context);
    verify(runner, times(1)).queueNormalOrDrop(any(PersistentJob.class));
  }
}
