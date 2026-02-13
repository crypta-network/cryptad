package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeClientCoreTransfers;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestSender;
import network.crypta.support.RandomGrabArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileInserterSenderTest {

  @Mock SplitFileInserterStorage storage;

  private InsertContext insertCtx;
  private SplitFileInserter parent;

  @BeforeEach
  void setup() throws Exception {
    insertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(1, 0)
                .splitfileSegmentLimits(128, 128)
                .clientOptions(new SimpleEventProducer(), true, true, false)
                .compressorDescriptor(null)
                .redundancy(0, 0)
                .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
                .build());
    // Default flags; individual tests may override
    insertCtx.setCanWriteClientCache(true);
    insertCtx.setLocalRequestOnly(false);
    insertCtx.setForkOnCacheable(true);

    // Create a Mockito mock instance of SplitFileInserter (constructor is heavy)
    parent = mock(SplitFileInserter.class);
    setFinalField(parent, "persistent", true);
    setFinalField(parent, "realTime", false);
    setFinalField(parent, "ctx", insertCtx);
    // Provide a minimal BaseClientPutter parent with priority/client
    BaseClientPutter base = mock(BaseClientPutter.class);
    lenient().when(base.getPriorityClass()).thenReturn((short) 7);
    RequestClient rc = mock(RequestClient.class);
    lenient().when(base.getClient()).thenReturn(rc);
    setFinalField(parent, "parent", base);
  }

  private static void setFinalField(Object target, String name, Object value) throws Exception {
    Class<?> cls = target.getClass();
    Field f = null;
    while (cls != null) {
      try {
        f = cls.getDeclaredField(name);
        break;
      } catch (NoSuchFieldException _) {
        cls = cls.getSuperclass();
      }
    }
    if (f == null) throw new NoSuchFieldException(name);
    f.setAccessible(true);
    f.set(target, value);
  }

  private SplitFileInserterSender newSender() {
    return new SplitFileInserterSender(parent, storage);
  }

  @Test
  void onSuccess_whenBlockInserted_callsSegmentOnInsertedBlock() {
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 5;
    SendableRequestItem token = new BlockInsert(segment, blockNo);
    ClientCHK key = mock(ClientCHK.class);

    sender.onSuccess(token, key, mock(ClientContext.class));

    verify(segment, times(1)).onInsertedBlock(blockNo, key);
  }

  @Test
  void onFailure_whenKeyNumNull_callsStorageFail() {
    SplitFileInserterSender sender = newSender();
    network.crypta.node.LowLevelPutException lpe =
        new network.crypta.node.LowLevelPutException(
            network.crypta.node.LowLevelPutException.INTERNAL_ERROR);

    sender.onFailure(lpe, null, mock(ClientContext.class));

    verify(storage, times(1)).fail(any(InsertException.class));
  }

  @Test
  void onFailure_whenBlockProvided_callsSegmentOnFailureWithConvertedException() {
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 2;
    SendableRequestItem token = new BlockInsert(segment, blockNo);
    network.crypta.node.LowLevelPutException lpe =
        new network.crypta.node.LowLevelPutException(
            network.crypta.node.LowLevelPutException.ROUTE_NOT_FOUND);

    sender.onFailure(lpe, token, mock(ClientContext.class));

    ArgumentCaptor<Integer> blk = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(segment).onFailure(blk.capture(), cap.capture());
    assertEquals(blockNo, blk.getValue().intValue());
    assertEquals(InsertException.InsertExceptionMode.ROUTE_NOT_FOUND, cap.getValue().mode);
  }

  @Test
  void canWriteClientCache_localRequestOnly_forkOnCacheable_reflectInsertContext() {
    insertCtx.setCanWriteClientCache(false);
    insertCtx.setLocalRequestOnly(true);
    insertCtx.setForkOnCacheable(false);
    SplitFileInserterSender sender = newSender();

    assertFalse(sender.canWriteClientCache());
    assertTrue(sender.localRequestOnly());
    assertFalse(sender.forkOnCacheable());
  }

  @Test
  void onEncode_whenStorageNotFinished_setsKeyOnSegment() throws IOException {
    when(storage.hasFinished()).thenReturn(false);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 1;
    SendableRequestItem token = new BlockInsert(segment, blockNo);
    ClientCHK key = mock(ClientCHK.class);

    sender.onEncode(token, key, mock(ClientContext.class));

    verify(segment, times(1)).setKey(blockNo, key);
    verify(storage, times(0)).failOnDiskError(any(IOException.class));
  }

  @Test
  void onEncode_whenStorageFinished_doesNothing() {
    when(storage.hasFinished()).thenReturn(true);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    SendableRequestItem token = new BlockInsert(segment, 0);

    sender.onEncode(token, mock(ClientCHK.class), mock(ClientContext.class));

    verifyNoMoreInteractions(segment);
    verify(storage, times(0)).failOnDiskError(any(IOException.class));
  }

  @Test
  void onEncode_whenSegmentSetKeyThrows_callsFailOnDiskError() throws IOException {
    when(storage.hasFinished()).thenReturn(false);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 3;
    SendableRequestItem token = new BlockInsert(segment, blockNo);
    ClientCHK key = mock(ClientCHK.class);
    IOException ioe = new IOException("boom");
    doThrow(ioe).when(segment).setKey(blockNo, key);

    sender.onEncode(token, key, mock(ClientContext.class));

    verify(storage, times(1)).failOnDiskError(ioe);
  }

  @Test
  void isEmpty_reflectsStorageHasFinished() {
    when(storage.hasFinished()).thenReturn(false, true);
    SplitFileInserterSender sender = newSender();
    assertFalse(sender.isEmpty());
    assertTrue(sender.isEmpty());
  }

  @Test
  void onResume_throwsUnsupportedOperationException() {
    SplitFileInserterSender sender = newSender();
    assertThrows(
        UnsupportedOperationException.class, () -> sender.onResume(mock(ClientContext.class)));
  }

  @Test
  void getPriorityClass_delegatesToBaseParent() {
    SplitFileInserterSender sender = newSender();
    assertEquals(7, sender.getPriorityClass());
  }

  @Test
  void chooseAndCount_delegatesToStorage() {
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    BlockInsert bi = new BlockInsert(segment, 9);
    when(storage.chooseBlock()).thenReturn(bi);
    when(storage.countAllKeys()).thenReturn(42L);
    when(storage.countSendableKeys()).thenReturn(7L);

    assertEquals(bi, sender.chooseKey(null, mock(ClientContext.class)));
    assertEquals(42L, sender.countAllKeys(mock(ClientContext.class)));
    assertEquals(7L, sender.countSendableKeys(mock(ClientContext.class)));
  }

  @Test
  void getSender_returnsBlockingSender() {
    SplitFileInserterSender sender = newSender();
    SendableRequestSender s = sender.getSender(mock(ClientContext.class));
    assertTrue(s.sendIsBlocking());
  }

  @Test
  void isSSK_isFalse() {
    SplitFileInserterSender sender = newSender();
    assertFalse(sender.isSSK());
  }

  @Test
  void schedule_registersInsertWhenNotRegistered() {
    SplitFileInserterSender sender = newSender();
    ClientContext ctx = mock(ClientContext.class);
    ClientRequestScheduler scheduler = mock(ClientRequestScheduler.class);
    lenient().when(ctx.getChkInsertScheduler(false)).thenReturn(scheduler);

    sender.schedule(ctx);

    verify(scheduler, times(1)).registerInsert(sender, true);
  }

  @Test
  void schedule_doesNothingWhenAlreadyRegistered() {
    SplitFileInserterSender sender = newSender();
    sender.setParentGrabArray(mock(RandomGrabArray.class));
    ClientContext ctx = mock(ClientContext.class);
    ClientRequestScheduler scheduler = mock(ClientRequestScheduler.class);
    lenient().when(ctx.getChkInsertScheduler(false)).thenReturn(scheduler);

    sender.schedule(ctx);

    verifyNoMoreInteractions(scheduler);
  }

  @Test
  void getWakeupTime_delegatesToStorage() {
    SplitFileInserterSender sender = newSender();
    ClientContext ctx = mock(ClientContext.class);
    when(storage.getWakeupTime(ctx, 123L)).thenReturn(456L);
    assertEquals(456L, sender.getWakeupTime(ctx, 123L));
  }

  @Test
  void send_whenLocalRequestOnly_storesLocally_andReportsSuccess() throws Exception {
    // Arrange
    insertCtx.setLocalRequestOnly(true);
    insertCtx.setCanWriteClientCache(true);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 11;
    BlockInsert token = new BlockInsert(segment, blockNo);

    ClientCHKBlock clientBlock = mock(ClientCHKBlock.class);
    CHKBlock chkBlock = mock(CHKBlock.class);
    ClientCHK clientKey = mock(ClientCHK.class);
    when(clientBlock.getBlock()).thenReturn(chkBlock);
    when(clientBlock.getClientKey()).thenReturn(clientKey);
    when(segment.encodeBlock(blockNo)).thenReturn(clientBlock);

    // Scheduler/context/job runner
    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    // Node core and local store
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(core.getNode()).thenReturn(node);

    // Build the chosen block with localRequestOnly=true
    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(true, false, true, false, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    verify(segment, times(1)).encodeBlock(blockNo);
    verify(node.storage(), times(1)).store(chkBlock, false, true, true, false);
    // onInsertSuccess -> sender.onSuccess -> segment.onInsertedBlock
    verify(segment, times(1)).onInsertedBlock(blockNo, clientKey);
  }

  @Test
  void send_whenRemote_realPutAndSuccess() throws Exception {
    // Arrange
    insertCtx.setLocalRequestOnly(false);
    insertCtx.setCanWriteClientCache(false);
    insertCtx.setForkOnCacheable(true);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 7;
    BlockInsert token = new BlockInsert(segment, blockNo);

    ClientCHKBlock clientBlock = mock(ClientCHKBlock.class);
    CHKBlock chkBlock = mock(CHKBlock.class);
    ClientCHK clientKey = mock(ClientCHK.class);
    when(clientBlock.getBlock()).thenReturn(chkBlock);
    when(clientBlock.getClientKey()).thenReturn(clientKey);
    when(segment.encodeBlock(blockNo)).thenReturn(clientBlock);

    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    NodeClientCore core = mock(NodeClientCore.class);
    NodeClientCoreTransfers transfers = mock(NodeClientCoreTransfers.class);
    when(core.getTransfers()).thenReturn(transfers);

    // Build a chosen block with localRequestOnly=false, canWriteClientCache=false,
    // forkOnCacheable=true
    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(false, false, false, true, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    verify(transfers, times(1))
        .realPut(
            chkBlock,
            false,
            true,
            Node.PREFER_INSERT_DEFAULT,
            Node.IGNORE_LOW_BACKOFF_DEFAULT,
            false);
    verify(segment, times(1)).onInsertedBlock(blockNo, clientKey);
  }

  @Test
  void send_whenKeyCollision_translatesToInsertExceptionCollision() throws Exception {
    // Arrange
    insertCtx.setLocalRequestOnly(true);
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 4;
    BlockInsert token = new BlockInsert(segment, blockNo);

    ClientCHKBlock clientBlock = mock(ClientCHKBlock.class);
    CHKBlock chkBlock = mock(CHKBlock.class);
    when(clientBlock.getBlock()).thenReturn(chkBlock);
    when(clientBlock.getClientKey()).thenReturn(mock(ClientCHK.class));
    when(segment.encodeBlock(blockNo)).thenReturn(clientBlock);

    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    network.crypta.node.subsystem.NodeStorageSubsystem nodeStorage =
        mock(network.crypta.node.subsystem.NodeStorageSubsystem.class);
    when(core.getNode()).thenReturn(node);
    when(node.storage()).thenReturn(nodeStorage);
    doThrow(new network.crypta.store.KeyCollisionException())
        .when(nodeStorage)
        .store(chkBlock, false, true, true, false);

    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(true, false, true, false, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    ArgumentCaptor<Integer> blk = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(segment).onFailure(blk.capture(), cap.capture());
    assertEquals(blockNo, blk.getValue().intValue());
    assertEquals(InsertException.InsertExceptionMode.COLLISION, cap.getValue().mode);
  }

  @Test
  void send_whenEncodeIOException_callsFailOnDiskError_andReportsFailure() throws Exception {
    // Arrange
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 8;
    BlockInsert token = new BlockInsert(segment, blockNo);
    IOException ioe = new IOException("encode fail");
    when(segment.encodeBlock(blockNo)).thenThrow(ioe);

    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    NodeClientCore core = mock(NodeClientCore.class);

    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(false, false, false, false, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    verify(storage, times(1)).failOnDiskError(ioe);
    ArgumentCaptor<Integer> blk = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(segment).onFailure(blk.capture(), cap.capture());
    assertEquals(blockNo, blk.getValue().intValue());
    assertEquals(InsertException.InsertExceptionMode.INTERNAL_ERROR, cap.getValue().mode);
  }

  @Test
  void send_whenUnexpectedThrowable_reportsFailureInternalError() throws Exception {
    // Arrange
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 13;
    BlockInsert token = new BlockInsert(segment, blockNo);
    when(segment.encodeBlock(blockNo)).thenThrow(new RuntimeException("boom"));

    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    NodeClientCore core = mock(NodeClientCore.class);

    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(false, false, false, false, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    ArgumentCaptor<Integer> blk = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(segment).onFailure(blk.capture(), cap.capture());
    assertEquals(blockNo, blk.getValue().intValue());
    assertEquals(InsertException.InsertExceptionMode.INTERNAL_ERROR, cap.getValue().mode);
  }

  @Test
  void send_whenAssertionError_reportsFailureInternalError() throws Exception {
    // Arrange
    SplitFileInserterSender sender = newSender();
    SplitFileInserterSegmentStorage segment = mock(SplitFileInserterSegmentStorage.class);
    int blockNo = 11;
    BlockInsert token = new BlockInsert(segment, blockNo);
    when(segment.encodeBlock(blockNo)).thenThrow(new AssertionError("boom-assert"));

    ClientContext ctx = mock(ClientContext.class);
    ImmediateRunner runner = new ImmediateRunner(ctx);
    when(ctx.getJobRunner(true)).thenReturn(runner);
    RequestScheduler sched = mock(RequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);

    NodeClientCore core = mock(NodeClientCore.class);

    ChosenBlockImpl chosen =
        new ChosenBlockImpl(
            sender,
            token,
            new KeyAndClientKey(null, null),
            new ChosenBlock.Options(false, false, false, false, false),
            sched,
            true);

    // Act
    boolean accepted = chosen.send(core, sched);

    // Assert
    assertTrue(accepted);
    ArgumentCaptor<Integer> blk = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(segment).onFailure(blk.capture(), cap.capture());
    assertEquals(blockNo, blk.getValue().intValue());
    assertEquals(InsertException.InsertExceptionMode.INTERNAL_ERROR, cap.getValue().mode);
  }

  /** Simple job runner that executes jobs immediately on the calling thread. */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class ImmediateRunner implements PersistentJobRunner {
    private final ClientContext ctx;

    ImmediateRunner(ClientContext ctx) {
      this.ctx = ctx;
    }

    @Override
    public void queue(PersistentJob persistentJob, int threadPriority) {
      persistentJob.run(ctx);
    }

    @Override
    public void queueNormalOrDrop(PersistentJob persistentJob) {
      persistentJob.run(ctx);
    }

    @Override
    public void queueInternal(PersistentJob job, int threadPriority) {
      job.run(ctx);
    }

    @Override
    public void queueInternal(PersistentJob job) {
      job.run(ctx);
    }

    @Override
    public void setCheckpointASAP() {
      // No-op in test stub: ImmediateRunner models a simplified persistence runner
      // and does not schedule or serialize checkpoints for unit tests.
    }

    @Override
    public boolean hasLoaded() {
      return true;
    }

    @Override
    public CheckpointLock lock() {
      // Return a no-op lock; unit tests do not exercise checkpoint serialization.
      return (_, _) -> {
        // No-op unlock in test stub
      };
    }

    @Override
    public boolean newSalt() {
      return false;
    }

    @Override
    public boolean shuttingDown() {
      return false;
    }
  }
}
