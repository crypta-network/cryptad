package network.crypta.client.async;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableRequest;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BinaryBlobInserterTest {

  @Mock private ClientPutter parent;
  @Mock private RequestClient requestClient;
  @Mock private ClientContext clientContext;
  @Mock private ClientRequestScheduler chkInsertScheduler;

  private static Bucket emptyBlob() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      BinaryBlob.writeBinaryBlobHeader(dos);
      BinaryBlob.writeEndBlob(dos);
    }
    return new SimpleReadOnlyArrayBucket(baos.toByteArray());
  }

  private static CHKBlock newChkBlock() {
    byte[] headers = new byte[CHKBlock.TOTAL_HEADERS_LENGTH];
    headers[0] = 0; // high byte of HASH_SHA256
    headers[1] = 1; // low byte of HASH_SHA256
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    try {
      return CHKBlock.construct(data, headers, Key.ALGO_AES_CTR_256_SHA256);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static Bucket blobWithChkBlocks(int numBlocks) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      BinaryBlob.writeBinaryBlobHeader(dos);
      for (int i = 0; i < numBlocks; i++) {
        CHKBlock block = newChkBlock();
        BinaryBlob.writeKey(dos, block, block.getKey());
      }
      BinaryBlob.writeEndBlob(dos);
    }
    return new SimpleReadOnlyArrayBucket(baos.toByteArray());
  }

  private static InsertContext newInsertCtx(int maxRetries, int rnfsToSuccess) {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(maxRetries, rnfsToSuccess)
            .splitfileSegmentLimits(128, 128)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  @Test
  void constructor_withNoBlocks_maybeFinish_callsOnSuccess() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);

    InsertContext ctx = newInsertCtx(3, 2);
    Bucket blob = emptyBlob();

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    // Constructor should set required blocks to 0 and notify clients once.
    verify(parent).addMustSucceedBlocks(0);
    verify(parent).notifyClients(same(clientContext));

    inserter.maybeFinish(clientContext);
    verify(parent).onSuccess(same(inserter), same(clientContext));
  }

  @Test
  void schedule_withSingleChkBlock_registersWithChkScheduler() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);
    when(clientContext.getChkInsertScheduler(false)).thenReturn(chkInsertScheduler);

    InsertContext ctx = newInsertCtx(3, 2);
    Bucket blob = blobWithChkBlocks(1);

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    inserter.schedule(clientContext);

    verify(chkInsertScheduler).registerInsert(any(SendableRequest.class), eq(false));
  }

  @Test
  void onFailure_whenConsecutiveRNFReached_countsAsSuccessAndCompletes() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);
    when(clientContext.getChkInsertScheduler(false)).thenReturn(chkInsertScheduler);
    when(parent.isCancelled()).thenReturn(false);

    InsertContext ctx = newInsertCtx(10, 2); // 2 RNFs count as success
    Bucket blob = blobWithChkBlocks(1);

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    // Simulate two RNF failures on the single block.
    BinaryBlobInserter.MySendableInsert si = inserter.inserters[0];
    si.onFailure(new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND), clientContext);
    si.onFailure(new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND), clientContext);

    // After threshold, it should count as success and complete the whole insert.
    verify(parent).completedBlock(false, clientContext);
    verify(parent).onSuccess(same(inserter), same(clientContext));
  }

  @Test
  void onFailure_whenRetriesExceedMax_reportsTooManyRetries() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);
    when(clientContext.getChkInsertScheduler(false)).thenReturn(chkInsertScheduler);
    when(parent.isCancelled()).thenReturn(false);

    InsertContext ctx = newInsertCtx(1, 10); // allow only 1 retry; RNF threshold irrelevant
    Bucket blob = blobWithChkBlocks(1);

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    BinaryBlobInserter.MySendableInsert si = inserter.inserters[0];
    // Two internal errors -> retries become 2 > maxRetries (1) -> fail overall.
    si.onFailure(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR), clientContext);
    si.onFailure(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR), clientContext);

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(parent).failedBlock(clientContext);
    verify(parent).onFailure(ex.capture(), same(inserter), same(clientContext));
    assertEquals(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, ex.getValue().getMode());
  }

  @Test
  void onFailure_whenParentCancelled_reportsFatalAndCancelled() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);
    when(clientContext.getChkInsertScheduler(false)).thenReturn(chkInsertScheduler);
    when(parent.isCancelled()).thenReturn(true);

    InsertContext ctx = newInsertCtx(3, 3);
    Bucket blob = blobWithChkBlocks(1);

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    BinaryBlobInserter.MySendableInsert si = inserter.inserters[0];
    si.onFailure(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR), clientContext);

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(parent).fatallyFailedBlock(clientContext);
    verify(parent).onFailure(ex.capture(), same(inserter), same(clientContext));
    assertEquals(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, ex.getValue().getMode());
  }

  @Test
  void cancel_callsParentOnFailureCancelled() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);

    InsertContext ctx = newInsertCtx(3, 3);
    Bucket blob = blobWithChkBlocks(2);

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    inserter.cancel(clientContext);

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(parent).onFailure(ex.capture(), same(inserter), same(clientContext));
    assertEquals(InsertExceptionMode.CANCELLED, ex.getValue().getMode());
    // Ensure it was reported once for the whole inserter.
    verify(parent, times(1))
        .onFailure(any(InsertException.class), same(inserter), same(clientContext));
  }

  @Test
  void onResume_throwsInsertExceptionInternalError() throws Exception {
    when(requestClient.realTimeFlag()).thenReturn(false);

    InsertContext ctx = newInsertCtx(3, 3);
    Bucket blob = emptyBlob();

    BinaryBlobInserter inserter =
        new BinaryBlobInserter(blob, parent, requestClient, false, (short) 1, ctx, clientContext);

    InsertException ex =
        assertThrows(InsertException.class, () -> inserter.onResume(clientContext));
    assertEquals(InsertExceptionMode.INTERNAL_ERROR, ex.getMode());
  }
}
