package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.TooBigException;
import network.crypta.node.LowLevelGetException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.InsufficientDiskSpaceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SimpleSingleFileFetcherTest {

  @Mock private ClientRequester parent;
  @Mock private GetCompletionCallback rcb;
  @Mock private ClientKey key;
  @Mock private FetchContext fetchCtx;
  @Mock private ClientContext clientContext;
  @Mock private ClientRequestScheduler scheduler;

  @Captor private ArgumentCaptor<FetchException> fetchExceptionCaptor;

  @BeforeEach
  void setup() {
    // Default (lenient to avoid UnnecessaryStubbing for tests not using these paths)
    lenient().when(clientContext.getChkFetchScheduler(false)).thenReturn(scheduler);
    lenient().when(parent.getPriorityClass()).thenReturn((short) 1);
    // parent.persistent() is invoked by SendableGet's constructor; on a Mockito mock this returns
    // default false (no special stubbing required). Keep default isCancelled=false unless tests
    // override it.
  }

  private SimpleSingleFileFetcher newFetcher(
      int maxRetries, boolean isEssential, boolean dontAdd, long token) {
    // Spy to be able to stub unregister() in paths that call unregisterAll().
    SimpleSingleFileFetcher f =
        new SimpleSingleFileFetcher(
            SimpleSingleFileFetcher.Cfg.create(
                    key, maxRetries, fetchCtx, parent, rcb, token, clientContext)
                .essential(isEssential)
                .dontAdd(dontAdd)
                .deleteFetchContext(false)
                .realTime(false));
    return spy(f);
  }

  @Test
  void constructor_whenEssentialAndNotDontAdd_expectAddMustAndNotify() {
    newFetcher(0, true, false, 123L);

    verify(parent).addMustSucceedBlocks(1);
    verify(parent).notifyClients(clientContext);
    // No further interactions required for this constructor behavior
  }

  @Test
  void constructor_whenNonEssentialAndNotDontAdd_expectAddBlockAndNotify() {
    newFetcher(0, false, false, 456L);

    verify(parent).addBlock();
    verify(parent).notifyClients(clientContext);
  }

  @Test
  void getToken_returnsProvidedToken() {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 987654321L);
    assertEquals(987654321L, f.getToken());
  }

  @Test
  void cancel_whenCalled_expectCallbackCancelledAndUnregisterAll() {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 42L);
    // Avoid SendableGet.unregister(context, ...) calling into context.checker by stubbing it out
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    f.cancel(clientContext);

    verify(scheduler).removePendingKeys(f, false);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.CANCELLED, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void onFailure_whenLowLevelNonFatalAndNoRetriesLeft_expectFailedAndCallback() {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 7L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    LowLevelGetException ll = new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND);
    f.onFailure(ll, null, clientContext);

    verify(scheduler).removePendingKeys(f, false);
    verify(parent).failedBlock(clientContext);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.DATA_NOT_FOUND, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void onFailure_whenCancelled_expectCancelCallbackAndFatalCount() {
    SimpleSingleFileFetcher f = newFetcher(1, false, true, 8L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());
    // Simulate already-cancelled state
    f.cancelled = true;

    LowLevelGetException ll = new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND);
    f.onFailure(ll, null, clientContext);

    verify(scheduler).removePendingKeys(f, false);
    verify(parent).fatallyFailedBlock(clientContext);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.CANCELLED, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void onSuccess_whenParentCancelled_expectBucketFreedAndCancelled() {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 9L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());
    when(parent.isCancelled()).thenReturn(true);

    Bucket bucket = mock(Bucket.class);
    FetchResult fr = FetchResult.create(new ClientMetadata(null), bucket);

    f.onSuccess(fr, clientContext);

    verify(bucket).free();
    verify(scheduler).removePendingKeys(f, false);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.CANCELLED, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void onSuccess_whenOk_callsCallbackWithStreamGeneratorAndMetadata() {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 10L);
    when(parent.isCancelled()).thenReturn(false);

    Bucket bucket = mock(Bucket.class);
    ClientMetadata meta = new ClientMetadata("text/plain");
    FetchResult fr = FetchResult.create(meta, bucket);

    // Capture onSuccess parameters
    ArgumentCaptor<StreamGenerator> sgCap = ArgumentCaptor.forClass(StreamGenerator.class);
    ArgumentCaptor<ClientMetadata> mdCap = ArgumentCaptor.forClass(ClientMetadata.class);

    f.onSuccess(fr, clientContext);

    verify(rcb).onSuccess(sgCap.capture(), mdCap.capture(), isNull(), eq(f), eq(clientContext));
    assertNotNull(sgCap.getValue());
    assertEquals(meta, mdCap.getValue());
  }

  @Test
  void extract_whenDecodeSucceeds_returnsBucketAndNoFailureCallback() throws Exception {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 11L);

    BucketFactory bf = mock(BucketFactory.class);
    when(clientContext.getBucketFactory(false)).thenReturn(bf);

    Bucket bucket = mock(Bucket.class);
    ClientKeyBlock block = mock(ClientKeyBlock.class);
    when(block.decode(eq(bf), anyInt(), eq(false))).thenReturn(bucket);

    Bucket ret = f.extract(block, clientContext);
    assertEquals(bucket, ret);
    verifyNoMoreInteractions(rcb);
  }

  @Test
  void extract_whenDecodeThrowsKeyDecode_reportsBlockDecodeError() throws Exception {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 12L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    BucketFactory bf = mock(BucketFactory.class);
    when(clientContext.getBucketFactory(false)).thenReturn(bf);

    ClientKeyBlock block = mock(ClientKeyBlock.class);
    when(block.decode(eq(bf), anyInt(), eq(false))).thenThrow(new KeyDecodeException("bad"));

    Bucket ret = f.extract(block, clientContext);
    assertNull(ret);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.BLOCK_DECODE_ERROR, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void extract_whenDecodeThrowsTooBig_reportsTooBig() throws Exception {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 13L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    BucketFactory bf = mock(BucketFactory.class);
    when(clientContext.getBucketFactory(false)).thenReturn(bf);

    ClientKeyBlock block = mock(ClientKeyBlock.class);
    when(block.decode(eq(bf), anyInt(), eq(false))).thenThrow(new TooBigException("huge"));

    Bucket ret = f.extract(block, clientContext);
    assertNull(ret);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.TOO_BIG, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void extract_whenDecodeThrowsInsufficientDisk_reportsNotEnoughDiskSpace() throws Exception {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 14L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    BucketFactory bf = mock(BucketFactory.class);
    when(clientContext.getBucketFactory(false)).thenReturn(bf);

    ClientKeyBlock block = mock(ClientKeyBlock.class);
    when(block.decode(eq(bf), anyInt(), eq(false))).thenThrow(new InsufficientDiskSpaceException());

    Bucket ret = f.extract(block, clientContext);
    assertNull(ret);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(
        FetchExceptionMode.NOT_ENOUGH_DISK_SPACE, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void extract_whenDecodeThrowsIO_reportsBucketError() throws Exception {
    SimpleSingleFileFetcher f = newFetcher(0, false, true, 15L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    BucketFactory bf = mock(BucketFactory.class);
    when(clientContext.getBucketFactory(false)).thenReturn(bf);

    ClientKeyBlock block = mock(ClientKeyBlock.class);
    when(block.decode(eq(bf), anyInt(), eq(false))).thenThrow(new java.io.IOException("io"));

    Bucket ret = f.extract(block, clientContext);
    assertNull(ret);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.BUCKET_ERROR, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void notFoundInStore_whenCalled_forcesFatalDataNotFound() {
    SimpleSingleFileFetcher f = newFetcher(1, false, true, 16L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    f.notFoundInStore(clientContext);

    verify(scheduler).removePendingKeys(f, false);
    verify(parent).fatallyFailedBlock(clientContext);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.DATA_NOT_FOUND, fetchExceptionCaptor.getValue().getMode());
  }

  @Test
  void onBlockDecodeError_whenCalled_forcesFatalBlockDecodeError() {
    SimpleSingleFileFetcher f = newFetcher(1, false, true, 17L);
    doNothing().when(f).unregister(any(ClientContext.class), anyShort());

    f.onBlockDecodeError(null, clientContext);

    verify(scheduler).removePendingKeys(f, false);
    verify(parent).fatallyFailedBlock(clientContext);
    verify(rcb).onFailure(fetchExceptionCaptor.capture(), eq(f), eq(clientContext));
    assertEquals(FetchExceptionMode.BLOCK_DECODE_ERROR, fetchExceptionCaptor.getValue().getMode());
  }
}
