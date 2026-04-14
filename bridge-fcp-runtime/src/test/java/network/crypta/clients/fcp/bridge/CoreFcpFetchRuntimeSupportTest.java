package network.crypta.clients.fcp.bridge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.function.Supplier;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.async.ClientContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.clients.fcp.ClientGet;
import network.crypta.clients.fcp.ClientGetExecution;
import network.crypta.clients.fcp.ClientGetExecutionSpec;
import network.crypta.clients.fcp.ClientGetFetchConfig;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpFetchRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private TransferAccessPort firstTransferAccess;
  @Mock private TransferAccessPort secondTransferAccess;
  @Mock private BucketFactory transientBucketFactory;
  @Mock private RandomAccessBucket bucket;
  @Mock private ClientGet request;
  @Mock private RequestClient requestClient;
  @Mock private ClientEventListener eventListener;

  @Test
  void constructor_whenCoreNull_throwsNullPointerException() {
    Supplier<TransferAccessPort> transferAccessSupplier = () -> firstTransferAccess;

    assertThrows(
        NullPointerException.class,
        () -> new CoreFcpFetchRuntimeSupport((NodeClientCore) null, transferAccessSupplier));
  }

  @Test
  void constructor_whenTransferAccessSupplierNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFcpFetchRuntimeSupport(core, null));
  }

  @Test
  void defaultPersistentFetchConfig_whenCalled_returnsDetachedCopy() {
    FetchContext fetchContext = baseFetchContext();
    fetchContext.setIgnoreStore(true);
    fetchContext.setFilterData(true);
    fetchContext.setMaxOutputLength(4096L);
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getDefaultPersistentFetchContext()).thenReturn(fetchContext);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    ClientGetFetchConfig actual = support.defaultPersistentFetchConfig();

    assertTrue(actual.getIgnoreStore());
    assertTrue(actual.getFilterData());
    assertEquals(4096L, actual.getMaxOutputLength());
  }

  @Test
  void
      defaultPersistentFetchConfig_whenCallerMutatesDetachedCopy_leavesSourceFetchContextUntouched() {
    FetchContext fetchContext = baseFetchContext();
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getDefaultPersistentFetchContext()).thenReturn(fetchContext);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    ClientGetFetchConfig actual = support.defaultPersistentFetchConfig();
    actual.setFilterData(true);
    actual.setMaxOutputLength(8192L);

    assertFalse(fetchContext.getFilterData());
    assertEquals(1024L, fetchContext.getMaxOutputLength());
  }

  @Test
  void encodeAndDecodeFetchConfig_whenRoundTripped_preservesFields() throws Exception {
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(clientContext, () -> firstTransferAccess);
    ClientGetFetchConfig fetchConfig = sampleFetchConfig();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(output)) {
      support.encodeFetchConfig(fetchConfig, dos);
    }

    ClientGetFetchConfig restored =
        support.decodeFetchConfig(
            new DataInputStream(new ByteArrayInputStream(output.toByteArray())));

    assertEquals(fetchConfig, restored);
  }

  @Test
  void transferAccess_whenSupplierChanges_returnsLatestPortOnEachCall() {
    @SuppressWarnings("unchecked")
    Supplier<TransferAccessPort> transferAccessSupplier = org.mockito.Mockito.mock(Supplier.class);
    when(transferAccessSupplier.get()).thenReturn(firstTransferAccess, secondTransferAccess);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, transferAccessSupplier);

    TransferAccessPort firstActual = support.transferAccess();
    TransferAccessPort secondActual = support.transferAccess();

    assertSame(firstTransferAccess, firstActual);
    assertSame(secondTransferAccess, secondActual);
    verify(transferAccessSupplier, times(2)).get();
  }

  @Test
  void createExecution_whenBinaryBlobNeedsBucket_usesRuntimeBucketFactory() throws Exception {
    when(request.getRequestClient()).thenReturn(requestClient);
    when(clientContext.getBucketFactory(false)).thenReturn(transientBucketFactory);
    when(transientBucketFactory.makeBucket(128L)).thenReturn(bucket);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(clientContext, () -> firstTransferAccess);
    ClientGetExecution execution = createBinaryBlobExecution(support);

    assertNotNull(execution);
    assertNotNull(execution.requester());
    verify(clientContext).getBucketFactory(false);
    //noinspection resource
    verify(transientBucketFactory).makeBucket(128L);
  }

  @Test
  void createExecution_whenBinaryBlobBucketProvided_skipsRuntimeBucketAllocation()
      throws Exception {
    when(request.getRequestClient()).thenReturn(requestClient);
    Bucket providedBucket = org.mockito.Mockito.mock(Bucket.class);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(clientContext, () -> firstTransferAccess);

    ClientGetExecution execution =
        support.createExecution(
            new ClientGetExecutionSpec(
                request,
                FreenetURI.EMPTY_CHK_URI,
                (short) 2,
                binaryBlobFetchConfig(),
                providedBucket,
                false,
                true,
                false,
                null,
                null,
                eventListener));

    assertNotNull(execution.requester());
    verify(clientContext, never()).getBucketFactory(false);
  }

  private ClientGetExecution createBinaryBlobExecution(CoreFcpFetchRuntimeSupport support)
      throws Exception {
    return support.createExecution(
        new ClientGetExecutionSpec(
            request,
            FreenetURI.EMPTY_CHK_URI,
            (short) 2,
            binaryBlobFetchConfig(),
            null,
            false,
            true,
            false,
            null,
            null,
            eventListener));
  }

  private static ClientGetFetchConfig sampleFetchConfig() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setMaxOutputLength(4096L);
    fetchConfig.setMaxTempLength(1024L);
    fetchConfig.setMaxNonSplitfileRetries(7);
    fetchConfig.setMaxSplitfileBlockRetries(8);
    fetchConfig.setIgnoreStore(true);
    fetchConfig.setFilterData(true);
    fetchConfig.setIgnoreUSKDatehints(true);
    fetchConfig.setCharset("UTF-8");
    fetchConfig.setOverrideMime("text/plain");
    fetchConfig.setSchemeHostAndPort("https://localhost:1234");
    return fetchConfig;
  }

  private static ClientGetFetchConfig binaryBlobFetchConfig() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setMaxOutputLength(128L);
    fetchConfig.setMaxTempLength(128L);
    return fetchConfig;
  }

  private static FetchContext baseFetchContext() {
    FetchContextOptions options =
        FetchContextOptions.builder()
            .limits(1024L, 1024L, 1024)
            .archiveLimits(3, 2, 4, false)
            .retryLimits(1, 2, 3)
            .splitfileLimits(true, 10, 5)
            .behavior(true, false, false)
            .clientOptions(new network.crypta.client.events.SimpleEventProducer(), false, true)
            .filterOverrides(null, null, null)
            .build();
    return new FetchContext(options);
  }
}
