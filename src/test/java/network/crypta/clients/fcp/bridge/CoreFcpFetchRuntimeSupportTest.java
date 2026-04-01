package network.crypta.clients.fcp.bridge;

import java.util.function.Supplier;
import network.crypta.client.FetchContext;
import network.crypta.client.async.ClientContext;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpFetchRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private FetchContext fetchContext;
  @Mock private TransferAccessPort firstTransferAccess;
  @Mock private TransferAccessPort secondTransferAccess;
  @Mock private BucketFactory persistentBucketFactory;
  @Mock private BucketFactory transientBucketFactory;
  @Mock private RandomAccessBucket bucket;

  @Test
  void constructor_whenCoreNull_throwsNullPointerException() {
    // Arrange
    Supplier<TransferAccessPort> transferAccessSupplier = () -> firstTransferAccess;

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> new CoreFcpFetchRuntimeSupport(null, transferAccessSupplier));
  }

  @Test
  void constructor_whenTransferAccessSupplierNull_throwsNullPointerException() {
    // Act + Assert
    assertThrows(NullPointerException.class, () -> new CoreFcpFetchRuntimeSupport(core, null));
  }

  @Test
  void clientContext_whenCalled_returnsLiveClientContext() {
    // Arrange
    when(core.getClientContext()).thenReturn(clientContext);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    // Act
    ClientContext actual = support.clientContext();

    // Assert
    assertSame(clientContext, actual);
    verify(core).getClientContext();
  }

  @Test
  void defaultPersistentFetchContext_whenCalled_returnsCoreDefaultFetchContext() {
    // Arrange
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getDefaultPersistentFetchContext()).thenReturn(fetchContext);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    // Act
    FetchContext actual = support.defaultPersistentFetchContext();

    // Assert
    assertSame(fetchContext, actual);
    verify(core).getClientContext();
    verify(clientContext).getDefaultPersistentFetchContext();
  }

  @Test
  void transferAccess_whenSupplierChanges_returnsLatestPortOnEachCall() {
    // Arrange
    @SuppressWarnings("unchecked")
    Supplier<TransferAccessPort> transferAccessSupplier = org.mockito.Mockito.mock(Supplier.class);
    when(transferAccessSupplier.get()).thenReturn(firstTransferAccess, secondTransferAccess);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, transferAccessSupplier);

    // Act
    TransferAccessPort firstActual = support.transferAccess();
    TransferAccessPort secondActual = support.transferAccess();

    // Assert
    assertSame(firstTransferAccess, firstActual);
    assertSame(secondTransferAccess, secondActual);
    verify(transferAccessSupplier, times(2)).get();
  }

  @Test
  void transferAccess_whenSupplierReturnsNull_throwsNullPointerException() {
    // Arrange
    CoreFcpFetchRuntimeSupport support = new CoreFcpFetchRuntimeSupport(core, () -> null);

    // Act + Assert
    assertThrows(NullPointerException.class, support::transferAccess);
  }

  @Test
  void allocateBinaryBlobBucket_whenTransientRequested_usesTransientBucketFactory()
      throws Exception {
    // Arrange
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getBucketFactory(false)).thenReturn(transientBucketFactory);
    when(transientBucketFactory.makeBucket(128L)).thenReturn(bucket);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    // Act
    Bucket actual = support.allocateBinaryBlobBucket(128L, false);

    // Assert
    assertSame(bucket, actual);
    verify(clientContext).getBucketFactory(false);
    verify(transientBucketFactory).makeBucket(128L);
  }

  @Test
  void allocateBinaryBlobBucket_whenPersistentRequested_usesPersistentBucketFactory()
      throws Exception {
    // Arrange
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getBucketFactory(true)).thenReturn(persistentBucketFactory);
    when(persistentBucketFactory.makeBucket(256L)).thenReturn(bucket);
    CoreFcpFetchRuntimeSupport support =
        new CoreFcpFetchRuntimeSupport(core, () -> firstTransferAccess);

    // Act
    Bucket actual = support.allocateBinaryBlobBucket(256L, true);

    // Assert
    assertSame(bucket, actual);
    verify(clientContext).getBucketFactory(true);
    verify(persistentBucketFactory).makeBucket(256L);
  }
}
