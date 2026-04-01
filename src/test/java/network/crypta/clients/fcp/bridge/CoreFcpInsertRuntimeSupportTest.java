package network.crypta.clients.fcp.bridge;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.PersistentTempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpInsertRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private TransferAccessPort transferAccess;
  @Mock private BucketFactory bucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RandomAccessBucket bucket;

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
}
