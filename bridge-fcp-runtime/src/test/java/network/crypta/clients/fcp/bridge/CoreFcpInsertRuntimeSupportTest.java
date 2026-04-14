package network.crypta.clients.fcp.bridge;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ManifestPutter;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientPutDir;
import network.crypta.clients.fcp.ClientPutDirExecution;
import network.crypta.clients.fcp.ClientPutDirExecutionSpec;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.clients.fcp.ClientRequestParams;
import network.crypta.keys.FreenetURI;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

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
  void defaultPersistentInsertContext_whenRequested_returnsClientContextDefault() {
    InsertContext defaultInsertContext = mock(InsertContext.class);
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getDefaultPersistentInsertContext()).thenReturn(defaultInsertContext);
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    InsertContext actual = support.defaultPersistentInsertContext();

    assertSame(defaultInsertContext, actual);
    verify(clientContext).getDefaultPersistentInsertContext();
  }

  @Test
  void transferAccess_whenRequested_returnsSupplierValue() {
    CoreFcpInsertRuntimeSupport support =
        new CoreFcpInsertRuntimeSupport(core, () -> transferAccess);

    assertSame(transferAccess, support.transferAccess());
  }

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

  @Test
  void directoryExecution_whenSerialized_doesNotCaptureEnclosingRuntimeSupport() throws Exception {
    ClientPutDirExecutionSpec executionSpec =
        new ClientPutDirExecutionSpec(
            newSerializableClientPutDir(),
            new ClientRequestParams(
                new FreenetURI("CHK", "target"),
                "put-dir",
                0,
                (short) 1,
                Persistence.REBOOT,
                false,
                null,
                false),
            mock(InsertContext.class, withSettings().serializable()),
            "index.html",
            null);
    ManifestPutter putter = mock(ManifestPutter.class, withSettings().serializable());

    ClientPutDirExecution execution = instantiateDirectoryExecution(executionSpec, putter);

    byte[] serialized = serialize(execution);

    assertTrue(serialized.length > 0);
  }

  private static ClientPutDirExecution instantiateDirectoryExecution(
      ClientPutDirExecutionSpec executionSpec, ManifestPutter putter) throws Exception {
    Class<?> executionClass =
        Class.forName(CoreFcpInsertRuntimeSupport.class.getName() + "$CoreClientPutDirExecution");
    assertTrue(Modifier.isStatic(executionClass.getModifiers()));
    Constructor<?> constructor =
        executionClass.getDeclaredConstructor(
            ClientPutDirExecutionSpec.class, ManifestPutter.class);
    constructor.setAccessible(true);
    return (ClientPutDirExecution) constructor.newInstance(executionSpec, putter);
  }

  private static ClientPutDir newSerializableClientPutDir() throws Exception {
    Constructor<ClientPutDir> constructor = ClientPutDir.class.getDeclaredConstructor();
    constructor.setAccessible(true);
    return constructor.newInstance();
  }

  private static byte[] serialize(Object value) throws Exception {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(value);
      objectOutput.flush();
      return output.toByteArray();
    }
  }
}
