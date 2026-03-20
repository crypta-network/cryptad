package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.crypt.RandomSource;
import network.crypta.node.NodeClientCore;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpServerRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private ClientContext clientContext;
  @Mock private TempBucketFactory tempBucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RandomSource randomSource;

  @Test
  void constructor_whenCoreNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFcpServerRuntimeSupport(null));
  }

  @Test
  void clientContext_whenQueried_returnsCoreClientContext() {
    when(core.getClientContext()).thenReturn(clientContext);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);

    assertSame(clientContext, support.clientContext());
  }

  @Test
  void persistenceAndBucketFactories_whenQueried_delegateToCore() {
    when(core.killedDatabase()).thenReturn(true);
    when(core.getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);

    assertTrue(support.persistenceDisabled());
    assertSame(tempBucketFactory, support.tempBucketFactory());
    assertSame(persistentTempBucketFactory, support.persistentTempBucketFactory());
  }

  @Test
  void fillSecureRandom_whenCalled_delegatesToCoreRandomSource() {
    when(core.getRandom()).thenReturn(randomSource);
    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);
    byte[] bytes = new byte[8];

    support.fillSecureRandom(bytes);

    verify(randomSource).nextBytes(bytes);
  }
}
