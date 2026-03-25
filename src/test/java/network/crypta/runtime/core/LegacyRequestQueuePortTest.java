package network.crypta.runtime.core;

import java.lang.reflect.Field;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.RequestQueuePriority;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.Ticker;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyRequestQueuePortTest {

  @Mock private NodeClientCore core;
  @Mock private PersistentJobRunner jobRunner;
  @Mock private Ticker ticker;
  @Mock private ClientContext clientContext;

  @BeforeEach
  void setUp() throws Exception {
    setClientContextField("jobRunner", jobRunner);
    setClientContextField("ticker", ticker);
  }

  @Test
  void isPersistenceDatabaseKilled_whenCoreReportsKilled_delegatesToCore() {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    when(core.killedDatabase()).thenReturn(true);

    assertTrue(port.isPersistenceDatabaseKilled());

    verify(core).killedDatabase();
  }

  @Test
  void submitPersistentJob_whenNormalPriority_mapsToNormPriority() throws Exception {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    stubClientContext();
    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);

    port.submitPersistentJob(() -> false, RequestQueuePriority.NORMAL);

    verify(jobRunner)
        .queue(jobCaptor.capture(), eq(NativeThread.PriorityLevel.NORM_PRIORITY.value));
    assertFalse(jobCaptor.getValue().run(clientContext));
  }

  @Test
  void submitPersistentJob_whenHighPriority_mapsToHighPriority() throws Exception {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    stubClientContext();

    port.submitPersistentJob(() -> true, RequestQueuePriority.HIGH);

    verify(jobRunner).queue(any(), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value));
  }

  @Test
  void submitPersistentJob_whenListingPriority_mapsToLegacyListingPriority() throws Exception {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    stubClientContext();

    port.submitPersistentJob(() -> true, RequestQueuePriority.LISTING);

    verify(jobRunner).queue(any(), eq(NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1));
  }

  @Test
  void scheduleLater_whenCalled_delegatesToTicker() {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    stubClientContext();
    Runnable task = org.mockito.Mockito.mock(Runnable.class);

    port.scheduleLater(task, 123L);

    verify(ticker).queueTimedJob(task, 123L);
  }

  @Test
  void submitPersistentJob_whenPersistenceDisabled_translatesException() throws Exception {
    LegacyRequestQueuePort port = new LegacyRequestQueuePort(core);
    stubClientContext();
    PersistenceDisabledException cause = new PersistenceDisabledException();
    doThrow(cause).when(jobRunner).queue(any(), anyInt());

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> port.submitPersistentJob(() -> false, RequestQueuePriority.NORMAL));

    assertSame(cause, thrown.getCause());
  }

  private void setClientContextField(String fieldName, Object value) throws Exception {
    Field field = ClientContext.class.getField(fieldName);
    field.setAccessible(true);
    field.set(clientContext, value);
  }

  private void stubClientContext() {
    when(core.getClientContext()).thenReturn(clientContext);
  }
}
