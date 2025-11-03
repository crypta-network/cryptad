package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.LowLevelPutException;
import network.crypta.node.RequestScheduler;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.node.SendableRequestSender;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ChosenBlockImplTest {

  @Mock private RequestScheduler sched;
  @Mock private ClientContext clientContext;
  @Mock private PersistentJobRunner persistentRunner;
  @Mock private PersistentJobRunner transientRunner;

  @Mock private SendableRequestItem token;
  @Mock private SendableRequestItemKey tokenKey;
  @Mock private Key nodeKey;
  @Mock private ClientKey clientKey;

  @Test
  void isCancelled_whenDelegated_returnsUnderlyingRequestState() {
    // Arrange
    SendableRequest req = org.mockito.Mockito.mock(SendableRequest.class);
    when(req.isCancelled()).thenReturn(true);
    ChosenBlockImpl block =
        new ChosenBlockImpl(
            req, token, nodeKey, clientKey, false, false, false, false, false, sched, false);

    // Act + Assert
    Assertions.assertTrue(block.isCancelled());
  }

  @Test
  void isPersistent_whenConstructed_reflectsFlag() {
    SendableRequest req = org.mockito.Mockito.mock(SendableRequest.class);

    ChosenBlockImpl ptrue =
        new ChosenBlockImpl(
            req, token, nodeKey, clientKey, false, false, false, false, false, sched, true);
    ChosenBlockImpl pfalse =
        new ChosenBlockImpl(
            req, token, nodeKey, clientKey, false, false, false, false, false, sched, false);

    Assertions.assertTrue(ptrue.isPersistent());
    Assertions.assertFalse(pfalse.isPersistent());
  }

  @Test
  void getPriority_whenCalled_delegatesToRequest() {
    SendableRequest req = org.mockito.Mockito.mock(SendableRequest.class);
    when(req.getPriorityClass()).thenReturn((short) 42);
    ChosenBlockImpl block =
        new ChosenBlockImpl(
            req, token, nodeKey, clientKey, false, false, false, false, true, sched, true);

    assertEquals(42, block.getPriority());
  }

  @Test
  void getSender_whenCalled_delegatesToRequest() {
    SendableRequest req = org.mockito.Mockito.mock(SendableRequest.class);
    SendableRequestSender sender = org.mockito.Mockito.mock(SendableRequestSender.class);
    when(req.getSender(clientContext)).thenReturn(sender);
    ChosenBlockImpl block =
        new ChosenBlockImpl(
            req, token, nodeKey, clientKey, false, true, false, false, false, sched, false);

    SendableRequestSender got = block.getSender(clientContext);
    assertSame(sender, got);
    verify(req, times(1)).getSender(clientContext);
  }

  @Test
  void onFailure_put_whenInsert_callsOnFailure_removesRunningInsert_andWakesStarter() {
    // Arrange
    SendableInsert insert = org.mockito.Mockito.mock(SendableInsert.class);
    when(token.getKey()).thenReturn(tokenKey);
    when(clientContext.getJobRunner(true)).thenReturn(persistentRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            insert, token, nodeKey, clientKey, false, false, false, false, false, sched, true);

    LowLevelPutException ex = new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD);

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    // Act: enqueue and then run the captured job
    block.onFailure(ex, clientContext);
    verify(clientContext, times(1)).getJobRunner(true);
    verify(persistentRunner, times(1)).queueNormalOrDrop(captor.capture());

    boolean result = captor.getValue().run(clientContext);

    // Assert: request failure called, insert removed, starter awakened, returns false
    verify(insert, times(1)).onFailure(ex, token, clientContext);
    verify(sched, times(1)).removeRunningInsert(same(insert), same(tokenKey));
    verify(sched, times(1)).wakeStarter();
    Assertions.assertFalse(result);
  }

  @Test
  void onInsertSuccess_whenCalled_callsOnSuccess_removesRunningInsert_andWakesStarter() {
    // Arrange
    SendableInsert insert = org.mockito.Mockito.mock(SendableInsert.class);
    when(token.getKey()).thenReturn(tokenKey);
    when(clientContext.getJobRunner(true)).thenReturn(persistentRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            insert, token, nodeKey, clientKey, false, false, false, false, true, sched, true);

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    // Act
    block.onInsertSuccess(clientKey, clientContext);
    verify(clientContext, times(1)).getJobRunner(true);
    verify(persistentRunner, times(1)).queueNormalOrDrop(captor.capture());

    boolean result = captor.getValue().run(clientContext);

    // Assert
    verify(insert, times(1)).onSuccess(token, clientKey, clientContext);
    verify(sched, times(1)).removeRunningInsert(same(insert), same(tokenKey));
    verify(sched, times(1)).wakeStarter();
    Assertions.assertFalse(result);
  }

  @Test
  void onFailure_get_whenCalled_callsGetFailure_removesFetchingKey_andWakesStarter() {
    // Arrange
    SendableGet get = org.mockito.Mockito.mock(SendableGet.class);
    when(clientContext.getJobRunner(false)).thenReturn(transientRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            get, token, nodeKey, clientKey, true, false, false, false, false, sched, false);

    LowLevelGetException ex = new LowLevelGetException(LowLevelGetException.ROUTE_NOT_FOUND);

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    // Act
    block.onFailure(ex, clientContext);
    verify(clientContext, times(1)).getJobRunner(false);
    verify(transientRunner, times(1)).queueNormalOrDrop(captor.capture());

    boolean result = captor.getValue().run(clientContext);

    // Assert
    verify(get, times(1)).onFailure(ex, token, clientContext);
    verify(sched, times(1)).removeFetchingKey(nodeKey);
    verify(sched, times(1)).wakeStarter();
    Assertions.assertFalse(result);
  }

  @Test
  void onFetchSuccess_whenCalled_marksSucceeded_removesFetchingKey_andWakesStarter() {
    // Arrange
    SendableGet get = org.mockito.Mockito.mock(SendableGet.class);
    when(clientContext.getJobRunner(false)).thenReturn(transientRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            get, token, nodeKey, clientKey, false, true, false, false, false, sched, false);

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    // Act
    block.onFetchSuccess(clientContext);
    verify(clientContext, times(1)).getJobRunner(false);
    verify(transientRunner, times(1)).queueNormalOrDrop(captor.capture());

    boolean result = captor.getValue().run(clientContext);

    // Assert
    verify(sched, times(1)).succeeded(get, false);
    verify(sched, times(1)).removeFetchingKey(nodeKey);
    verify(sched, times(1)).wakeStarter();
    Assertions.assertFalse(result);
  }

  @Test
  void onFailure_get_whenRequestCallbackThrows_removesFetchingKey_andPropagates() {
    // Arrange
    SendableGet get = org.mockito.Mockito.mock(SendableGet.class);
    when(clientContext.getJobRunner(false)).thenReturn(transientRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            get, token, nodeKey, clientKey, false, false, false, false, false, sched, false);

    LowLevelGetException ex = new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, "boom");

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    block.onFailure(ex, clientContext);
    verify(transientRunner, times(1)).queueNormalOrDrop(captor.capture());

    // Cause the request-level callback to throw
    RuntimeException thrown = new RuntimeException("fail");
    org.mockito.Mockito.doThrow(thrown).when(get).onFailure(ex, token, clientContext);

    // Act + Assert: exception propagates out of the job, but removal still happens (finally)
    PersistentJob job = captor.getValue();
    assertThrows(RuntimeException.class, () -> job.run(clientContext));
    verify(sched, times(1)).removeFetchingKey(nodeKey);
    // Wake is after try/finally; since the exception escapes the lambda, wakeStarter is not called.
    verify(sched, never()).wakeStarter();
  }

  @Test
  void onFailure_put_whenRequestCallbackThrows_removesRunningInsert_andPropagates() {
    // Arrange
    SendableInsert insert = org.mockito.Mockito.mock(SendableInsert.class);
    when(token.getKey()).thenReturn(tokenKey);
    when(clientContext.getJobRunner(true)).thenReturn(persistentRunner);

    ChosenBlockImpl block =
        new ChosenBlockImpl(
            insert, token, nodeKey, clientKey, false, false, false, false, false, sched, true);

    LowLevelPutException ex = new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);

    ArgumentCaptor<PersistentJob> captor = ArgumentCaptor.forClass(PersistentJob.class);

    block.onFailure(ex, clientContext);
    verify(persistentRunner, times(1)).queueNormalOrDrop(captor.capture());

    RuntimeException thrown = new RuntimeException("insert-fail");
    org.mockito.Mockito.doThrow(thrown).when(insert).onFailure(ex, token, clientContext);

    PersistentJob job = captor.getValue();
    assertThrows(RuntimeException.class, () -> job.run(clientContext));
    verify(sched, times(1)).removeRunningInsert(same(insert), same(tokenKey));
    verify(sched, never()).wakeStarter();
  }
}
