package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientGetRestartCoordinatorTest {

  @Test
  void constructor_whenRequestNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ClientGetRestartCoordinator(null));
  }

  @Test
  void canRestart_whenRequestNotFinished_returnsFalseWithoutConsultingGetter() throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    setClientGetField(request, "getter", getter);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.canRestart());
    verifyNoInteractions(getter);
  }

  @Test
  void canRestart_whenRequestAlreadySucceeded_returnsFalseWithoutConsultingGetter()
      throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    setClientGetField(request, "getter", getter);
    setClientRequestField(request, "finished", true);
    request.state().setSucceeded(true);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.canRestart());
    verifyNoInteractions(getter);
  }

  @Test
  void canRestart_whenFinishedAndGetterCanRestart_returnsTrue() throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    when(getter.canRestart()).thenReturn(true);
    setClientGetField(request, "getter", getter);
    setClientRequestField(request, "finished", true);
    request.state().setSucceeded(false);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertTrue(coordinator.canRestart());
    verify(getter).canRestart();
  }

  @Test
  void hasPermRedirect_whenFailureContainsRedirect_returnsTrue() throws Exception {
    ClientGet request = new ClientGet();
    FreenetURI redirect = new FreenetURI("KSK@redirect");
    FetchException exception =
        new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, "redirecting", redirect);
    request.state().setFailedMessage(new GetFailedMessage(exception, "req", false));

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertTrue(coordinator.hasPermRedirect());
  }

  @Test
  void hasPermRedirect_whenFailureMissing_returnsFalse() {
    ClientGet request = new ClientGet();
    request.state().setFailedMessage(null);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.hasPermRedirect());
  }

  @Test
  void restart_whenRequestCannotRestart_returnsFalse() {
    ClientGet request = new ClientGet();
    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.restart(mock(ClientContext.class), false));
  }

  @Test
  void restart_whenFetchContextMissing_returnsFalseWithoutRestartingGetter() throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    when(getter.canRestart()).thenReturn(true);
    setClientGetField(request, "getter", getter);
    setClientRequestField(request, "finished", true);
    request.state().setSucceeded(false);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.restart(mock(ClientContext.class), false));
    verify(getter).canRestart();
    verify(getter, never()).restart(any(), anyBoolean(), any(ClientContext.class));
  }

  @Test
  void restart_whenGetterRestartsWithRedirect_resetsStateAndNotifiesCache() throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);
    AtomicBoolean filterData = new AtomicBoolean(true);
    when(fetchContext.getFilterData()).thenAnswer(_ -> filterData.get());
    doAnswer(
            invocation -> {
              filterData.set(invocation.getArgument(0));
              return null;
            })
        .when(fetchContext)
        .setFilterData(anyBoolean());

    FreenetURI original = new FreenetURI("KSK@original");
    FreenetURI redirect = new FreenetURI("KSK@redirect");
    FetchException failure =
        new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, "redirecting", redirect);

    when(getter.canRestart()).thenReturn(true);
    when(getter.restart(redirect, false, context)).thenReturn(true);

    setClientRequestField(request, "identifier", "req-redirect");
    setClientRequestField(request, "uri", original);
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "finished", true);
    setClientRequestField(request, "started", true);
    setClientGetField(request, "getter", getter);
    setClientGetField(request, "fctx", fetchContext);

    request.state().setSucceeded(false);
    request.state().setFailedMessage(new GetFailedMessage(failure, "req-redirect", false));
    request.state().setProgressPending(mock(SimpleProgressMessage.class));
    request.state().setExpectedHashes(new ExpectedHashes(new HashResult[0], "req-redirect", false));
    Object compatibilityBefore = request.state().getCompatibilityAnalyser();

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertTrue(coordinator.restart(context, true));

    verify(fetchContext).setFilterData(false);
    verify(getter).restart(redirect, false, context);
    verify(cache).updateStarted("req-redirect", redirect);
    verify(cache).updateStarted("req-redirect", true);
    assertFalse(getClientRequestBooleanField(request, "finished"));
    assertTrue(getClientRequestBooleanField(request, "started"));
    assertSame(redirect, request.getURI());
    assertNull(request.state().getFailedMessage());
    assertNull(request.state().getProgressPending());
    assertNull(request.state().getExpectedHashes());
    assertNotNull(request.state().getCompatibilityAnalyser());
    assertNotSame(compatibilityBefore, request.state().getCompatibilityAnalyser());
  }

  @Test
  void restart_whenGetterDeclinesRestart_returnsTrueAndKeepsStartedFalse() throws Exception {
    ClientGet request = new ClientGet();
    ClientGetter getter = mock(ClientGetter.class);
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext context = mock(ClientContext.class);
    FreenetURI original = new FreenetURI("KSK@original-no-restart");

    when(getter.canRestart()).thenReturn(true);
    when(getter.restart(null, true, context)).thenReturn(false);
    when(fetchContext.getFilterData()).thenReturn(true);

    setClientRequestField(request, "uri", original);
    setClientRequestField(request, "finished", true);
    setClientRequestField(request, "started", true);
    setClientGetField(request, "getter", getter);
    setClientGetField(request, "fctx", fetchContext);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertTrue(coordinator.restart(context, false));

    verify(fetchContext, never()).setFilterData(anyBoolean());
    verify(getter).restart(null, true, context);
    assertFalse(getClientRequestBooleanField(request, "finished"));
    assertFalse(getClientRequestBooleanField(request, "started"));
    assertSame(original, request.getURI());
  }

  @Test
  void restart_whenGetterThrowsFetchException_invokesOnFailureAndReturnsFalse() throws Exception {
    ClientGet request = spy(new ClientGet());
    ClientGetter getter = mock(ClientGetter.class);
    FetchContext fetchContext = mock(FetchContext.class);
    ClientContext context = mock(ClientContext.class);
    PersistentRequestClient client = mock(PersistentRequestClient.class);
    RequestStatusCache cache = mock(RequestStatusCache.class);
    when(client.getRequestStatusCache()).thenReturn(cache);

    FetchException failure = new FetchException(FetchExceptionMode.INTERNAL_ERROR, "boom");
    when(getter.canRestart()).thenReturn(true);
    when(getter.restart(null, false, context)).thenThrow(failure);
    when(fetchContext.getFilterData()).thenReturn(false);
    doNothing().when(request).onFailure(any(FetchException.class));

    setClientRequestField(request, "identifier", "req-failure");
    setClientRequestField(request, "client", client);
    setClientRequestField(request, "finished", true);
    setClientGetField(request, "getter", getter);
    setClientGetField(request, "fctx", fetchContext);

    ClientGetRestartCoordinator coordinator = new ClientGetRestartCoordinator(request);

    assertFalse(coordinator.restart(context, false));

    verify(request).onFailure(failure);
    verify(cache).updateStarted(eq("req-failure"), isNull(FreenetURI.class));
    verify(cache, never()).updateStarted("req-failure", true);
  }

  @SuppressWarnings({"java:S3011"})
  private static void setClientRequestField(ClientRequest target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings({"java:S3011"})
  private static void setClientGetField(ClientGet target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = ClientGet.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  @SuppressWarnings({"java:S3011"})
  private static boolean getClientRequestBooleanField(ClientRequest target, String fieldName)
      throws ReflectiveOperationException {
    Field field = ClientRequest.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.getBoolean(target);
  }
}
