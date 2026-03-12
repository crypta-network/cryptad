package network.crypta.client.async;

import java.lang.reflect.Field;
import network.crypta.client.FetchContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableRequestItem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKStoreCheckerGetterTest {

  @Test
  @DisplayName("getContext_whenFetcherHasContext_returnsFetcherContext")
  void getContext_whenFetcherHasContext_returnsFetcherContext() {
    // Arrange
    FetchContext expectedContext = mock(FetchContext.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, expectedContext);
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    FetchContext actualContext = getter.getContext();

    // Assert
    assertSame(expectedContext, actualContext);
  }

  @Test
  @DisplayName("getCooldownWakeup_whenCalled_returnsMinusOne")
  void getCooldownWakeup_whenCalled_returnsMinusOne() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    long cooldownWakeup =
        getter.getCooldownWakeup(mock(SendableRequestItem.class), mock(ClientContext.class));

    // Assert
    assertEquals(-1L, cooldownWakeup);
  }

  @Test
  @DisplayName("getKey_whenCalled_returnsNull")
  void getKey_whenCalled_returnsNull() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    ClientKey key = getter.getKey(mock(SendableRequestItem.class));

    // Assert
    assertNull(key);
  }

  @Test
  @DisplayName("chooseKey_whenCalled_returnsNull")
  void chooseKey_whenCalled_returnsNull() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    SendableRequestItem chosen =
        getter.chooseKey(mock(KeysFetchingLocally.class), mock(ClientContext.class));

    // Assert
    assertNull(chosen);
  }

  @Test
  @DisplayName("listKeys_whenCheckerReturnsArray_returnsSameArray")
  void listKeys_whenCheckerReturnsArray_returnsSameArray() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    Key[] expectedKeys = new Key[] {mock(Key.class), mock(Key.class)};
    when(checker.getKeys()).thenReturn(expectedKeys);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    Key[] actualKeys = getter.listKeys();

    // Assert
    assertSame(expectedKeys, actualKeys);
    verify(checker).getKeys();
  }

  @Test
  @DisplayName("countAllKeys_whenFetcherReturnsCount_delegatesToFetcherCountKeys")
  void countAllKeys_whenFetcherReturnsCount_delegatesToFetcherCountKeys() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    when(fetcher.countKeys()).thenReturn(123L);
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(fetcher, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    long count = getter.countAllKeys(context);

    // Assert
    assertEquals(123L, count);
    verify(fetcher).countKeys();
  }

  @Test
  @DisplayName("countSendableKeys_whenCalled_returnsZero")
  void countSendableKeys_whenCalled_returnsZero() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    long count = getter.countSendableKeys(mock(ClientContext.class));

    // Assert
    assertEquals(0L, count);
  }

  @Test
  @DisplayName("getWakeupTime_whenCalled_returnsZero")
  void getWakeupTime_whenCalled_returnsZero() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    long wakeup = getter.getWakeupTime(mock(ClientContext.class), 123L);

    // Assert
    assertEquals(0L, wakeup);
  }

  @Test
  @DisplayName("isSSK_whenCalled_returnsTrue")
  void isSSK_whenCalled_returnsTrue() {
    // Arrange
    USKStoreCheckerGetter getter = newGetter();

    // Act
    boolean isSsk = getter.isSSK();

    // Assert
    assertTrue(isSsk);
  }

  @Test
  @DisplayName("getClientRequest_whenCalled_returnsParent")
  void getClientRequest_whenCalled_returnsParent() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    ClientRequester clientRequest = getter.getClientRequest();

    // Assert
    assertSame(parent, clientRequest);
  }

  @Test
  @DisplayName("getClientGetState_whenCalled_returnsFetcher")
  void getClientGetState_whenCalled_returnsFetcher() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(fetcher, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    ClientGetState state = getter.getClientGetState();

    // Assert
    assertSame(fetcher, state);
  }

  @Test
  @DisplayName("getPriorityClass_whenFetcherReturnsValue_delegatesToFetcher")
  void getPriorityClass_whenFetcherReturnsValue_delegatesToFetcher() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    when(fetcher.getPriorityClass()).thenReturn((short) 7);
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(fetcher, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    short priority = getter.getPriorityClass();

    // Assert
    assertEquals((short) 7, priority);
    verify(fetcher).getPriorityClass();
  }

  @Test
  @DisplayName("getClient_whenParentIsRealTime_returnsRcRt")
  void getClient_whenParentIsRealTime_returnsRcRt() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.realTimeFlag()).thenReturn(true);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    RequestClient client = getter.getClient();

    // Assert
    assertSame(USKManager.rcRT, client);
  }

  @Test
  @DisplayName("getClient_whenParentIsBulk_returnsRcBulk")
  void getClient_whenParentIsBulk_returnsRcBulk() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.realTimeFlag()).thenReturn(false);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    RequestClient client = getter.getClient();

    // Assert
    assertSame(USKManager.rcBulk, client);
  }

  @Test
  @DisplayName("isCancelled_whenNotDoneAndFetcherNotCancelled_returnsFalse")
  void isCancelled_whenNotDoneAndFetcherNotCancelled_returnsFalse() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    when(callbacks.isCancelled()).thenReturn(false);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    boolean cancelled = getter.isCancelled();

    // Assert
    assertFalse(cancelled);
    verify(callbacks).isCancelled();
  }

  @Test
  @DisplayName("isCancelled_whenFetcherCancelled_returnsTrue")
  void isCancelled_whenFetcherCancelled_returnsTrue() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    when(callbacks.isCancelled()).thenReturn(true);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    boolean cancelled = getter.isCancelled();

    // Assert
    assertTrue(cancelled);
    verify(callbacks).isCancelled();
  }

  @ParameterizedTest(name = "toNetwork={0}, delegateReturn={1}")
  @CsvSource({"true,true", "true,false", "false,true", "false,false"})
  @DisplayName("preRegister_whenCalled_delegatesAndMarksDone")
  void preRegister_whenCalled_delegatesAndMarksDone(boolean toNetwork, boolean delegateReturn) {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);
    when(coordinator.preRegisterStoreChecker(any(), same(checker), same(context), eq(toNetwork)))
        .thenReturn(delegateReturn);

    // Act
    boolean actualReturn = getter.preRegister(context, toNetwork);

    // Assert
    assertEquals(delegateReturn, actualReturn);
    assertTrue(getter.isCancelled(), "preRegister must mark the SendableGet as done in all cases");
    verify(coordinator)
        .preRegisterStoreChecker(same(getter), same(checker), same(context), eq(toNetwork));
  }

  @Test
  @DisplayName("preRegister_whenFetcherThrows_propagatesAndMarksDone")
  void preRegister_whenFetcherThrows_propagatesAndMarksDone() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);
    when(coordinator.preRegisterStoreChecker(any(), same(checker), same(context), eq(true)))
        .thenThrow(new IllegalStateException("boom"));

    // Act
    IllegalStateException thrown =
        assertThrows(IllegalStateException.class, () -> getter.preRegister(context, true));

    // Assert
    assertEquals("boom", thrown.getMessage());
    assertTrue(getter.isCancelled(), "preRegister must mark done=true even when it throws");
  }

  @Test
  @DisplayName("onFailure_whenCalled_doesNotThrowAndDoesNotMarkDone")
  void onFailure_whenCalled_doesNotThrowAndDoesNotMarkDone() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    when(callbacks.isCancelled()).thenReturn(false);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    USKStoreCheckerGetter getter =
        new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);

    // Act
    getter.onFailure(mock(LowLevelGetException.class), null, null);

    // Assert
    assertFalse(getter.isCancelled(), "onFailure is expected to be a no-op for store checking");
    verify(callbacks).isCancelled();
  }

  @Test
  @DisplayName("constructor_whenParentIsNull_throwsNullPointerException")
  void constructor_whenParentIsNull_throwsNullPointerException() {
    // Arrange
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    // Act + Assert
    assertThrows(
        NullPointerException.class,
        () -> new USKStoreCheckerGetter(coordinator, callbacks, null, checker));
  }

  private static USKStoreCheckCoordinator.USKStoreCheckCallbacks newCallbacks(
      USKFetcher fetcher, FetchContext context) {
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    if (fetcher != null) {
      when(callbacks.fetcher()).thenReturn(fetcher);
    }
    if (context != null) {
      when(callbacks.fetcherContext()).thenReturn(context);
    }
    return callbacks;
  }

  private static USKStoreCheckerGetter newGetter() {
    USKStoreCheckCoordinator coordinator = mock(USKStoreCheckCoordinator.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks = newCallbacks(null, null);
    ClientRequester parent = mock(ClientRequester.class);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    return new USKStoreCheckerGetter(coordinator, callbacks, parent, checker);
  }

  @SuppressWarnings("java:S3011")
  private static USKFetcher mockFetcherWithContext(FetchContext ctx) {
    USKFetcher fetcher = mock(USKFetcher.class);
    try {
      Field field = USKFetcher.class.getDeclaredField("ctx");
      field.setAccessible(true);
      field.set(fetcher, ctx);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Unable to set USKFetcher.ctx for test", e);
    }
    return fetcher;
  }
}
