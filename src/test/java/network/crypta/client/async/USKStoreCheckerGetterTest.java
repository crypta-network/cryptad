package network.crypta.client.async;

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

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKStoreCheckerGetterTest {

  @Test
  @DisplayName("getContext_whenFetcherHasContext_returnsFetcherContext")
  void getContext_whenFetcherHasContext_returnsFetcherContext() {
    // Arrange
    FetchContext expectedContext = mock(FetchContext.class);
    USKFetcher fetcher = mockFetcherWithContext(expectedContext);
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);
    Key[] expectedKeys = new Key[] {mock(Key.class), mock(Key.class)};
    when(checker.getKeys()).thenReturn(expectedKeys);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

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
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.realTimeFlag()).thenReturn(true);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

    // Act
    RequestClient client = getter.getClient();

    // Assert
    assertSame(USKManager.rcRT, client);
  }

  @Test
  @DisplayName("getClient_whenParentIsBulk_returnsRcBulk")
  void getClient_whenParentIsBulk_returnsRcBulk() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.realTimeFlag()).thenReturn(false);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

    // Act
    RequestClient client = getter.getClient();

    // Assert
    assertSame(USKManager.rcBulk, client);
  }

  @Test
  @DisplayName("isCancelled_whenNotDoneAndFetcherNotCancelled_returnsFalse")
  void isCancelled_whenNotDoneAndFetcherNotCancelled_returnsFalse() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    when(fetcher.isCancelled()).thenReturn(false);
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

    // Act
    boolean cancelled = getter.isCancelled();

    // Assert
    assertFalse(cancelled);
    verify(fetcher).isCancelled();
  }

  @Test
  @DisplayName("isCancelled_whenFetcherCancelled_returnsTrue")
  void isCancelled_whenFetcherCancelled_returnsTrue() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    when(fetcher.isCancelled()).thenReturn(true);
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

    // Act
    boolean cancelled = getter.isCancelled();

    // Assert
    assertTrue(cancelled);
    verify(fetcher).isCancelled();
  }

  @ParameterizedTest(name = "toNetwork={0}, delegateReturn={1}")
  @CsvSource({"true,true", "true,false", "false,true", "false,false"})
  @DisplayName("preRegister_whenCalled_delegatesAndMarksDone")
  void preRegister_whenCalled_delegatesAndMarksDone(boolean toNetwork, boolean delegateReturn) {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);
    when(fetcher.preRegisterStoreChecker(any(), same(checker), same(context), eq(toNetwork)))
        .thenReturn(delegateReturn);

    // Act
    boolean actualReturn = getter.preRegister(context, toNetwork);

    // Assert
    assertEquals(delegateReturn, actualReturn);
    assertTrue(getter.isCancelled(), "preRegister must mark the SendableGet as done in all cases");
    verify(fetcher)
        .preRegisterStoreChecker(same(getter), same(checker), same(context), eq(toNetwork));
  }

  @Test
  @DisplayName("preRegister_whenFetcherThrows_propagatesAndMarksDone")
  void preRegister_whenFetcherThrows_propagatesAndMarksDone() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);
    when(fetcher.preRegisterStoreChecker(any(), same(checker), same(context), eq(true)))
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
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    when(fetcher.isCancelled()).thenReturn(false);
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    USKStoreCheckerGetter getter = new USKStoreCheckerGetter(fetcher, parent, checker);

    // Act
    getter.onFailure(mock(LowLevelGetException.class), null, null);

    // Assert
    assertFalse(getter.isCancelled(), "onFailure is expected to be a no-op for store checking");
    verify(fetcher).isCancelled();
  }

  @Test
  @DisplayName("constructor_whenParentIsNull_throwsNullPointerException")
  void constructor_whenParentIsNull_throwsNullPointerException() {
    // Arrange
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> new USKStoreCheckerGetter(fetcher, null, checker));
  }

  private static USKStoreCheckerGetter newGetter() {
    USKFetcher fetcher = mockFetcherWithContext(mock(FetchContext.class));
    ClientRequester parent = mock(ClientRequester.class);
    USKFetcher.USKStoreChecker checker = mock(USKFetcher.USKStoreChecker.class);
    return new USKStoreCheckerGetter(fetcher, parent, checker);
  }

  @SuppressWarnings("java:S3011")
  private static USKFetcher mockFetcherWithContext(FetchContext ctx) {
    USKFetcher fetcher = mock(USKFetcher.class);
    try {
      Field field = USKFetcher.class.getDeclaredField("ctx");
      field.setAccessible(true);
      field.set(fetcher, ctx);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to set USKFetcher.ctx for test", e);
    }
    return fetcher;
  }
}
