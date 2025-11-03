package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.client.FetchContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.node.LowLevelGetException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class USKCheckerTest {

  @Mock private USKCheckerCallback callback;
  @Mock private ClientKey key;
  @Mock private FetchContext fetchContext;
  @Mock private ClientRequester parent;
  @Mock private ClientContext clientContext;

  @BeforeEach
  void setup() {
    when(fetchContext.getCooldownRetries()).thenReturn(1);
    when(fetchContext.getCooldownTime()).thenReturn(1000L);
    when(parent.getPriorityClass()).thenReturn((short) 17);
    when(callback.getPriority()).thenReturn((short) 42);
  }

  private USKChecker newCheckerSpy(int maxRetries) {
    USKChecker real = new USKChecker(callback, key, maxRetries, fetchContext, parent, false);
    return Mockito.spy(real);
  }

  @Test
  @DisplayName("onSuccess forwards ClientSSKBlock to callback")
  void onSuccess_whenBlockProvided_callsOnSuccess() {
    USKChecker checker = newCheckerSpy(0);
    ClientSSKBlock block = Mockito.mock(ClientSSKBlock.class);
    checker.onSuccess(block, false, null, clientContext);
    verify(callback).onSuccess(block, clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("getPriorityClass delegates to callback")
  void getPriorityClass_whenCalled_returnsCallbackPriority() {
    USKChecker checker = newCheckerSpy(0);
    assertEquals(42, checker.getPriorityClass());
  }

  @Test
  @DisplayName("onEnterFiniteCooldown delegates to callback")
  void onEnterFiniteCooldown_whenCalled_invokesCallback() {
    USKChecker checker = newCheckerSpy(0);
    checker.onEnterFiniteCooldown(clientContext);
    verify(callback).onEnterFiniteCooldown(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("onFailure CANCELLED triggers onCancelled and unregisters")
  void onFailure_whenCancelled_callsOnCancelled() {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());

    checker.onFailure(
        new LowLevelGetException(LowLevelGetException.CANCELLED), null, clientContext);

    verify(callback).onCancelled(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("onFailure DECODE_FAILED triggers onFatalAuthorError and unregisters")
  void onFailure_whenDecodeFailed_callsOnFatalAuthorError() {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());

    checker.onFailure(
        new LowLevelGetException(LowLevelGetException.DECODE_FAILED), null, clientContext);

    verify(callback).onFatalAuthorError(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        LowLevelGetException.DATA_NOT_FOUND,
        LowLevelGetException.DATA_NOT_FOUND_IN_STORE,
        LowLevelGetException.RECENTLY_FAILED
      })
  @DisplayName("onFailure DNF-ish errors with no retries call onDNF")
  void onFailure_whenDNFAndNoRetry_callsOnDNF(int code) {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());
    // Avoid BaseSingleFileFetcher.retry() side-effects (unregister) when retries are exhausted.
    Mockito.doReturn(false).when(checker).retry(any());

    checker.onFailure(new LowLevelGetException(code), null, clientContext);

    verify(callback).onDNF(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @ParameterizedTest
  @ValueSource(
      ints = {
        LowLevelGetException.INTERNAL_ERROR,
        LowLevelGetException.REJECTED_OVERLOAD,
        LowLevelGetException.ROUTE_NOT_FOUND,
        LowLevelGetException.TRANSFER_FAILED,
        LowLevelGetException.VERIFY_FAILED
      })
  @DisplayName("onFailure network-ish errors with no retries call onNetworkError")
  void onFailure_whenNetworkErrorAndNoRetry_callsOnNetworkError(int code) {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());
    Mockito.doReturn(false).when(checker).retry(any());

    checker.onFailure(new LowLevelGetException(code), null, clientContext);

    verify(callback).onNetworkError(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("onFailure unknown error code treated as network error when no retries")
  void onFailure_whenUnknownCode_callsOnNetworkError() {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());
    Mockito.doReturn(false).when(checker).retry(any());

    checker.onFailure(new LowLevelGetException(999, "unknown"), null, clientContext);

    verify(callback).onNetworkError(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("onFailure with retry allowed enters cooldown and returns early")
  void onFailure_whenCanRetry_entersCooldownAndNoTerminalCallback() {
    // Allow one retry so retry(context) returns true and we exit early.
    USKChecker checker = newCheckerSpy(1);
    doNothing().when(checker).unregisterAll(any());

    checker.onFailure(
        new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND), null, clientContext);

    // Early return: no terminal callbacks, but cooldown hook fires via BaseSingleFileFetcher
    verify(callback).onEnterFiniteCooldown(clientContext);
    verify(callback, never()).onDNF(any());
    verify(callback, never()).onNetworkError(any());
    verify(callback, never()).onCancelled(any());
    verify(callback, never()).onFatalAuthorError(any());
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("notFoundInStore unregisters and reports DNF")
  void notFoundInStore_whenCalled_unregistersAndCallsDNF() {
    USKChecker checker = newCheckerSpy(0);
    // We want to observe that unregisterAll is requested without executing heavy scheduler logic.
    doNothing().when(checker).unregisterAll(any());

    checker.notFoundInStore(clientContext);

    verify(checker).unregisterAll(clientContext);
    verify(callback).onDNF(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("onBlockDecodeError maps to DECODE_FAILED and triggers onFatalAuthorError")
  void onBlockDecodeError_whenTriggered_callsOnFatalAuthorError() {
    USKChecker checker = newCheckerSpy(0);
    doNothing().when(checker).unregisterAll(any());

    checker.onBlockDecodeError(null, clientContext);

    verify(callback).onFatalAuthorError(clientContext);
    verifyNoMoreInteractions(callback);
  }

  @Test
  @DisplayName("toString contains class context")
  void toString_whenCalled_containsClassContext() {
    USKChecker checker = newCheckerSpy(0);
    String s = checker.toString();
    assertTrue(s.contains("USKChecker for"));
  }
}
