package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SendableGetRequestSenderTest {

  @Mock private NodeClientCore core;
  @Mock private NodeClientCoreTransfers transfers;
  @Mock private RequestScheduler scheduler;
  @Mock private ClientContext context;

  @BeforeEach
  void setUp() {
    lenient().when(core.getTransfers()).thenReturn(transfers);
  }

  private SendableGetRequestSender newSender() {
    return new SendableGetRequestSender();
  }

  private ChosenBlock newChosenBlock(
      SendableRequestItem token,
      ClientKey clientKey,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag) {
    // Create a mock that calls the real constructor to set the final fields,
    // and lets us verify abstract callback invocations via Mockito.
    return mock(
        ChosenBlock.class,
        org.mockito.Mockito.withSettings()
            .useConstructor(
                token,
                null, // node-level key not used for SendableGet
                clientKey,
                new ChosenBlock.Options(
                    localOnly, ignoreStore, canWriteClientCache, false, realTimeFlag))
            .defaultAnswer(org.mockito.Answers.CALLS_REAL_METHODS));
  }

  @Test
  void sendIsBlocking_alwaysFalse() {
    // Arrange
    SendableGetRequestSender sender = newSender();

    // Act
    boolean blocking = sender.sendIsBlocking();

    // Assert
    assertFalse(blocking);
  }

  @Test
  void send_whenClientKeyNull_returnsFalseAndDoesNotCallCoreOrCallbacks() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    // ckey = null
    ChosenBlock req = newChosenBlock(token, null, false, false, false, false);

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertFalse(result);
    verifyNoInteractions(core);
    // onFailure should not be called in this branch
    verify(req, times(0)).onFailure(any(LowLevelGetException.class), eq(context));
  }

  @Test
  void send_whenCancelled_callsOnFailureCancelledAndReturnsFalse() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    ChosenBlock req = newChosenBlock(token, ckey, false, false, false, false);
    when(req.isCancelled()).thenReturn(true);

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertFalse(result);
    verifyNoInteractions(core);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(LowLevelGetException.CANCELLED, captor.getValue().code);
  }

  @Test
  void send_whenCancelled_failureCallbackThrows_isCaughtAndStillReturnsFalse() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    ChosenBlock req = newChosenBlock(token, ckey, false, false, false, false);
    when(req.isCancelled()).thenReturn(true);
    // Make the failure callback throw
    doThrow(new RuntimeException("boom-cancel"))
        .when(req)
        .onFailure(any(LowLevelGetException.class), eq(context));

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertFalse(result);
    verifyNoInteractions(core);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(LowLevelGetException.CANCELLED, captor.getValue().code);
  }

  @Test
  void send_whenAsyncGetSucceeds_invokesFetchSuccessCallback() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    Key nodeKey = mock(Key.class);
    when(ckey.getNodeKey()).thenReturn(nodeKey);
    ChosenBlock req = newChosenBlock(token, ckey, false, false, true, true);
    when(req.isCancelled()).thenReturn(false);

    // Capture the listener passed to asyncGet
    doAnswer(
            invocation -> {
              RequestCompletionListener l = invocation.getArgument(2);
              // Simulate success
              l.onSucceeded();
              return null;
            })
        .when(transfers)
        .asyncGet(
            eq(nodeKey),
            eq(false),
            any(RequestCompletionListener.class),
            eq(true), // canReadClientCache = !ignoreStore(false)
            eq(true), // canWriteClientCache
            eq(true), // realTimeFlag
            eq(false), // localOnly
            eq(false)); // ignoreStore

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertTrue(result);
    verify(req, times(1)).onFetchSuccess(context);
    verify(req, times(0)).onFailure(any(LowLevelGetException.class), any());
  }

  @Test
  void send_whenAsyncGetFails_invokesFailureCallbackWithSameException() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    Key nodeKey = mock(Key.class);
    when(ckey.getNodeKey()).thenReturn(nodeKey);
    ChosenBlock req = newChosenBlock(token, ckey, true, true, false, false);
    when(req.isCancelled()).thenReturn(false);

    LowLevelGetException failure = new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND);

    doAnswer(
            invocation -> {
              RequestCompletionListener l = invocation.getArgument(2);
              l.onFailed(failure);
              return null;
            })
        .when(transfers)
        .asyncGet(
            eq(nodeKey),
            eq(false),
            any(RequestCompletionListener.class),
            eq(false), // canReadClientCache = !ignoreStore(true)
            eq(false), // canWriteClientCache
            eq(false), // realTimeFlag
            eq(true), // localOnly
            eq(true)); // ignoreStore

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertTrue(result);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(failure, captor.getValue());
    verify(req, times(0)).onFetchSuccess(any());
  }

  @Test
  void send_whenKeyDerivationThrows_reportsInternalErrorAndReturnsTrue() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    when(ckey.getNodeKey()).thenThrow(new RuntimeException("boom"));
    ChosenBlock req = newChosenBlock(token, ckey, false, false, false, false);
    when(req.isCancelled()).thenReturn(false);

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertTrue(result);
    verifyNoInteractions(core);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(LowLevelGetException.INTERNAL_ERROR, captor.getValue().code);
  }

  @Test
  void send_whenInternalError_failureCallbackThrows_isCaughtAndStillReturnsTrue() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    when(ckey.getNodeKey()).thenThrow(new RuntimeException("boom-internal"));
    ChosenBlock req = newChosenBlock(token, ckey, false, false, false, false);
    when(req.isCancelled()).thenReturn(false);
    // Make the failure callback throw
    doThrow(new RuntimeException("boom-callback"))
        .when(req)
        .onFailure(any(LowLevelGetException.class), eq(context));

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertTrue(result);
    verifyNoInteractions(core);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(LowLevelGetException.INTERNAL_ERROR, captor.getValue().code);
  }

  @Test
  void send_whenCoreAsyncGetThrows_reportsInternalErrorAndReturnsTrue() {
    // Arrange
    SendableGetRequestSender sender = newSender();
    SendableRequestItem token = mock(SendableRequestItem.class);
    ClientKey ckey = mock(ClientKey.class);
    Key nodeKey = mock(Key.class);
    when(ckey.getNodeKey()).thenReturn(nodeKey);
    ChosenBlock req = newChosenBlock(token, ckey, false, false, false, false);
    when(req.isCancelled()).thenReturn(false);

    doThrow(new RuntimeException("asyncGet blew up"))
        .when(transfers)
        .asyncGet(
            eq(nodeKey),
            eq(false),
            any(RequestCompletionListener.class),
            eq(true),
            eq(false),
            eq(false),
            eq(false),
            eq(false));

    // Act
    boolean result = sender.send(core, scheduler, context, req);

    // Assert
    assertTrue(result);
    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(req).onFailure(captor.capture(), eq(context));
    assertEquals(LowLevelGetException.INTERNAL_ERROR, captor.getValue().code);
  }
}
