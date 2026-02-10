package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.SendableGet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKStoreCheckCoordinatorTest {

  @Test
  @DisplayName("fillKeysWatching_whenCheckerAlreadyRunning_returnsTrueWithoutRegistering")
  void fillKeysWatching_whenCheckerAlreadyRunning_returnsTrueWithoutRegistering() throws Exception {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    USKStoreCheckCoordinator coordinator =
        newCoordinator(watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, true);
    ClientContext context = mock(ClientContext.class);
    setRunningStoreChecker(coordinator, mock(USKStoreCheckerGetter.class));

    // Act
    boolean result = coordinator.fillKeysWatching(5L, context);

    // Assert
    assertTrue(result);
    verifyNoInteractions(watchingKeys);
  }

  @Test
  @DisplayName("fillKeysWatching_whenNoDatastoreCheckers_returnsFalse")
  void fillKeysWatching_whenNoDatastoreCheckers_returnsFalse() {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    when(watchingKeys.getDatastoreCheckers(10L)).thenReturn(null);

    USKStoreCheckCoordinator coordinator =
        newCoordinator(
            watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, false);
    ClientContext context = mock(ClientContext.class);

    // Act
    boolean result = coordinator.fillKeysWatching(10L, context);

    // Assert
    assertFalse(result);
  }

  @Test
  @DisplayName("fillKeysWatching_whenRegisterThrows_clearsRunningChecker")
  void fillKeysWatching_whenRegisterThrows_clearsRunningChecker() throws Exception {
    // Arrange
    USK usk = newUsk((byte) 1, (byte) 2, 1L);
    USKKeyWatchSet watchingKeys = new USKKeyWatchSet(usk, 0L, 1, false);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);

    USKStoreCheckCoordinator coordinator =
        newCoordinator(watchingKeys, attempts, parent, false, uskManager, usk, callbacks, true);
    ClientContext context = mock(ClientContext.class);
    ClientRequestScheduler scheduler = mock(ClientRequestScheduler.class);
    when(context.getSskFetchScheduler(true)).thenReturn(scheduler);
    doThrow(new IllegalStateException("boom"))
        .when(scheduler)
        .register(eq(null), any(SendableGet[].class), eq(false), eq(null), eq(false));

    // Act
    boolean result = coordinator.fillKeysWatching(0L, context);

    // Assert
    assertTrue(result);
    assertFalse(coordinator.isStoreCheckRunning());
  }

  @Test
  @DisplayName("preRegisterStoreChecker_whenCancelled_unregistersAndStops")
  void preRegisterStoreChecker_whenCancelled_unregistersAndStops() {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    when(callbacks.isCancelled()).thenReturn(true);

    USKStoreCheckCoordinator coordinator =
        newCoordinator(watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, true);
    USKStoreCheckerGetter storeChecker = mock(USKStoreCheckerGetter.class);
    when(storeChecker.getPriorityClass()).thenReturn((short) 2);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    ClientContext context = mock(ClientContext.class);

    // Act
    boolean result = coordinator.preRegisterStoreChecker(storeChecker, checker, context, true);

    // Assert
    //noinspection ConstantValue
    assertTrue(result);
    assertFalse(coordinator.isStoreCheckRunning());
    verify(storeChecker).unregister(context, (short) 2);
    verifyNoInteractions(attempts);
    verifyNoInteractions(parent);
    verifyNoInteractions(checker);
  }

  @Test
  @DisplayName("preRegisterStoreChecker_whenAttemptsAvailable_sendsToNetworkAndProcesses")
  void preRegisterStoreChecker_whenAttemptsAvailable_sendsToNetworkAndProcesses() {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    when(callbacks.isCancelled()).thenReturn(false);

    ClientContext context = mock(ClientContext.class);
    USKStoreCheckCoordinator coordinator =
        spy(
            newCoordinator(
                watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, true));
    doReturn(true).when(coordinator).fillKeysWatching(eq(42L), same(context));
    when(uskManager.lookupLatestSlot(origUsk)).thenReturn(42L);

    USKStoreCheckerGetter storeChecker = mock(USKStoreCheckerGetter.class);
    when(storeChecker.getPriorityClass()).thenReturn((short) 1);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    USKAttempt[] attemptsToStart = new USKAttempt[] {mock(USKAttempt.class)};
    when(attempts.snapshotAttemptsToStart()).thenReturn(attemptsToStart);

    // Act
    boolean result = coordinator.preRegisterStoreChecker(storeChecker, checker, context, false);

    // Assert
    //noinspection ConstantValue
    assertFalse(result);
    verify(storeChecker).unregister(context, (short) 1);
    verify(attempts).snapshotAttemptsToStart();
    verify(attempts).clearAttemptsToStart();
    verify(checker).checked();
    verify(parent).toNetwork(context);
    verify(callbacks).notifySendingToNetwork(context);
    verify(callbacks).processAttemptsAfterStoreCheck(attemptsToStart, context);
    verify(uskManager).lookupLatestSlot(origUsk);
    verify(coordinator).fillKeysWatching(42L, context);
  }

  @ParameterizedTest(name = "defer={0}")
  @CsvSource({"true", "false"})
  @DisplayName("preRegisterStoreChecker_whenStoreOnlyAndChecksFinished_finishesOrDefers")
  void preRegisterStoreChecker_whenStoreOnlyAndChecksFinished_finishesOrDefers(boolean defer) {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    when(callbacks.isCancelled()).thenReturn(false);
    when(callbacks.shouldDeferUntilDBRs()).thenReturn(defer);

    ClientContext context = mock(ClientContext.class);
    USKStoreCheckCoordinator coordinator =
        spy(
            newCoordinator(
                watchingKeys, attempts, parent, true, uskManager, origUsk, callbacks, true));
    doReturn(false).when(coordinator).fillKeysWatching(eq(9L), same(context));
    when(uskManager.lookupLatestSlot(origUsk)).thenReturn(9L);
    USKAttempt[] attemptsToStart = new USKAttempt[0];
    when(attempts.snapshotAttemptsToStart()).thenReturn(attemptsToStart);

    USKStoreCheckerGetter storeChecker = mock(USKStoreCheckerGetter.class);
    when(storeChecker.getPriorityClass()).thenReturn((short) 4);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);

    // Act
    boolean result = coordinator.preRegisterStoreChecker(storeChecker, checker, context, true);

    // Assert
    //noinspection ConstantValue
    assertTrue(result);
    verify(callbacks).processAttemptsAfterStoreCheck(attemptsToStart, context);
    if (defer) {
      verify(callbacks).setScheduleAfterDBRsDone(true);
      verify(callbacks, never()).finishSuccess(context);
    } else {
      verify(callbacks).finishSuccess(context);
      verify(callbacks, never()).setScheduleAfterDBRsDone(true);
    }
  }

  @Test
  @DisplayName("preRegisterStoreChecker_whenCancelledAfterSnapshot_ignoresAttempts")
  void preRegisterStoreChecker_whenCancelledAfterSnapshot_ignoresAttempts() {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    when(callbacks.isCancelled()).thenReturn(false, true);

    ClientContext context = mock(ClientContext.class);
    USKStoreCheckCoordinator coordinator =
        spy(
            newCoordinator(
                watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, true));
    doReturn(true).when(coordinator).fillKeysWatching(eq(4L), same(context));
    when(uskManager.lookupLatestSlot(origUsk)).thenReturn(4L);

    USKStoreCheckerGetter storeChecker = mock(USKStoreCheckerGetter.class);
    when(storeChecker.getPriorityClass()).thenReturn((short) 3);
    USKStoreCheckCoordinator.USKStoreChecker checker =
        mock(USKStoreCheckCoordinator.USKStoreChecker.class);
    USKAttempt[] attemptsToStart = new USKAttempt[] {mock(USKAttempt.class)};
    when(attempts.snapshotAttemptsToStart()).thenReturn(attemptsToStart);

    // Act
    coordinator.preRegisterStoreChecker(storeChecker, checker, context, false);

    // Assert
    ArgumentCaptor<USKAttempt[]> captor = ArgumentCaptor.forClass(USKAttempt[].class);
    verify(callbacks).processAttemptsAfterStoreCheck(captor.capture(), same(context));
    assertEquals(0, captor.getValue().length);
    verify(parent, never()).toNetwork(context);
    verify(callbacks, never()).notifySendingToNetwork(context);
  }

  @Test
  @DisplayName("cancelStoreChecker_whenRunning_unregistersAndClears")
  void cancelStoreChecker_whenRunning_unregistersAndClears() throws Exception {
    // Arrange
    USKKeyWatchSet watchingKeys = mock(USKKeyWatchSet.class);
    USKAttemptManager attempts = mock(USKAttemptManager.class);
    ClientRequester parent = mock(ClientRequester.class);
    USKManager uskManager = mock(USKManager.class);
    USK origUsk = mock(USK.class);
    USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks =
        mock(USKStoreCheckCoordinator.USKStoreCheckCallbacks.class);
    USKStoreCheckCoordinator coordinator =
        newCoordinator(watchingKeys, attempts, parent, false, uskManager, origUsk, callbacks, true);

    USKStoreCheckerGetter storeChecker = mock(USKStoreCheckerGetter.class);
    when(storeChecker.getPriorityClass()).thenReturn((short) 7);
    setRunningStoreChecker(coordinator, storeChecker);
    ClientContext context = mock(ClientContext.class);

    // Act
    coordinator.cancelStoreChecker(context);

    // Assert
    assertFalse(coordinator.isStoreCheckRunning());
    verify(storeChecker).unregister(context, (short) 7);
  }

  @Test
  @DisplayName("uskStoreChecker_getKeys_whenSingleChecker_returnsOriginalArray")
  void uskStoreChecker_getKeys_whenSingleChecker_returnsOriginalArray() throws Exception {
    // Arrange
    USK usk = newUsk((byte) 9, (byte) 10, 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    NodeSSK key = nodeKeyForEdition(usk, 0L);
    USKKeyWatchSet.KeyList.StoreSubChecker subChecker =
        newStoreSubChecker(watchSet, new NodeSSK[] {key});
    USKStoreCheckCoordinator.USKStoreChecker checker =
        new USKStoreCheckCoordinator.USKStoreChecker(List.of(subChecker));

    // Act
    Key[] keys = checker.getKeys();

    // Assert
    assertSame(subChecker.keysToCheck, keys);
  }

  @Test
  @DisplayName("uskStoreChecker_getKeys_whenMultipleCheckers_deduplicates")
  void uskStoreChecker_getKeys_whenMultipleCheckers_deduplicates() throws Exception {
    // Arrange
    USK usk = newUsk((byte) 12, (byte) 13, 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    NodeSSK key1 = nodeKeyForEdition(usk, 0L);
    NodeSSK key2 = nodeKeyForEdition(usk, 1L);
    NodeSSK key3 = nodeKeyForEdition(usk, 2L);
    USKKeyWatchSet.KeyList.StoreSubChecker first =
        newStoreSubChecker(watchSet, new NodeSSK[] {key1, key2});
    USKKeyWatchSet.KeyList.StoreSubChecker second =
        newStoreSubChecker(watchSet, new NodeSSK[] {key2, key3});

    USKStoreCheckCoordinator.USKStoreChecker checker =
        new USKStoreCheckCoordinator.USKStoreChecker(List.of(first, second));

    // Act
    Key[] keys = checker.getKeys();

    // Assert
    assertArrayEquals(new Key[] {key1, key2, key3}, keys);
  }

  @Test
  @DisplayName("uskStoreChecker_checked_whenCalled_notifiesSubCheckers")
  void uskStoreChecker_checked_whenCalled_notifiesSubCheckers() throws Exception {
    // Arrange
    USK usk = newUsk((byte) 20, (byte) 21, 0L);
    USKKeyWatchSet watchSet = new USKKeyWatchSet(usk, 0L, 1, false);
    NodeSSK key = nodeKeyForEdition(usk, 0L);
    USKKeyWatchSet.KeyList.StoreSubChecker realChecker =
        newStoreSubChecker(watchSet, new NodeSSK[] {key});
    USKKeyWatchSet.KeyList.StoreSubChecker subChecker = spy(realChecker);

    USKStoreCheckCoordinator.USKStoreChecker checker =
        new USKStoreCheckCoordinator.USKStoreChecker(List.of(subChecker));

    // Act
    checker.checked();

    // Assert
    verify(subChecker).checked();
  }

  private static USKStoreCheckCoordinator newCoordinator(
      USKKeyWatchSet watchingKeys,
      USKAttemptManager attempts,
      ClientRequester parent,
      boolean checkStoreOnly,
      USKManager uskManager,
      USK origUsk,
      USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks,
      boolean realTimeFlag) {
    USKStoreCheckCoordinator.Params params =
        USKStoreCheckCoordinator.Params.builder()
            .watchingKeys(watchingKeys)
            .attempts(attempts)
            .parent(parent)
            .checkStoreOnly(checkStoreOnly)
            .uskManager(uskManager)
            .origUSK(origUsk)
            .callbacks(callbacks)
            .realTimeFlag(realTimeFlag)
            .build();
    return new USKStoreCheckCoordinator(params);
  }

  private static USK newUsk(byte pubKeySeed, byte cryptoSeed, long suggestedEdition)
      throws MalformedURLException {
    byte[] pubKeyHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    byte[] extras =
        new byte[] {
          NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, (byte) KeyBlock.HASH_SHA256
        };
    Arrays.fill(pubKeyHash, pubKeySeed);
    Arrays.fill(cryptoKey, cryptoSeed);
    return new USK(pubKeyHash, cryptoKey, extras, "site", suggestedEdition);
  }

  private static NodeSSK nodeKeyForEdition(USK usk, long edition) {
    ClientSSK clientKey = usk.getSSK(edition);
    return new NodeSSK(usk.getPubKeyHash(), clientKey.ehDocname, Key.ALGO_AES_PCFB_256_SHA256);
  }

  @SuppressWarnings("java:S3011")
  private static USKKeyWatchSet.KeyList.StoreSubChecker newStoreSubChecker(
      USKKeyWatchSet watchSet, NodeSSK[] keys) {
    USKKeyWatchSet.KeyList keyList = watchSet.new KeyList(0L);
    try {
      Constructor<USKKeyWatchSet.KeyList.StoreSubChecker> constructor =
          USKKeyWatchSet.KeyList.StoreSubChecker.class.getDeclaredConstructor(
              USKKeyWatchSet.KeyList.class, NodeSSK[].class, long.class, long.class);
      constructor.setAccessible(true);
      return constructor.newInstance(keyList, keys, 0L, (long) keys.length);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Unable to build StoreSubChecker for test", e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setRunningStoreChecker(
      USKStoreCheckCoordinator coordinator, USKStoreCheckerGetter checker) throws Exception {
    java.lang.reflect.Field field =
        USKStoreCheckCoordinator.class.getDeclaredField("runningStoreChecker");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    java.util.concurrent.atomic.AtomicReference<USKStoreCheckerGetter> holder =
        (java.util.concurrent.atomic.AtomicReference<USKStoreCheckerGetter>) field.get(coordinator);
    holder.set(checker);
  }
}
