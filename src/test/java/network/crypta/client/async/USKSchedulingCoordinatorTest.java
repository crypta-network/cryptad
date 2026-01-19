package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKSchedulingCoordinatorTest {

  @Mock private USKAttemptManager attempts;
  @Mock private USKStoreCheckCoordinator storeChecks;
  @Mock private USKDateHintFetches dbrHintFetches;
  @Mock private ClientContext context;

  @Test
  void buildSchedulePlan_whenNoAttemptsAndStoreChecksNeeded_addsAttemptsAndRegisters() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    when(attempts.hasPendingAttempts()).thenReturn(false);
    when(attempts.hasRunningAttempts()).thenReturn(false);
    when(attempts.hasNoPollingAttempts()).thenReturn(true);
    when(storeChecks.fillKeysWatching(3L, context)).thenReturn(false);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(3L, false, context, true);

    verify(attempts).addNewAttempts(3L, context, true);
    verify(storeChecks).fillKeysWatching(3L, context);
    assertTrue(plan.registerNow);
    assertFalse(plan.completeCheckingStore);
    assertTrue(coordinator.isStarted());
    assertFalse(coordinator.scheduleAfterDBRsDone());
    assertEquals(4L, coordinator.valueAtSchedule());
  }

  @Test
  void buildSchedulePlan_whenStoreCheckAlreadyRunning_doesNotRegister() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    when(storeChecks.fillKeysWatching(5L, context)).thenReturn(true);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(5L, false, context, false);

    verify(storeChecks).fillKeysWatching(5L, context);
    assertFalse(plan.registerNow);
  }

  @Test
  void buildSchedulePlan_whenStartedDBRsWithUnknownEdition_defersScheduling() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(0L, true, context, false);

    assertFalse(plan.registerNow);
    assertTrue(coordinator.scheduleAfterDBRsDone());
    verify(storeChecks, never()).fillKeysWatching(0L, context);
  }

  @Test
  void buildSchedulePlan_whenDeferredAndDBRsOutstanding_skipsStoreCheck() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    coordinator.setScheduleAfterDBRsDone(true);
    when(dbrHintFetches.hasOutstanding()).thenReturn(true);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(2L, false, context, false);

    verify(dbrHintFetches).hasOutstanding();
    verify(storeChecks, never()).fillKeysWatching(2L, context);
    assertFalse(plan.registerNow);
  }

  @Test
  void buildSchedulePlan_whenDeferredAndDBRsComplete_registersStoreCheck() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    coordinator.setScheduleAfterDBRsDone(true);
    when(dbrHintFetches.hasOutstanding()).thenReturn(false);
    when(storeChecks.fillKeysWatching(7L, context)).thenReturn(false);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(7L, false, context, false);

    verify(dbrHintFetches).hasOutstanding();
    verify(storeChecks).fillKeysWatching(7L, context);
    assertTrue(plan.registerNow);
  }

  @Test
  void buildSchedulePlan_whenStoreOnlyAndChecksFinished_marksCompleteCheckingStore() {
    USKSchedulingCoordinator coordinator = newCoordinator(true);
    coordinator.setScheduleAfterDBRsDone(true);
    when(storeChecks.fillKeysWatching(9L, context)).thenReturn(true);
    when(storeChecks.isStoreCheckRunning()).thenReturn(false);

    USKSchedulingCoordinator.SchedulePlan plan =
        coordinator.buildSchedulePlan(9L, false, context, false);

    verify(attempts, never()).addNewAttempts(9L, context, false);
    assertTrue(plan.completeCheckingStore);
    assertFalse(plan.registerNow);
  }

  @Test
  void valueAtSchedule_whenCalledMultipleTimes_tracksMaxValue() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    when(storeChecks.fillKeysWatching(4L, context)).thenReturn(true);
    when(storeChecks.fillKeysWatching(1L, context)).thenReturn(true);

    coordinator.buildSchedulePlan(4L, false, context, false);
    coordinator.buildSchedulePlan(1L, false, context, false);

    assertEquals(5L, coordinator.valueAtSchedule());
  }

  @Test
  void resetStarted_whenCalled_clearsStartedFlag() {
    USKSchedulingCoordinator coordinator = newCoordinator(false);
    when(storeChecks.fillKeysWatching(6L, context)).thenReturn(true);

    coordinator.buildSchedulePlan(6L, false, context, false);
    coordinator.resetStarted();

    assertFalse(coordinator.isStarted());
  }

  private USKSchedulingCoordinator newCoordinator(boolean checkStoreOnly) {
    return new USKSchedulingCoordinator(attempts, storeChecks, dbrHintFetches, checkStoreOnly);
  }
}
