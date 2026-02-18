package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class DummyJobRunnerTest {
  private static final String PRIO_RUNNABLE_MSG = "Runnable should implement PrioRunnable";

  @Test
  @DisplayName("queue schedules PrioRunnable and runs job with provided context")
  void queue_whenCalled_executesJobWithContextAndPriorityPreserved() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    PersistentJob job = Mockito.mock(PersistentJob.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    int priority = NativeThread.PriorityLevel.HIGH_PRIORITY.value;

    runner.queue(job, priority);

    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor, times(1)).execute(captor.capture());

    Runnable r = captor.getValue();
    assertNotNull(r, "Executor should receive a runnable");
    assertInstanceOf(PrioRunnable.class, r, PRIO_RUNNABLE_MSG);
    PrioRunnable pr = (PrioRunnable) r;
    // Assert priority is preserved
    org.junit.jupiter.api.Assertions.assertEquals(priority, pr.getPriority());

    // When run, the job executes with the exact context instance
    pr.run();
    verify(job, times(1)).run(context);
  }

  @Test
  @DisplayName("queueNormalOrDrop uses NORM priority and runs job")
  void queueNormalOrDrop_whenCalled_usesNormPriority() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    PersistentJob job = Mockito.mock(PersistentJob.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);

    runner.queueNormalOrDrop(job);

    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor, times(1)).execute(captor.capture());

    Runnable r = captor.getValue();
    assertInstanceOf(PrioRunnable.class, r, PRIO_RUNNABLE_MSG);
    PrioRunnable pr = (PrioRunnable) r;
    org.junit.jupiter.api.Assertions.assertEquals(
        NativeThread.PriorityLevel.NORM_PRIORITY.value, pr.getPriority());

    pr.run();
    verify(job, times(1)).run(context);
  }

  @Test
  @DisplayName("queueInternal(priority) delegates to queue and preserves priority")
  void queueInternal_withPriority_delegatesToQueue() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    PersistentJob job = Mockito.mock(PersistentJob.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    int priority = NativeThread.PriorityLevel.LOW_PRIORITY.value;

    runner.queueInternal(job, priority);

    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor, times(1)).execute(captor.capture());

    Runnable r = captor.getValue();
    assertInstanceOf(PrioRunnable.class, r, PRIO_RUNNABLE_MSG);
    PrioRunnable pr = (PrioRunnable) r;
    org.junit.jupiter.api.Assertions.assertEquals(priority, pr.getPriority());

    pr.run();
    verify(job, times(1)).run(context);
  }

  @Test
  @DisplayName("queueInternal() uses NORM priority")
  void queueInternal_withoutPriority_usesNormPriority() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    PersistentJob job = Mockito.mock(PersistentJob.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);

    runner.queueInternal(job);

    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor, times(1)).execute(captor.capture());

    Runnable r = captor.getValue();
    assertInstanceOf(PrioRunnable.class, r, PRIO_RUNNABLE_MSG);
    PrioRunnable pr = (PrioRunnable) r;
    org.junit.jupiter.api.Assertions.assertEquals(
        NativeThread.PriorityLevel.NORM_PRIORITY.value, pr.getPriority());

    pr.run();
    verify(job, times(1)).run(context);
  }

  @Test
  @DisplayName("lock returns a no-op CheckpointLock")
  void lock_whenUnlockCalled_doesNothing() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    PersistentJobRunner.CheckpointLock lock = runner.lock();
    assertNotNull(lock, "lock() must return a CheckpointLock instance");
    assertDoesNotThrow(
        () -> lock.unlock(true, NativeThread.PriorityLevel.MAX_PRIORITY.value),
        "Unlocking the dummy lock should not throw");
  }

  @Test
  @DisplayName("hasLoaded always returns true")
  void hasLoaded_whenCalled_returnsTrue() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    assertTrue(runner.hasLoaded());
  }

  @Test
  @DisplayName("newSalt always returns false")
  void newSalt_whenCalled_returnsFalse() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    assertFalse(runner.newSalt());
  }

  @Test
  @DisplayName("shuttingDown always returns false")
  void shuttingDown_whenCalled_returnsFalse() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    ClientContext context = Mockito.mock(ClientContext.class);
    DummyJobRunner runner = new DummyJobRunner(executor, context);
    assertFalse(runner.shuttingDown());
  }

  @Test
  @DisplayName("queue passes null context through to job.run")
  void queue_whenContextIsNull_jobReceivesNull() {
    PriorityAwareExecutor executor = Mockito.mock(PriorityAwareExecutor.class);
    PersistentJob job = Mockito.mock(PersistentJob.class);
    DummyJobRunner runner = new DummyJobRunner(executor, null);

    runner.queue(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);

    ArgumentCaptor<Runnable> captor = ArgumentCaptor.forClass(Runnable.class);
    verify(executor, times(1)).execute(captor.capture());

    Runnable r = captor.getValue();
    assertInstanceOf(PrioRunnable.class, r, PRIO_RUNNABLE_MSG);
    r.run();

    verify(job, times(1)).run(isNull());
  }
}
