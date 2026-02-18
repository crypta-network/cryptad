package network.crypta.node;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SemiOrderedShutdownHookTest {

  // No global cleanup needed; each test controls its own threads via latches and joins.

  @Test
  void get_whenCalledMultipleTimes_returnsSameSingletonInstance() {
    // Arrange & Act
    SemiOrderedShutdownHook h1 = SemiOrderedShutdownHook.get();
    SemiOrderedShutdownHook h2 = SemiOrderedShutdownHook.get();

    // Assert
    assertSame(h1, h2, "get() must return the same singleton instance");
  }

  @Test
  void run_whenEarlyAndLateJobsAdded_lateStartsOnlyAfterAllEarlyFinish() throws Exception {
    // Arrange
    SemiOrderedShutdownHook hook = new SemiOrderedShutdownHookAccessor().instance();
    List<String> events = Collections.synchronizedList(new ArrayList<>());

    Thread early1 =
        new Thread(
            () -> {
              events.add("early1-start");
              events.add("early1-done");
            },
            "early1");

    Thread early2 =
        new Thread(
            () -> {
              events.add("early2-start");
              events.add("early2-done");
            },
            "early2");

    Thread late1 =
        new Thread(
            () -> {
              events.add("late1-start");
              events.add("late1-done");
            },
            "late1");

    Thread late2 =
        new Thread(
            () -> {
              events.add("late2-start");
              events.add("late2-done");
            },
            "late2");

    hook.addEarlyJob(early1);
    hook.addEarlyJob(early2);
    hook.addLateJob(late1);
    hook.addLateJob(late2);

    // Act: execute the hook in its own thread, as it would run at JVM shutdown
    hook.start();
    hook.join(2000);

    // Assert
    // All early jobs must fully complete before any late job starts, because run() joins early jobs
    // before starting late ones.
    int posEarly1Done = events.indexOf("early1-done");
    int posEarly2Done = events.indexOf("early2-done");
    int posFirstLateStart = Math.min(events.indexOf("late1-start"), events.indexOf("late2-start"));

    assertTrue(posEarly1Done >= 0 && posEarly2Done >= 0, "early jobs must record completion");
    assertTrue(
        posFirstLateStart > posEarly1Done && posFirstLateStart > posEarly2Done,
        "No late job may start before all early jobs finish");
  }

  @Test
  void run_whenInterruptedDuringEarlyJoin_startsLateJobsEvenIfAnEarlyIsStillRunning()
      throws Exception {
    // Arrange
    SemiOrderedShutdownHook hook = new SemiOrderedShutdownHookAccessor().instance();
    List<String> events = Collections.synchronizedList(new ArrayList<>());
    CountDownLatch allowEarlySlowToFinish = new CountDownLatch(1);

    Thread earlySlow =
        new Thread(
            () -> {
              events.add("earlySlow-start");
              try {
                allowEarlySlowToFinish.await();
              } catch (InterruptedException _) {
                // ignored for test: we want deterministic completion ordering
              }
              events.add("earlySlow-done");
            },
            "earlySlow");

    Thread earlyFast =
        new Thread(
            () -> {
              events.add("earlyFast-start");
              events.add("earlyFast-done");
            },
            "earlyFast");

    Thread late =
        new Thread(
            () -> {
              events.add("late-start");
              events.add("late-done");
            },
            "late");

    // Register the slow early job first so the first join() in run() targets it and throws
    // immediately when the current thread's interrupt flag is set below.
    hook.addEarlyJob(earlySlow);
    hook.addEarlyJob(earlyFast);
    hook.addLateJob(late);

    // Act: mark the hook thread interrupted before it starts so its first join() throws
    hook.interrupt();
    hook.start();
    hook.join(2000);

    // Assert: late started before earlySlow was allowed to finish
    int posLateStart = events.indexOf("late-start");
    int posEarlySlowDone = events.indexOf("earlySlow-done");
    assertTrue(posLateStart >= 0, "late job must have started");
    assertTrue(
        posEarlySlowDone == -1 || posLateStart < posEarlySlowDone,
        "late must start before earlySlow completes due to interrupted join");

    // Cleanup the blocked earlySlow thread to avoid leaks
    allowEarlySlowToFinish.countDown();
    earlySlow.join(2000);
  }

  @Test
  void run_whenSameThreadAddedToEarlyAndLate_throwsIllegalThreadStateException() throws Exception {
    // Arrange
    SemiOrderedShutdownHook hook = new SemiOrderedShutdownHookAccessor().instance();
    List<String> events = Collections.synchronizedList(new ArrayList<>());

    Thread t =
        new Thread(
            () -> {
              events.add("t-start");
              events.add("t-done");
            },
            "dup-thread");

    hook.addEarlyJob(t);
    hook.addLateJob(t); // starting the same Thread twice is illegal

    // Act: capture the uncaught exception from the hook thread when it attempts to start the
    // same thread twice (once in early, then again in late phase).
    final Throwable[] thrown = new Throwable[1];
    hook.setUncaughtExceptionHandler((tThread, ex) -> thrown[0] = ex);
    hook.start();
    hook.join(2000);

    // Assert
    assertInstanceOf(
        IllegalThreadStateException.class,
        thrown[0],
        "Starting the same Thread twice should fail with IllegalThreadStateException");
  }

  /**
   * Isolates tests from the JVM-registered singleton to avoid cross-test interference while still
   * exercising the production logic. The accessor creates a fresh instance via reflection to avoid
   * depending on the static, globally registered shutdown hook.
   */
  static final class SemiOrderedShutdownHookAccessor {
    SemiOrderedShutdownHook instance() {
      try {
        var ctor = SemiOrderedShutdownHook.class.getDeclaredConstructor();
        ctor.setAccessible(true);
        return ctor.newInstance();
      } catch (ReflectiveOperationException e) {
        throw new LinkageError("Failed to construct SemiOrderedShutdownHook for test", e);
      }
    }
  }
}
