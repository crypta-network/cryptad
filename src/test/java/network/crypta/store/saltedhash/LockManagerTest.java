package network.crypta.store.saltedhash;

import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LockManagerTest {

  private final ExecutorService executor = Executors.newCachedThreadPool();

  @AfterEach
  void tearDown() {
    executor.shutdownNow();
  }

  @Test
  void lockEntry_whenNotLocked_returnsNonNullCondition() {
    // Arrange
    LockManager manager = new LockManager();

    // Act
    Condition cond = manager.lockEntry(42L);

    // Assert
    assertNotNull(cond, "First lock acquire should return a condition");
    manager.unlockEntry(42L, cond);
  }

  @Test
  void lockEntry_concurrentOnSameOffset_blocksUntilUnlock() throws Exception {
    // Arrange
    LockManager manager = new LockManager();
    Condition first = manager.lockEntry(1L);
    assertNotNull(first);

    // Act
    Future<Condition> secondFuture = executor.submit(() -> manager.lockEntry(1L));

    // Assert (does not complete before unlock)
    assertThrows(
        TimeoutException.class,
        () -> {
          try {
            secondFuture.get(200, MILLISECONDS);
          } catch (InterruptedException | ExecutionException e) {
            throw new AssertionError(e);
          }
        });

    // Act (now unlock and ensure the waiter proceeds)
    manager.unlockEntry(1L, first);

    Condition second = secondFuture.get(2, SECONDS);
    assertNotNull(second, "Second acquire should succeed after unlock");

    // Cleanup
    manager.unlockEntry(1L, second);
  }

  @Test
  void lockEntry_afterShutdown_returnsNull() {
    // Arrange
    LockManager manager = new LockManager();

    // Act
    manager.shutdown();
    Condition cond = manager.lockEntry(100L);

    // Assert
    assertNull(cond, "Lock acquire after shutdown must return null");
  }

  @Test
  void lockEntry_whenInterrupted_returnsNull() throws Exception {
    // Arrange
    LockManager manager = new LockManager();
    Condition held = manager.lockEntry(5L);
    assertNotNull(held);

    AtomicReference<Condition> resultRef = new AtomicReference<>();
    CountDownLatch started = new CountDownLatch(1);
    Thread t =
        new Thread(
            () -> {
              started.countDown();
              resultRef.set(manager.lockEntry(5L));
            },
            "lock-waiter");

    // Act
    t.start();
    // Ensure the waiter has started attempting to lock before we interrupt
    assertTrue(
        started.await(2, SECONDS), "Waiter thread did not begin lock attempt within timeout");
    t.interrupt();
    t.join(2000);

    // Assert
    assertNull(resultRef.get(), "Interrupted waiter should observe null from lockEntry");

    // Cleanup
    manager.unlockEntry(5L, held);
  }

  @Test
  void shutdown_waitsUntilAllEntriesUnlocked() throws Exception {
    // Arrange
    LockManager manager = new LockManager();
    Condition c1 = manager.lockEntry(11L);
    Condition c2 = manager.lockEntry(22L);
    assertNotNull(c1);
    assertNotNull(c2);

    CountDownLatch shutdownDone = new CountDownLatch(1);
    Thread shutdownThread =
        new Thread(
            () -> {
              manager.shutdown();
              shutdownDone.countDown();
            },
            "shutdown-thread");

    // Act: start shutdown in parallel
    shutdownThread.start();

    // Assert: should not finish until both locks are released
    assertFalse(
        shutdownDone.await(200, MILLISECONDS), "Shutdown should be waiting for locks to release");

    manager.unlockEntry(11L, c1);
    assertFalse(
        shutdownDone.await(200, MILLISECONDS), "Shutdown should still wait for remaining locks");

    manager.unlockEntry(22L, c2);
    assertTrue(shutdownDone.await(3, SECONDS), "Shutdown should complete after all unlocks");

    // After shutdown, further lock attempts must return null
    assertNull(manager.lockEntry(33L));
  }

  @Test
  void unlockEntry_whenOffsetNotLocked_throwsAssertionOrNpe() {
    // Arrange
    LockManager manager = new LockManager();
    Condition bogus = new ReentrantLock().newCondition();

    // Act + Assert: either AssertionError (asserts enabled) or NPE (asserts disabled)
    Callable<Void> call =
        () -> {
          manager.unlockEntry(123L, bogus);
          return null; // unreachable when an exception is thrown
        };

    if (assertionsEnabled()) {
      assertThrows(AssertionError.class, call::call);
    } else {
      assertThrows(NullPointerException.class, call::call);
    }
  }

  // Helper: detect whether JVM assertions are enabled for this class
  @SuppressWarnings({"AssertWithSideEffects", "ConstantValue"})
  private static boolean assertionsEnabled() {
    return LockManagerTest.class.desiredAssertionStatus();
  }
}
