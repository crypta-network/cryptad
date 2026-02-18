package network.crypta.clients.fcp;

import java.io.IOException;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FCPPluginConnectionTrackerTest {

  private static final Field CONNECTIONS_BY_ID_FIELD = locateField("connectionsByID");
  private static final Field CONNECTIONS_LOCK_FIELD = locateField("connectionsByIDLock");

  @Test
  void getConnection_whenRegistered_expectSameInstance() throws IOException {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    UUID id = UUID.randomUUID();
    FCPPluginConnectionImpl connection = mockConnection(id);

    tracker.registerConnection(connection);

    FCPPluginConnectionImpl result = tracker.getConnection(id);

    assertSame(connection, result);
  }

  @Test
  void getConnection_whenConnectionMissing_expectIOException() {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    UUID id = UUID.randomUUID();

    IOException exception = assertThrows(IOException.class, () -> tracker.getConnection(id));

    assertTrue(exception.getMessage().contains(id.toString()));
  }

  @Test
  void getConnection_whenReferenceCleared_expectIOException() {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    UUID id = UUID.randomUUID();
    FCPPluginConnectionImpl connection = mockConnection(id);
    tracker.registerConnection(connection);

    FCPPluginConnectionTracker.ConnectionWeakReference reference =
        getConnectionReference(tracker, id);
    assertNotNull(reference);
    reference.clear();

    IOException exception = assertThrows(IOException.class, () -> tracker.getConnection(id));

    assertTrue(exception.getMessage().contains(id.toString()));
  }

  @Test
  void getConnectionWeakReference_whenRegistered_expectStoredWeakReference() throws IOException {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    UUID id = UUID.randomUUID();
    FCPPluginConnectionImpl connection = mockConnection(id);
    tracker.registerConnection(connection);

    FCPPluginConnectionTracker.ConnectionWeakReference returned =
        tracker.getConnectionWeakReference(id);

    ReadWriteLock lock = connectionsLock(tracker);
    lock.readLock().lock();
    try {
      FCPPluginConnectionTracker.ConnectionWeakReference stored = connectionsById(tracker).get(id);
      assertSame(stored, returned);
      assertSame(connection, returned.get());
    } finally {
      lock.readLock().unlock();
    }
  }

  @Test
  void getConnectionWeakReference_whenMissing_expectIOException() {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();

    assertThrows(IOException.class, () -> tracker.getConnectionWeakReference(UUID.randomUUID()));
  }

  @Test
  void realRun_whenWeakReferenceEnqueued_expectRemovalAndShutdown() throws Exception {
    FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
    UUID id = UUID.randomUUID();
    FCPPluginConnectionImpl connection = mockConnection(id);
    tracker.registerConnection(connection);

    FCPPluginConnectionTracker.ConnectionWeakReference reference =
        getConnectionReference(tracker, id);
    assertNotNull(reference);
    reference.clear();
    assertTrue(reference.enqueue());

    AtomicReference<Throwable> uncaught = new AtomicReference<>();
    Thread worker = new Thread(tracker::realRun, "FCPPluginConnectionTrackerTest-realRun");
    worker.setDaemon(true);
    worker.setUncaughtExceptionHandler((t, e) -> uncaught.set(e));
    worker.start();

    try {
      waitForCondition(() -> getConnectionsSize(tracker) == 0, Duration.ofSeconds(2));
      waitForCondition(() -> worker.getState() == Thread.State.WAITING, Duration.ofSeconds(2));
    } finally {
      worker.interrupt();
      worker.join(1000);
    }

    assertEquals(0, getConnectionsSize(tracker));
    Throwable termination = uncaught.get();
    assertNotNull(termination);
    assertInstanceOf(RuntimeException.class, termination);
    assertInstanceOf(InterruptedException.class, termination.getCause());
  }

  private static FCPPluginConnectionImpl mockConnection(UUID id) {
    FCPPluginConnectionImpl connection = mock(FCPPluginConnectionImpl.class);
    when(connection.getID()).thenReturn(id);
    return connection;
  }

  private static Map<UUID, FCPPluginConnectionTracker.ConnectionWeakReference> connectionsById(
      FCPPluginConnectionTracker tracker) {
    try {
      @SuppressWarnings("unchecked")
      Map<UUID, FCPPluginConnectionTracker.ConnectionWeakReference> map =
          (Map<UUID, FCPPluginConnectionTracker.ConnectionWeakReference>)
              CONNECTIONS_BY_ID_FIELD.get(tracker);
      return map;
    } catch (IllegalAccessException e) {
      throw new AssertionError(e);
    }
  }

  private static ReadWriteLock connectionsLock(FCPPluginConnectionTracker tracker) {
    try {
      return (ReadWriteLock) CONNECTIONS_LOCK_FIELD.get(tracker);
    } catch (IllegalAccessException e) {
      throw new AssertionError(e);
    }
  }

  private static FCPPluginConnectionTracker.ConnectionWeakReference getConnectionReference(
      FCPPluginConnectionTracker tracker, UUID id) {
    ReadWriteLock lock = connectionsLock(tracker);
    lock.readLock().lock();
    try {
      return connectionsById(tracker).get(id);
    } finally {
      lock.readLock().unlock();
    }
  }

  private static int getConnectionsSize(FCPPluginConnectionTracker tracker) {
    ReadWriteLock lock = connectionsLock(tracker);
    lock.readLock().lock();
    try {
      return connectionsById(tracker).size();
    } finally {
      lock.readLock().unlock();
    }
  }

  private static Field locateField(String name) {
    try {
      Field field = FCPPluginConnectionTracker.class.getDeclaredField(name);
      field.setAccessible(true);
      return field;
    } catch (NoSuchFieldException e) {
      throw new AssertionError(e);
    }
  }

  private static void waitForCondition(BooleanSupplier condition, Duration timeout)
      throws InterruptedException {
    if (condition.getAsBoolean()) {
      return;
    }

    CountDownLatch latch = new CountDownLatch(1);
    ThreadFactory factory =
        runnable -> {
          Thread t = new Thread(runnable, "FCPPluginConnectionTrackerTest-await");
          t.setDaemon(true);
          return t;
        };
    try (ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(factory)) {
      ScheduledFuture<?> monitor =
          scheduler.scheduleAtFixedRate(
              () -> {
                if (condition.getAsBoolean()) {
                  latch.countDown();
                }
              },
              0,
              5,
              TimeUnit.MILLISECONDS);
      try {
        if (!latch.await(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
          fail("Condition not satisfied within " + timeout);
        }
      } finally {
        monitor.cancel(true);
      }
    }
  }
}
