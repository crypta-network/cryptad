package network.crypta.support;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientRequestSelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SectoredRandomGrabArrayWithObject} focusing on its public API: storing and
 * retrieving the associated object and the {@code toString()} contract. Concurrency behavior is
 * validated in a deterministic way by coordinating threads around the shared {@code root} monitor
 * used by the implementation.
 */
@ExtendWith(MockitoExtension.class)
class SectoredRandomGrabArrayWithObjectTest {

  @Mock private ClientRequestSelector root;

  @Mock private RemoveRandomParent parent;

  @Test
  @DisplayName("getObject returns initial object passed to constructor")
  void getObject_whenConstructed_expectInitialValue() {
    // Arrange
    String initial = "client-A";
    final ClientRequestSelector monitor = root;
    SectoredRandomGrabArrayWithObject<String, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>(initial, parent, monitor);

    // Act
    String result = underTest.getObject();

    // Assert
    assertEquals(initial, result, "getObject should return the initial object");
  }

  @Test
  @DisplayName("setObject updates value observed by getObject")
  void setObject_whenUpdated_expectNewValue() {
    // Arrange
    SectoredRandomGrabArrayWithObject<String, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>("first", parent, root);

    // Act
    underTest.setObject("second");
    String result = underTest.getObject();

    // Assert
    assertEquals("second", result, "getObject should reflect the last set value");
  }

  @Test
  @DisplayName("null object is allowed and reflected in toString")
  void getObject_andToString_whenNull_expectNullAndSuffixNull() {
    // Arrange
    SectoredRandomGrabArrayWithObject<String, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>(null, parent, root);

    // Act
    String value = underTest.getObject();
    String str = underTest.toString();

    // Assert
    assertNull(value, "getObject should return null when constructed with null");
    assertTrue(
        str.contains("SectoredRandomGrabArrayWithObject"),
        "toString should include the class name of the instance");
    assertTrue(
        str.endsWith(":null"),
        "toString should append ':' and the object's string representation (null)");
  }

  @Test
  @DisplayName("toString appends ':' and object's toString()")
  void toString_whenNonNull_expectAppendedObjectString() {
    // Arrange
    class Obj {
      @Override
      public String toString() {
        return "MYOBJ";
      }
    }

    Obj obj = new Obj();
    SectoredRandomGrabArrayWithObject<Obj, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>(obj, parent, root);

    // Act
    String str = underTest.toString();

    // Assert
    assertTrue(str.contains("SectoredRandomGrabArrayWithObject"));
    assertTrue(str.endsWith(":" + obj));
  }

  @Test
  @DisplayName("getObject blocks on root monitor held by another thread, then returns value")
  void getObject_whenRootLockedInOtherThread_blocksUntilReleased() throws InterruptedException {
    // Arrange
    String initial = "value";
    final ClientRequestSelector monitor = root;
    SectoredRandomGrabArrayWithObject<String, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>(initial, parent, monitor);

    AtomicReference<String> resultRef = new AtomicReference<>();
    CountDownLatch done = new CountDownLatch(1);

    // Hold the root monitor in this thread and start a worker that attempts to get the object.
    boolean sawBlockedState = false;
    synchronized (monitor) {
      Thread t =
          new Thread(
              () -> {
                String r = underTest.getObject();
                resultRef.set(r);
                done.countDown();
              },
              "getObject-worker");
      t.start();

      // Busy-wait with small yields until the worker is BLOCKED trying to enter the monitor
      // or until it terminates unexpectedly. Bound the wait to avoid flakiness.
      long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      while (System.nanoTime() < deadlineNanos) {
        Thread.State s = t.getState();
        if (s == Thread.State.BLOCKED) {
          sawBlockedState = true;
          break;
        }
        Thread.onSpinWait();
      }

      // Still holding the monitor here; release below so the worker can proceed.
      assertTrue(sawBlockedState, "Worker should block on the root monitor before we release it");
    }

    // After releasing the monitor, the worker should complete quickly and return the value.
    assertTrue(done.await(2, TimeUnit.SECONDS), "Worker should finish after monitor is released");
    assertEquals(initial, resultRef.get());
  }

  @Test
  @DisplayName("setObject blocks on root monitor held by another thread and applies after release")
  void setObject_whenRootLockedInOtherThread_blocksAndApplies() throws InterruptedException {
    // Arrange
    final ClientRequestSelector monitor = root;
    SectoredRandomGrabArrayWithObject<String, Object, RemoveRandomWithObject<Object>> underTest =
        new SectoredRandomGrabArrayWithObject<>("before", parent, monitor);

    CountDownLatch done = new CountDownLatch(1);

    // Hold the root monitor so the background setter must wait.
    boolean sawBlockedState = false;
    synchronized (monitor) {
      Thread setter =
          new Thread(
              () -> {
                underTest.setObject("after");
                done.countDown();
              },
              "setObject-worker");
      setter.start();

      long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      while (System.nanoTime() < deadlineNanos) {
        Thread.State s = setter.getState();
        if (s == Thread.State.BLOCKED) {
          sawBlockedState = true;
          break;
        }
        Thread.onSpinWait();
      }

      assertTrue(sawBlockedState, "Setter should block on the root monitor before we release it");
    }

    assertTrue(done.await(2, TimeUnit.SECONDS), "Setter should finish after monitor is released");
    assertEquals("after", underTest.getObject());
  }
}
