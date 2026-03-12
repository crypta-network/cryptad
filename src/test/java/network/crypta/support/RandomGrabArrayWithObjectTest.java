package network.crypta.support;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Test method names use when/expect style
class RandomGrabArrayWithObjectTest {

  @Mock private RemoveRandomParent parent;

  @Mock private ClientRequestSelector root;

  /** Simple deterministic item used for exercising inherited RGA behavior. */
  private static final class TestItem implements RandomGrabArrayItem {
    private RandomGrabArray parent;

    @Override
    public long getWakeupTime(network.crypta.client.async.ClientContext context, long now) {
      return 0; // Always ready
    }

    @Override
    public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
      return false; // No-op for tests
    }

    @Override
    public void clearWakeupTime(ClientContext context) {
      // No-op for tests
    }

    @Override
    public boolean knowsParentGrabArray() {
      return true;
    }

    @Override
    public void setParentGrabArray(RandomGrabArray parent) {
      this.parent = parent;
    }

    @Override
    public RandomGrabArray getParentGrabArray() {
      return parent;
    }
  }

  @Test
  @DisplayName("constructor_and_getObject_whenInitialized_returnsClientAndEmpty")
  void constructor_and_getObject_whenInitialized_returnsClientAndEmpty() {
    // Arrange
    String client = "client-1";
    RandomGrabArrayWithObject<String> rga = new RandomGrabArrayWithObject<>(client, parent, root);

    // Act
    String got = rga.getObject();

    // Assert
    assertSame(client, got, "getObject should return the constructor-provided client");
    assertTrue(rga.isEmpty(), "Newly constructed RGA must be empty");
    assertEquals(0, rga.size(), "Newly constructed RGA has size 0");
  }

  @Test
  @DisplayName("setObject_whenReplacingWithNull_getObjectReturnsNull")
  void setObject_whenReplacingWithNull_getObjectReturnsNull() {
    // Arrange
    RandomGrabArrayWithObject<String> rga = new RandomGrabArrayWithObject<>("x", parent, root);

    // Act
    rga.setObject(null);

    // Assert
    assertNull(
        rga.getObject(), "getObject should reflect the last setObject() value, including null");
  }

  @Test
  @DisplayName("getObject_whenRootLockHeld_blocksUntilReleased")
  void getObject_whenRootLockHeld_blocksUntilReleased() throws InterruptedException {
    // Arrange
    RandomGrabArrayWithObject<String> rga = new RandomGrabArrayWithObject<>("client", parent, root);
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch finished = new CountDownLatch(1);
    AtomicReference<String> observed = new AtomicReference<>();

    Thread t =
        new Thread(
            () -> {
              started.countDown();
              // This call should block until the main thread releases the monitor on 'root'.
              observed.set(rga.getObject());
              finished.countDown();
            },
            "rga-getObject-thread");

    // Act & Assert (AAA split across interactions with the shared monitor)
    final ClientRequestSelector syncRoot = root; // capture to satisfy sync-on-field rules
    synchronized (syncRoot) { // hold the exact same monitor used by RandomGrabArrayWithObject
      t.start();
      assertTrue(started.await(2, TimeUnit.SECONDS), "Worker thread did not start in time");
      // While we hold the monitor, the worker call must not complete.
      assertFalse(
          finished.await(200, TimeUnit.MILLISECONDS),
          "getObject() should be blocked while root lock is held");
    }
    // After releasing the monitor, the worker should complete quickly and observe the client.
    assertTrue(finished.await(2, TimeUnit.SECONDS), "getObject() did not complete after unlock");
    assertEquals("client", observed.get());
  }

  @Test
  @DisplayName("isEmpty_addAndRemove_singleItemTransitionsAndNotifiesParent")
  void isEmpty_addAndRemove_singleItemTransitionsAndNotifiesParent() {
    // Arrange
    RandomGrabArrayWithObject<String> rga = new RandomGrabArrayWithObject<>("client", parent, root);
    TestItem item = new TestItem();
    assertTrue(rga.isEmpty());

    // Act: add one item (context may be null; add() tolerates null context)
    rga.add(item, null);

    // Assert: non-empty, contains item, and item's parent pointer set
    assertFalse(rga.isEmpty(), "Array should not be empty after add");
    assertTrue(rga.contains(item), "contains() should find the added item");
    assertSame(rga, item.getParentGrabArray(), "Item should track its parent RGA");

    // Act: remove the only item; use a mocked context for the callback path
    ClientContext ctx = Mockito.mock(ClientContext.class);
    rga.remove(item, ctx);

    // Assert: empty again and parent notified
    assertTrue(rga.isEmpty(), "Array should be empty after removing the sole item");
    Mockito.verify(parent).maybeRemove(rga, ctx);
  }
}
