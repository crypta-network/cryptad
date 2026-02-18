package network.crypta.support;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientRequestSelector;
import network.crypta.node.ClientContextResources;
import network.crypta.support.RemoveRandom.RemoveRandomReturn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method naming per provided convention
class RandomGrabArrayTest {

  // ---- Helpers ------------------------------------------------------------

  private static ClientContext ctxWithSeed(long seed) {
    // Reuse the pattern from PersistentJobRunnerImplTest to ensure signature parity.
    var exec =
        new network.crypta.support.WaitableExecutor(new network.crypta.support.PooledExecutor());
    var ticker = new network.crypta.support.CheatingTicker(exec);
    return new ClientContext(
        0L,
        new ClientContextRuntime(null, exec, null, ticker, null, new Random(seed), null),
        new ClientContextStorageFactories(null, null, null, null, null, null, null),
        new ClientContextRafFactories(null, null),
        new ClientContextServices(
            new ClientContextResources(null, null), null, null, null, null, null),
        new ClientContextDefaults(null, null, null));
  }

  private static class TestItem implements RandomGrabArrayItem {
    private final String name;
    private final long wake;
    private volatile RandomGrabArray parent;

    TestItem(String name, long wake) {
      this.name = name;
      this.wake = wake;
    }

    @Override
    public long getWakeupTime(ClientContext context, long now) {
      return wake;
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

    @Override
    public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
      // Not needed for tests; items do not propagate.
      return false;
    }

    @Override
    public void clearWakeupTime(ClientContext context) {
      // Not needed for tests.
    }

    @Override
    public String toString() {
      return "TestItem{" + name + ", wake=" + wake + '}';
    }
  }

  private static class FixedExclusions implements RandomGrabArrayItemExclusionList {
    private final Map<RandomGrabArrayItem, Long> times = new HashMap<>();
    private final long defaultTime;

    FixedExclusions(long defaultTime) {
      this.defaultTime = defaultTime;
    }

    FixedExclusions put(RandomGrabArrayItem item, long time) {
      times.put(item, time);
      return this;
    }

    @Override
    public long exclude(RandomGrabArrayItem item, ClientContext context, long now) {
      return times.getOrDefault(item, defaultTime);
    }
  }

  // ---- Tests: add / contains / size / get --------------------------------

  @Test
  void add_whenContextNull_addsEvenIfCancelled() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);

    TestItem item = new TestItem("A", -1); // would be considered cancelled if context present

    rga.add(item, null); // context null → skip finished check

    assertFalse(rga.isEmpty());
    assertEquals(1, rga.size());
    assertSame(item, rga.get(0));
    assertTrue(rga.contains(item));
  }

  @Test
  void add_whenDuplicate_doesNotIncreaseSize() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);

    TestItem item = new TestItem("A", 0);

    rga.add(item, null);
    rga.add(item, null);

    assertEquals(1, rga.size());
  }

  @Test
  void add_whenFinishedWithContext_ignoresItem() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);

    // Use Mockito to verify setParentGrabArray is not called when item reports finished (<0).
    RandomGrabArrayItem mockItem = mock(RandomGrabArrayItem.class);
    ClientContext ctx = ctxWithSeed(123);
    doReturn(-1L)
        .when(mockItem)
        .getWakeupTime(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyLong());

    rga.add(mockItem, ctx);

    assertTrue(rga.isEmpty());
    assertEquals(0, rga.size());
    // setParentGrabArray must not be invoked because add() returned early.
    verify(mockItem, times(0)).setParentGrabArray(rga);
  }

  // ---- Tests: removeRandom (exhaustive path) -------------------------------

  @Test
  void removeRandom_whenEmpty_returnsNull() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RandomGrabArray rga = new RandomGrabArray(null, root);

    RemoveRandomReturn ret = rga.removeRandom(new FixedExclusions(0), ctxWithSeed(42), 123L);
    assertNull(ret);
  }

  @Test
  void removeRandom_whenAllValidBelowThreshold_selectsDeterministically() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RandomGrabArray rga = new RandomGrabArray(null, root);
    ClientContext ctx = ctxWithSeed(98765);

    TestItem a = new TestItem("A", 0);
    TestItem b = new TestItem("B", 0);
    TestItem c = new TestItem("C", 0);
    rga.add(a, null);
    rga.add(b, null);
    rga.add(c, null);

    // valid == 3 → expected index is nextInt(3) with same seed
    int expectedIndex = new Random(98765).nextInt(3);

    RemoveRandomReturn ret = rga.removeRandom(new FixedExclusions(0), ctx, 1L);
    assertNotNull(ret);
    assertNotNull(ret.item);

    RandomGrabArrayItem expected = expectedIndex == 0 ? a : expectedIndex == 1 ? b : c;
    assertSame(expected, ret.item);
    // Array is not modified for ready items
    assertEquals(3, rga.size());
  }

  @Test
  void removeRandom_whenAllExcluded_returnsEarliestWakeupAndStoresIt() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RandomGrabArray rga = new RandomGrabArray(null, root);
    ClientContext ctx = ctxWithSeed(1);

    long now = 1_000L;
    TestItem a = new TestItem("A", 0);
    TestItem b = new TestItem("B", 0);
    rga.add(a, null);
    rga.add(b, null);

    long t1 = now + 5000;
    long t2 = now + 3000; // earliest
    FixedExclusions excl = new FixedExclusions(0).put(a, t1).put(b, t2);

    RemoveRandomReturn ret = rga.removeRandom(excl, ctx, now);
    assertNotNull(ret);
    assertNull(ret.item);
    assertEquals(t2, ret.wakeupTime);

    // Wakeup is stored on the RGA until time passes
    assertEquals(t2, rga.getWakeupTime(ctx, now));
    // Clearing should propagate to parent; when no parent, it just clears locally.
    rga.clearWakeupTime(ctx);
    assertEquals(0L, rga.getWakeupTime(ctx, now));
  }

  @Test
  void removeRandom_whenCancelledItem_compactsAndReturnsNullWhenEmpty() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RandomGrabArray rga = new RandomGrabArray(null, root);
    ClientContext ctx = ctxWithSeed(7);

    TestItem a = new TestItem("A", -1); // cancelled
    rga.add(a, null);

    RemoveRandomReturn ret = rga.removeRandom(new FixedExclusions(0), ctx, 0L);
    assertNull(ret); // empty container → null per contract
    assertTrue(rga.isEmpty());
  }

  @Test
  void removeRandom_whenLimitedPathFallsBack_returnsEarliestWake() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RandomGrabArray rga = new RandomGrabArray(null, root);
    ClientContext ctx = ctxWithSeed(12345); // deterministic

    long now = 10_000L;
    // Fill with >= MAX_EXCLUDED items so limited path is used first.
    // All items are ready (0) but exclusion list defers them to the same time.
    final int n = RandomGrabArray.MAX_EXCLUDED + 2; // 12
    long wake = now + 42_000L;
    for (int i = 0; i < n; i++) {
      rga.add(new TestItem("I" + i, 0), null);
    }
    FixedExclusions excl = new FixedExclusions(wake);

    RemoveRandomReturn ret = rga.removeRandom(excl, ctx, now);
    assertNotNull(ret);
    assertNull(ret.item);
    assertEquals(wake, ret.wakeupTime);
    assertEquals(wake, rga.getWakeupTime(ctx, now));
  }

  // ---- Tests: remove(item) + parent propagation ---------------------------

  @Test
  void remove_whenLastItem_callsMaybeRemoveOnParent() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);
    ClientContext ctx = ctxWithSeed(777);

    TestItem a = new TestItem("A", 0);
    rga.add(a, null);
    assertEquals(1, rga.size());

    rga.remove(a, ctx);

    assertEquals(0, rga.size());
    assertTrue(rga.isEmpty());
    verify(parent, times(1)).maybeRemove(rga, ctx);
  }

  @Test
  void remove_whenItemNotPresent_noop() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);
    ClientContext ctx = ctxWithSeed(9);

    TestItem a = new TestItem("A", 0);

    rga.remove(a, ctx); // not added

    assertEquals(0, rga.size());
    assertTrue(rga.isEmpty());
    verify(parent, times(0)).maybeRemove(rga, ctx);
  }

  // ---- Tests: wakeup reduce/clear propagation to parent -------------------

  @Test
  void reduceWakeupTime_whenReduced_propagatesToParent() {
    ClientRequestSelector root = mock(ClientRequestSelector.class);
    RemoveRandomParent parent = mock(RemoveRandomParent.class);
    RandomGrabArray rga = new RandomGrabArray(parent, root);
    ClientContext ctx = ctxWithSeed(55);

    long now = 1_000L;
    long later = now + 100_000L;
    long earlier = now + 10_000L;

    // Establish a later wakeup by running a selection where all items are excluded.
    TestItem tmp = new TestItem("X", 0);
    rga.add(tmp, null);
    rga.removeRandom(new FixedExclusions(later), ctx, now);
    assertEquals(later, rga.getWakeupTime(ctx, now));

    // Now reduce; should propagate.
    boolean changed = rga.reduceWakeupTime(earlier, ctx);
    assertTrue(changed);
    assertEquals(earlier, rga.getWakeupTime(ctx, now));
    verify(parent, times(1)).reduceWakeupTime(earlier, ctx);
  }
}
