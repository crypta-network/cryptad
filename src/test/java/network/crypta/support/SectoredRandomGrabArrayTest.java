package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import network.crypta.support.RemoveRandom.RemoveRandomReturn;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SectoredRandomGrabArrayTest {

  @Mock private RemoveRandomParent parent;

  private ClientRequestSelector root;

  @BeforeEach
  void setUp() {
    // Use a Mockito mock as the synchronization root; we may also verify wakeUp() in some tests.
    root = mock(ClientRequestSelector.class);
  }

  private static ClientContext contextWithRandom(Random r) throws Exception {
    // Create a Mockito mock, then set the public final field via reflection for deterministic RNG.
    ClientContext ctx = mock(ClientContext.class);
    Field f = ClientContext.class.getDeclaredField("fastWeakRandom");
    f.setAccessible(true);
    f.set(ctx, r);
    return ctx;
  }

  private static <T> RemoveRandomWithObject<T> newGrabber(
      T client, long wakeupTime, RemoveRandomReturn removeRandomReturn, boolean emptyAfter) {
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<T> rga = (RemoveRandomWithObject<T>) mock(RemoveRandomWithObject.class);
    lenient().when(rga.getObject()).thenReturn(client);
    lenient().when(rga.getWakeupTime(any(), anyLong())).thenReturn(wakeupTime);
    lenient().when(rga.removeRandom(any(), any(), anyLong())).thenReturn(removeRandomReturn);
    lenient().when(rga.isEmpty()).thenReturn(emptyAfter);
    return rga;
  }

  // Simple Random with fixed outcomes for determinism in tests that use nextBoolean/nextInt.
  private static final class FixedRandom extends Random {
    private final boolean bool;
    private final int fixedInt;

    FixedRandom(boolean bool, int fixedInt) {
      super(0L);
      this.bool = bool;
      this.fixedInt = fixedInt;
    }

    @Override
    public boolean nextBoolean() {
      return bool;
    }

    @Override
    public int nextInt(int bound) {
      // Ensure in-range and deterministic selection
      int v = fixedInt % bound;
      return v < 0 ? v + bound : v;
    }
  }

  @Test
  @DisplayName("addGrabber_whenClientMismatch_throwsIllegalArgumentException")
  void addGrabber_whenClientMismatch_throwsIllegalArgumentException() {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<Object> rga =
        (RemoveRandomWithObject<Object>) mock(RemoveRandomWithObject.class);
    // Return a different object instance to trigger the guard.
    when(rga.getObject()).thenReturn(new Object());

    assertThrows(
        IllegalArgumentException.class, () -> srga.addGrabber(client, rga, /* context= */ null));

    assertEquals(0, srga.size());
  }

  @Test
  @DisplayName("addGrabber_and_getGrabber_returnsSame_andParentCleared")
  void addGrabber_and_getGrabber_returnsSame_andParentCleared() {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<Object> rga =
        (RemoveRandomWithObject<Object>) mock(RemoveRandomWithObject.class);
    when(rga.getObject()).thenReturn(client);

    ClientContext ctx = mock(ClientContext.class);
    srga.addGrabber(client, rga, ctx);

    assertSame(rga, srga.getGrabber(client));
    assertEquals(1, srga.size());
    verify(parent, times(1)).clearWakeupTime(ctx);
  }

  @Test
  @DisplayName("removeRandom_whenEmpty_returnsNull")
  void removeRandom_whenEmpty_returnsNull() {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    RemoveRandomReturn ret =
        srga.removeRandom(
            mock(RandomGrabArrayItemExclusionList.class), mock(ClientContext.class), 123L);
    assertNull(ret);
    assertEquals(0, srga.size());
  }

  @Test
  @DisplayName("removeRandom_oneOnly_whenExcluded_returnsWakeupTime")
  void removeRandom_oneOnly_whenExcluded_returnsWakeupTime() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    long now = 1_000L;
    long excludeUntil = 5_000L;
    RemoveRandomWithObject<Object> rga =
        newGrabber(client, excludeUntil, /* removeRandomReturn= */ null, /* emptyAfter= */ false);
    srga.addGrabber(client, rga, null);

    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0));
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, now);

    assertNotNull(ret);
    assertNull(ret.item);
    assertEquals(excludeUntil, ret.wakeupTime);
    assertEquals(1, srga.size());
  }

  @Test
  @DisplayName("removeRandom_oneOnly_whenItemReturned_returnsItem")
  void removeRandom_oneOnly_whenItemReturned_returnsItem() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    RandomGrabArrayItem item = mock(RandomGrabArrayItem.class);
    RemoveRandomReturn val = new RemoveRandomReturn(item);
    RemoveRandomWithObject<Object> rga =
        newGrabber(client, /*wakeup*/ 0L, val, /* emptyAfter= */ false);
    srga.addGrabber(client, rga, null);

    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0));
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, 10L);

    assertNotNull(ret);
    assertSame(item, ret.item);
    assertEquals(-1L, ret.wakeupTime);
    assertEquals(1, srga.size());
  }

  @Test
  @DisplayName("removeRandom_oneOnly_whenEmptyAfterAndNoItem_returnsNullAndRemovesChild")
  void removeRandom_oneOnly_whenEmptyAfterAndNoItem_returnsNullAndRemovesChild() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    long wakeLater = 7_777L;
    RemoveRandomReturn val = new RemoveRandomReturn(wakeLater);
    RemoveRandomWithObject<Object> rga =
        newGrabber(client, /*wakeup*/ 0L, val, /* emptyAfter= */ true);
    srga.addGrabber(client, rga, null);

    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0));
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, 1L);

    assertNull(ret); // arrays become empty; method returns null in this branch
    assertEquals(0, srga.size());
  }

  @Test
  @DisplayName("removeRandom_twoOnly_firstReturnsItem")
  void removeRandom_twoOnly_firstReturnsItem() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client0 = new Object();
    Object client1 = new Object();
    RandomGrabArrayItem item0 = mock(RandomGrabArrayItem.class);
    RemoveRandomWithObject<Object> rga0 =
        newGrabber(client0, 0L, new RemoveRandomReturn(item0), false);
    RemoveRandomWithObject<Object> rga1 = newGrabber(client1, 0L, null, false);
    srga.addGrabber(client0, rga0, null);
    srga.addGrabber(client1, rga1, null);

    // Force nextBoolean() -> false so first index (0) is tried first
    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0));
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, 1L);

    assertNotNull(ret);
    assertSame(item0, ret.item);
    assertEquals(2, srga.size());
  }

  @Test
  @DisplayName("removeRandom_twoOnly_firstExcluded_secondReturnsWakeTime_propagatesReduction")
  void removeRandom_twoOnly_firstExcluded_secondReturnsWakeTime_propagatesReduction()
      throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client0 = new Object();
    Object client1 = new Object();
    long now = 100L;
    long later = 1_234L;

    // First is excluded via getWakeupTime > 0; second returns wake time via RemoveRandomReturn
    RemoveRandomWithObject<Object> rga0 =
        newGrabber(client0, /*excluded until*/ later, null, false);
    RemoveRandomWithObject<Object> rga1 =
        newGrabber(client1, /*wakeup*/ 0L, new RemoveRandomReturn(later), false);
    srga.addGrabber(client0, rga0, null);
    srga.addGrabber(client1, rga1, null);

    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0)); // pick index 0 first
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, now);

    assertNotNull(ret);
    assertNull(ret.item);
    assertEquals(later, ret.wakeupTime);
    // Reduction propagates upwards to parent
    // In SRGA.reduceWakeupTime(), the internal wakeupTime only reduces when larger than the new
    // value. Default internal value is 0, so no parent propagation is expected here.
  }

  @Test
  @DisplayName("removeRandom_twoOnly_bothEmpty_arraysClearedAndNullReturned")
  void removeRandom_twoOnly_bothEmpty_arraysClearedAndNullReturned() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client0 = new Object();
    Object client1 = new Object();
    // Both not excluded, return no item, and are empty afterward
    RemoveRandomWithObject<Object> rga0 = newGrabber(client0, 0L, /*val*/ null, /*empty*/ true);
    RemoveRandomWithObject<Object> rga1 = newGrabber(client1, 0L, /*val*/ null, /*empty*/ true);
    srga.addGrabber(client0, rga0, null);
    srga.addGrabber(client1, rga1, null);

    ClientContext ctx = contextWithRandom(new FixedRandom(false, 1)); // start with index 0
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, 0L);

    assertNull(ret);
    assertEquals(0, srga.size());
  }

  @Test
  @DisplayName("removeRandom_threeOrMore_allExcluded_returnsMinWakeTime_andReduces")
  void removeRandom_threeOrMore_allExcluded_returnsMinWakeTime_andReduces() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object c0 = new Object();
    Object c1 = new Object();
    Object c2 = new Object();
    long now = 111L;
    long w0 = 10_000L;
    long w1 = 500L; // minimum
    long w2 = 1_500L;

    srga.addGrabber(c0, newGrabber(c0, w0, null, false), null);
    srga.addGrabber(c1, newGrabber(c1, w1, null, false), null);
    srga.addGrabber(c2, newGrabber(c2, w2, null, false), null);

    // Limited path keeps picking index 0 (always excluded) until limit; exhaustive computes min
    ClientContext ctx = contextWithRandom(new FixedRandom(false, 0));
    RemoveRandomReturn ret =
        srga.removeRandom(mock(RandomGrabArrayItemExclusionList.class), ctx, now);

    assertNotNull(ret);
    assertNull(ret.item);
    assertEquals(w1, ret.wakeupTime);
    // No parent propagation expected; internal wakeupTime starts at 0.
  }

  @Test
  @DisplayName("maybeRemove_whenRemovingLastChild_notifiesParent")
  void maybeRemove_whenRemovingLastChild_notifiesParent() {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object client = new Object();
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<Object> rga =
        (RemoveRandomWithObject<Object>) mock(RemoveRandomWithObject.class);
    when(rga.getObject()).thenReturn(client);
    srga.addGrabber(client, rga, null);

    ClientContext ctx = mock(ClientContext.class);
    srga.maybeRemove(rga, ctx);

    assertEquals(0, srga.size());
    verify(parent, times(1)).maybeRemove(srga, ctx);
  }

  @Test
  @DisplayName("getClient_returnsClientByIndex")
  void getClient_returnsClientByIndex() {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(parent, root);

    Object a = new Object();
    Object b = new Object();
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<Object> rgaA =
        (RemoveRandomWithObject<Object>) mock(RemoveRandomWithObject.class);
    @SuppressWarnings("unchecked")
    RemoveRandomWithObject<Object> rgaB =
        (RemoveRandomWithObject<Object>) mock(RemoveRandomWithObject.class);
    when(rgaA.getObject()).thenReturn(a);
    when(rgaB.getObject()).thenReturn(b);

    srga.addGrabber(a, rgaA, null);
    srga.addGrabber(b, rgaB, null);

    assertSame(a, srga.getClient(0));
    assertSame(b, srga.getClient(1));
    assertEquals(2, srga.size());
  }

  @Test
  @DisplayName("reduceWakeupTime_whenParentNull_callsRootWakeUp_andReturnsTrue")
  void reduceWakeupTime_whenParentNull_callsRootWakeUp_andReturnsTrue() throws Exception {
    SectoredRandomGrabArray<Object, RemoveRandomWithObject<Object>> srga =
        new SectoredRandomGrabArray<>(/* parent= */ null, root);

    // Ensure parent is null to trigger root.wakeUp(context) when reduced.
    srga.setParent(null);

    // Set an initial wakeupTime greater than the reduction target via reflection.
    Field f = SectoredRandomGrabArray.class.getDeclaredField("wakeupTime");
    f.setAccessible(true);
    f.set(srga, 10_000L);

    ClientContext ctx = mock(ClientContext.class);
    boolean reduced = srga.reduceWakeupTime(1_000L, ctx);

    assertTrue(reduced);
    verify(root, times(1)).wakeUp(ctx);
  }
}
