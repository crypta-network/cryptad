package network.crypta.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class IdentityHashSetTest {

  @Test
  void add_whenAddingNewObject_returnsTrueAndContainsByIdentity() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object o1 = new Object();

    boolean added = set.add(o1);

    assertTrue(added, "First add should return true");
    assertTrue(set.contains(o1), "Set should contain the exact reference");
    assertFalse(set.contains(new Object()), "Equal-by-default new Object should not be contained");
  }

  @Test
  void add_whenAddingEqualButDifferentInstances_considersDistinct() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue a1 = new EqValue("a");
    EqValue a2 = new EqValue("a");

    assertTrue(set.add(a1));
    assertTrue(set.add(a2), "Different instance with same value should be added");
    assertEquals(2, set.size());
    assertTrue(set.contains(a1));
    assertTrue(set.contains(a2));
  }

  @Test
  void add_whenAddingSameReferenceTwice_secondReturnsFalse() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object o = new Object();

    assertTrue(set.add(o));
    assertFalse(set.add(o), "Adding the same reference twice should return false");
    assertEquals(1, set.size());
  }

  @Test
  void remove_whenPresent_returnsTrueAndRemovesByIdentityOnly() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue x1 = new EqValue("x");
    EqValue x2 = new EqValue("x");

    set.add(x1);
    set.add(x2);

    assertTrue(set.remove(x1), "Removing existing exact reference should return true");
    assertFalse(set.contains(x1));
    assertTrue(set.contains(x2), "Other instance with equal value remains");
    assertFalse(
        set.remove(new EqValue("x")), "Removing equal but different instance should return false");
  }

  @Test
  void containsAll_whenAllReferencesPresent_true_andEqualButNotSame_false() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue s1 = new EqValue("s");
    EqValue s2 = new EqValue("s");
    set.add(s1);
    set.add(s2);

    List<EqValue> sameRefs = Arrays.asList(s1, s2);
    List<EqValue> equalButDifferent = Arrays.asList(new EqValue("s"), new EqValue("s"));

    assertTrue(set.containsAll(sameRefs), "Should contain all exact references");
    assertFalse(
        set.containsAll(equalButDifferent),
        "Should not contain collection with only equal-but-different instances");
  }

  @Test
  void removeAll_whenCollectionContainsSomePresent_returnsTrueAndRemovesThoseOnly() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();
    // Intentionally keep only 'a' and 'b' for this scenario
    set.add(a);
    set.add(b);

    Set<Object> toRemove = new IdentityHashSet<>();
    toRemove.add(b);
    toRemove.add(new Object());
    toRemove.add(new Object());
    boolean changed = set.removeAll(toRemove);

    assertTrue(changed, "Should report change when at least one element was removed");
    assertTrue(set.contains(a));
    assertFalse(set.contains(b));
    assertEquals(1, set.size());
  }

  @Test
  void iterator_returnsAllElementsByIdentity() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue v1 = new EqValue("v");
    EqValue v2 = new EqValue("v");
    set.add(v1);
    set.add(v2);

    List<EqValue> seen = new ArrayList<>(set);

    assertEquals(2, seen.size());
    // Verify identity, not just equality
    assertTrue(containsByIdentity(seen, v1));
    assertTrue(containsByIdentity(seen, v2));
  }

  @Test
  void toArray_noArg_returnsAllElements() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();
    Object c = new Object();
    set.add(a);
    set.add(b);
    set.add(c);

    Object[] arr = set.toArray();

    assertEquals(3, arr.length);
    assertTrue(containsByIdentity(Arrays.asList(arr), a));
    assertTrue(containsByIdentity(Arrays.asList(arr), b));
    assertTrue(containsByIdentity(Arrays.asList(arr), c));
  }

  @Test
  void toArray_typedArray_smallerProvided_returnsNewArrayOfType() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue a = new EqValue("a");
    EqValue b = new EqValue("b");
    set.add(a);
    set.add(b);

    EqValue[] provided = new EqValue[0];
    EqValue[] out = set.toArray(provided);

    assertEquals(2, out.length);
    assertTrue(containsByIdentity(Arrays.asList(out), a));
    assertTrue(containsByIdentity(Arrays.asList(out), b));
  }

  @Test
  void toArray_typedArray_largerProvided_fillsAndSetsNullAtEnd() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();
    Object c = new Object();
    set.add(a);
    set.add(b);
    set.add(c);

    Object[] provided = new Object[5];
    Object[] out = set.toArray(provided);

    assertSame(provided, out, "Should return the same provided array when it is large enough");
    assertTrue(containsByIdentity(Arrays.asList(out[0], out[1], out[2]), a));
    assertTrue(containsByIdentity(Arrays.asList(out[0], out[1], out[2]), b));
    assertTrue(containsByIdentity(Arrays.asList(out[0], out[1], out[2]), c));
    assertArrayEquals(new Object[] {null, null}, new Object[] {out[3], out[4]});
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void clear_and_isEmpty_workAsExpected() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    assertTrue(set.isEmpty());
    set.add(new Object());
    assertFalse(set.isEmpty());
    set.clear();
    assertTrue(set.isEmpty());
    assertEquals(0, set.size());
  }

  @Test
  @SuppressWarnings("OverwrittenKey")
  void size_reflectsNumberOfDistinctIdentities() {
    IdentityHashSet<EqValue> set = new IdentityHashSet<>();
    EqValue s1 = new EqValue("same");
    EqValue s2 = new EqValue("same");
    set.add(s1);
    set.add(s2);
    set.add(s1); // duplicate reference
    assertEquals(2, set.size());
  }

  @Test
  void addAll_whenAddingOnlyNewElements_returnsTrueAndElementsAdded() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();

    boolean changed = set.addAll(Arrays.asList(a, b));

    assertTrue(changed, "addAll must return true when the set changes");
    assertEquals(2, set.size());
    assertTrue(set.contains(a));
    assertTrue(set.contains(b));
  }

  @Test
  void addAll_whenAddingSomePresentSomeNew_returnsTrue() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();
    set.add(a);

    boolean changed = set.addAll(Arrays.asList(a, b));

    assertTrue(changed, "addAll must return true when at least one new element is added");
    assertEquals(2, set.size());
    assertTrue(set.contains(a));
    assertTrue(set.contains(b));
  }

  @Test
  void addAll_whenAddingOnlyDuplicates_returnsFalseAndNoChangeInSize() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    Object a = new Object();
    Object b = new Object();
    set.add(a);
    set.add(b);

    boolean changed = set.addAll(Arrays.asList(a, b));

    assertFalse(changed, "addAll must return false when the set does not change");
    assertEquals(2, set.size());
  }

  @Test
  void retainAll_whenCalled_throwsUnsupportedOperationException() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    List<Object> empty = List.of();
    assertThrows(UnsupportedOperationException.class, () -> set.retainAll(empty));
  }

  @Test
  void nullHandling_addContainsRemoveNull_supported() {
    IdentityHashSet<Object> set = new IdentityHashSet<>();
    assertTrue(set.add(null));
    assertTrue(set.contains(null));
    assertFalse(set.add(null), "Adding null again should return false");
    assertTrue(set.remove(null));
    assertFalse(set.contains(null));
  }

  private static boolean containsByIdentity(Iterable<?> it, Object needle) {
    for (Object o : it) {
      if (o == needle) return true;
    }
    return false;
  }

  private static final class EqValue {
    private final String value;

    EqValue(String value) {
      this.value = value;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null || getClass() != obj.getClass()) return false;
      EqValue other = (EqValue) obj;
      return value.equals(other.value);
    }

    @Override
    public int hashCode() {
      return value.hashCode();
    }

    @Override
    public String toString() {
      return "EqValue{" + value + '}';
    }
  }
}
