package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.NoSuchElementException;
import network.crypta.support.DoublyLinkedListImpl.Item;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // test method naming with underscores per project conventions
class DoublyLinkedListImplTest {
  @Test
  void push_and_pop_whenAddedInOrder_expectLIFOFromTail() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(0));
    list.push(new T(1));
    list.push(new T(2));
    list.push(new T(3));

    assertFalse(list.isEmpty(), "isEmpty()");
    T r1 = list.pop();
    assertNotNull(r1);
    r1.assertV(3);
    assertFalse(list.isEmpty(), "isEmpty()");
    T r2 = list.pop();
    assertNotNull(r2);
    r2.assertV(2);
    assertFalse(list.isEmpty(), "isEmpty()");

    // add again
    list.push(new T(4));
    list.push(new T(5));

    T r3 = list.pop();
    assertNotNull(r3);
    r3.assertV(5);
    assertFalse(list.isEmpty(), "isEmpty()");
    T r4 = list.pop();
    assertNotNull(r4);
    r4.assertV(4);
    assertFalse(list.isEmpty(), "isEmpty()");
    T r5 = list.pop();
    assertNotNull(r5);
    r5.assertV(1);
    assertFalse(list.isEmpty(), "isEmpty()");
    T r6 = list.pop();
    assertNotNull(r6);
    r6.assertV(0);

    assertTrue(list.isEmpty(), "isEmpty()");
    assertNull(list.pop(), "pop()");
  }

  @Test
  void unshift_and_shift_whenAddedInOrder_expectFIFOFromHead() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.unshift(new T(0));
    list.unshift(new T(1));
    list.unshift(new T(2));
    list.unshift(new T(3));

    assertFalse(list.isEmpty(), "isEmpty()");
    T s1 = list.shift();
    assertNotNull(s1);
    s1.assertV(3);
    assertFalse(list.isEmpty(), "isEmpty()");
    T s2 = list.shift();
    assertNotNull(s2);
    s2.assertV(2);
    assertFalse(list.isEmpty(), "isEmpty()");

    // add again
    list.unshift(new T(4));
    list.unshift(new T(5));

    T s3 = list.shift();
    assertNotNull(s3);
    s3.assertV(5);
    assertFalse(list.isEmpty(), "isEmpty()");
    T s4 = list.shift();
    assertNotNull(s4);
    s4.assertV(4);
    assertFalse(list.isEmpty(), "isEmpty()");
    T s5 = list.shift();
    assertNotNull(s5);
    s5.assertV(1);
    assertFalse(list.isEmpty(), "isEmpty()");
    T s6 = list.shift();
    assertNotNull(s6);
    s6.assertV(0);

    assertTrue(list.isEmpty(), "isEmpty()");
    assertNull(list.shift(), "shift()");
  }

  @Test
  void clear_whenListHasElements_expectSizeZeroAndEmpty() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.unshift(new T(0));
    list.unshift(new T(1));
    list.unshift(new T(2));
    list.unshift(new T(3));

    assertEquals(4, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");
    T cs1 = list.shift();
    assertNotNull(cs1);
    cs1.assertV(3);
    assertEquals(3, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");
    T cs2 = list.shift();
    assertNotNull(cs2);
    cs2.assertV(2);
    assertEquals(2, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");

    list.clear();

    assertEquals(0, list.size(), "size()");
    assertTrue(list.isEmpty(), "isEmpty()");

    // add again
    list.unshift(new T(4));
    list.unshift(new T(5));
    assertEquals(2, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");

    T cs3 = list.shift();
    assertNotNull(cs3);
    cs3.assertV(5);
    T cs4 = list.shift();
    assertNotNull(cs4);
    cs4.assertV(4);

    assertEquals(0, list.size(), "size()");
    assertTrue(list.isEmpty(), "isEmpty()");
  }

  @Test
  void shift_whenNWithinAndBeyondBounds_expectCorrectPartitioning() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();

    for (int i = 0; i < 5; i++) {
      list.push(new T(i));
    }

    DoublyLinkedList<T> list2 = list.shift(2);
    assertEquals(2, list2.size(), "list2.size()");
    T s2a = list2.shift();
    assertNotNull(s2a);
    s2a.assertV(0);
    T s2b = list2.shift();
    assertNotNull(s2b);
    s2b.assertV(1);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    assertEquals(3, list.size(), "list.size()");
    T sRemain = list.shift();
    assertNotNull(sRemain);
    sRemain.assertV(2);

    list2 = list.shift(20);
    assertTrue(list.isEmpty(), "list.isEmpty()");
    T s2c = list2.shift();
    assertNotNull(s2c);
    s2c.assertV(3);
    T s2d = list2.shift();
    assertNotNull(s2d);
    s2d.assertV(4);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    list2 = list.shift(20);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");
  }

  @Test
  void pop_whenNWithinAndBeyondBounds_expectCorrectPartitioning() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();

    for (int i = 0; i < 5; i++) {
      list.unshift(new T(i));
    }

    DoublyLinkedList<T> list2 = list.pop(2);
    assertEquals(2, list2.size(), "list2.size()");
    T p2a = list2.pop();
    assertNotNull(p2a);
    p2a.assertV(0);
    T p2b = list2.pop();
    assertNotNull(p2b);
    p2b.assertV(1);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    assertEquals(3, list.size(), "list.size()");
    T pRemain = list.pop();
    assertNotNull(pRemain);
    pRemain.assertV(2);

    list2 = list.pop(20);
    assertTrue(list.isEmpty(), "list.isEmpty()");
    T p2c = list2.pop();
    assertNotNull(p2c);
    p2c.assertV(3);
    T p2d = list2.pop();
    assertNotNull(p2d);
    p2d.assertV(4);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    list2 = list.pop(20);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");
  }

  @Test
  void head_and_tail_whenListChanges_expectUpdatedEnds() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();

    assertNull(list.head(), "head() == null");
    assertNull(list.tail(), "tail() == null");

    T[] array = new T[5];
    for (int i = 0; i < 5; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    assertSame(array[0], list.head(), "head() == 0");
    assertSame(array[4], list.tail(), "tail() == 4");

    list.shift();
    assertSame(array[1], list.head(), "head() == 1");
    assertSame(array[4], list.tail(), "tail() == 4");

    list.pop();
    assertSame(array[1], list.head(), "head() == 1");
    assertSame(array[3], list.tail(), "tail() == 3");

    list.clear();

    assertNull(list.head(), "head() == null");
    assertNull(list.tail(), "tail() == null");
  }

  @Test
  void iterator_manualForwardAndReverse_expectOrder() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    T[] array = new T[5];

    for (int i = 0; i < 5; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    // manual, forward
    T h = list.head();
    for (int i = 0; i < 5; i++) {
      assertEquals(array[i], h, "manual iterate, forward");
      assertEquals(i != 4, list.hasNext(h), "hasNext()");
      assertEquals(i != 0, list.hasPrev(h), "hasPrev()");

      assertNotNull(h);
      h.assertV(i);

      h = list.next(h);
    }
    assertNull(h, "h==null");

    // manual, reverse
    T t = list.tail();
    for (int i = 4; i >= 0; i--) {
      assertEquals(array[i], t, "manual iterate, reverse");
      assertEquals(i != 4, list.hasNext(t), "hasNext()");
      assertEquals(i != 0, list.hasPrev(t), "hasPrev()");

      assertNotNull(t);
      t.assertV(i);

      t = list.prev(t);
    }
    assertNull(t, "t==null");

    Iterator<T> e = list.elements();
    for (int i = 0; i < 5; i++) {
      assertTrue(e.hasNext(), "hasNext()");

      T n = e.next();
      assertNotNull(n);
      n.assertV(i);

      assertEquals(i != 4, e.hasNext(), "hasNext()");
    }
    assertThrows(NoSuchElementException.class, e::next);
  }

  @Test
  void remove_whenRemovingFromMiddle_thenPushBack_expectOrderPreserved() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    T[] array = new T[5];

    for (int i = 0; i < 5; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    assertSame(list.remove(array[3]), array[3]);
    list.push(array[3]);

    // Remove non-exist item -> give null
    assertNull(list.remove(new T(-1)));

    // Remove non-identical (but equal) item -> give null
    assertNull(list.remove(new T(2)));

    T rr0 = list.shift();
    assertNotNull(rr0);
    rr0.assertV(0);
    T rr1 = list.shift();
    assertNotNull(rr1);
    rr1.assertV(1);
    T rr2 = list.shift();
    assertNotNull(rr2);
    rr2.assertV(2);
    T rr3 = list.shift();
    assertNotNull(rr3);
    rr3.assertV(4);
    T rr4 = list.shift();
    assertNotNull(rr4);
    rr4.assertV(3);

    assertNull(list.remove(new T(-1)));
  }

  @Test
  void shift_and_push_whenInterleaved_expectDeterministicOrder() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(0));
    list.push(new T(1));
    list.unshift(new T(2));
    list.push(new T(3));
    list.unshift(new T(4));
    list.unshift(new T(5));

    T rsp0 = list.shift();
    assertNotNull(rsp0);
    rsp0.assertV(5);
    T rpp0 = list.pop();
    assertNotNull(rpp0);
    rpp0.assertV(3);
    T rpp1 = list.pop();
    assertNotNull(rpp1);
    rpp1.assertV(1);
    T rpp2 = list.pop();
    assertNotNull(rpp2);
    rpp2.assertV(0);
    T rsp1 = list.shift();
    assertNotNull(rsp1);
    rsp1.assertV(4);
    T rsp2 = list.shift();
    assertNotNull(rsp2);
    rsp2.assertV(2);
  }

  @Test
  void insertPrev_and_insertNext_whenAnchored_expectOrderAndGuards() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    T[] array = new T[5];

    for (int i = 0; i < 5; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    list.insertPrev(array[0], new T(100));
    list.insertPrev(array[2], new T(102));
    list.insertNext(array[4], new T(104));
    list.insertNext(array[4], new T(105));

    DoublyLinkedList<T> list2 = new DoublyLinkedListImpl<>();
    T l2 = new T(9999);
    list2.push(l2);
    assertThrows(PromiscuousItemException.class, () -> list2.insertNext(l2, l2));
    assertThrows(PromiscuousItemException.class, () -> list2.insertNext(l2, l2));
    T notInListForPrev = new T(8888);
    T notInListForNext = new T(8888);
    assertThrows(
        PromiscuousItemException.class, () -> list2.insertPrev(array[3], notInListForPrev));
    assertThrows(
        PromiscuousItemException.class, () -> list2.insertNext(array[3], notInListForNext));
    assertThrows(PromiscuousItemException.class, () -> list2.insertPrev(l2, array[3]));
    assertThrows(PromiscuousItemException.class, () -> list2.insertNext(l2, array[3]));

    T l3 = new T(9999);
    list2.push(l3);
    l3.setPrev(null); // corrupt it
    T virginPrev = new T(8888);
    assertThrows(VirginItemException.class, () -> list2.insertPrev(l3, virginPrev));
    l2.setNext(null); // corrupt it
    T virginNext = new T(8888);
    assertThrows(VirginItemException.class, () -> list2.insertNext(l2, virginNext));

    int[] expected = {100, 0, 1, 102, 2, 3, 4, 105, 104};
    int[] actual = new int[expected.length];
    for (int i = 0; i < expected.length; i++) {
      T node = list.shift();
      assertNotNull(node);
      actual[i] = node.value;
    }
    org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual);
  }

  @Test
  void contains_whenEquivalentItemPresent_expectTrue() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(1));
    list.push(new T(2));
    list.push(new T(3));

    assertTrue(list.contains(new T(2)));
    assertFalse(list.contains(new T(99)));
  }

  @Test
  void iterator_whenExhausted_expectNoSuchElementException() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(1));
    Iterator<T> it = list.iterator();
    assertTrue(it.hasNext());
    assertNotNull(it.next());
    assertFalse(it.hasNext());
    assertThrows(NoSuchElementException.class, it::next);
  }

  @Test
  void iterator_remove_expectUnsupportedOperation() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(1));
    Iterator<T> it = list.iterator();
    assertThrows(UnsupportedOperationException.class, it::remove);
  }

  @Test
  void reverseElements_whenIterated_expectReverseOrder() {
    DoublyLinkedListImpl<T> list = new DoublyLinkedListImpl<>();
    T[] array = new T[4];
    for (int i = 0; i < array.length; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    Iterator<T> rev = list.reverseElements();
    for (int i = array.length - 1; i >= 0; i--) {
      assertTrue(rev.hasNext());
      assertSame(array[i], rev.next());
    }
    assertFalse(rev.hasNext());
    assertThrows(NoSuchElementException.class, rev::next);
  }

  @Test
  void shift_whenNLessThanOne_expectEmptyReturnedAndListUnchanged() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(1));
    list.push(new T(2));
    int before = list.size();
    DoublyLinkedList<T> out = list.shift(0);
    assertTrue(out.isEmpty());
    assertEquals(before, list.size());
  }

  @Test
  void pop_whenNLessThanOne_expectEmptyReturnedAndListUnchanged() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(1));
    list.push(new T(2));
    int before = list.size();
    DoublyLinkedList<T> out = list.pop(0);
    assertTrue(out.isEmpty());
    assertEquals(before, list.size());
  }

  @Test
  void remove_whenItemBelongsToOtherList_expectPromiscuousItemException() {
    DoublyLinkedListImpl<T> l1 = new DoublyLinkedListImpl<>();
    DoublyLinkedList<T> l2 = new DoublyLinkedListImpl<>();
    T x = new T(10);
    l2.push(x);
    // ensure l1 is non-empty so remove() does not return null early
    l1.push(new T(-1));
    assertThrows(PromiscuousItemException.class, () -> l1.remove(x));
  }

  @Test
  void clear_whenCalled_expectNodesDetached() {
    DoublyLinkedListImpl<T> list = new DoublyLinkedListImpl<>();
    T a = new T(1);
    T b = new T(2);
    T c = new T(3);
    list.push(a);
    list.push(b);
    list.push(c);

    list.clear();
    assertEquals(0, list.size());
    assertNull(list.head());
    assertNull(list.tail());
    // All nodes detached
    assertNull(a.getParent());
    assertNull(b.getParent());
    assertNull(c.getParent());
    assertNull(a.getNext());
    assertNull(b.getNext());
    assertNull(c.getNext());
    assertNull(a.getPrev());
    assertNull(b.getPrev());
    assertNull(c.getPrev());
  }

  @Test
  void remove_whenItemClearedFromList_expectNullOnSecondRemoval() {
    DoublyLinkedListImpl<T> list = new DoublyLinkedListImpl<>();
    T a = new T(1);
    list.push(a);
    assertSame(a, list.remove(a));
    assertNull(list.remove(a));
  }

  private static class T extends Item<T> {
    T(int v) {
      value = v;
    }

    // No clone() override needed for tests; avoid Sonar S1182 on super.clone().

    @Override
    public String toString() {
      if (isClone) {
        return "[" + value + "]";
      } else {
        return "(" + value + ")";
      }
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof T t)) {
        return false;
      }
      return t.value == value && t.isClone == isClone;
    }

    @Override
    public int hashCode() {
      return value;
    }

    void assertV(int v) {
      assertEquals(v, value);
    }

    int value;
    boolean isClone;
  }
}
