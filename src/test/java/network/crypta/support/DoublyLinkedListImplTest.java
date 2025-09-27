package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Enumeration;
import java.util.NoSuchElementException;
import network.crypta.support.DoublyLinkedListImpl.Item;
import org.junit.jupiter.api.Test;

public class DoublyLinkedListImplTest {
  @Test
  public void testForwardPushPop() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(0));
    list.push(new T(1));
    list.push(new T(2));
    list.push(new T(3));

    assertFalse(list.isEmpty(), "isEmpty()");
    list.pop().assertV(3);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.pop().assertV(2);
    assertFalse(list.isEmpty(), "isEmpty()");

    // add again
    list.push(new T(4));
    list.push(new T(5));

    list.pop().assertV(5);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.pop().assertV(4);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.pop().assertV(1);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.pop().assertV(0);

    assertTrue(list.isEmpty(), "isEmpty()");
    assertNull(list.pop(), "pop()");
  }

  @Test
  public void testForwardShiftUnshift() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.unshift(new T(0));
    list.unshift(new T(1));
    list.unshift(new T(2));
    list.unshift(new T(3));

    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(3);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(2);
    assertFalse(list.isEmpty(), "isEmpty()");

    // add again
    list.unshift(new T(4));
    list.unshift(new T(5));

    list.shift().assertV(5);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(4);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(1);
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(0);

    assertTrue(list.isEmpty(), "isEmpty()");
    assertNull(list.shift(), "shift()");
  }

  @Test
  public void testClearSize() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.unshift(new T(0));
    list.unshift(new T(1));
    list.unshift(new T(2));
    list.unshift(new T(3));

    assertEquals(4, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(3);
    assertEquals(3, list.size(), "size()");
    assertFalse(list.isEmpty(), "isEmpty()");
    list.shift().assertV(2);
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

    list.shift().assertV(5);
    list.shift().assertV(4);

    assertEquals(0, list.size(), "size()");
    assertTrue(list.isEmpty(), "isEmpty()");
  }

  @Test
  public void testShiftN() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();

    for (int i = 0; i < 5; i++) {
      list.push(new T(i));
    }

    DoublyLinkedList<T> list2 = list.shift(2);
    assertEquals(2, list2.size(), "list2.size()");
    list2.shift().assertV(0);
    list2.shift().assertV(1);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    assertEquals(3, list.size(), "list.size()");
    list.shift().assertV(2);

    list2 = list.shift(20);
    assertTrue(list.isEmpty(), "list.isEmpty()");
    list2.shift().assertV(3);
    list2.shift().assertV(4);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    list2 = list.shift(20);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");
  }

  //	public void testClone() {
  //		DoublyLinkedList<T> list = new DoublyLinkedListImpl<T>();
  //		for (int i = 0; i < 3; i++) {
  //			list.unshift(new T(i));
  //		}
  //
  //		DoublyLinkedList<T> listClone = list.clone();
  //
  //		for (int i = 2; i >= 0; i--) {
  //			T t = (T) list.shift();
  //			t.assertV(i);
  //			t.assertIsNotClone();
  //
  //			T tc = (T) listClone.shift();
  //			tc.assertV(i);
  //			tc.assertIsClone();
  //		}
  //	}

  @Test
  public void testPopN() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();

    for (int i = 0; i < 5; i++) {
      list.unshift(new T(i));
    }

    DoublyLinkedList<T> list2 = list.pop(2);
    assertEquals(2, list2.size(), "list2.size()");
    list2.pop().assertV(0);
    list2.pop().assertV(1);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    assertEquals(3, list.size(), "list.size()");
    list.pop().assertV(2);

    list2 = list.pop(20);
    assertTrue(list.isEmpty(), "list.isEmpty()");
    list2.pop().assertV(3);
    list2.pop().assertV(4);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");

    list2 = list.pop(20);
    assertTrue(list2.isEmpty(), "list2.isEmpty()");
  }

  @Test
  public void testHeadTail() {
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
  public void testIternator() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    T[] array = new T[5];

    for (int i = 0; i < 5; i++) {
      array[i] = new T(i);
      list.push(array[i]);
    }

    // manual, forward
    T h = list.head();
    for (int i = 0; i < 5; i++) {
      assertEquals(array[i], h, "manual iternate, forward");
      // assertEquals(h.getNext(), list.next(h), "DoublyLinkedList.next() == Item.next()");
      assertEquals(i != 4, list.hasNext(h), "hasNext()");
      assertEquals(i != 0, list.hasPrev(h), "hasPrev()");

      h.assertV(i);

      h = list.next(h);
    }
    assertNull(h, "h==null");

    // manual, reverse
    T t = list.tail();
    for (int i = 4; i >= 0; i--) {
      assertEquals(array[i], t, "manual iternate, reverse");
      // assertEquals(tail.getPrev(), list.prev(tail), "DoublyLinkedList.prev() == Item.getPrev()");
      assertEquals(i != 4, list.hasNext(t), "hasNext()");
      assertEquals(i != 0, list.hasPrev(t), "hasPrev()");

      t.assertV(i);

      t = list.prev(t);
    }
    assertNull(t, "t==null");

    Enumeration<T> e = list.elements();
    for (int i = 0; i < 5; i++) {
      assertTrue(e.hasMoreElements(), "hasMoreElements()");

      T n = e.nextElement();
      n.assertV(i);

      assertEquals(i != 4, e.hasMoreElements(), "hasMoreElements()");
    }
    try {
      e.nextElement();
      fail("NoSuchElementException");
    } catch (NoSuchElementException nsee) {
    }
  }

  @Test
  public void testRandomRemovePush() {
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

    list.shift().assertV(0);
    list.shift().assertV(1);
    list.shift().assertV(2);
    list.shift().assertV(4);
    list.shift().assertV(3);

    assertNull(list.remove(new T(-1)));
  }

  @Test
  public void testRandomShiftPush() {
    DoublyLinkedList<T> list = new DoublyLinkedListImpl<>();
    list.push(new T(0));
    list.push(new T(1));
    list.unshift(new T(2));
    list.push(new T(3));
    list.unshift(new T(4));
    list.unshift(new T(5));

    list.shift().assertV(5);
    list.pop().assertV(3);
    list.pop().assertV(1);
    list.pop().assertV(0);
    list.shift().assertV(4);
    list.shift().assertV(2);
  }

  @Test
  public void testRandomInsert() {
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
    try {
      // already exist
      list2.insertNext(l2, l2);
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }
    try {
      // already exist
      list2.insertNext(l2, l2);
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }
    try {
      // bad position
      list2.insertPrev(array[3], new T(8888));
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }
    try {
      // bad position
      list2.insertNext(array[3], new T(8888));
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }

    try {
      // item in other list
      list2.insertPrev(l2, array[3]);
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }
    try {
      // item in other list
      list2.insertNext(l2, array[3]);
      fail("PromiscuousItemException");
    } catch (PromiscuousItemException pie) {
    }

    T l3 = new T(9999);
    list2.push(l3);
    try {
      // VirginItemException
      l3.setPrev(null); // corrupt it
      list2.insertPrev(l3, new T(8888));
      fail("VirginItemException");
    } catch (VirginItemException vie) {
    }
    try {
      // VirginItemException
      l2.setNext(null); // corrupt it
      list2.insertNext(l2, new T(8888));
      fail("VirginItemException");
    } catch (VirginItemException vie) {
    }

    list.shift().assertV(100);
    list.shift().assertV(0);
    list.shift().assertV(1);
    list.shift().assertV(102);
    list.shift().assertV(2);
    list.shift().assertV(3);
    list.shift().assertV(4);
    list.shift().assertV(105);
    list.shift().assertV(104);
  }

  private static class T extends Item<T> {
    T(int v) {
      value = v;
    }

    @Override
    public T clone() {
      T c = new T(value);
      c.isClone = true;
      return c;
    }

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
      if (o == null) {
        return false;
      }
      if (o.getClass() != this.getClass()) {
        return false;
      }
      T t = (T) o;
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
