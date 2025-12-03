package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class TupleTest {

  @Test
  void constructorAndGetters_whenValuesProvided_returnSameObjects() {
    Object left = "left";
    Object right = 42;

    Tuple tuple = new Tuple(left, right);

    assertSame(left, tuple.getLeft());
    assertSame(right, tuple.getRight());
    assertSame(left, tuple.getCar());
    assertSame(right, tuple.getCdr());
  }

  @Test
  void equals_whenSameReference_returnsTrue() {
    Tuple tuple = new Tuple("a", "b");

    //noinspection EqualsWithItself
    assertEquals(tuple, tuple);
  }

  @Test
  void equals_whenEqualValuesDifferentInstances_returnsTrue() {
    Tuple first = new Tuple("a", "b");
    Tuple second = new Tuple("a", "b");

    assertEquals(first, second);
    assertEquals(second, first);
  }

  @Test
  void equals_whenDifferentLeft_returnsFalse() {
    Tuple first = new Tuple("a", "b");
    Tuple second = new Tuple("x", "b");

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenDifferentRight_returnsFalse() {
    Tuple first = new Tuple("a", "b");
    Tuple second = new Tuple("a", "y");

    assertNotEquals(first, second);
  }

  @Test
  void equals_whenComparedToNonTuple_returnsFalse() {
    Tuple tuple = new Tuple("a", "b");

    //noinspection AssertBetweenInconvertibleTypes
    assertNotEquals("not-a-tuple", tuple);
  }

  @Test
  void equals_whenLeftIsNull_throwsNullPointerException() {
    Tuple tupleWithNullLeft = new Tuple(null, "b");
    Tuple other = new Tuple(null, "b");

    assertThrows(NullPointerException.class, () -> tupleWithNullLeft.equals(other));
  }

  @Test
  void hashCode_whenEqualTuples_returnsSameValue() {
    Tuple first = new Tuple("left", "right");
    Tuple second = new Tuple("left", "right");

    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void hashCode_whenLeftIsNull_throwsNullPointerException() {
    Tuple tuple = new Tuple(null, "right");

    assertThrows(NullPointerException.class, tuple::hashCode);
  }

  @Test
  void hashCode_whenRightIsNull_throwsNullPointerException() {
    Tuple tuple = new Tuple("left", null);

    assertThrows(NullPointerException.class, tuple::hashCode);
  }
}
