package com.onionnetworks.util;

import java.text.ParseException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("java:S100")
class RangeSetTest {

  @Test
  void add_singleValue_createsRangeAndContains() {
    RangeSet rs = new RangeSet();

    rs.add(5);

    assertTrue(rs.contains(5));
    assertEquals(1L, rs.size());
    assertEquals("5", rs.toString());
  }

  @Test
  void add_overlappingRanges_mergesIntoSingleRange() {
    RangeSet rs = new RangeSet();

    rs.add(1, 5);
    rs.add(3, 10);

    assertEquals("1-10", rs.toString());
    assertTrue(rs.contains(9));
    assertEquals(10L, rs.size());
  }

  @Test
  void add_adjacentRanges_mergesIntoSingleRange() {
    RangeSet rs = new RangeSet();

    rs.add(1, 5);
    rs.add(6, 8);

    assertEquals("1-8", rs.toString());
    assertTrue(rs.contains(6));
    assertTrue(rs.contains(8));
  }

  @Test
  void add_whenMinGreaterThanMax_throwsIllegalArgumentException() {
    RangeSet rs = new RangeSet();

    assertThrows(IllegalArgumentException.class, () -> rs.add(10, 2));
  }

  @Test
  void containsRange_whenSubset_returnsTrueOtherwiseFalse() {
    RangeSet rs = new RangeSet();
    rs.add(1, 10);

    assertTrue(rs.contains(new Range(3, 7)));
    assertFalse(rs.contains(new Range(0, 5)));
  }

  @Test
  void intersect_whenRangesOverlap_returnsIntersection() {
    RangeSet a = new RangeSet();
    a.add(1, 10);
    RangeSet b = new RangeSet();
    b.add(5, 15);

    RangeSet result = a.intersect(b);

    assertEquals("5-10", result.toString());
    assertTrue(result.contains(5));
    assertTrue(result.contains(10));
    assertFalse(result.contains(4));
    assertFalse(result.contains(11));
  }

  @Test
  void intersect_whenNoOverlap_returnsEmptySet() {
    RangeSet a = new RangeSet();
    a.add(1, 3);
    RangeSet b = new RangeSet();
    b.add(5, 7);

    RangeSet result = a.intersect(b);

    assertTrue(result.isEmpty());
    assertEquals("", result.toString());
  }

  @Test
  void union_mergesDistinctAndOverlappingRanges() {
    RangeSet a = new RangeSet();
    a.add(1, 3);
    a.add(10, 12);
    RangeSet b = new RangeSet();
    b.add(2, 5);
    b.add(14, 16);

    RangeSet result = a.union(b);

    assertEquals("1-5,10-12,14-16", result.toString());
    assertTrue(result.contains(4));
    assertFalse(result.contains(13));
  }

  @Test
  void remove_singleValue_splitsRange() {
    RangeSet rs = new RangeSet();
    rs.add(1, 5);

    rs.remove(3);

    assertEquals("1-2,4-5", rs.toString());
    assertFalse(rs.contains(3));
  }

  @Test
  void remove_range_removesMiddleOfExistingRange() {
    RangeSet rs = new RangeSet();
    rs.add(1, 10);

    rs.remove(3, 7);

    assertEquals("1-2,8-10", rs.toString());
    assertFalse(rs.contains(5));
    assertTrue(rs.contains(9));
  }

  @Test
  void complement_withFiniteRanges_invertsSet() {
    RangeSet rs = new RangeSet();
    rs.add(1, 3);
    rs.add(5, 6);

    RangeSet complement = rs.complement();

    assertEquals("(-0,4,7-)", complement.toString());
    assertFalse(complement.contains(1));
    assertTrue(complement.contains(7));
  }

  @Test
  void size_withInfiniteRange_returnsMinusOne() {
    RangeSet rs = new RangeSet(new Range(true, true));

    assertEquals(-1L, rs.size());
  }

  @Test
  void parse_validString_createsEquivalentRangeSet() throws ParseException {
    RangeSet rs = RangeSet.parse("1-3,5,7-)");

    assertEquals("1-3,5,7-)", rs.toString());
    assertTrue(rs.contains(1));
    assertTrue(rs.contains(5));
    assertTrue(rs.contains(1000));
    assertFalse(rs.contains(4));
  }

  @Test
  void parse_invalidString_throwsParseException() {
    assertThrows(ParseException.class, () -> RangeSet.parse("bad"));
  }

  @Test
  void equalsAndHashCode_whenRangesMatch_areEqual() {
    RangeSet first = new RangeSet();
    first.add(1, 3);
    first.add(5, 6);
    RangeSet second = new RangeSet();
    second.add(5, 6);
    second.add(1, 3);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  void copy_createsIndependentCopy() {
    RangeSet original = new RangeSet();
    original.add(1, 3);

    RangeSet copy = original.copy();
    copy.add(10);

    assertTrue(original.contains(2));
    assertFalse(original.contains(10));
    assertTrue(copy.contains(10));
  }
}
