package network.crypta.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TimeSortedHashtableTest {
  @Test
  @DisplayName("push_whenFirstInsert_expectCountsAndContains")
  void push_whenFirstInsert_expectCountsAndContains() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();

    // Act
    tsh.push("KEY1", 100);

    // Assert
    assertEquals(1, tsh.size());
    assertEquals(1, tsh.countValuesAfter(0));
    assertEquals(1, tsh.countValuesAfter(99));
    assertEquals(0, tsh.countValuesAfter(100));
    assertEquals(0, tsh.countValuesAfter(101));
    assertTrue(tsh.containsValue("KEY1"));
  }

  @Test
  @DisplayName("push_whenSecondSameTimestamp_expectCountsAndContains")
  void push_whenSecondSameTimestamp_expectCountsAndContains() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);

    // Act
    tsh.push("KEY2", 100);

    // Assert
    assertEquals(2, tsh.size());
    assertEquals(2, tsh.countValuesAfter(0));
    assertEquals(0, tsh.countValuesAfter(100));
    assertEquals(0, tsh.countValuesAfter(101));
    assertTrue(tsh.containsValue("KEY1"));
    assertTrue(tsh.containsValue("KEY2"));
  }

  @Test
  @DisplayName("push_whenThirdLaterTimestamp_expectCountsAfter100Equals1")
  void push_whenThirdLaterTimestamp_expectCountsAfter100Equals1() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);

    // Act
    tsh.push("KEY3", 300);

    // Assert
    assertEquals(3, tsh.size());
    assertEquals(3, tsh.countValuesAfter(0));
    assertEquals(1, tsh.countValuesAfter(100));
    assertEquals(1, tsh.countValuesAfter(101));
    assertTrue(tsh.containsValue("KEY1"));
    assertTrue(tsh.containsValue("KEY2"));
    assertTrue(tsh.containsValue("KEY3"));
  }

  @Test
  @DisplayName("push_whenPromoteExisting_expectSizeUnchangedAndCountsUpdated")
  void push_whenPromoteExisting_expectSizeUnchangedAndCountsUpdated() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    tsh.push("KEY1", 200);

    // Assert
    assertEquals(3, tsh.size());
    assertEquals(3, tsh.countValuesAfter(0));
    assertEquals(2, tsh.countValuesAfter(100));
    assertEquals(2, tsh.countValuesAfter(101));
    assertTrue(tsh.containsValue("KEY1"));
    assertTrue(tsh.containsValue("KEY2"));
    assertTrue(tsh.containsValue("KEY3"));
  }

  @Test
  @DisplayName("removeValue_whenExisting_expectCountsAndContains")
  void removeValue_whenExisting_expectCountsAndContains() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 200); // after promotion
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    boolean removed = tsh.removeValue("KEY1");

    // Assert
    assertTrue(removed);
    assertEquals(2, tsh.size());
    assertEquals(2, tsh.countValuesAfter(0));
    assertEquals(1, tsh.countValuesAfter(100));
    assertEquals(1, tsh.countValuesAfter(101));
    assertFalse(tsh.containsValue("KEY1"));
    assertTrue(tsh.containsValue("KEY2"));
    assertTrue(tsh.containsValue("KEY3"));
  }

  @Test
  @DisplayName("removeBefore_when105_expectOnlyNewerRemain")
  void removeBefore_when105_expectOnlyNewerRemain() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    tsh.removeBefore(105);

    // Assert
    assertEquals(1, tsh.size());
    assertEquals(1, tsh.countValuesAfter(0));
    assertEquals(1, tsh.countValuesAfter(100));
    assertEquals(1, tsh.countValuesAfter(101));
    assertFalse(tsh.containsValue("KEY1"));
    assertFalse(tsh.containsValue("KEY2"));
    assertTrue(tsh.containsValue("KEY3"));
  }

  @Test
  @DisplayName("removeBefore_when105_afterBusySetup_expectStateUpdated")
  void removeBefore_when105_afterBusySetup_expectStateUpdated() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);
    tsh.push("KEY1", 200); // promote

    // Act
    tsh.removeBefore(105);

    // Assert
    assertEquals(2, tsh.size());
    assertEquals(2, tsh.countValuesAfter(0));
    assertEquals(2, tsh.countValuesAfter(100));
    assertEquals(1, tsh.countValuesAfter(201));
    assertEquals(0, tsh.countValuesAfter(301));
    assertTrue(tsh.containsValue("KEY1"));
    assertFalse(tsh.containsValue("KEY2"));
    assertTrue(tsh.containsValue("KEY3"));
  }

  @Test
  @DisplayName("getTime_whenMultipleKeys_expectPresentTimesAndMissingMinusOne")
  void getTime_whenMultipleKeys_expectPresentTimesAndMissingMinusOne() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);
    tsh.push("KEY1", 200);
    tsh.removeBefore(105); // remaining: KEY1@200, KEY3@300

    // Act & Assert
    assertEquals(200, tsh.getTime("KEY1"));
    assertEquals(-1, tsh.getTime("KEY2"));
    assertEquals(300, tsh.getTime("KEY3"));
  }

  @Test
  @DisplayName("push_whenNullValue_expectNullPointerException")
  void push_whenNullValue_expectNullPointerException() {
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();

    assertThrows(NullPointerException.class, () -> tsh.push(null, 1L));
    assertEquals(0, tsh.size());
  }

  @Test
  @DisplayName("removeValue_whenMissing_expectFalseAndNoChange")
  void removeValue_whenMissing_expectFalseAndNoChange() {
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("A", 10L);

    assertFalse(tsh.removeValue("B"));
    assertTrue(tsh.containsValue("A"));
    assertEquals(1, tsh.size());
    assertEquals(1, tsh.countValuesAfter(-1));
  }

  @Test
  @DisplayName("getTime_whenExisting_expectReturnedTimeAndMappingRemovedButElementsCountUnchanged")
  void getTime_whenExisting_expectReturnedTimeAndMappingRemovedButElementsCountUnchanged() {
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("Z", 123L);

    long t = tsh.getTime("Z");
    assertEquals(123L, t);

    // Side-effect of current implementation: mapping removed but element remains in set
    assertFalse(tsh.containsValue("Z"));
    assertEquals(1, tsh.size()); // size is backed by the internal TreeSet
    assertEquals(1, tsh.countValuesAfter(-1));
  }

  @ParameterizedTest(name = "countValuesAfter({0}) = {1}")
  @CsvSource({"-1, 3", "0, 3", "9, 3", "10, 1", "11, 0", "20, 0"})
  @DisplayName("countValuesAfter_whenVariousTimestamps_expectStrictlyAfter")
  void countValuesAfter_whenVariousTimestamps_expectStrictlyAfter(long ts, int expected) {
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    // Two values at t=10, one at t=11
    tsh.push("A", 10L);
    tsh.push("B", 10L);
    tsh.push("C", 11L);

    assertEquals(expected, tsh.countValuesAfter(ts));
  }

  @Test
  @DisplayName("removeBefore_whenBoundaryExact_isInclusive")
  void removeBefore_whenBoundaryExact_isInclusive() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    tsh.removeBefore(100);

    // Assert
    assertEquals(1, tsh.size());
  }

  @Test
  @DisplayName("pairsAfter_whenMinusOne_returnsAllPairsInOrder")
  void pairsAfter_whenMinusOne_returnsAllPairsInOrder() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    Object[] p = tsh.pairsAfter(-1, new String[3]);

    // Assert
    assertArrayEquals(new Long[] {100L, 100L, 300L}, (Long[]) p[1]);
    assertArrayEquals(new String[] {"KEY1", "KEY2", "KEY3"}, (String[]) p[0]);
  }

  @Test
  @DisplayName("pairsAfter_whenPromoteValue_reflectsNewOrdering")
  void pairsAfter_whenPromoteValue_reflectsNewOrdering() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);

    // Act
    tsh.push("KEY1", 200);
    Object[] p = tsh.pairsAfter(-1, new String[3]);

    // Assert
    assertArrayEquals(new Long[] {100L, 200L, 300L}, (Long[]) p[1]);
    assertArrayEquals(new String[] {"KEY2", "KEY1", "KEY3"}, (String[]) p[0]);
  }

  @Test
  @DisplayName("pairsAfter_whenRemovedBefore105_returnsRemainingPairs")
  void pairsAfter_whenRemovedBefore105_returnsRemainingPairs() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 100);
    tsh.push("KEY2", 100);
    tsh.push("KEY3", 300);
    tsh.push("KEY1", 200);

    // Act
    tsh.removeBefore(105);
    Object[] p = tsh.pairsAfter(-1, new String[2]);

    // Assert
    assertArrayEquals(new Long[] {200L, 300L}, (Long[]) p[1]);
    assertArrayEquals(new String[] {"KEY1", "KEY3"}, (String[]) p[0]);
  }

  @Test
  @DisplayName("pairsAfter_whenTimestamp200_returnsOnlyAfterThreshold")
  void pairsAfter_whenTimestamp200_returnsOnlyAfterThreshold() {
    // Arrange
    TimeSortedHashtable<String> tsh = new TimeSortedHashtable<>();
    tsh.push("KEY1", 200);
    tsh.push("KEY3", 300);

    // Act
    Object[] after200 = tsh.pairsAfter(200, new String[1]);

    // Assert
    assertArrayEquals(new Long[] {300L}, (Long[]) after200[1]);
    assertArrayEquals(new String[] {"KEY3"}, (String[]) after200[0]);
  }
}
