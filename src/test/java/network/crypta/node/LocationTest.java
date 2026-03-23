package network.crypta.node;

import network.crypta.support.math.KeyspaceMath;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LocationTest {

  // Maximal acceptable difference to consider two doubles equal.
  private static final double EPSILON = 1e-12;

  // Just some valid non-corner case locations.
  private static final double VALID_1 = 0.2;
  private static final double VALID_2 = 0.75;

  // Precalculated distances between valid locations.
  private static final double DIST_12 = 0.45;
  private static final double CHANGE_12 = -0.45;
  private static final double CHANGE_21 = 0.45;

  // Just some invalid locations.
  private static final double INVALID_1 = -1;
  private static final double INVALID_2 = 1.1;

  @Test
  void isValid_whenWithinAndAtBounds_expectTrueOtherwiseFalse() {
    // Simple cases.
    assertTrue(Location.isValid(VALID_1));
    assertTrue(Location.isValid(VALID_2));
    assertFalse(Location.isValid(INVALID_1));
    assertFalse(Location.isValid(INVALID_2));

    // Corner cases.
    assertTrue(Location.isValid(0.0));
    assertTrue(Location.isValid(1.0));
  }

  @Test
  void equals_whenVariousValidAndInvalidCombinations_expectExpectedTruthValues() {
    // Simple cases.
    assertTrue(Location.equals(VALID_1, VALID_1));
    assertTrue(Location.equals(VALID_2, VALID_2));
    assertFalse(Location.equals(VALID_1, VALID_2));
    assertFalse(Location.equals(VALID_2, VALID_1));

    // Cases with invalid locations.
    assertFalse(Location.equals(INVALID_1, VALID_1));
    assertFalse(Location.equals(INVALID_1, VALID_2));
    assertFalse(Location.equals(INVALID_2, VALID_1));
    assertFalse(Location.equals(INVALID_2, VALID_2));
    assertTrue(Location.equals(INVALID_1, INVALID_1));
    assertTrue(Location.equals(INVALID_2, INVALID_2));
    assertTrue(Location.equals(INVALID_1, INVALID_2));
    assertTrue(Location.equals(INVALID_2, INVALID_1));

    // Corner cases.
    assertTrue(Location.equals(0.0, 0.0));
    assertTrue(Location.equals(0.0, 1.0));
    assertTrue(Location.equals(1.0, 0.0));
    assertTrue(Location.equals(1.0, 1.0));
  }

  @Test
  void distance_whenValidLocations_expectShortestCircularDistance() {
    // Simple cases.
    assertEquals(DIST_12, Location.distance(VALID_1, VALID_2), EPSILON);
    assertEquals(DIST_12, Location.distance(VALID_2, VALID_1), EPSILON);

    // Corner case.
    assertEquals(0.5, Location.distance(VALID_1, Location.normalize(VALID_1 + 0.5)), EPSILON);
    assertEquals(0.5, Location.distance(VALID_1, Location.normalize(VALID_1 - 0.5)), EPSILON);
    assertEquals(0.5, Location.distance(VALID_2, Location.normalize(VALID_2 + 0.5)), EPSILON);
    assertEquals(0.5, Location.distance(VALID_2, Location.normalize(VALID_2 - 0.5)), EPSILON);

    // Identity.
    assertEquals(0.0, Location.distance(VALID_1, VALID_1), EPSILON);
    assertEquals(0.0, Location.distance(VALID_2, VALID_2), EPSILON);
  }

  @Test
  void change_whenValidLocations_expectSignedShortestChange() {
    // Simple cases.
    assertEquals(CHANGE_12, Location.change(VALID_1, VALID_2), EPSILON);
    assertEquals(CHANGE_21, Location.change(VALID_2, VALID_1), EPSILON);

    // Maximal change is always positive.
    assertEquals(0.5, Location.change(VALID_1, Location.normalize(VALID_1 + 0.5)), EPSILON);
    assertEquals(0.5, Location.change(VALID_1, Location.normalize(VALID_1 - 0.5)), EPSILON);
    assertEquals(0.5, Location.change(VALID_2, Location.normalize(VALID_2 + 0.5)), EPSILON);
    assertEquals(0.5, Location.change(VALID_2, Location.normalize(VALID_2 - 0.5)), EPSILON);

    // Identity.
    assertEquals(0.0, Location.change(VALID_1, VALID_1), EPSILON);
    assertEquals(0.0, Location.change(VALID_2, VALID_2), EPSILON);
  }

  @Test
  void normalize_whenOffsetsApplied_expectValueWrappedIntoRange() {
    // Simple cases.
    for (int i = 0; i < 5; i++) {
      assertEquals(VALID_1, Location.normalize(VALID_1 + i), EPSILON);
      assertEquals(VALID_1, Location.normalize(VALID_1 - i), EPSILON);
      assertEquals(VALID_2, Location.normalize(VALID_2 + i), EPSILON);
      assertEquals(VALID_2, Location.normalize(VALID_2 - i), EPSILON);
    }

    // Corner case.
    assertEquals(0.0, Location.normalize(1.0), EPSILON);
  }

  @ParameterizedTest
  @CsvSource({"-1.75", "-0.25", "0.0", "0.2", "1.0", "1.75"})
  void normalize_whenDelegated_expectSameAsKeyspaceMath(double input) {
    assertEquals(KeyspaceMath.normalize(input), Location.normalize(input), EPSILON);
  }

  @ParameterizedTest
  @CsvSource({"0.2, 0.75", "0.75, 0.2", "0.9, 0.1", "0.1, 0.9", "0.0, 0.5", "0.5, 0.0"})
  void change_whenDelegated_expectSameAsKeyspaceMath(double from, double to) {
    assertEquals(KeyspaceMath.change(from, to), Location.change(from, to), EPSILON);
  }

  @ParameterizedTest
  @CsvSource({"0.2, 0.75", "0.75, 0.2", "0.9, 0.1", "0.1, 0.9", "0.0, 0.5", "0.25, 0.25"})
  void distance_whenDelegated_expectSameAsKeyspaceMath(double from, double to) {
    assertEquals(KeyspaceMath.distance(from, to), Location.distance(from, to), EPSILON);
  }

  @Test
  void distanceAllowInvalid_whenAnyInvalid_expectSpecifiedSemantics() {
    // Simple cases.
    assertEquals(DIST_12, Location.distanceAllowInvalid(VALID_1, VALID_2), EPSILON);
    assertEquals(DIST_12, Location.distanceAllowInvalid(VALID_2, VALID_1), EPSILON);

    // Corner case.
    assertEquals(
        0.5, Location.distanceAllowInvalid(VALID_1, Location.normalize(VALID_1 + 0.5)), EPSILON);
    assertEquals(
        0.5, Location.distanceAllowInvalid(VALID_1, Location.normalize(VALID_1 - 0.5)), EPSILON);
    assertEquals(
        0.5, Location.distanceAllowInvalid(VALID_2, Location.normalize(VALID_2 + 0.5)), EPSILON);
    assertEquals(
        0.5, Location.distanceAllowInvalid(VALID_2, Location.normalize(VALID_2 - 0.5)), EPSILON);

    // Identity.
    assertEquals(0.0, Location.distanceAllowInvalid(VALID_1, VALID_1), EPSILON);
    assertEquals(0.0, Location.distanceAllowInvalid(VALID_2, VALID_2), EPSILON);

    // Normal operation with invalid.
    assertEquals(2.0 - VALID_1, Location.distanceAllowInvalid(INVALID_1, VALID_1), EPSILON);
    assertEquals(2.0 - VALID_1, Location.distanceAllowInvalid(VALID_1, INVALID_1), EPSILON);
    assertEquals(2.0 - VALID_1, Location.distanceAllowInvalid(INVALID_2, VALID_1), EPSILON);
    assertEquals(2.0 - VALID_1, Location.distanceAllowInvalid(VALID_1, INVALID_2), EPSILON);
    assertEquals(2.0 - VALID_2, Location.distanceAllowInvalid(INVALID_1, VALID_2), EPSILON);
    assertEquals(2.0 - VALID_2, Location.distanceAllowInvalid(VALID_2, INVALID_1), EPSILON);
    assertEquals(2.0 - VALID_2, Location.distanceAllowInvalid(INVALID_2, VALID_2), EPSILON);
    assertEquals(2.0 - VALID_2, Location.distanceAllowInvalid(VALID_2, INVALID_2), EPSILON);

    // Identity of invalid.
    assertEquals(0.0, Location.distanceAllowInvalid(INVALID_1, INVALID_1), EPSILON);
    assertEquals(0.0, Location.distanceAllowInvalid(INVALID_1, INVALID_2), EPSILON);
    assertEquals(0.0, Location.distanceAllowInvalid(INVALID_2, INVALID_1), EPSILON);
    assertEquals(0.0, Location.distanceAllowInvalid(INVALID_2, INVALID_2), EPSILON);
  }

  // --- Additional tests for untested public methods ---

  @ParameterizedTest
  @CsvSource({
    // valid inputs
    "0, 0.0",
    "0.0, 0.0",
    "1.0, 1.0",
    "0.25, 0.25",
    // whitespace tolerated by Double.parseDouble
    " 0.5 , 0.5"
  })
  void getLocation_whenParsableAndInRange_expectSameValue(String input, double expected) {
    // Act
    double result = Location.getLocation(input);
    // Assert
    assertEquals(expected, result, EPSILON);
  }

  @ParameterizedTest
  @CsvSource({
    // parse errors
    "abc",
    "\"\"",
    // numbers out of range
    "-0.1",
    "1.0000000001",
    // non-finite values
    "NaN",
    "Infinity",
    "-Infinity"
  })
  void getLocation_whenUnparsableOrOutOfRange_expectLocationInvalid(String input) {
    // Act
    double result = Location.getLocation(input);
    // Assert
    assertEquals(Location.LOCATION_INVALID, result, EPSILON);
  }

  @Test
  void getLocation_whenNullInput_expectLocationInvalid() {
    // Act
    double result = Location.getLocation(null);
    // Assert
    assertEquals(Location.LOCATION_INVALID, result, EPSILON);
  }

  @Test
  void distance_withPeerNode_whenPeerAndTargetValid_expectSameAsDoubleDistance() {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Mockito.when(peer.getLocation()).thenReturn(VALID_1);
    double expected = Location.distance(VALID_1, VALID_2);

    // Act
    double result = Location.distance(peer, VALID_2);

    // Assert
    assertEquals(expected, result, EPSILON);
  }

  @Test
  void distance_withPeerNode_whenPeerLocationInvalid_expectIllegalArgumentException() {
    // Arrange
    PeerNode peer = Mockito.mock(PeerNode.class);
    Mockito.when(peer.getLocation()).thenReturn(INVALID_1);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> Location.distance(peer, VALID_1));
  }
}
