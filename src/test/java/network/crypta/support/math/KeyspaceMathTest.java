package network.crypta.support.math;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class KeyspaceMathTest {

  private static final double EPSILON = 1e-12;

  @ParameterizedTest
  @CsvSource({
    "0.0, 0.0",
    "0.2, 0.2",
    "0.75, 0.75",
    "1.0, 0.0",
    "1.75, 0.75",
    "-0.25, 0.75",
    "-1.75, 0.25"
  })
  void normalize_whenValueProvided_expectCanonicalPosition(double input, double expected) {
    // Act
    double normalized = KeyspaceMath.normalize(input);

    // Assert
    assertEquals(expected, normalized, EPSILON);
  }

  @ParameterizedTest
  @CsvSource({
    "0.2, 0.75, -0.45",
    "0.75, 0.2, 0.45",
    "0.9, 0.1, 0.2",
    "0.1, 0.9, -0.2",
    "0.0, 0.5, 0.5",
    "0.5, 0.0, 0.5",
    "0.25, 0.25, 0.0"
  })
  void change_whenValuesProvided_expectShortestSignedDelta(
      double from, double to, double expected) {
    // Act
    double change = KeyspaceMath.change(from, to);

    // Assert
    assertEquals(expected, change, EPSILON);
  }

  @ParameterizedTest
  @CsvSource({
    "0.2, 0.75, 0.45",
    "0.75, 0.2, 0.45",
    "0.9, 0.1, 0.2",
    "0.1, 0.9, 0.2",
    "0.0, 0.5, 0.5",
    "0.25, 0.25, 0.0"
  })
  void distance_whenValuesProvided_expectShortestAbsoluteArc(
      double from, double to, double expected) {
    // Act
    double distance = KeyspaceMath.distance(from, to);

    // Assert
    assertEquals(expected, distance, EPSILON);
  }
}
