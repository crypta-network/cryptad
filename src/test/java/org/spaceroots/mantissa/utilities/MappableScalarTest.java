package org.spaceroots.mantissa.utilities;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MappableScalarTest {

  static Stream<Double> scalarValues() {
    return Stream.of(
        0.0, -0.0, 1.25, -42.5, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, Double.NaN);
  }

  @Test
  void constructor_whenDefault_constructsWithZeroValue() {
    // Arrange / Act
    MappableScalar scalar = new MappableScalar();

    // Assert
    assertEquals(0.0, scalar.getValue());
  }

  @ParameterizedTest
  @MethodSource("scalarValues")
  void constructor_whenInitialValueProvided_storesValue(double initialValue) {
    // Arrange / Act
    MappableScalar scalar = new MappableScalar(initialValue);

    // Assert
    assertSameDoubleValue(initialValue, scalar.getValue());
  }

  @ParameterizedTest
  @MethodSource("scalarValues")
  void setValue_whenCalled_updatesValue(double newValue) {
    // Arrange
    MappableScalar scalar = new MappableScalar(123.0);

    // Act
    scalar.setValue(newValue);

    // Assert
    assertSameDoubleValue(newValue, scalar.getValue());
  }

  @Test
  void getStateDimension_whenCalled_returnsOne() {
    // Arrange
    MappableScalar scalar = new MappableScalar(5.0);

    // Act
    int dimension = scalar.getStateDimension();

    // Assert
    assertEquals(1, dimension);
  }

  @ParameterizedTest
  @MethodSource("scalarValues")
  void mapStateFromArray_whenStartOffsetProvided_readsValueFromArray(double expectedValue) {
    // Arrange
    MappableScalar scalar = new MappableScalar(999.0);
    double[] source = new double[] {-123.0, expectedValue, 456.0};

    // Act
    scalar.mapStateFromArray(1, source);

    // Assert
    assertSameDoubleValue(expectedValue, scalar.getValue());
  }

  @Test
  void mapStateFromArray_whenArrayNull_throwsNullPointerException() {
    // Arrange
    MappableScalar scalar = new MappableScalar();

    // Act / Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> scalar.mapStateFromArray(0, null));
  }

  @Test
  void mapStateFromArray_whenStartNegative_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableScalar scalar = new MappableScalar();

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> scalar.mapStateFromArray(-1, new double[] {1.0}));
  }

  @Test
  void mapStateFromArray_whenStartPastEnd_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableScalar scalar = new MappableScalar();

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> scalar.mapStateFromArray(1, new double[] {1.0}));
  }

  @ParameterizedTest
  @MethodSource("scalarValues")
  void mapStateToArray_whenStartOffsetProvided_writesValueIntoArray(double value) {
    // Arrange
    MappableScalar scalar = new MappableScalar(value);
    double[] destination = new double[] {-1.0, -1.0, -1.0};

    // Act
    scalar.mapStateToArray(1, destination);

    // Assert
    assertSameDoubleValue(value, destination[1]);
    assertEquals(-1.0, destination[0]);
    assertEquals(-1.0, destination[2]);
  }

  @Test
  void mapStateToArray_whenArrayNull_throwsNullPointerException() {
    // Arrange
    MappableScalar scalar = new MappableScalar(1.0);

    // Act / Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> scalar.mapStateToArray(0, null));
  }

  @Test
  void mapStateToArray_whenStartNegative_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableScalar scalar = new MappableScalar(1.0);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> scalar.mapStateToArray(-1, new double[1]));
  }

  @Test
  void mapStateToArray_whenStartPastEnd_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableScalar scalar = new MappableScalar(1.0);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> scalar.mapStateToArray(1, new double[] {0.0}));
  }

  private static void assertSameDoubleValue(double expected, double actual) {
    if (Double.isNaN(expected)) {
      assertTrue(Double.isNaN(actual));
      return;
    }

    assertEquals(Double.doubleToRawLongBits(expected), Double.doubleToRawLongBits(actual));
  }
}
