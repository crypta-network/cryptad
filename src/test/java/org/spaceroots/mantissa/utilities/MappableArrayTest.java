package org.spaceroots.mantissa.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class MappableArrayTest {

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 3})
  void constructor_whenUsingDimension_initializesWithZerosAndCorrectDimension(int dimension) {
    // Arrange
    MappableArray mappable = new MappableArray(dimension);

    // Act
    int stateDimension = mappable.getStateDimension();
    double[] snapshot = mappable.getArray();

    // Assert
    assertEquals(dimension, stateDimension);
    assertArrayEquals(new double[dimension], snapshot);
  }

  @Test
  void constructor_whenDimensionNegative_throwsNegativeArraySizeException() {
    assertThrows(NegativeArraySizeException.class, () -> new MappableArray(-1));
  }

  @Test
  void constructor_whenUsingArray_clonesInputArray() {
    // Arrange
    double[] input = new double[] {1.0, 2.0, 3.0};

    // Act
    MappableArray mappable = new MappableArray(input);
    input[1] = 999.0;

    // Assert
    assertArrayEquals(new double[] {1.0, 2.0, 3.0}, mappable.getArray());
  }

  @Test
  void getArray_whenCalled_returnsDefensiveCopy() {
    // Arrange
    MappableArray mappable = new MappableArray(new double[] {4.0, 5.0});

    // Act
    double[] first = mappable.getArray();
    first[0] = -123.0;
    double[] second = mappable.getArray();

    // Assert
    assertArrayEquals(new double[] {4.0, 5.0}, second);
  }

  @Test
  void mapStateFromArray_whenStartOffsetProvided_copiesSliceIntoInternalState() {
    // Arrange
    MappableArray mappable = new MappableArray(3);
    double[] source = new double[] {10.0, 20.0, 30.0, 40.0, 50.0};

    // Act
    mappable.mapStateFromArray(1, source);

    // Assert
    assertArrayEquals(new double[] {20.0, 30.0, 40.0}, mappable.getArray());
  }

  @Test
  void mapStateFromArray_whenSourceArrayNull_throwsNullPointerException() {
    // Arrange
    MappableArray mappable = new MappableArray(1);

    // Act / Assert
    assertThrows(NullPointerException.class, () -> mappable.mapStateFromArray(0, null));
  }

  @Test
  void mapStateFromArray_whenStartNegative_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableArray mappable = new MappableArray(1);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> mappable.mapStateFromArray(-1, new double[] {1.0}));
  }

  @Test
  void mapStateFromArray_whenNotEnoughSourceData_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableArray mappable = new MappableArray(2);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> mappable.mapStateFromArray(1, new double[] {1.0, 2.0}));
  }

  @Test
  void mapStateToArray_whenStartOffsetProvided_writesInternalSliceIntoDestinationArray() {
    // Arrange
    MappableArray mappable = new MappableArray(new double[] {7.0, 8.0, 9.0});
    double[] destination = new double[] {-1.0, -1.0, -1.0, -1.0, -1.0};

    // Act
    mappable.mapStateToArray(2, destination);

    // Assert
    assertArrayEquals(new double[] {-1.0, -1.0, 7.0, 8.0, 9.0}, destination);
  }

  @Test
  void mapStateToArray_whenDestinationArrayNull_throwsNullPointerException() {
    // Arrange
    MappableArray mappable = new MappableArray(1);

    // Act / Assert
    assertThrows(NullPointerException.class, () -> mappable.mapStateToArray(0, null));
  }

  @Test
  void mapStateToArray_whenStartNegative_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableArray mappable = new MappableArray(1);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> mappable.mapStateToArray(-1, new double[1]));
  }

  @Test
  void mapStateToArray_whenNotEnoughDestinationSpace_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MappableArray mappable = new MappableArray(2);

    // Act / Assert
    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> mappable.mapStateToArray(1, new double[2]));
  }
}
