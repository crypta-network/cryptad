package org.spaceroots.mantissa.linalg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100")
class GeneralMatrixTest {

  @Test
  void constructor_whenAnyDimensionNonPositive_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new GeneralMatrix(0, 2));
    assertThrows(IllegalArgumentException.class, () -> new GeneralMatrix(2, -1));
  }

  @Test
  void constructorWithData_whenSourceArrayModified_matrixRetainsOriginalValues() {
    double[] source = {1.0, 2.0, 3.0, 4.0};

    GeneralMatrix matrix = new GeneralMatrix(2, 2, source);
    source[0] = 99.0;

    assertEquals(1.0, matrix.getElement(0, 0));
    assertEquals(2.0, matrix.getElement(0, 1));
    assertEquals(3.0, matrix.getElement(1, 0));
    assertEquals(4.0, matrix.getElement(1, 1));
  }

  @Test
  void duplicate_whenCalled_returnsIndependentCopyWithSameValues() {
    GeneralMatrix original = new GeneralMatrix(2, 2, new double[] {1.0, 2.0, 3.0, 4.0});

    Matrix copy = original.duplicate();
    copy.setElement(0, 0, 10.0);

    assertInstanceOf(GeneralMatrix.class, copy);
    assertNotSame(original, copy);
    assertEquals(1.0, original.getElement(0, 0));
    assertEquals(2.0, original.getElement(0, 1));
    assertEquals(3.0, original.getElement(1, 0));
    assertEquals(4.0, original.getElement(1, 1));
    assertEquals(10.0, copy.getElement(0, 0));
  }

  @Test
  void selfAdd_whenDimensionsMatch_addsInPlace() {
    GeneralMatrix matrix = new GeneralMatrix(2, 2, new double[] {1.0, 2.0, 3.0, 4.0});
    Matrix toAdd = new GeneralMatrix(2, 2, new double[] {4.0, 3.0, 2.0, 1.0});

    matrix.selfAdd(toAdd);

    assertEquals(5.0, matrix.getElement(0, 0));
    assertEquals(5.0, matrix.getElement(0, 1));
    assertEquals(5.0, matrix.getElement(1, 0));
    assertEquals(5.0, matrix.getElement(1, 1));
  }

  @Test
  void selfAdd_whenDimensionsDiffer_throwsIllegalArgumentException() {
    GeneralMatrix matrix = new GeneralMatrix(2, 2);
    Matrix differentSize = new GeneralMatrix(3, 2);

    assertThrows(IllegalArgumentException.class, () -> matrix.selfAdd(differentSize));
  }

  @Test
  void selfSub_whenDimensionsMatch_subtractsInPlace() {
    GeneralMatrix matrix = new GeneralMatrix(2, 2, new double[] {5.0, 7.0, 9.0, 11.0});
    Matrix toSubtract = new GeneralMatrix(2, 2, new double[] {1.0, 2.0, 3.0, 4.0});

    matrix.selfSub(toSubtract);

    assertEquals(4.0, matrix.getElement(0, 0));
    assertEquals(5.0, matrix.getElement(0, 1));
    assertEquals(6.0, matrix.getElement(1, 0));
    assertEquals(7.0, matrix.getElement(1, 1));
  }

  @Test
  void selfSub_whenDimensionsDiffer_throwsIllegalArgumentException() {
    GeneralMatrix matrix = new GeneralMatrix(2, 2);
    Matrix differentSize = new GeneralMatrix(1, 2);

    assertThrows(IllegalArgumentException.class, () -> matrix.selfSub(differentSize));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2})
  void getRangeForRow_whenAnyRowRequested_returnsFullColumnRange(int rowIndex) {
    GeneralMatrix matrix = new GeneralMatrix(3, 4);

    NonNullRange range = matrix.getRangeForRow(rowIndex);

    assertEquals(0, range.begin);
    assertEquals(4, range.end);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2, 3})
  void getRangeForColumn_whenAnyColumnRequested_returnsFullRowRange(int columnIndex) {
    GeneralMatrix matrix = new GeneralMatrix(4, 3);

    NonNullRange range = matrix.getRangeForColumn(columnIndex);

    assertEquals(0, range.begin);
    assertEquals(4, range.end);
  }

  @Test
  void setElementAndGetElement_whenIndicesValid_writesAndReadsValues() {
    GeneralMatrix matrix = new GeneralMatrix(2, 3);

    matrix.setElement(0, 0, 1.5);
    matrix.setElement(1, 2, -3.5);

    assertEquals(1.5, matrix.getElement(0, 0));
    assertEquals(-3.5, matrix.getElement(1, 2));
  }

  @Test
  void setElement_whenIndexOutOfBounds_throwsIllegalArgumentException() {
    GeneralMatrix matrix = new GeneralMatrix(2, 2);

    assertThrows(IllegalArgumentException.class, () -> matrix.setElement(-1, 0, 1.0));
    assertThrows(IllegalArgumentException.class, () -> matrix.setElement(0, 2, 1.0));
  }
}
