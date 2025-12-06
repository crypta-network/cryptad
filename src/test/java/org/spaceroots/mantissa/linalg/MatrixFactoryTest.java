package org.spaceroots.mantissa.linalg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class MatrixFactoryTest {

  @Test
  void buildMatrix_withSquareAndNoOffDiagonal_returnsDiagonalMatrix() {
    double[] data = {1.0, 0.0, 0.0, 2.0};

    Matrix matrix = MatrixFactory.buildMatrix(2, 2, data, 0, 0);

    assertInstanceOf(DiagonalMatrix.class, matrix);
    assertEquals(1.0, matrix.getElement(0, 0));
    assertEquals(2.0, matrix.getElement(1, 1));
  }

  @Test
  void buildMatrix_withOnlyUpperNonZero_returnsUpperTriangularMatrix() {
    double[] data = {
      1.0, 2.0, 3.0,
      0.0, 4.0, 5.0,
      0.0, 0.0, 6.0
    };

    Matrix matrix = MatrixFactory.buildMatrix(3, 3, data, 0, 3);

    assertInstanceOf(UpperTriangularMatrix.class, matrix);
    assertEquals(3.0, matrix.getElement(0, 2));
    assertEquals(0.0, matrix.getElement(2, 0));
  }

  @Test
  void buildMatrix_withOnlyLowerNonZero_returnsLowerTriangularMatrix() {
    double[] data = {
      7.0, 0.0, 0.0,
      8.0, 9.0, 0.0,
      10.0, 11.0, 12.0
    };

    Matrix matrix = MatrixFactory.buildMatrix(3, 3, data, 6, 0);

    assertInstanceOf(LowerTriangularMatrix.class, matrix);
    assertEquals(10.0, matrix.getElement(2, 0));
    assertEquals(0.0, matrix.getElement(0, 2));
  }

  @Test
  void buildMatrix_withUpperAndLowerNonZero_returnsGeneralSquareMatrix() {
    double[] data = {1.0, 2.0, 3.0, 4.0};

    Matrix matrix = MatrixFactory.buildMatrix(2, 2, data, 1, 1);

    assertInstanceOf(GeneralSquareMatrix.class, matrix);
    assertEquals(2.0, matrix.getElement(0, 1));
    assertEquals(3.0, matrix.getElement(1, 0));
  }

  @Test
  void buildMatrix_withRectangularShape_returnsGeneralMatrix() {
    double[] data = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0};

    Matrix matrix = MatrixFactory.buildMatrix(2, 3, data, 1, 2);

    assertInstanceOf(GeneralMatrix.class, matrix);
    assertEquals(2, matrix.getRows());
    assertEquals(3, matrix.getColumns());
  }

  @Test
  void buildMatrixDimensionOnly_withSquareShape_returnsGeneralSquareMatrix() {
    double[] data = {1.0, 0.0, 0.0, 1.0};

    Matrix matrix = MatrixFactory.buildMatrix(2, 2, data);

    assertInstanceOf(GeneralSquareMatrix.class, matrix);
    assertEquals(1.0, matrix.getElement(1, 1));
  }

  @Test
  void buildMatrixDimensionOnly_withRectangularShape_returnsGeneralMatrix() {
    double[] data = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0};

    Matrix matrix = MatrixFactory.buildMatrix(2, 3, data);

    assertInstanceOf(GeneralMatrix.class, matrix);
    assertEquals(2, matrix.getRows());
    assertEquals(3, matrix.getColumns());
  }
}
