package org.spaceroots.mantissa.linalg;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class DiagonalMatrixTest {

  @Test
  void constructorWithOrder_whenPositive_buildsIdentityMatrix() {
    DiagonalMatrix matrix = new DiagonalMatrix(3);

    for (int i = 0; i < 3; i++) {
      assertEquals(1.0, matrix.getElement(i, i));
      for (int j = 0; j < 3; j++) {
        if (i != j) {
          assertEquals(0.0, matrix.getElement(i, j));
        }
      }
    }
  }

  @Test
  void constructorWithValue_whenProvided_setsUniformDiagonal() {
    DiagonalMatrix matrix = new DiagonalMatrix(2, 5.5);

    assertEquals(5.5, matrix.getElement(0, 0));
    assertEquals(5.5, matrix.getElement(1, 1));
    assertEquals(0.0, matrix.getElement(0, 1));
    assertEquals(0.0, matrix.getElement(1, 0));
  }

  @Test
  void constructorWithData_whenSourceModified_matrixRemainsUnchanged() {
    double[] source = {1.0, 0.0, 0.0, 2.0};

    DiagonalMatrix matrix = new DiagonalMatrix(2, source);
    source[0] = 10.0;

    assertEquals(1.0, matrix.getElement(0, 0));
    assertEquals(2.0, matrix.getElement(1, 1));
  }

  @Test
  void constructorWithOrder_whenNonPositive_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new DiagonalMatrix(0));
  }

  @Test
  void setElement_whenOnDiagonal_updatesValue() {
    DiagonalMatrix matrix = new DiagonalMatrix(2);

    matrix.setElement(1, 1, 7.0);

    assertEquals(7.0, matrix.getElement(1, 1));
  }

  @Test
  void setElement_whenOffDiagonal_throwsArrayIndexOutOfBounds() {
    DiagonalMatrix matrix = new DiagonalMatrix(2);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> matrix.setElement(0, 1, 3.0));
  }

  @Test
  void duplicate_whenCalled_returnsIndependentDiagonalMatrix() {
    DiagonalMatrix original = new DiagonalMatrix(3, 2.0);
    original.setElement(1, 1, 4.0);

    Matrix copy = original.duplicate();
    original.setElement(0, 0, 10.0);

    assertInstanceOf(DiagonalMatrix.class, copy);
    assertEquals(2.0, copy.getElement(0, 0));
    assertEquals(4.0, copy.getElement(1, 1));
    assertEquals(2.0, copy.getElement(2, 2));
  }

  @Test
  void getDeterminant_whenDiagonalFilled_returnsProduct() {
    DiagonalMatrix matrix = new DiagonalMatrix(3, 1.0);
    matrix.setElement(0, 0, 2.0);
    matrix.setElement(1, 1, 3.0);
    matrix.setElement(2, 2, 4.0);

    double determinant = matrix.getDeterminant(1.0e-12);

    assertEquals(24.0, determinant);
  }

  @Test
  void getInverse_whenDiagonalAboveEpsilon_returnsReciprocalMatrix()
      throws SingularMatrixException {
    DiagonalMatrix matrix = new DiagonalMatrix(2, 1.0);
    matrix.setElement(0, 0, 2.0);
    matrix.setElement(1, 1, 4.0);

    SquareMatrix inverse = matrix.getInverse(1.0e-6);

    assertInstanceOf(DiagonalMatrix.class, inverse);
    assertEquals(0.5, inverse.getElement(0, 0));
    assertEquals(0.25, inverse.getElement(1, 1));
    assertEquals(2.0, matrix.getElement(0, 0));
    assertEquals(4.0, matrix.getElement(1, 1));
  }

  @Test
  void getInverse_whenDiagonalBelowEpsilon_throwsSingularMatrixException() {
    DiagonalMatrix matrix = new DiagonalMatrix(2, 1.0);
    matrix.setElement(0, 0, 1.0e-8);
    matrix.setElement(1, 1, 1.0);

    assertThrows(SingularMatrixException.class, () -> matrix.getInverse(1.0e-6));
  }

  @Test
  void solve_whenDiagonalNonZero_scalesRowsByInverseDiagonal() throws SingularMatrixException {
    DiagonalMatrix matrix = new DiagonalMatrix(2, 1.0);
    matrix.setElement(0, 0, 2.0);
    matrix.setElement(1, 1, 4.0);
    Matrix rightHandSide =
        new GeneralMatrix(2, 2, new double[] {2.0, 4.0, 6.0, 8.0}); // rows: [2,4] and [6,8]

    Matrix solution = matrix.solve(rightHandSide, 1.0e-6);

    assertEquals(1.0, solution.getElement(0, 0));
    assertEquals(2.0, solution.getElement(0, 1));
    assertEquals(1.5, solution.getElement(1, 0));
    assertEquals(2.0, solution.getElement(1, 1));
    assertEquals(2.0, rightHandSide.getElement(0, 0));
  }

  @Test
  void solve_whenDiagonalZero_throwsSingularMatrixException() {
    DiagonalMatrix matrix = new DiagonalMatrix(2, 1.0);
    matrix.setElement(0, 0, 0.0);
    matrix.setElement(1, 1, 3.0);
    Matrix rightHandSide = new GeneralMatrix(2, 1, new double[] {2.0, 6.0});

    assertThrows(SingularMatrixException.class, () -> matrix.solve(rightHandSide, 1.0e-9));
  }

  @Test
  void getRangeForRow_whenCalled_returnsSingleIndexRange() {
    DiagonalMatrix matrix = new DiagonalMatrix(4);

    NonNullRange range = matrix.getRangeForRow(2);

    assertEquals(2, range.begin);
    assertEquals(3, range.end);
  }

  @Test
  void getRangeForColumn_whenCalled_returnsSingleIndexRange() {
    DiagonalMatrix matrix = new DiagonalMatrix(4);

    NonNullRange range = matrix.getRangeForColumn(1);

    assertEquals(1, range.begin);
    assertEquals(2, range.end);
  }
}
