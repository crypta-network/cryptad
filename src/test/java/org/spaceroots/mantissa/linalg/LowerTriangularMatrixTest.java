package org.spaceroots.mantissa.linalg;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class LowerTriangularMatrixTest {

  @Test
  void setElement_whenOnOrBelowDiagonal_updatesValue() {
    LowerTriangularMatrix matrix = new LowerTriangularMatrix(3);

    matrix.setElement(2, 1, 5.5);

    assertEquals(5.5, matrix.getElement(2, 1));
    assertEquals(0.0, matrix.getElement(2, 2));
  }

  @Test
  void setElement_whenAboveDiagonal_throwsArrayIndexOutOfBoundsException() {
    LowerTriangularMatrix matrix = new LowerTriangularMatrix(2);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> matrix.setElement(0, 1, 3.0));
  }

  @Test
  void duplicate_whenCalled_returnsIndependentCopyOfSameType() {
    LowerTriangularMatrix original = new LowerTriangularMatrix(2);
    original.setElement(1, 0, 4.0);
    original.setElement(1, 1, 2.0);

    Matrix copy = original.duplicate();
    original.setElement(1, 0, 8.0);

    assertInstanceOf(LowerTriangularMatrix.class, copy);
    assertEquals(4.0, copy.getElement(1, 0));
    assertEquals(2.0, copy.getElement(1, 1));
  }

  @Test
  void selfAdd_whenSameOrder_addsLowerTriangleElements() {
    LowerTriangularMatrix left = new LowerTriangularMatrix(3);
    left.setElement(0, 0, 1.0);
    left.setElement(1, 0, 2.0);
    left.setElement(1, 1, 3.0);
    left.setElement(2, 1, 4.0);

    LowerTriangularMatrix right = new LowerTriangularMatrix(3);
    right.setElement(0, 0, 5.0);
    right.setElement(1, 0, 6.0);
    right.setElement(1, 1, 7.0);
    right.setElement(2, 0, 8.0);

    left.selfAdd(right);

    assertEquals(6.0, left.getElement(0, 0));
    assertEquals(8.0, left.getElement(1, 0));
    assertEquals(10.0, left.getElement(1, 1));
    assertEquals(8.0, left.getElement(2, 0));
    assertEquals(4.0, left.getElement(2, 1));
  }

  @Test
  void selfAdd_whenDimensionMismatch_throwsIllegalArgumentException() {
    LowerTriangularMatrix left = new LowerTriangularMatrix(2);
    LowerTriangularMatrix right = new LowerTriangularMatrix(3);

    assertThrows(IllegalArgumentException.class, () -> left.selfAdd(right));
  }

  @Test
  void selfSub_whenSameOrder_subtractsLowerTriangleElements() {
    LowerTriangularMatrix left = new LowerTriangularMatrix(2);
    left.setElement(0, 0, 5.0);
    left.setElement(1, 0, 4.0);
    left.setElement(1, 1, 3.0);

    LowerTriangularMatrix right = new LowerTriangularMatrix(2);
    right.setElement(0, 0, 2.0);
    right.setElement(1, 0, 1.5);
    right.setElement(1, 1, 1.0);

    left.selfSub(right);

    assertEquals(3.0, left.getElement(0, 0));
    assertEquals(2.5, left.getElement(1, 0));
    assertEquals(2.0, left.getElement(1, 1));
  }

  @Test
  void selfSub_whenDimensionMismatch_throwsIllegalArgumentException() {
    LowerTriangularMatrix left = new LowerTriangularMatrix(3);
    LowerTriangularMatrix right = new LowerTriangularMatrix(2);

    assertThrows(IllegalArgumentException.class, () -> left.selfSub(right));
  }

  @Test
  void getDeterminant_whenDiagonalPresent_returnsProductOfDiagonal() {
    LowerTriangularMatrix matrix =
        new LowerTriangularMatrix(3, new double[] {2.0, 0.0, 0.0, 3.0, 3.0, 0.0, 5.0, 6.0, 7.0});

    double determinant = matrix.getDeterminant(1.0e-9);

    assertEquals(42.0, determinant);
  }

  @Test
  void solve_whenLowerTriangularRhs_returnsForwardSubstitutionSolution()
      throws SingularMatrixException {
    LowerTriangularMatrix coefficient = new LowerTriangularMatrix(2);
    coefficient.setElement(0, 0, 2.0);
    coefficient.setElement(1, 0, 3.0);
    coefficient.setElement(1, 1, 5.0);

    LowerTriangularMatrix rhs = new LowerTriangularMatrix(2);
    rhs.setElement(0, 0, 1.0);
    rhs.setElement(1, 0, 0.0);
    rhs.setElement(1, 1, 1.0);

    Matrix solution = coefficient.solve(rhs, 1.0e-9);

    assertInstanceOf(LowerTriangularMatrix.class, solution);
    assertEquals(0.5, solution.getElement(0, 0), 1.0e-12);
    assertEquals(0.0, solution.getElement(0, 1), 1.0e-12);
    assertEquals(-0.3, solution.getElement(1, 0), 1.0e-12);
    assertEquals(0.2, solution.getElement(1, 1), 1.0e-12);
  }

  @Test
  void solve_whenDiagonalBelowEpsilon_throwsSingularMatrixException() {
    LowerTriangularMatrix coefficient = new LowerTriangularMatrix(2);
    coefficient.setElement(0, 0, 1.0e-8);
    coefficient.setElement(1, 1, 2.0);
    Matrix rhs = new GeneralMatrix(2, 1, new double[] {1.0, 2.0});

    assertThrows(SingularMatrixException.class, () -> coefficient.solve(rhs, 1.0e-6));
  }

  @Test
  void solve_whenRowCountDiffers_throwsIllegalArgumentException() {
    LowerTriangularMatrix coefficient = new LowerTriangularMatrix(2);
    Matrix rhs = new GeneralMatrix(3, 1, new double[] {1.0, 2.0, 3.0});

    assertThrows(IllegalArgumentException.class, () -> coefficient.solve(rhs, 1.0e-9));
  }

  @Test
  void getRangeForRow_whenCalled_returnsZeroToInclusiveIndexRange() {
    LowerTriangularMatrix matrix = new LowerTriangularMatrix(4);

    NonNullRange range = matrix.getRangeForRow(2);

    assertEquals(0, range.begin);
    assertEquals(3, range.end);
  }

  @Test
  void getRangeForColumn_whenCalled_returnsColumnIndexToEndRange() {
    LowerTriangularMatrix matrix = new LowerTriangularMatrix(4);

    NonNullRange range = matrix.getRangeForColumn(1);

    assertEquals(1, range.begin);
    assertEquals(4, range.end);
  }
}
