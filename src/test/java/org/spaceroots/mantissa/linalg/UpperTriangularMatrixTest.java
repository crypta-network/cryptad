package org.spaceroots.mantissa.linalg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class UpperTriangularMatrixTest {

  @Test
  void setElement_whenOnOrAboveDiagonal_updatesValue() {
    UpperTriangularMatrix matrix = new UpperTriangularMatrix(3);

    matrix.setElement(0, 2, 7.5);

    assertEquals(7.5, matrix.getElement(0, 2));
    assertEquals(0.0, matrix.getElement(2, 2));
  }

  @Test
  void setElement_whenBelowDiagonal_throwsArrayIndexOutOfBoundsException() {
    UpperTriangularMatrix matrix = new UpperTriangularMatrix(2);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> matrix.setElement(1, 0, 3.0));
  }

  @Test
  void duplicate_whenCalled_returnsIndependentCopyOfSameType() {
    UpperTriangularMatrix original = new UpperTriangularMatrix(2);
    original.setElement(0, 1, 4.0);
    original.setElement(0, 0, 1.5);

    Matrix copy = original.duplicate();
    original.setElement(0, 1, 8.0);

    assertInstanceOf(UpperTriangularMatrix.class, copy);
    assertEquals(4.0, copy.getElement(0, 1));
    assertEquals(1.5, copy.getElement(0, 0));
  }

  @Test
  void selfAdd_whenSameOrder_addsUpperTriangleElements() {
    UpperTriangularMatrix left = new UpperTriangularMatrix(3);
    left.setElement(0, 0, 1.0);
    left.setElement(0, 1, 2.0);
    left.setElement(0, 2, 3.0);
    left.setElement(1, 1, 4.0);
    left.setElement(1, 2, 5.0);
    left.setElement(2, 2, 6.0);

    UpperTriangularMatrix right = new UpperTriangularMatrix(3);
    right.setElement(0, 0, 10.0);
    right.setElement(0, 1, 20.0);
    right.setElement(0, 2, 30.0);
    right.setElement(1, 1, 40.0);
    right.setElement(1, 2, 50.0);
    right.setElement(2, 2, 60.0);

    left.selfAdd(right);

    assertEquals(11.0, left.getElement(0, 0));
    assertEquals(22.0, left.getElement(0, 1));
    assertEquals(33.0, left.getElement(0, 2));
    assertEquals(44.0, left.getElement(1, 1));
    assertEquals(55.0, left.getElement(1, 2));
    assertEquals(66.0, left.getElement(2, 2));
    assertEquals(0.0, left.getElement(1, 0));
  }

  @Test
  void selfAdd_whenDimensionMismatch_throwsIllegalArgumentException() {
    UpperTriangularMatrix left = new UpperTriangularMatrix(2);
    UpperTriangularMatrix right = new UpperTriangularMatrix(3);

    assertThrows(IllegalArgumentException.class, () -> left.selfAdd(right));
  }

  @Test
  void selfSub_whenSameOrder_subtractsUpperTriangleElements() {
    UpperTriangularMatrix left = new UpperTriangularMatrix(2);
    left.setElement(0, 0, 5.0);
    left.setElement(0, 1, 4.0);
    left.setElement(1, 1, 3.0);

    UpperTriangularMatrix right = new UpperTriangularMatrix(2);
    right.setElement(0, 0, 2.0);
    right.setElement(0, 1, 1.5);
    right.setElement(1, 1, 1.0);

    left.selfSub(right);

    assertEquals(3.0, left.getElement(0, 0));
    assertEquals(2.5, left.getElement(0, 1));
    assertEquals(2.0, left.getElement(1, 1));
    assertEquals(0.0, left.getElement(1, 0));
  }

  @Test
  void selfSub_whenDimensionMismatch_throwsIllegalArgumentException() {
    UpperTriangularMatrix left = new UpperTriangularMatrix(3);
    UpperTriangularMatrix right = new UpperTriangularMatrix(2);

    assertThrows(IllegalArgumentException.class, () -> left.selfSub(right));
  }

  @Test
  void getDeterminant_whenDiagonalPresent_returnsProductOfDiagonal() {
    UpperTriangularMatrix matrix =
        new UpperTriangularMatrix(3, new double[] {2.0, 1.0, 1.0, 0.0, 3.0, 2.0, 0.0, 0.0, 4.0});

    double determinant = matrix.getDeterminant(1.0e-9);

    assertEquals(24.0, determinant);
  }

  @Test
  void solve_whenUpperTriangularRhs_returnsBackSubstitutionSolution()
      throws SingularMatrixException {
    UpperTriangularMatrix coefficient =
        new UpperTriangularMatrix(3, new double[] {2.0, 1.0, 1.0, 0.0, 3.0, 2.0, 0.0, 0.0, 4.0});

    GeneralSquareMatrix rhs = new GeneralSquareMatrix(3);
    rhs.setElement(0, 0, 1.0);
    rhs.setElement(1, 1, 1.0);
    rhs.setElement(2, 2, 1.0);

    Matrix solution = coefficient.solve(rhs, 1.0e-9);

    assertEquals(0.5, solution.getElement(0, 0), 1.0e-12);
    assertEquals(-1.0 / 6.0, solution.getElement(0, 1), 1.0e-12);
    assertEquals(-1.0 / 24.0, solution.getElement(0, 2), 1.0e-12);
    assertEquals(0.0, solution.getElement(1, 0), 1.0e-12);
    assertEquals(1.0 / 3.0, solution.getElement(1, 1), 1.0e-12);
    assertEquals(-1.0 / 6.0, solution.getElement(1, 2), 1.0e-12);
    assertEquals(0.0, solution.getElement(2, 0), 1.0e-12);
    assertEquals(0.0, solution.getElement(2, 1), 1.0e-12);
    assertEquals(0.25, solution.getElement(2, 2), 1.0e-12);
  }

  @Test
  void solve_whenDiagonalBelowEpsilon_throwsSingularMatrixException() {
    UpperTriangularMatrix coefficient = new UpperTriangularMatrix(2);
    coefficient.setElement(0, 0, 1.0e-8);
    coefficient.setElement(1, 1, 2.0);
    Matrix rhs = new GeneralMatrix(2, 1, new double[] {1.0, 2.0});

    assertThrows(SingularMatrixException.class, () -> coefficient.solve(rhs, 1.0e-6));
  }

  @Test
  void solve_whenRowCountDiffers_throwsIllegalArgumentException() {
    UpperTriangularMatrix coefficient = new UpperTriangularMatrix(2);
    Matrix rhs = new GeneralMatrix(3, 1, new double[] {1.0, 2.0, 3.0});

    assertThrows(IllegalArgumentException.class, () -> coefficient.solve(rhs, 1.0e-9));
  }

  @Test
  void getRangeForRow_whenCalled_returnsIndexToEndRange() {
    UpperTriangularMatrix matrix = new UpperTriangularMatrix(4);

    NonNullRange range = matrix.getRangeForRow(2);

    assertEquals(2, range.begin);
    assertEquals(4, range.end);
  }

  @Test
  void getRangeForColumn_whenCalled_returnsZeroToInclusiveRange() {
    UpperTriangularMatrix matrix = new UpperTriangularMatrix(4);

    NonNullRange range = matrix.getRangeForColumn(1);

    assertEquals(0, range.begin);
    assertEquals(2, range.end);
  }
}
