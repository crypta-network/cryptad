package org.spaceroots.mantissa.linalg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100")
class GeneralSquareMatrixTest {

  @Test
  void duplicate_whenCalled_returnsIndependentCopy() {
    GeneralSquareMatrix original = new GeneralSquareMatrix(2, new double[] {1.0, 2.0, 3.0, 4.0});

    Matrix copy = original.duplicate();
    copy.setElement(0, 0, 9.0);

    assertInstanceOf(GeneralSquareMatrix.class, copy);
    assertNotSame(original, copy);
    assertEquals(1.0, original.getElement(0, 0));
    assertEquals(9.0, copy.getElement(0, 0));
  }

  @Test
  void setElement_whenCalled_resetsCachedFactorization() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2, new double[] {1.0, 2.0, 3.0, 4.0});

    double initialDeterminant = matrix.getDeterminant(1.0e-12);
    matrix.setElement(0, 0, 2.0);
    double updatedDeterminant = matrix.getDeterminant(1.0e-12);

    assertEquals(-2.0, initialDeterminant, 1.0e-12);
    assertEquals(2.0, updatedDeterminant, 1.0e-12);
  }

  @Test
  void selfAdd_whenDimensionsMatch_addsInPlace() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2, new double[] {1.0, 2.0, 3.0, 4.0});
    SquareMatrix toAdd = new GeneralSquareMatrix(2, new double[] {4.0, 3.0, 2.0, 1.0});

    matrix.selfAdd(toAdd);

    assertEquals(5.0, matrix.getElement(0, 0));
    assertEquals(5.0, matrix.getElement(0, 1));
    assertEquals(5.0, matrix.getElement(1, 0));
    assertEquals(5.0, matrix.getElement(1, 1));
  }

  @Test
  void selfAdd_whenDimensionMismatch_throwsIllegalArgumentException() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2);
    SquareMatrix different = new GeneralSquareMatrix(3);

    assertThrows(IllegalArgumentException.class, () -> matrix.selfAdd(different));
  }

  @Test
  void selfSub_whenDimensionsMatch_subtractsInPlace() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2, new double[] {5.0, 7.0, 9.0, 11.0});
    SquareMatrix toSubtract = new GeneralSquareMatrix(2, new double[] {1.0, 2.0, 3.0, 4.0});

    matrix.selfSub(toSubtract);

    assertEquals(4.0, matrix.getElement(0, 0));
    assertEquals(5.0, matrix.getElement(0, 1));
    assertEquals(6.0, matrix.getElement(1, 0));
    assertEquals(7.0, matrix.getElement(1, 1));
  }

  @Test
  void selfSub_whenDimensionMismatch_throwsIllegalArgumentException() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2);
    SquareMatrix different = new GeneralSquareMatrix(1);

    assertThrows(IllegalArgumentException.class, () -> matrix.selfSub(different));
  }

  @Test
  void getDeterminant_whenPivotingOccurs_adjustsSignWithPermutations() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2, new double[] {0.0, 1.0, 2.0, 3.0});

    double determinant = matrix.getDeterminant(1.0e-12);

    assertEquals(-2.0, determinant);
  }

  @Test
  void getDeterminant_whenMatrixSingular_returnsZero() {
    GeneralSquareMatrix singular = new GeneralSquareMatrix(2, new double[] {1.0, 2.0, 2.0, 4.0});

    double determinant = singular.getDeterminant(1.0e-12);

    assertEquals(0.0, determinant);
  }

  @Test
  void solve_whenPivotingNeeded_appliesPermutationsToRightHandSide()
      throws SingularMatrixException {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2, new double[] {0.0, 1.0, 2.0, 3.0});
    Matrix rhs = new GeneralMatrix(2, 1, new double[] {1.0, 5.0});

    Matrix solution = matrix.solve(rhs, 1.0e-12);

    assertEquals(1.0, solution.getElement(0, 0));
    assertEquals(1.0, solution.getElement(1, 0));
  }

  @Test
  void solve_whenDimensionMismatch_throwsIllegalArgumentException() {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(2);
    Matrix rhs = new GeneralMatrix(3, 1);

    assertThrows(IllegalArgumentException.class, () -> matrix.solve(rhs, 1.0e-6));
  }

  @Test
  void solve_whenPivotBelowEpsilon_throwsSingularMatrixException() {
    GeneralSquareMatrix nearlySingular =
        new GeneralSquareMatrix(2, new double[] {1.0e-9, 0.0, 0.0, 1.0e-9});
    Matrix rhs = new GeneralMatrix(2, 1, new double[] {1.0, 1.0});

    assertThrows(SingularMatrixException.class, () -> nearlySingular.solve(rhs, 1.0e-8));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2})
  void getRangeForRow_whenAnyRowRequested_returnsFullRange(int rowIndex) {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(3);

    NonNullRange range = matrix.getRangeForRow(rowIndex);

    assertEquals(0, range.begin);
    assertEquals(3, range.end);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 2})
  void getRangeForColumn_whenAnyColumnRequested_returnsFullRange(int columnIndex) {
    GeneralSquareMatrix matrix = new GeneralSquareMatrix(3);

    NonNullRange range = matrix.getRangeForColumn(columnIndex);

    assertEquals(0, range.begin);
    assertEquals(3, range.end);
  }
}
