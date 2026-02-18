package org.spaceroots.mantissa.linalg;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class SymetricalMatrixTest {

  private static final double EPS = 1.0e-12;

  @Test
  void setElement_whenOffDiagonal_throwsArrayIndexOutOfBoundsException() {
    SymetricalMatrix matrix = new SymetricalMatrix(2);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> matrix.setElement(0, 1, 2.0));
  }

  @Test
  void setElementAndSymetricalElement_whenOffDiagonal_setsBothSides() {
    SymetricalMatrix matrix = new SymetricalMatrix(2);

    matrix.setElementAndSymetricalElement(0, 1, 5.5);

    assertEquals(5.5, matrix.getElement(0, 1), EPS);
    assertEquals(5.5, matrix.getElement(1, 0), EPS);
    assertEquals(0.0, matrix.getElement(0, 0), EPS);
    assertEquals(0.0, matrix.getElement(1, 1), EPS);
  }

  @Test
  void setElementAndSymetricalElement_whenDiagonal_setsSingleElement() {
    SymetricalMatrix matrix = new SymetricalMatrix(3);

    matrix.setElementAndSymetricalElement(1, 1, 7.0);

    assertEquals(7.0, matrix.getElement(1, 1), EPS);
    assertEquals(0.0, matrix.getElement(0, 1), EPS);
    assertEquals(0.0, matrix.getElement(1, 2), EPS);
  }

  @Test
  void constructor_withWeightAndVector_buildsSymmetricOuterProduct() {
    double[] vector = {1.0, 2.0, 3.0};

    SymetricalMatrix matrix = new SymetricalMatrix(2.0, vector);

    for (int i = 0; i < vector.length; i++) {
      for (int j = 0; j < vector.length; j++) {
        double expected = 2.0 * vector[i] * vector[j];
        assertEquals(expected, matrix.getElement(i, j), EPS);
      }
    }
  }

  @Test
  void selfAdd_whenDimensionsMismatch_throwsIllegalArgumentException() {
    SymetricalMatrix first = new SymetricalMatrix(2);
    SymetricalMatrix other = new SymetricalMatrix(3);

    assertThrows(IllegalArgumentException.class, () -> first.selfAdd(other));
  }

  @Test
  void selfAdd_whenValid_preservesSymmetryAndAddsCoefficients() {
    SymetricalMatrix base = new SymetricalMatrix(2);
    base.setElementAndSymetricalElement(0, 1, 3.0);
    base.setElement(0, 0, 1.0);
    base.setElement(1, 1, 4.0);

    SymetricalMatrix increment = new SymetricalMatrix(2);
    increment.setElementAndSymetricalElement(0, 1, -2.0);
    increment.setElement(0, 0, 5.0);
    increment.setElement(1, 1, 6.0);

    base.selfAdd(increment);

    assertEquals(6.0, base.getElement(0, 0), EPS);
    assertEquals(10.0, base.getElement(1, 1), EPS);
    assertEquals(1.0, base.getElement(0, 1), EPS);
    assertEquals(1.0, base.getElement(1, 0), EPS);
  }

  @Test
  void selfSub_whenDimensionsMismatch_throwsIllegalArgumentException() {
    SymetricalMatrix first = new SymetricalMatrix(3);
    SymetricalMatrix other = new SymetricalMatrix(2);

    assertThrows(IllegalArgumentException.class, () -> first.selfSub(other));
  }

  @Test
  void selfSub_whenValid_preservesSymmetryAndSubtractsCoefficients() {
    SymetricalMatrix base = new SymetricalMatrix(2);
    base.setElementAndSymetricalElement(0, 1, 4.0);
    base.setElement(0, 0, 10.0);
    base.setElement(1, 1, 8.0);

    SymetricalMatrix decrement = new SymetricalMatrix(2);
    decrement.setElementAndSymetricalElement(0, 1, 1.5);
    decrement.setElement(0, 0, 3.0);
    decrement.setElement(1, 1, 2.0);

    base.selfSub(decrement);

    assertEquals(7.0, base.getElement(0, 0), EPS);
    assertEquals(6.0, base.getElement(1, 1), EPS);
    assertEquals(2.5, base.getElement(0, 1), EPS);
    assertEquals(2.5, base.getElement(1, 0), EPS);
  }

  @Test
  void selfAddWAAt_whenVectorLengthMismatch_throwsIllegalArgumentException() {
    SymetricalMatrix matrix = new SymetricalMatrix(2);
    double[] vector = {1.0, 2.0, 3.0};

    assertThrows(IllegalArgumentException.class, () -> matrix.selfAddWAAt(1.0, vector));
  }

  @Test
  void selfAddWAAt_whenValid_accumulatesWeightedOuterProduct() {
    SymetricalMatrix matrix = new SymetricalMatrix(2);
    matrix.setElement(0, 0, 1.0);
    matrix.setElement(1, 1, 1.0);
    matrix.setElementAndSymetricalElement(0, 1, 3.0);

    double[] vector = {4.0, -2.0};

    matrix.selfAddWAAt(0.5, vector);

    assertEquals(9.0, matrix.getElement(0, 0), EPS);
    assertEquals(3.0, matrix.getElement(1, 1), EPS);
    assertEquals(-1.0, matrix.getElement(0, 1), EPS);
    assertEquals(-1.0, matrix.getElement(1, 0), EPS);
  }

  @Test
  void duplicate_createsIndependentCopy() {
    SymetricalMatrix original = new SymetricalMatrix(2);
    original.setElementAndSymetricalElement(0, 1, 2.0);
    original.setElement(0, 0, 5.0);
    original.setElement(1, 1, 7.0);

    SymetricalMatrix copy = (SymetricalMatrix) original.duplicate();

    original.setElement(0, 0, 99.0);

    assertEquals(5.0, copy.getElement(0, 0), EPS);
    assertEquals(7.0, copy.getElement(1, 1), EPS);
    assertEquals(2.0, copy.getElement(0, 1), EPS);
    assertEquals(2.0, copy.getElement(1, 0), EPS);
  }
}
