package org.spaceroots.mantissa.random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.linalg.Matrix;
import org.spaceroots.mantissa.linalg.SymetricalMatrix;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CorrelatedRandomVectorGeneratorTest {

  @Mock private NormalizedRandomGenerator generator;

  @Test
  void constructor_withMeanLengthDifferentFromCovariance_throwsIllegalArgumentException() {
    // Arrange
    double[] mean = new double[] {1.0};
    SymetricalMatrix covariance = identity2();

    // Act
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> new CorrelatedRandomVectorGenerator(mean, covariance, generator));

    // Assert
    assertEquals("dimension mismatch 1 != 2", ex.getMessage());
  }

  @Test
  void constructor_withNegativeDiagonal_throwsNotPositiveDefiniteMatrixException() {
    // Arrange
    SymetricalMatrix covariance = new SymetricalMatrix(1);
    covariance.setElement(0, 0, -1.0);

    // Act + Assert
    assertThrows(
        NotPositiveDefiniteMatrixException.class,
        () -> new CorrelatedRandomVectorGenerator(covariance, generator));
  }

  @Test
  void nextVector_withIdentityCovariance_returnsNormalizedSamples() throws Exception {
    // Arrange
    SymetricalMatrix covariance = identity2();
    when(generator.nextDouble()).thenReturn(0.3, -0.7);
    CorrelatedRandomVectorGenerator vectorGenerator =
        new CorrelatedRandomVectorGenerator(covariance, generator);

    // Act
    double[] vector = vectorGenerator.nextVector();

    // Assert
    assertArrayEquals(new double[] {0.3, -0.7}, vector, 1.0e-12);
    assertEquals(2, vectorGenerator.getRank());

    Matrix root = vectorGenerator.getRootMatrix();
    assertEquals(2, root.getRows());
    assertEquals(2, root.getColumns());
    assertEquals(1.0, root.getElement(0, 0), 1.0e-12);
    assertEquals(0.0, root.getElement(0, 1), 1.0e-12);
    assertEquals(0.0, root.getElement(1, 0), 1.0e-12);
    assertEquals(1.0, root.getElement(1, 1), 1.0e-12);

    assertEquals(generator, vectorGenerator.getGenerator());
  }

  @Test
  void nextVector_withNonZeroMeanAndCorrelatedCovariance_combinesComponents() throws Exception {
    // Arrange
    double[] mean = new double[] {1.0, -1.0};
    SymetricalMatrix covariance = new SymetricalMatrix(2);
    covariance.setElement(0, 0, 4.0);
    covariance.setElementAndSymetricalElement(1, 0, 2.0);
    covariance.setElement(1, 1, 3.0);

    when(generator.nextDouble()).thenReturn(0.5, -0.5);

    CorrelatedRandomVectorGenerator vectorGenerator =
        new CorrelatedRandomVectorGenerator(mean, covariance, generator);

    // Act
    double[] vector = vectorGenerator.nextVector();

    // Assert
    Matrix root = vectorGenerator.getRootMatrix();
    assertEquals(2.0, root.getElement(0, 0), 1.0e-12);
    assertEquals(0.0, root.getElement(0, 1), 1.0e-12);
    assertEquals(1.0, root.getElement(1, 0), 1.0e-12);
    assertEquals(Math.sqrt(2.0), root.getElement(1, 1), 1.0e-12);

    //noinspection PointlessArithmeticExpression
    double expectedSecond = -1.0 + 1.0 * 0.5 + Math.sqrt(2.0) * -0.5;
    assertArrayEquals(new double[] {2.0, expectedSecond}, vector, 1.0e-12);
  }

  @Test
  void nextVector_withSemiDefiniteCovariance_usesComputedRankAndZeroColumns() throws Exception {
    // Arrange
    SymetricalMatrix covariance = new SymetricalMatrix(2);
    covariance.setElement(0, 0, 1.0);
    covariance.setElementAndSymetricalElement(1, 0, 1.0);
    covariance.setElement(1, 1, 1.0);

    when(generator.nextDouble()).thenReturn(1.0, 2.0);

    CorrelatedRandomVectorGenerator vectorGenerator =
        new CorrelatedRandomVectorGenerator(covariance, generator);

    // Act
    double[] vector = vectorGenerator.nextVector();

    // Assert
    assertEquals(2, vectorGenerator.getRank());

    Matrix root = vectorGenerator.getRootMatrix();
    assertEquals(1.0, root.getElement(0, 0), 1.0e-12);
    assertEquals(0.0, root.getElement(0, 1), 1.0e-12);
    assertEquals(1.0, root.getElement(1, 0), 1.0e-12);
    assertEquals(0.0, root.getElement(1, 1), 1.0e-12);

    assertArrayEquals(new double[] {1.0, 1.0}, vector, 1.0e-12);
  }

  private static SymetricalMatrix identity2() {
    SymetricalMatrix matrix = new SymetricalMatrix(2);
    for (int i = 0; i < 2; ++i) {
      matrix.setElement(i, i, 1.0);
    }
    return matrix;
  }
}
