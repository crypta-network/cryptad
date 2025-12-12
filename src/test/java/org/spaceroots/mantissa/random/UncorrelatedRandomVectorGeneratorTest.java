package org.spaceroots.mantissa.random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UncorrelatedRandomVectorGeneratorTest {

  @Mock private NormalizedRandomGenerator generator;

  @Test
  void constructor_withMeanStdDevLengthMismatch_throwsIllegalArgumentException() {
    // Arrange
    double[] mean = new double[] {1.0, 2.0};
    double[] standardDeviation = new double[] {1.0};

    // Act
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> new UncorrelatedRandomVectorGenerator(mean, standardDeviation, generator));

    // Assert
    assertEquals("dimension mismatch", ex.getMessage());
  }

  @Test
  void constructor_clonesMeanAndStandardDeviationArrays() {
    // Arrange
    double[] mean = new double[] {1.0, 2.0};
    double[] standardDeviation = new double[] {0.5, 1.0};
    when(generator.nextDouble()).thenReturn(1.0, 1.0);
    UncorrelatedRandomVectorGenerator vectorGenerator =
        new UncorrelatedRandomVectorGenerator(mean, standardDeviation, generator);

    mean[0] = 100.0;
    standardDeviation[1] = 10.0;

    // Act
    double[] vector = vectorGenerator.nextVector();

    // Assert
    assertArrayEquals(new double[] {1.5, 3.0}, vector, 1.0e-12);
  }

  @Test
  void constructor_withDimensionInitializesNullMeanAndUnitStdDev() {
    // Arrange
    when(generator.nextDouble()).thenReturn(0.25, -0.75);
    UncorrelatedRandomVectorGenerator vectorGenerator =
        new UncorrelatedRandomVectorGenerator(2, generator);

    // Act
    double[] vector = vectorGenerator.nextVector();

    // Assert
    assertArrayEquals(new double[] {0.25, -0.75}, vector, 1.0e-12);
  }

  @Test
  void constructor_withNegativeDimension_throwsNegativeArraySizeException() {
    // Arrange
    int negativeDimension = -1;

    // Act + Assert
    assertThrows(
        NegativeArraySizeException.class,
        () -> new UncorrelatedRandomVectorGenerator(negativeDimension, generator));
  }

  @Test
  void nextVector_returnsNewArrayEachCall() {
    // Arrange
    when(generator.nextDouble()).thenReturn(0.0, 1.0, 2.0, 3.0);
    UncorrelatedRandomVectorGenerator vectorGenerator =
        new UncorrelatedRandomVectorGenerator(2, generator);

    // Act
    double[] first = vectorGenerator.nextVector();
    double[] second = vectorGenerator.nextVector();

    // Assert
    assertNotSame(first, second);
    assertArrayEquals(new double[] {0.0, 1.0}, first, 1.0e-12);
    assertArrayEquals(new double[] {2.0, 3.0}, second, 1.0e-12);
  }

  @Test
  void getGenerator_returnsUnderlyingGenerator() {
    // Arrange
    UncorrelatedRandomVectorGenerator vectorGenerator =
        new UncorrelatedRandomVectorGenerator(1, generator);

    // Act
    NormalizedRandomGenerator returned = vectorGenerator.getGenerator();

    // Assert
    assertEquals(generator, returned);
  }

  @Test
  void nextVector_withNullGenerator_throwsNullPointerException() {
    // Arrange
    UncorrelatedRandomVectorGenerator vectorGenerator =
        new UncorrelatedRandomVectorGenerator(1, null);

    // Act + Assert
    assertThrows(NullPointerException.class, vectorGenerator::nextVector);
  }
}
