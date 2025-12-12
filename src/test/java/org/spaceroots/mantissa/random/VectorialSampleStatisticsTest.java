package org.spaceroots.mantissa.random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.linalg.SymetricalMatrix;

@SuppressWarnings("java:S100")
class VectorialSampleStatisticsTest {

  private static final double EPS = 1e-12;

  @Test
  void size_whenNew_expectZero() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act
    int size = stats.size();

    // Assert
    assertEquals(0, size);
  }

  @Test
  void getMean_whenEmpty_expectEmptyArray() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act
    double[] mean = stats.getMean();

    // Assert
    assertArrayEquals(new double[0], mean, EPS);
  }

  @Test
  void getCovarianceMatrix_whenLessThanTwoPoints_expectNull() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(new double[] {1.0, 2.0});

    // Act
    SymetricalMatrix covariance = stats.getCovarianceMatrix(null);

    // Assert
    assertNull(covariance);
  }

  @Test
  void getMin_whenEmpty_expectNullPointerException() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act / Assert
    assertThrows(NullPointerException.class, stats::getMin);
  }

  @Test
  void getMax_whenEmpty_expectNullPointerException() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act / Assert
    assertThrows(NullPointerException.class, stats::getMax);
  }

  @Test
  void getMinIndices_whenEmpty_expectNullPointerException() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act / Assert
    assertThrows(NullPointerException.class, stats::getMinIndices);
  }

  @Test
  void getMaxIndices_whenEmpty_expectNullPointerException() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();

    // Act / Assert
    assertThrows(NullPointerException.class, stats::getMaxIndices);
  }

  @Test
  void add_whenFirstPointAdded_initializesStatisticsAndDefensivelyCopies() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    double[] point = new double[] {1.0, -2.0, 3.0};

    // Act
    stats.add(point);
    point[0] = 100.0;
    point[1] = 100.0;
    point[2] = 100.0;

    // Assert
    assertEquals(1, stats.size());
    assertArrayEquals(new double[] {1.0, -2.0, 3.0}, stats.getMin(), EPS);
    assertArrayEquals(new double[] {1.0, -2.0, 3.0}, stats.getMax(), EPS);
    assertArrayEquals(new double[] {1.0, -2.0, 3.0}, stats.getMean(), EPS);
    assertArrayEquals(new int[] {0, 0, 0}, stats.getMinIndices());
    assertArrayEquals(new int[] {0, 0, 0}, stats.getMaxIndices());
  }

  @Test
  void add_whenSecondPointUpdatesMinMaxAndMean() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(new double[] {1.0, 2.0});

    // Act
    stats.add(new double[] {0.0, 5.0});

    // Assert
    assertEquals(2, stats.size());
    assertArrayEquals(new double[] {0.0, 2.0}, stats.getMin(), EPS);
    assertArrayEquals(new double[] {1.0, 5.0}, stats.getMax(), EPS);
    assertArrayEquals(new int[] {1, 0}, stats.getMinIndices());
    assertArrayEquals(new int[] {0, 1}, stats.getMaxIndices());
    assertArrayEquals(new double[] {0.5, 3.5}, stats.getMean(), EPS);
  }

  @Test
  void add_whenEqualValues_expectIndicesUnchanged() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(new double[] {1.0, 1.0});

    // Act
    stats.add(new double[] {1.0, 1.0});

    // Assert
    assertEquals(2, stats.size());
    assertArrayEquals(new int[] {0, 0}, stats.getMinIndices());
    assertArrayEquals(new int[] {0, 0}, stats.getMaxIndices());
    assertArrayEquals(new double[] {1.0, 1.0}, stats.getMean(), EPS);
  }

  @Test
  void addArray_whenMultiplePoints_expectSameAsSequentialAdds() {
    // Arrange
    double[][] points = new double[][] {{1.0, 0.0}, {2.0, 3.0}, {0.0, -1.0}};
    VectorialSampleStatistics byArray = new VectorialSampleStatistics();
    VectorialSampleStatistics sequential = new VectorialSampleStatistics();

    // Act
    byArray.add(points);
    for (double[] p : points) {
      sequential.add(p);
    }

    // Assert
    assertEquals(sequential.size(), byArray.size());
    assertArrayEquals(sequential.getMin(), byArray.getMin(), EPS);
    assertArrayEquals(sequential.getMax(), byArray.getMax(), EPS);
    assertArrayEquals(sequential.getMean(), byArray.getMean(), EPS);
    assertArrayEquals(sequential.getMinIndices(), byArray.getMinIndices());
    assertArrayEquals(sequential.getMaxIndices(), byArray.getMaxIndices());
  }

  @Test
  void addSample_whenThisEmpty_clonesStatisticsAndDoesNotShareState() {
    // Arrange
    VectorialSampleStatistics source = new VectorialSampleStatistics();
    source.add(new double[] {1.0, 2.0});
    source.add(new double[] {3.0, -1.0});

    VectorialSampleStatistics target = new VectorialSampleStatistics();

    // Act
    target.add(source);
    source.add(new double[] {-5.0, 100.0});

    // Assert
    assertEquals(2, target.size());
    assertArrayEquals(new double[] {1.0, -1.0}, target.getMin(), EPS);
    assertArrayEquals(new double[] {3.0, 2.0}, target.getMax(), EPS);
    assertArrayEquals(new double[] {2.0, 0.5}, target.getMean(), EPS);
  }

  @Test
  void addSample_whenBothNonEmpty_mergesWithBoundaryIndices() {
    // Arrange
    VectorialSampleStatistics first = new VectorialSampleStatistics();
    first.add(new double[] {5.0, 5.0});
    first.add(new double[] {6.0, 0.0});

    VectorialSampleStatistics second = new VectorialSampleStatistics();
    second.add(new double[] {4.0, 10.0});

    // Act
    first.add(second);

    // Assert
    assertEquals(3, first.size());
    assertArrayEquals(new double[] {4.0, 0.0}, first.getMin(), EPS);
    assertArrayEquals(new double[] {6.0, 10.0}, first.getMax(), EPS);
    assertArrayEquals(new int[] {2, 1}, first.getMinIndices());
    assertArrayEquals(new int[] {1, 2}, first.getMaxIndices());
    assertArrayEquals(new double[] {5.0, 5.0}, first.getMean(), EPS);
  }

  @Test
  void add_whenShorterVectorThanDimension_expectArrayIndexOutOfBoundsException() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(new double[] {1.0, 2.0});

    // Act / Assert
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> stats.add(new double[] {3.0}));
  }

  @Test
  void add_whenLongerVectorThanDimension_ignoresExtraComponents() {
    // Arrange
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(new double[] {1.0, 2.0});

    // Act
    stats.add(new double[] {3.0, 4.0, 1000.0});

    // Assert
    assertEquals(2, stats.size());
    assertArrayEquals(new double[] {1.0, 2.0}, stats.getMin(), EPS);
    assertArrayEquals(new double[] {3.0, 4.0}, stats.getMax(), EPS);
    assertArrayEquals(new double[] {2.0, 3.0}, stats.getMean(), EPS);
  }

  @Test
  void getCovarianceMatrix_whenValidSample_returnsExpectedAndReusesPlaceholder() {
    // Arrange
    double[][] points = new double[][] {{1.0, 2.0}, {3.0, 4.0}, {5.0, 0.0}};
    VectorialSampleStatistics stats = new VectorialSampleStatistics();
    stats.add(points);

    // Act
    SymetricalMatrix covariance = stats.getCovarianceMatrix(null);
    SymetricalMatrix placeholder = new SymetricalMatrix(2);
    SymetricalMatrix reused = stats.getCovarianceMatrix(placeholder);

    // Assert
    assertNotNull(covariance);
    assertSame(placeholder, reused);

    double[][] expected = computeSampleCovariance(points);
    assertEquals(expected[0][0], covariance.getElement(0, 0), EPS);
    assertEquals(expected[1][1], covariance.getElement(1, 1), EPS);
    assertEquals(expected[0][1], covariance.getElement(0, 1), EPS);
    assertEquals(expected[0][1], covariance.getElement(1, 0), EPS);

    assertEquals(expected[0][0], reused.getElement(0, 0), EPS);
    assertEquals(expected[1][1], reused.getElement(1, 1), EPS);
    assertEquals(expected[0][1], reused.getElement(0, 1), EPS);
  }

  private static double[][] computeSampleCovariance(double[][] points) {
    int n = points.length;
    int dim = points[0].length;

    double[] mean = new double[dim];
    for (double[] p : points) {
      for (int i = 0; i < dim; i++) {
        mean[i] += p[i];
      }
    }
    for (int i = 0; i < dim; i++) {
      mean[i] /= n;
    }

    double[][] cov = new double[dim][dim];
    for (double[] p : points) {
      for (int i = 0; i < dim; i++) {
        double di = p[i] - mean[i];
        for (int j = 0; j < dim; j++) {
          double dj = p[j] - mean[j];
          cov[i][j] += di * dj;
        }
      }
    }
    double denom = n - 1.0;
    for (int i = 0; i < dim; i++) {
      for (int j = 0; j < dim; j++) {
        cov[i][j] /= denom;
      }
    }

    return cov;
  }
}
