package org.spaceroots.mantissa.fitting;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationProblem;
import org.spaceroots.mantissa.estimation.Estimator;
import org.spaceroots.mantissa.fitting.AbstractCurveFitter.FitMeasurement;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

@SuppressWarnings("java:S100")
class F2FP2IteratorTest {

  private static final double EPS = 1.0e-12;
  private static final DummyCurveFitter FITTER = new DummyCurveFitter();

  @Test
  void getDimension_whenCalled_returnsTwo() {
    // Arrange
    F2FP2Iterator iterator = new F2FP2Iterator(sampleThreePoints());

    // Act
    int dimension = iterator.getDimension();

    // Assert
    assertEquals(2, dimension);
  }

  @Test
  void nextSamplePoint_withThreeMeasurements_returnsSquaredValueAndDerivative()
      throws ExhaustedSampleException, FunctionException {
    // Arrange
    F2FP2Iterator iterator = new F2FP2Iterator(sampleThreePoints());

    // Act
    VectorialValuedPair point = iterator.nextSamplePoint();

    // Assert
    assertEquals(1.0, point.x, EPS);
    assertArrayEquals(new double[] {4.0, 4.0}, point.y, EPS);
    assertFalse(iterator.hasNext());
  }

  @Test
  void nextSamplePoint_withFourMeasurements_stepsThroughSequence()
      throws ExhaustedSampleException, FunctionException {
    // Arrange
    FitMeasurement[] measurements =
        new FitMeasurement[] {
          measurement(0.0, 1.0),
          measurement(1.0, 3.0),
          measurement(2.0, 5.0),
          measurement(4.0, 11.0)
        };
    F2FP2Iterator iterator = new F2FP2Iterator(measurements);

    // Act
    VectorialValuedPair first = iterator.nextSamplePoint();
    VectorialValuedPair second = iterator.nextSamplePoint();

    // Assert
    assertFalse(iterator.hasNext());
    assertEquals(1.0, first.x, EPS);
    assertArrayEquals(new double[] {9.0, 4.0}, first.y, EPS);
    assertEquals(2.0, second.x, EPS);
    assertArrayEquals(new double[] {25.0, 7.111111111111111}, second.y, EPS);
  }

  @Test
  void nextSamplePoint_whenExhausted_throwsExhaustedSampleException() {
    // Arrange
    F2FP2Iterator iterator = new F2FP2Iterator(sampleTwoPoints());

    // Act + Assert
    assertFalse(iterator.hasNext());
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
  }

  private static FitMeasurement[] sampleThreePoints() {
    return new FitMeasurement[] {
      measurement(0.0, 1.0), measurement(1.0, 2.0), measurement(2.0, 5.0)
    };
  }

  private static FitMeasurement[] sampleTwoPoints() {
    return new FitMeasurement[] {measurement(0.0, 1.0), measurement(1.0, 2.0)};
  }

  private static FitMeasurement measurement(double x, double y) {
    return FITTER.new FitMeasurement(1.0, x, y);
  }

  private static class DummyCurveFitter extends AbstractCurveFitter {
    DummyCurveFitter() {
      super(1, new NoOpEstimator());
    }

    @Override
    public double valueAt(double x) {
      return 0.0;
    }

    @Override
    public double partial(double x, EstimatedParameter p) {
      return 0.0;
    }
  }

  private static class NoOpEstimator implements Estimator {

    @Override
    public void estimate(EstimationProblem problem) {
      // no-op for tests
    }

    @Override
    public double getRMS(EstimationProblem problem) {
      return 0.0;
    }
  }
}
