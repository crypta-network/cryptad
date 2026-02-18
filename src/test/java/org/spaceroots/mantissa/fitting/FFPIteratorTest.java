package org.spaceroots.mantissa.fitting;

import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationProblem;
import org.spaceroots.mantissa.estimation.Estimator;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FFPIteratorTest {

  private static final double EPS = 1.0e-12;

  @Test
  void nextSamplePoint_whenThreeMeasurements_returnsValueAndCentralDerivative()
      throws FunctionException, ExhaustedSampleException {

    FitMeasurementFactory factory = new FitMeasurementFactory();
    AbstractCurveFitter.FitMeasurement[] measurements = {
      factory.create(0.0, 0.0), factory.create(1.0, 1.0), factory.create(2.0, 4.0)
    };

    FFPIterator iterator = new FFPIterator(measurements);

    assertTrue(iterator.hasNext());

    VectorialValuedPair pair = iterator.nextSamplePoint();

    assertFalse(iterator.hasNext());
    assertEquals(1.0, pair.x, EPS);
    assertEquals(1.0, pair.y[0], EPS);
    assertEquals(2.0, pair.y[1], EPS);
  }

  @Test
  void nextSamplePoint_multipleCalls_progressesAndUpdatesDerivative()
      throws FunctionException, ExhaustedSampleException {

    FitMeasurementFactory factory = new FitMeasurementFactory();
    AbstractCurveFitter.FitMeasurement[] measurements = {
      factory.create(0.0, 0.0),
      factory.create(1.0, 2.0),
      factory.create(2.0, 4.0),
      factory.create(3.0, 8.0)
    };

    FFPIterator iterator = new FFPIterator(measurements);

    VectorialValuedPair first = iterator.nextSamplePoint();
    assertTrue(iterator.hasNext());
    assertEquals(1.0, first.x, EPS);
    assertEquals(2.0, first.y[0], EPS);
    assertEquals(2.0, first.y[1], EPS);

    VectorialValuedPair second = iterator.nextSamplePoint();
    assertFalse(iterator.hasNext());
    assertEquals(2.0, second.x, EPS);
    assertEquals(4.0, second.y[0], EPS);
    assertEquals(3.0, second.y[1], EPS);
  }

  @Test
  void nextSamplePoint_whenNoSamplesLeft_throwsExhaustedSampleException()
      throws FunctionException, ExhaustedSampleException {

    FitMeasurementFactory factory = new FitMeasurementFactory();
    AbstractCurveFitter.FitMeasurement[] measurements = {
      factory.create(0.0, 0.0),
      factory.create(1.0, 1.0),
      factory.create(2.0, 2.0),
      factory.create(3.0, 3.0)
    };

    FFPIterator iterator = new FFPIterator(measurements);

    iterator.nextSamplePoint();
    iterator.nextSamplePoint();

    assertFalse(iterator.hasNext());
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
  }

  @Test
  void nextSamplePoint_whenInsufficientMeasurements_throwsImmediately() {
    FitMeasurementFactory factory = new FitMeasurementFactory();
    AbstractCurveFitter.FitMeasurement[] measurements = {
      factory.create(0.0, 0.0), factory.create(1.0, 1.0)
    };

    FFPIterator iterator = new FFPIterator(measurements);

    assertFalse(iterator.hasNext());
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
  }

  private static final class FitMeasurementFactory extends AbstractCurveFitter {

    FitMeasurementFactory() {
      super(0, new DummyEstimator());
    }

    AbstractCurveFitter.FitMeasurement create(double x, double y) {
      return new FitMeasurement(1.0, x, y);
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

  private static final class DummyEstimator implements Estimator {

    @Override
    public void estimate(EstimationProblem problem) {
      // No-op: test iterator does not rely on parameter estimation.
    }

    @Override
    public double getRMS(EstimationProblem problem) {
      return 0.0;
    }
  }
}
