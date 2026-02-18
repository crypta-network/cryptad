package org.spaceroots.mantissa.fitting;

import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationException;
import org.spaceroots.mantissa.estimation.EstimationProblem;
import org.spaceroots.mantissa.estimation.Estimator;
import org.spaceroots.mantissa.fitting.AbstractCurveFitter.FitMeasurement;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class HarmonicCoefficientsGuesserTest {

  private static final double AMPLITUDE = 2.5;
  private static final double OMEGA = 1.7;
  private static final double PHI = 0.4;
  private static final double STEP = 0.2;
  private static final DummyCurveFitter FITTER = new DummyCurveFitter();

  @Test
  void guess_whenGivenCleanCosine_returnsCloseCoefficients()
      throws ExhaustedSampleException,
          EstimationException,
          org.spaceroots.mantissa.functions.FunctionException {
    // Arrange
    FitMeasurement[] measurements = cosineSample();
    HarmonicCoefficientsGuesser guesser = new HarmonicCoefficientsGuesser(measurements);

    // Act
    guesser.guess();

    // Assert
    assertEquals(AMPLITUDE, guesser.getA(), 1.0e-6);
    assertEquals(OMEGA, guesser.getOmega(), 5.0e-2);
    double angleError =
        Math.atan2(Math.sin(PHI - guesser.getPhi()), Math.cos(PHI - guesser.getPhi()));
    assertEquals(0.0, angleError, 1.0e-1);
    assertTrue(rootMeanSquareError(measurements, guesser) < 1.0e-1);
  }

  @Test
  void guess_whenSampleHasTooFewPoints_throwsExhaustedSampleException() {
    // Arrange
    FitMeasurement[] measurements =
        new FitMeasurement[] {measurement(0.0, 0.0), measurement(1.0, 1.0)};
    HarmonicCoefficientsGuesser guesser = new HarmonicCoefficientsGuesser(measurements);

    // Act + Assert
    assertThrows(ExhaustedSampleException.class, guesser::guess);
  }

  @Test
  void guess_whenSquaredTermsAreNegative_throwsEstimationException() {
    // Arrange
    FitMeasurement[] measurements =
        new FitMeasurement[] {
          measurement(0.0, 0.0),
          measurement(1.0, 1.0),
          measurement(2.0, -2.0),
          measurement(3.0, 3.0),
          measurement(4.0, -4.0),
          measurement(5.0, 5.0)
        };
    HarmonicCoefficientsGuesser guesser = new HarmonicCoefficientsGuesser(measurements);

    // Act + Assert
    assertThrows(EstimationException.class, guesser::guess);
  }

  private static FitMeasurement[] cosineSample() {
    FitMeasurement[] sample = new FitMeasurement[25];
    for (int i = 0; i < sample.length; i++) {
      double x = i * STEP;
      double y = AMPLITUDE * Math.cos(OMEGA * x + PHI);
      sample[i] = measurement(x, y);
    }
    return sample;
  }

  private static FitMeasurement measurement(double x, double y) {
    return FITTER.new FitMeasurement(1.0, x, y);
  }

  private static double rootMeanSquareError(
      FitMeasurement[] measurements, HarmonicCoefficientsGuesser guesser) {
    double sum = 0.0;
    for (FitMeasurement measurement : measurements) {
      double predicted =
          guesser.getA() * Math.cos(guesser.getOmega() * measurement.x + guesser.getPhi());
      double error = predicted - measurement.getMeasuredValue();
      sum += error * error;
    }
    return Math.sqrt(sum / measurements.length);
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
