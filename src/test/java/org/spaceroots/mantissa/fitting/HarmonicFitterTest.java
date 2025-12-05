package org.spaceroots.mantissa.fitting;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationException;
import org.spaceroots.mantissa.estimation.Estimator;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HarmonicFitterTest {

  @Mock private Estimator estimator;

  @Test
  void constructor_withEstimator_initializesDefaultCoefficients() {
    HarmonicFitter fitter = new HarmonicFitter(estimator);

    assertEquals(2.0 * Math.PI, fitter.getAmplitude(), 1.0e-12);
    assertEquals(0.0, fitter.getPulsation(), 1.0e-12);
    assertEquals(0.0, fitter.getPhase(), 1.0e-12);
  }

  @Test
  void fit_withTooFewMeasurements_throwsEstimationException() throws EstimationException {
    HarmonicFitter fitter = new HarmonicFitter(estimator);
    fitter.addWeightedPair(1.0, 0.0, 1.0);
    fitter.addWeightedPair(1.0, 1.0, 0.5);
    fitter.addWeightedPair(1.0, 2.0, -0.5);

    assertThrows(EstimationException.class, fitter::fit);
    verify(estimator, never()).estimate(fitter);
  }

  @Test
  void fit_whenFirstGuessNeeded_sortsMeasurementsAndInvokesEstimator() throws EstimationException {
    TrackingHarmonicFitter fitter = new TrackingHarmonicFitter(estimator);
    // Unsorted sample of f(t) = 1.5 * cos(2 * t + 0.3)
    double[] times = {1.0, 0.0, 1.6, 0.4, 0.8, 1.2, 0.2, 1.4, 0.6};
    for (double t : times) {
      fitter.addWeightedPair(1.0, t, 1.5 * Math.cos(2.0 * t + 0.3));
    }
    doNothing().when(estimator).estimate(fitter);

    double[] result = fitter.fit();

    assertTrue(fitter.sortCalled);
    assertFalse(Double.isNaN(fitter.getAmplitude()));
    assertFalse(Double.isNaN(fitter.getPulsation()));
    assertFalse(Double.isNaN(fitter.getPhase()));
    assertEquals(fitter.getAmplitude(), result[0], 1.0e-12);
    assertEquals(fitter.getPulsation(), result[1], 1.0e-12);
    assertEquals(fitter.getPhase(), result[2], 1.0e-12);
    verify(estimator).estimate(fitter);

    double[] sortedXs = new double[] {0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 1.2, 1.4, 1.6};
    double[] actualXs = new double[fitter.getMeasurements().length];
    for (int i = 0; i < actualXs.length; i++) {
      actualXs[i] = ((AbstractCurveFitter.FitMeasurement) fitter.getMeasurements()[i]).x;
    }
    assertArrayEquals(sortedXs, actualXs, 1.0e-12);
  }

  @Test
  void fit_whenFirstGuessNotNeeded_usesProvidedCoefficients() throws EstimationException {
    EstimatedParameter[] coefficients = new EstimatedParameter[3];
    coefficients[0] = new EstimatedParameter("a", 5.0);
    coefficients[1] = new EstimatedParameter("omega", 3.0);
    coefficients[2] = new EstimatedParameter("phi", 1.0);
    HarmonicFitter fitter = new HarmonicFitter(coefficients, estimator);
    fitter.addWeightedPair(1.0, 1.0, 0.0);
    doNothing().when(estimator).estimate(fitter);

    double[] result = fitter.fit();

    assertArrayEquals(new double[] {5.0, 3.0, 1.0}, result, 1.0e-12);
    verify(estimator).estimate(fitter);
  }

  @Test
  void valueAt_withCurrentEstimates_returnsExpectedValue() {
    EstimatedParameter[] coefficients = new EstimatedParameter[3];
    coefficients[0] = new EstimatedParameter("a", 3.0);
    coefficients[1] = new EstimatedParameter("omega", 2.0);
    coefficients[2] = new EstimatedParameter("phi", 0.5);
    HarmonicFitter fitter = new HarmonicFitter(coefficients, estimator);

    double result = fitter.valueAt(0.75);

    assertEquals(3.0 * Math.cos(2.0 * 0.75 + 0.5), result, 1.0e-12);
  }

  @Test
  void partial_withAmplitudeParameter_returnsCosineDerivative() {
    HarmonicFitter fitter = new HarmonicFitter(estimator);
    EstimatedParameter amplitude = fitter.getAllParameters()[0];

    double derivative = fitter.partial(0.3, amplitude);

    assertEquals(Math.cos(fitter.getPulsation() * 0.3 + fitter.getPhase()), derivative, 1.0e-12);
  }

  @Test
  void partial_withPulsationParameter_returnsPulsationDerivative() {
    HarmonicFitter fitter = new HarmonicFitter(estimator);
    EstimatedParameter pulsation = fitter.getAllParameters()[1];
    fitter.getAllParameters()[0].setEstimate(4.0);
    fitter.getAllParameters()[1].setEstimate(1.5);
    fitter.getAllParameters()[2].setEstimate(0.25);

    double derivative = fitter.partial(0.5, pulsation);

    double expected =
        -fitter.getAmplitude() * 0.5 * Math.sin(fitter.getPulsation() * 0.5 + fitter.getPhase());
    assertEquals(expected, derivative, 1.0e-12);
  }

  @Test
  void partial_withPhaseParameter_returnsPhaseDerivative() {
    HarmonicFitter fitter = new HarmonicFitter(estimator);
    EstimatedParameter phase = fitter.getAllParameters()[2];
    fitter.getAllParameters()[0].setEstimate(2.5);
    fitter.getAllParameters()[1].setEstimate(1.2);
    fitter.getAllParameters()[2].setEstimate(0.3);

    double derivative = fitter.partial(1.1, phase);

    double expected =
        -fitter.getAmplitude() * Math.sin(fitter.getPulsation() * 1.1 + fitter.getPhase());
    assertEquals(expected, derivative, 1.0e-12);
  }

  private static final class TrackingHarmonicFitter extends HarmonicFitter {

    private boolean sortCalled;

    private TrackingHarmonicFitter(Estimator estimator) {
      super(estimator);
    }

    @Override
    protected void sortMeasurements() {
      sortCalled = true;
      super.sortMeasurements();
    }
  }
}
