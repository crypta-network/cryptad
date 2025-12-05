package org.spaceroots.mantissa.fitting;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationException;
import org.spaceroots.mantissa.estimation.EstimationProblem;
import org.spaceroots.mantissa.estimation.Estimator;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PolynomialFitterTest {

  @Mock private Estimator estimator;

  @Test
  void constructor_whenDegreeGiven_createsSequentialCoefficients() {
    PolynomialFitter fitter = new PolynomialFitter(2, estimator);

    EstimatedParameter[] parameters = fitter.getAllParameters();

    assertEquals(3, parameters.length);
    assertEquals("a0", parameters[0].getName());
    assertEquals("a1", parameters[1].getName());
    assertEquals("a2", parameters[2].getName());
  }

  @Test
  void valueAt_whenCoefficientsSet_returnsPolynomialValue() {
    PolynomialFitter fitter = new PolynomialFitter(2, estimator);
    EstimatedParameter[] parameters = fitter.getAllParameters();
    parameters[0].setEstimate(1.0);
    parameters[1].setEstimate(2.0);
    parameters[2].setEstimate(3.0);

    double result = fitter.valueAt(2.0);

    assertEquals(17.0, result);
  }

  @Test
  void partial_whenPolynomialCoefficient_returnsPowerOfX() {
    PolynomialCoefficient coefficient = new PolynomialCoefficient(2);
    PolynomialFitter fitter =
        new PolynomialFitter(new PolynomialCoefficient[] {coefficient}, estimator);

    double result = fitter.partial(3.0, coefficient);

    assertEquals(9.0, result);
  }

  @Test
  void partial_whenNonPolynomialCoefficient_throwsIllegalArgumentException() {
    PolynomialFitter fitter = new PolynomialFitter(1, estimator);
    EstimatedParameter unrelated = new EstimatedParameter("p", 0.0);

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> fitter.partial(1.0, unrelated));

    assertEquals("internal error", ex.getMessage());
  }

  @Test
  void fit_whenEstimatorAdjustsValues_returnsAdjustedCoefficients() throws EstimationException {
    PolynomialFitter fitter = new PolynomialFitter(1, estimator);
    doAnswer(
            invocation -> {
              EstimationProblem problem = invocation.getArgument(0);
              for (EstimatedParameter parameter : problem.getAllParameters()) {
                parameter.setEstimate(parameter.getName().equals("a0") ? 1.5 : -0.5);
              }
              return null;
            })
        .when(estimator)
        .estimate(fitter);

    double[] fitted = fitter.fit();

    verify(estimator).estimate(fitter);
    assertArrayEquals(new double[] {1.5, -0.5}, fitted);
  }

  @Test
  void fit_whenEstimatorFails_propagatesException() throws EstimationException {
    PolynomialFitter fitter = new PolynomialFitter(0, estimator);
    EstimationException failure = new EstimationException("failure");
    doAnswer(
            invocation -> {
              throw failure;
            })
        .when(estimator)
        .estimate(fitter);

    EstimationException thrown = assertThrows(EstimationException.class, fitter::fit);

    assertEquals(failure, thrown);
  }
}
