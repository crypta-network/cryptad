package org.spaceroots.mantissa.quadrature.scalar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

@SuppressWarnings("java:S100")
class GaussLegendreIntegratorTest {

  @ParameterizedTest
  @CsvSource({
    "2, 2", // minPoints <= 2
    "3, 3", // minPoints in (2, 3]
    "4, 4", // minPoints in (3, 4]
    "5, 5", // minPoints in (4, 5]
    "10, 5" // minPoints > 4 falls back to 5-point rule
  })
  void getEvaluationsPerStep_whenMinPointsBucketed_expectCorrectCount(
      int minPoints, int expectedCount) {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(minPoints, 0.1);

    assertEquals(expectedCount, integrator.getEvaluationsPerStep());
  }

  @Test
  void integrate_whenBoundsReversed_expectCorrectIntegralAndEvaluationCount()
      throws FunctionException {
    double rawStep = 1.0;
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(3, rawStep);
    AtomicInteger evaluations = new AtomicInteger();
    ComputableFunction constant =
        x -> {
          evaluations.incrementAndGet();
          return 1.5;
        };

    double result = integrator.integrate(constant, 2.0, -1.0);

    double intervalLength = 3.0;
    long expectedSteps = Math.round(0.5 + intervalLength / rawStep);
    assertEquals(1.5 * intervalLength, result, 1.0e-12);
    assertEquals(expectedSteps * integrator.getEvaluationsPerStep(), evaluations.get());
  }

  @Test
  void integrate_whenPolynomialWithinExactnessDegree_expectExactValue() throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(3, 0.45);
    ComputableFunction polynomial = x -> x * x * x * x + 2 * x * x + 1;

    double result = integrator.integrate(polynomial, 0.0, 2.0);

    double expected = 206.0 / 15.0;
    assertEquals(expected, result, 1.0e-12);
  }

  @Test
  void integrate_whenFunctionThrows_propagatesFunctionException() {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(4, 0.3);
    ComputableFunction failing =
        x -> {
          throw new FunctionException("failure");
        };

    assertThrows(FunctionException.class, () -> integrator.integrate(failing, 0.0, 1.0));
  }

  @Test
  void integrate_whenZeroLengthInterval_returnsZeroAndEvaluatesOncePerRoot()
      throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(5, 0.2);
    AtomicInteger evaluations = new AtomicInteger();
    ComputableFunction square =
        x -> {
          evaluations.incrementAndGet();
          return x * x;
        };

    double result = integrator.integrate(square, 1.0, 1.0);

    assertEquals(0.0, result, 1.0e-12);
    assertEquals(integrator.getEvaluationsPerStep(), evaluations.get());
  }

  @Test
  void integrate_whenFunctionUndefinedAtBounds_doesNotSampleEndpoints() throws FunctionException {
    double lower = 0.0;
    double upper = 1.0;
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(2, 0.3);
    ComputableFunction safeConstant =
        x -> {
          if (Math.abs(x - lower) < 1.0e-14 || Math.abs(x - upper) < 1.0e-14) {
            throw new FunctionException("endpoint");
          }
          return 2.0;
        };

    double result = integrator.integrate(safeConstant, lower, upper);

    assertEquals(2.0 * (upper - lower), result, 1.0e-12);
  }
}
