package org.spaceroots.mantissa.quadrature.vectorial;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.ComputableFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GaussLegendreIntegratorTest {

  private static final double EPS = 1.0e-12;

  @ParameterizedTest
  @CsvSource({"1,2", "2,2", "3,3", "4,4", "5,5", "8,5"})
  void getEvaluationsPerStep_whenDifferentMinPoints_returnsExpectedCount(
      int minPoints, int expectedEvaluations) {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(minPoints, 1.0);

    int evaluationsPerStep = integrator.getEvaluationsPerStep();

    assertEquals(expectedEvaluations, evaluationsPerStep);
  }

  @Test
  void integrate_whenUsingTwoPointRule_integratesCubicExactly() throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(2, 4.0);
    ComputableFunction cubicAndSquare = new PolynomialVectorFunction(3, 2);

    double[] result = integrator.integrate(cubicAndSquare, -1.0, 1.0);

    assertArrayEquals(new double[] {0.0, 2.0 / 3.0}, result, EPS);
  }

  @Test
  void integrate_whenUsingFivePointRule_integratesDegreeEightExactly() throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(6, 1.0);
    ComputableFunction degreeEight = new PolynomialVectorFunction(8);

    double[] result = integrator.integrate(degreeEight, 0.0, 1.0);

    assertArrayEquals(new double[] {1.0 / 9.0}, result, EPS);
  }

  @Test
  void integrate_whenBoundsProvidedInReverse_returnsNegatedResult() throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(3, 0.7);
    ComputableFunction affine =
        new ComputableFunction() {
          @Override
          public int getDimension() {
            return 1;
          }

          @Override
          public double[] valueAt(double x) {
            return new double[] {2.0 * x + 1.0};
          }
        };

    double[] forward = integrator.integrate(affine, -1.0, 2.0);
    double[] reversed = integrator.integrate(affine, 2.0, -1.0);

    assertEquals(6.0, forward[0], EPS);
    assertArrayEquals(new double[] {-forward[0]}, reversed, EPS);
  }

  @Test
  void integrate_whenStepRoundedStillIntegratesConstantExactly() throws FunctionException {
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(4, 0.3);
    ComputableFunction constant = new ConstantVectorFunction(3.0, 1);

    double[] result = integrator.integrate(constant, 0.0, 1.0);

    assertArrayEquals(new double[] {3.0}, result, EPS);
  }

  @Test
  void integrate_whenFunctionThrows_propagatesFunctionException() throws FunctionException {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.getDimension()).thenReturn(1);
    FunctionException expected = new FunctionException("boom");
    when(function.valueAt(anyDouble())).thenThrow(expected);
    GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(2, 4.0);

    FunctionException thrown =
        assertThrows(FunctionException.class, () -> integrator.integrate(function, 0.0, 1.0));

    assertSame(expected, thrown);
  }

  private static final class PolynomialVectorFunction implements ComputableFunction {
    private final int[] powers;

    PolynomialVectorFunction(int... powers) {
      this.powers = powers;
    }

    @Override
    public int getDimension() {
      return powers.length;
    }

    @Override
    public double[] valueAt(double x) {
      double[] values = new double[powers.length];
      for (int i = 0; i < powers.length; i++) {
        values[i] = Math.pow(x, powers[i]);
      }
      return values;
    }
  }

  private static final class ConstantVectorFunction implements ComputableFunction {
    private final double value;
    private final int dimension;

    ConstantVectorFunction(double value, int dimension) {
      this.value = value;
      this.dimension = dimension;
    }

    @Override
    public int getDimension() {
      return dimension;
    }

    @Override
    public double[] valueAt(double x) {
      double[] values = new double[dimension];
      for (int i = 0; i < dimension; i++) {
        values[i] = value;
      }
      return values;
    }
  }
}
