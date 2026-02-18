package org.spaceroots.mantissa.quadrature.scalar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.BasicSampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.SampledFunction;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.ScalarValuedPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class EnhancedSimpsonIntegratorTest {

  private static final double EPS = 1.0e-12;

  @Test
  void integrate_withRegularSpacingExactQuadratic_expectSimpsonResult() throws Exception {
    double[] x = {0.0, 1.0, 2.0};
    double[] y = {0.0, 1.0, 4.0};
    SampledFunctionIterator iterator = iteratorFromArrays(x, y);

    double result = new EnhancedSimpsonIntegrator().integrate(iterator);

    assertEquals(8.0 / 3.0, result, EPS);
  }

  @Test
  void integrate_withNonUniformLinear_expectExactIntegral() throws Exception {
    double[] x = {0.0, 1.0, 1.5};
    double[] y = {0.0, 1.0, 1.5};
    SampledFunctionIterator iterator = iteratorFromArrays(x, y);

    double result = new EnhancedSimpsonIntegrator().integrate(iterator);

    assertEquals(1.125, result, EPS);
  }

  @Test
  void integrate_withTwoPointSample_expectTrapezoidFallback() throws Exception {
    double[] x = {0.0, 2.0};
    double[] y = {3.0, 3.0};
    SampledFunctionIterator iterator = iteratorFromArrays(x, y);

    double result = new EnhancedSimpsonIntegrator().integrate(iterator);

    assertEquals(6.0, result, EPS);
  }

  @Test
  void integrate_whenFunctionExceptionThrown_propagates() throws Exception {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint()).thenThrow(new FunctionException("boom"));

    assertThrows(
        FunctionException.class, () -> new EnhancedSimpsonIntegrator().integrate(iterator));
  }

  private static SampledFunctionIterator iteratorFromArrays(double[] x, double[] y) {
    if (x.length != y.length) {
      throw new IllegalArgumentException("x and y must have the same length");
    }
    SampledFunction function =
        new SampledFunction() {
          @Override
          public int size() {
            return x.length;
          }

          @Override
          public ScalarValuedPair samplePointAt(int index) {
            if (index < 0 || index >= x.length) {
              throw new ArrayIndexOutOfBoundsException(index);
            }
            return new ScalarValuedPair(x[index], y[index]);
          }
        };

    return new BasicSampledFunctionIterator(function);
  }
}
