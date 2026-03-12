package org.spaceroots.mantissa.quadrature.scalar;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.BasicSampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.SampledFunction;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.ScalarValuedPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TrapezoidIntegratorTest {

  private static final double EPS = 1.0e-12;

  @Test
  void integrate_whenSamplesDescribeLinearFunction_returnsExactIntegral()
      throws FunctionException, ExhaustedSampleException {
    double[] x = {0.0, 0.5, 1.0};
    double[] y = {0.0, 0.5, 1.0};
    SampledFunctionIterator iterator = iteratorFromArrays(x, y);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    double result = integrator.integrate(iterator);

    assertEquals(0.5, result, EPS);
  }

  @Test
  void integrate_whenOnlySingleSample_returnsZeroArea()
      throws FunctionException, ExhaustedSampleException {
    double[] x = {2.0};
    double[] y = {3.0};
    SampledFunctionIterator iterator = iteratorFromArrays(x, y);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    double result = integrator.integrate(iterator);

    assertEquals(0.0, result, EPS);
  }

  @Test
  void integrate_whenIteratorEmpty_throwsExhaustedSampleException() {
    SampledFunctionIterator iterator = iteratorFromArrays(new double[0], new double[0]);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    assertThrows(ExhaustedSampleException.class, () -> integrator.integrate(iterator));
  }

  @Test
  void integrate_whenUnderlyingIteratorFails_propagatesFunctionException()
      throws ExhaustedSampleException, FunctionException {
    ScalarValuedPair firstSample = new ScalarValuedPair(0.0, 0.0);
    when(iteratorMock.nextSamplePoint())
        .thenReturn(firstSample)
        .thenThrow(new FunctionException("boom"));
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    assertThrows(FunctionException.class, () -> integrator.integrate(iteratorMock));
  }

  private SampledFunctionIterator iteratorFromArrays(double[] x, double[] y) {
    return new BasicSampledFunctionIterator(new ArraySampledFunction(x, y));
  }

  private static final class ArraySampledFunction implements SampledFunction {

    private final double[] x;
    private final double[] y;

    ArraySampledFunction(double[] x, double[] y) {
      if (x.length != y.length) {
        throw new IllegalArgumentException(
            "Abscissa and ordinate arrays must have identical length.");
      }
      this.x = Arrays.copyOf(x, x.length);
      this.y = Arrays.copyOf(y, y.length);
    }

    @Override
    public int size() {
      return x.length;
    }

    @Override
    public ScalarValuedPair samplePointAt(int index) throws ArrayIndexOutOfBoundsException {
      if (index < 0 || index >= x.length) {
        throw new ArrayIndexOutOfBoundsException(index);
      }
      return new ScalarValuedPair(x[index], y[index]);
    }
  }

  @Mock private SampledFunctionIterator iteratorMock;
}
