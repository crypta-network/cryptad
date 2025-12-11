package org.spaceroots.mantissa.quadrature.vectorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EnhancedSimpsonIntegratorTest {

  @Test
  void integrate_whenSamplesUnevenQuadratic_returnsExactIntegral()
      throws ExhaustedSampleException, FunctionException {
    List<VectorialValuedPair> points =
        Arrays.asList(
            pair(0.0, new double[] {0.0, 0.0}),
            pair(1.0, new double[] {1.0, 2.0}),
            pair(3.0, new double[] {9.0, 6.0}));

    double[] result = new EnhancedSimpsonIntegrator().integrate(new ListIterator(points));

    assertArrayEquals(new double[] {9.0, 9.0}, result, 1.0e-12);
  }

  @Test
  void integrate_whenOnlyTwoSamples_usesTrapezoidForFinalStep()
      throws ExhaustedSampleException, FunctionException {
    List<VectorialValuedPair> points =
        Arrays.asList(pair(0.0, new double[] {0.0, 0.0}), pair(2.0, new double[] {2.0, 4.0}));

    double[] result = new EnhancedSimpsonIntegrator().integrate(new ListIterator(points));

    assertArrayEquals(new double[] {2.0, 4.0}, result, 1.0e-12);
  }

  @Test
  void integrate_whenOnlyOneSample_returnsNull()
      throws ExhaustedSampleException, FunctionException {
    List<VectorialValuedPair> points = List.of(pair(0.0, new double[] {1.0, 2.0}));

    double[] result = new EnhancedSimpsonIntegrator().integrate(new ListIterator(points));

    assertNull(result);
  }

  @Test
  void integrate_whenFunctionThrows_propagatesException()
      throws ExhaustedSampleException, FunctionException {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    when(iter.nextSamplePoint()).thenThrow(new FunctionException("boom"));

    assertThrows(FunctionException.class, () -> new EnhancedSimpsonIntegrator().integrate(iter));
  }

  private static VectorialValuedPair pair(double x, double[] y) {
    return new VectorialValuedPair(x, y);
  }

  private static final class ListIterator implements SampledFunctionIterator {

    private final List<VectorialValuedPair> points;
    private int index;

    ListIterator(List<VectorialValuedPair> points) {
      this.points = points;
    }

    @Override
    public int getDimension() {
      return points.getFirst().y.length;
    }

    @Override
    public boolean hasNext() {
      return index < points.size();
    }

    @Override
    public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException {
      if (index >= points.size()) {
        throw new ExhaustedSampleException(points.size());
      }
      return points.get(index++);
    }
  }
}
