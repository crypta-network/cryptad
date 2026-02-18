package org.spaceroots.mantissa.quadrature.vectorial;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class RiemannIntegratorTest {

  @Test
  void integrate_whenMultipleSamples_returnsCumulativeSumVector() throws Exception {
    // Arrange
    List<VectorialValuedPair> samples =
        Arrays.asList(pair(0.0, 1.0, 2.0), pair(0.5, 2.0, 4.0), pair(1.5, 4.0, 8.0));
    RiemannIntegrator integrator = new RiemannIntegrator();
    SampledFunctionIterator iterator = new StubIterator(samples);

    // Act
    double[] result = integrator.integrate(iterator);

    // Assert
    assertArrayEquals(new double[] {2.5, 5.0}, result, 1.0e-12);
  }

  @Test
  void integrate_whenIteratorHasSingleSample_returnsNull() throws Exception {
    // Arrange
    List<VectorialValuedPair> samples = List.of(pair(3.0, 7.0, -1.0));
    RiemannIntegrator integrator = new RiemannIntegrator();
    SampledFunctionIterator iterator = new StubIterator(samples);

    // Act
    double[] result = integrator.integrate(iterator);

    // Assert
    assertNull(result);
  }

  @Test
  void integrate_whenFunctionEvaluationFails_propagatesFunctionException() {
    // Arrange
    List<VectorialValuedPair> samples = Arrays.asList(pair(0.0, 1.0), pair(1.0, 2.0));
    RiemannIntegrator integrator = new RiemannIntegrator();
    SampledFunctionIterator iterator = new StubIterator(samples, 1);

    // Act & Assert
    assertThrows(FunctionException.class, () -> integrator.integrate(iterator));
  }

  @Test
  void integrate_whenIteratorEmpty_propagatesExhaustionFromConstructor() {
    // Arrange
    SampledFunctionIterator iterator = new StubIterator(List.of());
    RiemannIntegrator integrator = new RiemannIntegrator();

    // Act & Assert
    assertThrows(ExhaustedSampleException.class, () -> integrator.integrate(iterator));
  }

  private static VectorialValuedPair pair(double x, double... y) {
    return new VectorialValuedPair(x, y);
  }

  private static final class StubIterator implements SampledFunctionIterator {
    private final List<VectorialValuedPair> points;
    private final int failingIndex;
    private int index;

    StubIterator(List<VectorialValuedPair> points) {
      this(points, -1);
    }

    StubIterator(List<VectorialValuedPair> points, int failingIndex) {
      this.points = points;
      this.failingIndex = failingIndex;
    }

    @Override
    public int getDimension() {
      return points.isEmpty() ? 0 : points.getFirst().y.length;
    }

    @Override
    public boolean hasNext() {
      return index < points.size();
    }

    @Override
    public VectorialValuedPair nextSamplePoint()
        throws ExhaustedSampleException, FunctionException {

      if (index == failingIndex) {
        throw new FunctionException("forced failure");
      }

      if (index >= points.size()) {
        throw new ExhaustedSampleException(points.size());
      }

      return points.get(index++);
    }
  }
}
