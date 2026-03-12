package org.spaceroots.mantissa.quadrature.scalar;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.ScalarValuedPair;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class RiemannIntegratorTest {

  private static final double EPS = 1.0e-12;

  @Test
  void integrate_whenUniformSamples_expectLeftRiemannSum()
      throws FunctionException, ExhaustedSampleException {
    List<ScalarValuedPair> samples =
        List.of(
            new ScalarValuedPair(0.0, 0.0),
            new ScalarValuedPair(0.25, 0.25),
            new ScalarValuedPair(0.5, 0.5),
            new ScalarValuedPair(0.75, 0.75),
            new ScalarValuedPair(1.0, 1.0));
    SampledFunctionIterator iterator = new StubSampledFunctionIterator(samples);
    RiemannIntegrator integrator = new RiemannIntegrator();

    double result = integrator.integrate(iterator);

    assertEquals(0.375, result, EPS);
  }

  @Test
  void integrate_whenIteratorThrowsFunctionException_propagatesException() {
    List<ScalarValuedPair> samples =
        List.of(new ScalarValuedPair(0.0, 0.0), new ScalarValuedPair(1.0, 1.0));
    SampledFunctionIterator iterator =
        new StubSampledFunctionIterator(samples, /* functionExceptionAt= */ 1);
    RiemannIntegrator integrator = new RiemannIntegrator();

    assertThrows(FunctionException.class, () -> integrator.integrate(iterator));
  }

  @Test
  void integrate_whenIteratorEmpty_throwsExhaustedSampleException() {
    SampledFunctionIterator iterator = new StubSampledFunctionIterator(List.of());
    RiemannIntegrator integrator = new RiemannIntegrator();

    assertThrows(ExhaustedSampleException.class, () -> integrator.integrate(iterator));
  }

  private static final class StubSampledFunctionIterator implements SampledFunctionIterator {

    private final List<ScalarValuedPair> samples;
    private final int functionExceptionAt;
    private int index;

    StubSampledFunctionIterator(List<ScalarValuedPair> samples) {
      this(samples, -1);
    }

    StubSampledFunctionIterator(List<ScalarValuedPair> samples, int functionExceptionAt) {
      this.samples = samples;
      this.functionExceptionAt = functionExceptionAt;
    }

    @Override
    public boolean hasNext() {
      return index < samples.size();
    }

    @Override
    public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
      if (index == functionExceptionAt) {
        throw new FunctionException("boom");
      }
      if (index >= samples.size()) {
        throw new ExhaustedSampleException(samples.size());
      }
      return samples.get(index++);
    }
  }
}
