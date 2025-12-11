package org.spaceroots.mantissa.quadrature.vectorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class TrapezoidIntegratorTest {

  private static final double EPS = 1e-12;

  @Test
  void integrate_withUniformSamples_returnsVectorIntegral() throws Exception {
    // Arrange
    VectorialValuedPair[] samples =
        new VectorialValuedPair[] {
          new VectorialValuedPair(0.0, new double[] {0.0, 0.0}),
          new VectorialValuedPair(1.0, new double[] {1.0, 2.0}),
          new VectorialValuedPair(2.0, new double[] {2.0, 4.0})
        };
    SampledFunctionIterator iterator = new StubIterator(samples);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    // Act
    double[] result = integrator.integrate(iterator);

    // Assert
    assertArrayEquals(new double[] {2.0, 4.0}, result, EPS);
  }

  @Test
  void integrate_whenFunctionExceptionFromIterator_propagates() {
    // Arrange
    VectorialValuedPair[] samples =
        new VectorialValuedPair[] {
          new VectorialValuedPair(0.0, new double[] {0.0}),
          new VectorialValuedPair(1.0, new double[] {1.0})
        };
    SampledFunctionIterator iterator = new StubIterator(samples, 1, true);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    // Act + Assert
    assertThrows(FunctionException.class, () -> integrator.integrate(iterator));
  }

  @Test
  void integrate_whenIteratorHasNoSamples_throwsExhaustedSampleException() {
    // Arrange
    SampledFunctionIterator iterator = new StubIterator(new VectorialValuedPair[0]);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    // Act + Assert
    assertThrows(ExhaustedSampleException.class, () -> integrator.integrate(iterator));
  }

  @Test
  void integrate_whenOnlyOneSample_returnsNull() throws Exception {
    // Arrange
    VectorialValuedPair[] samples =
        new VectorialValuedPair[] {new VectorialValuedPair(0.0, new double[] {1.0, 2.0})};
    SampledFunctionIterator iterator = new StubIterator(samples);
    TrapezoidIntegrator integrator = new TrapezoidIntegrator();

    // Act
    double[] result = integrator.integrate(iterator);

    // Assert
    assertNull(result);
  }

  /**
   * Minimal deterministic iterator for tests.
   *
   * <p>{@code failAtIndex} indicates the zero-based invocation of {@link #nextSamplePoint()} that
   * will throw a {@link FunctionException} when {@code failWithFunctionException} is true.
   */
  private static final class StubIterator implements SampledFunctionIterator {

    private final VectorialValuedPair[] samples;
    private final int failAtIndex;
    private final boolean failWithFunctionException;
    private int index;

    StubIterator(VectorialValuedPair[] samples) {
      this(samples, -1, false);
    }

    StubIterator(
        VectorialValuedPair[] samples, int failAtIndex, boolean failWithFunctionException) {
      this.samples = samples;
      this.failAtIndex = failAtIndex;
      this.failWithFunctionException = failWithFunctionException;
      this.index = 0;
    }

    @Override
    public int getDimension() {
      return samples.length == 0 ? 0 : samples[0].y.length;
    }

    @Override
    public boolean hasNext() {
      return index < samples.length;
    }

    @Override
    public VectorialValuedPair nextSamplePoint()
        throws ExhaustedSampleException, FunctionException {

      if (failWithFunctionException && index == failAtIndex) {
        throw new FunctionException("forced failure");
      }

      if (!hasNext()) {
        throw new ExhaustedSampleException(samples.length);
      }

      return samples[index++];
    }
  }
}
