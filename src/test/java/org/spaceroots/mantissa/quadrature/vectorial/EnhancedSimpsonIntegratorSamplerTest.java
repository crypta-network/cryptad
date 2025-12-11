package org.spaceroots.mantissa.quadrature.vectorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EnhancedSimpsonIntegratorSamplerTest {

  private static final double EPS = 1.0e-12;

  @Mock private SampledFunctionIterator delegate;

  @Test
  void nextSamplePoint_uniformSpacing_linearFunction_returnsExactIntegral()
      throws ExhaustedSampleException, FunctionException {
    // Arrange
    double[] xs = {0.0, 1.0, 2.0};
    double[][] ys = {
      {0.0}, // f(0) = 0
      {1.0}, // f(1) = 1
      {2.0} // f(2) = 2
    };
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new FixedIterator(xs, ys));

    // Act
    VectorialValuedPair integrated = sampler.nextSamplePoint();

    // Assert
    assertEquals(2.0, integrated.x, EPS);
    assertArrayEquals(new double[] {2.0}, integrated.y, EPS);
  }

  @Test
  void nextSamplePoint_nonUniformSpacing_constantFunction_handlesUnequalSteps()
      throws ExhaustedSampleException, FunctionException {
    // Arrange: constant function y = 1 with non-uniform spacing 0, 1, 3
    double[] xs = {0.0, 1.0, 3.0};
    double[][] ys = {{1.0}, {1.0}, {1.0}};
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new FixedIterator(xs, ys));

    // Act
    VectorialValuedPair integrated = sampler.nextSamplePoint();

    // Assert: exact integral of constant function on [0,3] is 3
    assertEquals(3.0, integrated.x, EPS);
    assertArrayEquals(new double[] {3.0}, integrated.y, EPS);
  }

  @Test
  void nextSamplePoint_incompleteFinalStep_usesTrapezoidRule()
      throws ExhaustedSampleException, FunctionException {
    // Arrange: only two points available so catch block executes
    double[] xs = {0.0, 1.0};
    double[][] ys = {{1.0}, {3.0}};
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new FixedIterator(xs, ys));

    // Act
    VectorialValuedPair integrated = sampler.nextSamplePoint();

    // Assert: trapezoid area = 0.5*(1)*(1+3) = 2
    assertEquals(1.0, integrated.x, EPS);
    assertArrayEquals(new double[] {2.0}, integrated.y, EPS);
  }

  @Test
  void nextSamplePoint_calledTwice_accumulatesAcrossSegments()
      throws ExhaustedSampleException, FunctionException {
    // Arrange: five equally spaced points for f(x) = x on [0,4]; exact integral is 8
    double[] xs = {0.0, 1.0, 2.0, 3.0, 4.0};
    double[][] ys = {{0.0}, {1.0}, {2.0}, {3.0}, {4.0}};
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new FixedIterator(xs, ys));

    // Act
    sampler.nextSamplePoint(); // integrates over [0,2]
    VectorialValuedPair integrated = sampler.nextSamplePoint(); // integrates over [2,4]

    // Assert: cumulative integral equals exact value 8 at x = 4
    assertEquals(4.0, integrated.x, EPS);
    assertArrayEquals(new double[] {8.0}, integrated.y, EPS);
  }

  @Test
  void hasNext_delegatesToUnderlyingIterator() throws ExhaustedSampleException, FunctionException {
    // Arrange
    VectorialValuedPair first = new VectorialValuedPair(0.0, new double[] {0.0});
    org.mockito.Mockito.when(delegate.nextSamplePoint()).thenReturn(first);
    org.mockito.Mockito.when(delegate.getDimension()).thenReturn(1);
    org.mockito.Mockito.when(delegate.hasNext()).thenReturn(true, false);
    EnhancedSimpsonIntegratorSampler sampler = new EnhancedSimpsonIntegratorSampler(delegate);

    // Act & Assert
    assertTrue(sampler.hasNext());
    assertFalse(sampler.hasNext());
    org.mockito.Mockito.verify(delegate, org.mockito.Mockito.times(2)).hasNext();
  }

  /** Simple deterministic iterator backed by fixed arrays for test purposes. */
  private static final class FixedIterator implements SampledFunctionIterator {

    private final double[] xs;
    private final double[][] ys;
    private int index;

    FixedIterator(double[] xs, double[][] ys) {
      this.xs = xs;
      this.ys = ys;
      this.index = 0;
    }

    @Override
    public int getDimension() {
      return ys[0].length;
    }

    @Override
    public boolean hasNext() {
      return index < xs.length;
    }

    @Override
    public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException {
      if (!hasNext()) {
        throw new ExhaustedSampleException(xs.length);
      }
      int current = index++;
      return new VectorialValuedPair(xs[current], ys[current]);
    }
  }
}
