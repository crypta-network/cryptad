package org.spaceroots.mantissa.quadrature.scalar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.ScalarValuedPair;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class EnhancedSimpsonIntegratorSamplerTest {

  private static final double EPS = 1.0e-12;

  @Test
  void nextSamplePoint_whenEquallySpacedQuadratic_matchesSimpsonIntegral()
      throws ExhaustedSampleException, FunctionException {
    List<ScalarValuedPair> points =
        Arrays.asList(
            new ScalarValuedPair(0.0, 0.0),
            new ScalarValuedPair(1.0, 1.0),
            new ScalarValuedPair(2.0, 4.0));
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new ListSampledFunctionIterator(points));

    ScalarValuedPair result = sampler.nextSamplePoint();

    assertEquals(2.0, result.getX(), EPS);
    assertEquals(8.0 / 3.0, result.getY(), EPS);
    assertFalse(sampler.hasNext());
  }

  @Test
  void nextSamplePoint_whenUnevenSpacing_usesEnhancedWeights()
      throws ExhaustedSampleException, FunctionException {
    List<ScalarValuedPair> points =
        Arrays.asList(
            new ScalarValuedPair(0.0, 0.0),
            new ScalarValuedPair(1.0, 1.0),
            new ScalarValuedPair(3.0, 3.0));
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new ListSampledFunctionIterator(points));

    ScalarValuedPair result = sampler.nextSamplePoint();

    assertEquals(3.0, result.getX(), EPS);
    assertEquals(4.5, result.getY(), EPS);
  }

  @Test
  void nextSamplePoint_whenFinalStepIncomplete_usesTrapezoidRule()
      throws ExhaustedSampleException, FunctionException {
    List<ScalarValuedPair> points =
        Arrays.asList(new ScalarValuedPair(0.0, 0.0), new ScalarValuedPair(2.0, 4.0));
    EnhancedSimpsonIntegratorSampler sampler =
        new EnhancedSimpsonIntegratorSampler(new ListSampledFunctionIterator(points));

    ScalarValuedPair result = sampler.nextSamplePoint();

    assertEquals(2.0, result.getX(), EPS);
    assertEquals(4.0, result.getY(), EPS);
    assertFalse(sampler.hasNext());
  }

  @Test
  void constructor_whenIteratorHasNoSamples_throwsExhaustedSampleException() {
    SampledFunctionIterator emptyIterator = new ListSampledFunctionIterator(List.of());

    assertThrows(
        ExhaustedSampleException.class, () -> new EnhancedSimpsonIntegratorSampler(emptyIterator));
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrowsFunctionException_propagates() throws Exception {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 0.0))
        .thenReturn(new ScalarValuedPair(1.0, 1.0))
        .thenThrow(new FunctionException("failure"));

    EnhancedSimpsonIntegratorSampler sampler = new EnhancedSimpsonIntegratorSampler(iterator);

    assertThrows(FunctionException.class, sampler::nextSamplePoint);
  }

  private static final class ListSampledFunctionIterator implements SampledFunctionIterator {

    private final List<ScalarValuedPair> points;
    private int index;

    ListSampledFunctionIterator(List<ScalarValuedPair> points) {
      this.points = points;
      this.index = 0;
    }

    @Override
    public boolean hasNext() {
      return index < points.size();
    }

    @Override
    public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException {
      if (!hasNext()) {
        throw new ExhaustedSampleException(points.size());
      }
      return points.get(index++);
    }
  }
}
