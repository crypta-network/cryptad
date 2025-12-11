package org.spaceroots.mantissa.quadrature.scalar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

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
class TrapezoidIntegratorSamplerTest {

  private static final double EPS = 1.0e-12;

  @Test
  void nextSamplePoint_withLinearFunction_matchesExactIntegral()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator =
        new ListSampledFunctionIterator(
            List.of(
                new ScalarValuedPair(0.0, 0.0),
                new ScalarValuedPair(1.0, 1.0),
                new ScalarValuedPair(2.0, 2.0)));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iterator);

    ScalarValuedPair first = sampler.nextSamplePoint();
    ScalarValuedPair second = sampler.nextSamplePoint();

    assertEquals(1.0, first.getX(), EPS);
    assertEquals(0.5, first.getY(), EPS);
    assertEquals(2.0, second.getX(), EPS);
    assertEquals(2.0, second.getY(), EPS);
  }

  @Test
  void nextSamplePoint_withNonUniformSpacing_accumulatesTrapezoidArea()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator =
        new ListSampledFunctionIterator(
            List.of(
                new ScalarValuedPair(0.0, 2.0),
                new ScalarValuedPair(0.5, 4.0),
                new ScalarValuedPair(2.0, 1.0)));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iterator);

    ScalarValuedPair first = sampler.nextSamplePoint();
    ScalarValuedPair second = sampler.nextSamplePoint();

    assertEquals(0.5, first.getX(), EPS);
    assertEquals(1.5, first.getY(), EPS);
    assertEquals(2.0, second.getX(), EPS);
    assertEquals(5.25, second.getY(), EPS);
  }

  @Test
  void hasNext_whenUnderlyingIteratorChangesState_delegatesToIterator()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint()).thenReturn(new ScalarValuedPair(0.0, 1.0));
    when(iterator.hasNext()).thenReturn(true).thenReturn(false);

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iterator);

    assertTrue(sampler.hasNext());
    assertFalse(sampler.hasNext());

    verify(iterator, times(1)).nextSamplePoint();
    verify(iterator, times(2)).hasNext();
    verifyNoMoreInteractions(iterator);
  }

  @Test
  void constructor_whenIteratorHasNoSamples_throwsExhaustedSampleException() {
    SampledFunctionIterator emptyIterator = new ListSampledFunctionIterator(List.of());

    assertThrows(
        ExhaustedSampleException.class, () -> new TrapezoidIntegratorSampler(emptyIterator));
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrowsFunctionException_propagates()
      throws ExhaustedSampleException, FunctionException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 0.0))
        .thenThrow(new FunctionException("failure"));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iterator);

    assertThrows(FunctionException.class, sampler::nextSamplePoint);
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrowsExhaustedSampleException_propagates()
      throws ExhaustedSampleException, FunctionException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 0.0))
        .thenThrow(new ExhaustedSampleException(1));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iterator);

    assertThrows(ExhaustedSampleException.class, sampler::nextSamplePoint);
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
