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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.scalar.ScalarValuedPair;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RiemannIntegratorSamplerTest {

  private static final double EPS = 1.0e-12;

  @Test
  void nextSamplePoint_whenCalledSequentially_accumulatesLeftRiemannSum()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 0.0))
        .thenReturn(new ScalarValuedPair(1.0, 1.0))
        .thenReturn(new ScalarValuedPair(2.0, 4.0));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    ScalarValuedPair first = sampler.nextSamplePoint();
    ScalarValuedPair second = sampler.nextSamplePoint();

    assertEquals(1.0, first.getX(), EPS);
    assertEquals(0.0, first.getY(), EPS);
    assertEquals(2.0, second.getX(), EPS);
    assertEquals(1.0, second.getY(), EPS);
  }

  @Test
  void nextSamplePoint_withNonUniformSpacing_accumulatesWeightedArea()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 2.0))
        .thenReturn(new ScalarValuedPair(0.5, 3.0))
        .thenReturn(new ScalarValuedPair(1.5, 1.0));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    ScalarValuedPair first = sampler.nextSamplePoint();
    ScalarValuedPair second = sampler.nextSamplePoint();

    assertEquals(0.5, first.getX(), EPS);
    assertEquals(1.0, first.getY(), EPS);
    assertEquals(1.5, second.getX(), EPS);
    assertEquals(4.0, second.getY(), EPS);
  }

  @Test
  void hasNext_whenUnderlyingIteratorChangesState_delegatesToIterator()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint()).thenReturn(new ScalarValuedPair(0.0, 1.0));
    when(iterator.hasNext()).thenReturn(true).thenReturn(false);

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    assertTrue(sampler.hasNext());
    assertFalse(sampler.hasNext());

    verify(iterator, times(1)).nextSamplePoint();
    verify(iterator, times(2)).hasNext();
    verifyNoMoreInteractions(iterator);
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrowsFunctionException_propagates()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 0.0))
        .thenThrow(new FunctionException("fail"));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    assertThrows(FunctionException.class, sampler::nextSamplePoint);
  }

  @Test
  void nextSamplePoint_whenSamplesExhausted_propagatesExhaustedSampleException()
      throws FunctionException, ExhaustedSampleException {
    SampledFunctionIterator iterator = mock(SampledFunctionIterator.class);
    when(iterator.nextSamplePoint())
        .thenReturn(new ScalarValuedPair(0.0, 1.0))
        .thenThrow(new ExhaustedSampleException(1));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    assertThrows(ExhaustedSampleException.class, sampler::nextSamplePoint);
  }
}
