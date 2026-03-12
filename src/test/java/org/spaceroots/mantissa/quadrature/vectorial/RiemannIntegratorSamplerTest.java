package org.spaceroots.mantissa.quadrature.vectorial;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class RiemannIntegratorSamplerTest {

  @Mock private SampledFunctionIterator iterator;

  @Test
  void nextSamplePoint_whenCalledTwice_accumulatesLeftRiemannSum() throws Exception {
    when(iterator.getDimension()).thenReturn(2);
    when(iterator.nextSamplePoint())
        .thenReturn(pair(0.0, 1.0, 2.0))
        .thenReturn(pair(0.5, 3.0, 4.0))
        .thenReturn(pair(1.0, 5.0, 6.0));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    VectorialValuedPair firstIntegral = sampler.nextSamplePoint();
    VectorialValuedPair secondIntegral = sampler.nextSamplePoint();

    assertEquals(0.5, firstIntegral.x);
    assertArrayEquals(new double[] {0.5, 1.0}, firstIntegral.y);
    assertEquals(1.0, secondIntegral.x);
    assertArrayEquals(new double[] {2.0, 3.0}, secondIntegral.y);
  }

  @Test
  void nextSamplePoint_whenReturnedArrayModified_internalSumUnaffected() throws Exception {
    when(iterator.getDimension()).thenReturn(2);
    when(iterator.nextSamplePoint())
        .thenReturn(pair(0.0, 1.0, 2.0))
        .thenReturn(pair(0.5, 3.0, 4.0))
        .thenReturn(pair(1.0, 5.0, 6.0));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    VectorialValuedPair firstIntegral = sampler.nextSamplePoint();
    firstIntegral.y[0] = 42.0;
    firstIntegral.y[1] = -100.0;

    VectorialValuedPair secondIntegral = sampler.nextSamplePoint();

    assertArrayEquals(new double[] {2.0, 3.0}, secondIntegral.y);
  }

  @Test
  void constructor_whenIteratorExhausted_throwsExhaustedSampleException() throws Exception {
    when(iterator.nextSamplePoint()).thenThrow(new ExhaustedSampleException(0));

    assertThrows(ExhaustedSampleException.class, () -> new RiemannIntegratorSampler(iterator));
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrows_propagatesFunctionException() throws Exception {
    when(iterator.getDimension()).thenReturn(1);
    when(iterator.nextSamplePoint())
        .thenReturn(pair(0.0, 1.0))
        .thenThrow(new FunctionException("failure"));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    assertThrows(FunctionException.class, sampler::nextSamplePoint);
  }

  @Test
  void delegation_methodsReflectIteratorValues() throws Exception {
    when(iterator.getDimension()).thenReturn(3);
    when(iterator.hasNext()).thenReturn(true, false);
    when(iterator.nextSamplePoint()).thenReturn(pair(0.0, 1.0, 2.0, 3.0));

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iterator);

    assertEquals(3, sampler.getDimension());
    assertTrue(sampler.hasNext());
    assertFalse(sampler.hasNext());
  }

  private VectorialValuedPair pair(double x, double... y) {
    return new VectorialValuedPair(x, y);
  }
}
