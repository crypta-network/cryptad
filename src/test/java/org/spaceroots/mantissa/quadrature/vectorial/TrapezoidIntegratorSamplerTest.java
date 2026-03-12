package org.spaceroots.mantissa.quadrature.vectorial;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TrapezoidIntegratorSamplerTest {

  @Test
  void constructor_whenUnderlyingIteratorExhausted_throwsExhaustedSampleException()
      throws ExhaustedSampleException, FunctionException {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    doThrow(new ExhaustedSampleException(0)).when(iter).nextSamplePoint();

    assertThrows(ExhaustedSampleException.class, () -> new TrapezoidIntegratorSampler(iter));
  }

  @Test
  void constructor_whenUnderlyingIteratorFails_throwsFunctionException()
      throws ExhaustedSampleException, FunctionException {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    doThrow(new FunctionException("boom")).when(iter).nextSamplePoint();

    assertThrows(FunctionException.class, () -> new TrapezoidIntegratorSampler(iter));
  }

  @Test
  void constructor_whenCreated_readsFirstSampleBeforeDimension() throws Exception {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    when(iter.nextSamplePoint()).thenReturn(new VectorialValuedPair(0.0, new double[] {0.0, 0.0}));
    when(iter.getDimension()).thenReturn(2);

    new TrapezoidIntegratorSampler(iter);

    InOrder order = inOrder(iter);
    order.verify(iter).nextSamplePoint();
    order.verify(iter).getDimension();
  }

  @Test
  void hasNext_and_getDimension_whenCalled_delegateToUnderlyingIterator() throws Exception {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    when(iter.nextSamplePoint()).thenReturn(new VectorialValuedPair(0.0, new double[] {0.0}));
    when(iter.getDimension()).thenReturn(1);
    when(iter.hasNext()).thenReturn(true);

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);

    boolean hasNext = sampler.hasNext();
    int dimension = sampler.getDimension();

    assertTrue(hasNext);
    assertEquals(1, dimension);
    verify(iter).hasNext();
    verify(iter, times(2)).getDimension();
  }

  @Test
  void nextSamplePoint_whenCalled_accumulatesIntegralUsingTrapezoidRule() throws Exception {
    ListSampledFunctionIterator iter =
        new ListSampledFunctionIterator(
            Arrays.asList(
                new VectorialValuedPair(0.0, new double[] {0.0, 0.0}),
                new VectorialValuedPair(1.0, new double[] {1.0, 2.0}),
                new VectorialValuedPair(3.0, new double[] {3.0, 4.0})));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);

    VectorialValuedPair first = sampler.nextSamplePoint();
    VectorialValuedPair second = sampler.nextSamplePoint();

    assertEquals(1.0, first.x, 0.0);
    assertArrayEquals(new double[] {0.5, 1.0}, first.y, 1e-12);
    assertEquals(3.0, second.x, 0.0);
    assertArrayEquals(new double[] {4.5, 7.0}, second.y, 1e-12);
  }

  @Test
  void nextSamplePoint_whenXDecreases_subtractsArea() throws Exception {
    ListSampledFunctionIterator iter =
        new ListSampledFunctionIterator(
            Arrays.asList(
                new VectorialValuedPair(2.0, new double[] {2.0}),
                new VectorialValuedPair(1.0, new double[] {1.0})));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);

    VectorialValuedPair result = sampler.nextSamplePoint();

    assertEquals(1.0, result.x, 0.0);
    assertArrayEquals(new double[] {-1.5}, result.y, 1e-12);
  }

  @Test
  void nextSamplePoint_whenCallerMutatesReturnedArray_doesNotAffectLaterResults() throws Exception {
    ListSampledFunctionIterator iter =
        new ListSampledFunctionIterator(
            Arrays.asList(
                new VectorialValuedPair(0.0, new double[] {0.0}),
                new VectorialValuedPair(1.0, new double[] {1.0}),
                new VectorialValuedPair(2.0, new double[] {1.0})));

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);

    VectorialValuedPair first = sampler.nextSamplePoint();
    double firstValue = first.y[0];
    first.y[0] = 999.0;
    VectorialValuedPair second = sampler.nextSamplePoint();

    assertNotSame(first.y, second.y);
    assertArrayEquals(new double[] {0.5}, new double[] {firstValue}, 1e-12);
    assertArrayEquals(new double[] {1.5}, second.y, 1e-12);
  }

  @Test
  void nextSamplePoint_whenUnderlyingThrows_propagatesException() throws Exception {
    SampledFunctionIterator iter = mock(SampledFunctionIterator.class);
    when(iter.nextSamplePoint())
        .thenReturn(new VectorialValuedPair(0.0, new double[] {0.0}))
        .thenThrow(new FunctionException("fail"));
    when(iter.getDimension()).thenReturn(1);

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);

    assertThrows(FunctionException.class, sampler::nextSamplePoint);
    verify(iter, times(2)).nextSamplePoint();
  }

  private static final class ListSampledFunctionIterator implements SampledFunctionIterator {

    private final List<VectorialValuedPair> points;
    private int index;

    private ListSampledFunctionIterator(List<VectorialValuedPair> points) {
      this.points = points;
      this.index = 0;
    }

    @Override
    public int getDimension() {
      if (points.isEmpty()) {
        return 0;
      }
      return points.getFirst().y.length;
    }

    @Override
    public boolean hasNext() {
      return index < points.size();
    }

    @Override
    public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException {
      if (!hasNext()) {
        throw new ExhaustedSampleException(points.size());
      }
      return points.get(index++);
    }
  }
}
