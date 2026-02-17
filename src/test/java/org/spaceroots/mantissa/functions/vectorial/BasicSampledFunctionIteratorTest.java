// package and imports
package org.spaceroots.mantissa.functions.vectorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BasicSampledFunctionIteratorTest {

  private static void ignoreInt(int ignored) {}

  @Mock private SampledFunction function;

  @Test
  void getDimension_whenDelegateReturnsValue_returnsSame() {
    when(function.getDimension()).thenReturn(3);

    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    assertEquals(3, iterator.getDimension());
    verify(function, times(1)).getDimension();
  }

  @Test
  void hasNext_whenSizePositiveAndNoIteration_returnsTrue() {
    when(function.size()).thenReturn(2);

    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    assertTrue(iterator.hasNext());
    ignoreInt(verify(function, times(1)).size());
  }

  @Test
  void hasNext_afterConsumingAllSamples_returnsFalse() throws Exception {
    when(function.size()).thenReturn(1);
    VectorialValuedPair pair = new VectorialValuedPair(1.0, new double[] {2.0});
    when(function.samplePointAt(0)).thenReturn(pair);
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    iterator.nextSamplePoint();

    assertFalse(iterator.hasNext());
    ignoreInt(verify(function, times(2)).size());
  }

  @Test
  void nextSamplePoint_whenIterating_returnsValuesSequentially() throws Exception {
    when(function.size()).thenReturn(2);
    VectorialValuedPair first = new VectorialValuedPair(0.5, new double[] {1.0, 2.0});
    VectorialValuedPair second = new VectorialValuedPair(1.5, new double[] {-1.0, 3.0});
    when(function.samplePointAt(0)).thenReturn(first);
    when(function.samplePointAt(1)).thenReturn(second);
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    VectorialValuedPair firstResult = iterator.nextSamplePoint();
    VectorialValuedPair secondResult = iterator.nextSamplePoint();

    assertEquals(first.x, firstResult.x);
    assertArrayEquals(first.y, firstResult.y);
    assertEquals(second.x, secondResult.x);
    assertArrayEquals(second.y, secondResult.y);
    assertFalse(iterator.hasNext());

    var order = inOrder(function);
    ignoreInt(order.verify(function).size());
    order.verify(function).samplePointAt(0);
    ignoreInt(order.verify(function).size());
    order.verify(function).samplePointAt(1);
    ignoreInt(order.verify(function).size());
  }

  @Test
  void nextSamplePoint_whenExhausted_throwsExhaustedSampleException() throws Exception {
    when(function.size()).thenReturn(1);
    VectorialValuedPair pair = new VectorialValuedPair(2.0, new double[] {4.0});
    when(function.samplePointAt(0)).thenReturn(pair);
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    iterator.nextSamplePoint();

    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
    // size() is called once on the initial read and twice on the exhausted call (guard + message)
    ignoreInt(verify(function, times(3)).size());
    verify(function, times(1)).samplePointAt(0);
    verifyNoMoreInteractions(function);
  }

  @Test
  void nextSamplePoint_whenDelegateThrowsFunctionException_propagatesAndAdvancesIndex()
      throws Exception {
    when(function.size()).thenReturn(1);
    when(function.samplePointAt(0)).thenThrow(new FunctionException("boom"));
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    assertThrows(FunctionException.class, iterator::nextSamplePoint);
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);

    verify(function, times(1)).samplePointAt(0);
  }
}
