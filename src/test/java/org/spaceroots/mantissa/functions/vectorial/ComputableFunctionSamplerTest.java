package org.spaceroots.mantissa.functions.vectorial;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyDouble;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ComputableFunctionSamplerTest {

  @Mock private ComputableFunction function;

  @Test
  void size_whenCreatedWithDirectParameters_returnsProvidedCount() {
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 1.0, 0.5, 4);

    assertEquals(4, sampler.size());
  }

  @Test
  void samplePointAt_whenValidIndex_returnsPairWithComputedAbscissaAndClonedValue()
      throws FunctionException {
    double[] rawValue = new double[] {1.0, -2.0};
    when(function.valueAt(1.5)).thenReturn(rawValue);
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 1.0, 0.5, 4);

    VectorialValuedPair pair = sampler.samplePointAt(1);

    assertEquals(1.5, pair.x);
    assertArrayEquals(rawValue, pair.y);
    assertNotSame(rawValue, pair.y);
  }

  @Test
  void getDimension_whenCalled_delegatesToUnderlyingFunction() {
    when(function.getDimension()).thenReturn(3);
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 0.0, 1.0, 2);

    int dimension = sampler.getDimension();

    assertEquals(3, dimension);
    verify(function, times(1)).getDimension();
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 3})
  void samplePointAt_whenIndexOutOfBounds_throwsException(int index) {
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 0.0, 1.0, 3);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> sampler.samplePointAt(index));
  }

  @Test
  void constructorWithRangeAndCount_whenSamplingLastPoint_hitsUpperBound()
      throws FunctionException {
    ArgumentCaptor<Double> xCaptor = ArgumentCaptor.forClass(Double.class);
    when(function.valueAt(anyDouble())).thenReturn(new double[] {42.0});
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {2.0, 4.0}, 5);

    sampler.samplePointAt(4);

    verify(function).valueAt(xCaptor.capture());
    assertEquals(4.0, xCaptor.getValue(), 1.0e-12);
    assertEquals(5, sampler.size());
  }

  @Test
  void
      constructorWithRangeAndStepAdjustTrue_whenSamplingLastPoint_usesAdjustedStepToReachUpperBound()
          throws FunctionException {
    ArgumentCaptor<Double> xCaptor = ArgumentCaptor.forClass(Double.class);
    when(function.valueAt(anyDouble())).thenReturn(new double[] {7.0});
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {0.0, 1.0}, 0.3, true);

    sampler.samplePointAt(sampler.size() - 1);

    verify(function).valueAt(xCaptor.capture());
    assertEquals(1.0, xCaptor.getValue(), 1.0e-12);
    assertEquals(4, sampler.size());
  }

  @Test
  void constructorWithRangeAndStepAdjustFalse_whenSamplingLastPoint_keepsOriginalStep()
      throws FunctionException {
    ArgumentCaptor<Double> xCaptor = ArgumentCaptor.forClass(Double.class);
    when(function.valueAt(anyDouble())).thenReturn(new double[] {3.0});
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {0.0, 1.0}, 0.3, false);

    sampler.samplePointAt(sampler.size() - 1);

    verify(function).valueAt(xCaptor.capture());
    assertEquals(0.6, xCaptor.getValue(), 1.0e-12);
    assertEquals(3, sampler.size());
  }
}
