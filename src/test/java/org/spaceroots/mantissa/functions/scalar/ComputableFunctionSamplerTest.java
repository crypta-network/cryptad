package org.spaceroots.mantissa.functions.scalar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.FunctionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ComputableFunctionSamplerTest {

  @Test
  void size_whenConstructedWithExplicitValues_returnsProvidedCount() {
    ComputableFunction function = mock(ComputableFunction.class);
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 0.0, 0.5, 4);

    int result = sampler.size();

    assertEquals(4, result);
  }

  @Test
  void samplePointAt_whenIndexWithinBounds_returnsPairAndDelegatesToFunction() throws Exception {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.valueAt(anyDouble()))
        .thenAnswer(invocation -> 2.0 * (Double) invocation.getArgument(0));
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 1.0, 0.5, 5);

    ScalarValuedPair pair = sampler.samplePointAt(2);

    assertEquals(2.0, pair.getX());
    assertEquals(4.0, pair.getY());
    verify(function, times(1)).valueAt(2.0);
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 3})
  void samplePointAt_whenIndexIsOutOfRange_throwsArrayIndexOutOfBoundsException(int invalidIndex) {
    ComputableFunction function = mock(ComputableFunction.class);
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 0.0, 1.0, 3);

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> sampler.samplePointAt(invalidIndex));
  }

  @Test
  void constructorWithRangeAndCount_whenSamplingLastPoint_hitsUpperBound() throws Exception {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.valueAt(anyDouble())).thenAnswer(invocation -> invocation.getArgument(0));
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {2.0, 3.0}, 5);

    ScalarValuedPair pair = sampler.samplePointAt(4);

    assertEquals(3.0, pair.getX());
    assertEquals(3.0, pair.getY());
  }

  @Test
  void constructorWithRangeStepAdjustTrue_whenSamplingLastPoint_matchesUpperBound()
      throws Exception {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.valueAt(anyDouble())).thenAnswer(invocation -> invocation.getArgument(0));
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {0.0, 1.0}, 0.3, true);

    ScalarValuedPair pair = sampler.samplePointAt(sampler.size() - 1);

    assertEquals(1.0, pair.getX(), 1e-12);
    assertEquals(1.0, pair.getY(), 1e-12);
  }

  @Test
  void constructorWithRangeStepAdjustFalse_whenSamplingLastPoint_respectsUnadjustedStep()
      throws Exception {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.valueAt(anyDouble())).thenAnswer(invocation -> invocation.getArgument(0));
    ComputableFunctionSampler sampler =
        new ComputableFunctionSampler(function, new double[] {0.0, 1.0}, 0.3, false);

    ScalarValuedPair pair = sampler.samplePointAt(sampler.size() - 1);

    assertEquals(0.6, pair.getX(), 1e-12);
    assertEquals(0.6, pair.getY(), 1e-12);
    assertEquals(3, sampler.size());
  }

  @Test
  void samplePointAt_whenFunctionThrows_propagatesFunctionException() throws Exception {
    ComputableFunction function = mock(ComputableFunction.class);
    when(function.valueAt(anyDouble())).thenThrow(new FunctionException("failure"));
    ComputableFunctionSampler sampler = new ComputableFunctionSampler(function, 0.0, 1.0, 2);

    assertThrows(FunctionException.class, () -> sampler.samplePointAt(0));
  }
}
