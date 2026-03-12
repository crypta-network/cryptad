package org.spaceroots.mantissa.functions.scalar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BasicSampledFunctionIteratorTest {

  @Mock private SampledFunction function;

  @Test
  void hasNext_whenIteratorCreatedAndSizePositive_returnsTrue() {
    // Arrange
    when(function.size()).thenReturn(2);
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    // Act
    boolean result = iterator.hasNext();

    // Assert
    assertTrue(result);
  }

  @Test
  void hasNext_whenNoElements_returnsFalse() {
    // Arrange
    when(function.size()).thenReturn(0);
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    // Act
    boolean result = iterator.hasNext();

    // Assert
    assertFalse(result);
  }

  @Test
  void nextSamplePoint_whenCalledSequentially_returnsPointsAndAdvances() throws Exception {
    // Arrange
    when(function.size()).thenReturn(2);
    when(function.samplePointAt(0)).thenReturn(new ScalarValuedPair(0.0, 1.0));
    when(function.samplePointAt(1)).thenReturn(new ScalarValuedPair(2.0, 3.0));
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    // Act
    ScalarValuedPair first = iterator.nextSamplePoint();
    ScalarValuedPair second = iterator.nextSamplePoint();

    // Assert
    assertEquals(0.0, first.getX());
    assertEquals(1.0, first.getY());
    assertEquals(2.0, second.getX());
    assertEquals(3.0, second.getY());
    assertFalse(iterator.hasNext());
    verify(function, times(1)).samplePointAt(0);
    verify(function, times(1)).samplePointAt(1);
  }

  @Test
  void nextSamplePoint_whenExhausted_throwsExhaustedSampleException() throws Exception {
    // Arrange
    when(function.size()).thenReturn(1);
    when(function.samplePointAt(0)).thenReturn(new ScalarValuedPair(0.0, 0.0));
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    // Act
    iterator.nextSamplePoint();

    // Assert
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
    verify(function, times(1)).samplePointAt(0);
    verify(function, never()).samplePointAt(1);
  }

  @Test
  void nextSamplePoint_whenUnderlyingFunctionThrows_propagatesExceptionAndAdvancesIndex()
      throws Exception {
    // Arrange
    when(function.size()).thenReturn(2);
    when(function.samplePointAt(0)).thenReturn(new ScalarValuedPair(1.0, 1.5));
    when(function.samplePointAt(1)).thenThrow(new FunctionException("failure"));
    BasicSampledFunctionIterator iterator = new BasicSampledFunctionIterator(function);

    // Act
    iterator.nextSamplePoint();

    // Assert
    assertThrows(FunctionException.class, iterator::nextSamplePoint);
    assertFalse(iterator.hasNext());
    assertThrows(ExhaustedSampleException.class, iterator::nextSamplePoint);
    verify(function, times(1)).samplePointAt(1);
  }
}
