package org.spaceroots.mantissa.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ArrayMapperTest {

  @Mock private ArraySliceMappable mock1;
  @Mock private ArraySliceMappable mock2;

  @Test
  void constructor_default_whenNoObjects_expectEmptyDataArrayAndNoOpUpdates() {
    ArrayMapper mapper = new ArrayMapper();

    assertArrayEquals(new double[0], mapper.getDataArray());

    mapper.updateArray();
    mapper.updateObjects();
  }

  @Test
  void constructor_withObject_whenInitialized_expectSizeAndUpdateArrayRoundTrip() {
    DummyMappable dummy = new DummyMappable(2);
    dummy.setState(7.0, 8.0);

    ArrayMapper mapper = new ArrayMapper(dummy);

    assertEquals(2, mapper.getDataArray().length);

    mapper.updateArray();
    assertArrayEquals(new double[] {7.0, 8.0}, mapper.getDataArray());

    mapper.updateObjects(new double[] {1.0, 2.0});
    assertArrayEquals(new double[] {1.0, 2.0}, dummy.getState());
  }

  @Test
  void manageMappable_whenAddedToEmptyMapper_expectOffsetsAndDispatching() {
    DummyMappable first = new DummyMappable(2);
    DummyMappable second = new DummyMappable(3);

    ArrayMapper mapper = new ArrayMapper();
    mapper.manageMappable(first);
    mapper.manageMappable(second);

    double[] flat = new double[] {10.0, 11.0, 12.0, 13.0, 14.0};
    mapper.updateObjects(flat);

    assertArrayEquals(new double[] {10.0, 11.0}, first.getState());
    assertArrayEquals(new double[] {12.0, 13.0, 14.0}, second.getState());

    first.setState(20.0, 21.0);
    second.setState(22.0, 23.0, 24.0);

    double[] out = new double[5];
    mapper.updateArray(out);
    assertArrayEquals(new double[] {20.0, 21.0, 22.0, 23.0, 24.0}, out);
  }

  @Test
  void updateObjects_whenInternalDataNull_expectLazyInitAndCorrectOffsets() {
    when(mock1.getStateDimension()).thenReturn(1);
    when(mock2.getStateDimension()).thenReturn(2);

    ArrayMapper mapper = new ArrayMapper();
    mapper.manageMappable(mock1);
    mapper.manageMappable(mock2);

    mapper.updateObjects();

    ArgumentCaptor<double[]> captor = ArgumentCaptor.forClass(double[].class);
    verify(mock1).mapStateFromArray(eq(0), captor.capture());
    double[] dataForFirst = captor.getValue();

    ArgumentCaptor<double[]> captorSecond = ArgumentCaptor.forClass(double[].class);
    verify(mock2).mapStateFromArray(eq(1), captorSecond.capture());
    double[] dataForSecond = captorSecond.getValue();

    assertNotSame(null, dataForFirst);
    assertEquals(3, dataForFirst.length);
    assertEquals(dataForFirst, dataForSecond);
  }

  @Test
  void updateArray_whenInternalDataNull_expectLazyInitAndCorrectOffsets() {
    when(mock1.getStateDimension()).thenReturn(2);
    when(mock2.getStateDimension()).thenReturn(1);

    ArrayMapper mapper = new ArrayMapper();
    mapper.manageMappable(mock1);
    mapper.manageMappable(mock2);

    mapper.updateArray();

    ArgumentCaptor<double[]> captor = ArgumentCaptor.forClass(double[].class);
    verify(mock1).mapStateToArray(eq(0), captor.capture());
    double[] dataForFirst = captor.getValue();

    ArgumentCaptor<double[]> captorSecond = ArgumentCaptor.forClass(double[].class);
    verify(mock2).mapStateToArray(eq(2), captorSecond.capture());
    double[] dataForSecond = captorSecond.getValue();

    assertEquals(3, dataForFirst.length);
    assertEquals(dataForFirst, dataForSecond);
  }

  @Test
  void getDataArray_whenMutatedByCaller_expectDefensiveCopy() {
    DummyMappable dummy = new DummyMappable(2);
    ArrayMapper mapper = new ArrayMapper(dummy);

    double[] first = mapper.getDataArray();
    first[0] = 123.0;

    double[] second = mapper.getDataArray();

    assertEquals(0.0, second[0]);
  }

  @Test
  void manageMappable_whenInternalDataAlreadyInitialized_expectInternalDataReset() {
    DummyMappable first = new DummyMappable(2);
    first.setState(5.0, 6.0);
    DummyMappable second = new DummyMappable(1);

    ArrayMapper mapper = new ArrayMapper(first);
    mapper.updateArray();
    assertArrayEquals(new double[] {5.0, 6.0}, mapper.getDataArray());

    mapper.manageMappable(second);
    mapper.updateObjects();

    assertArrayEquals(new double[] {0.0, 0.0}, first.getState());
    assertArrayEquals(new double[] {0.0}, second.getState());
  }

  @Test
  void updateObjects_whenDataTooShort_expectArrayIndexOutOfBoundsException() {
    DummyMappable dummy = new DummyMappable(3);
    ArrayMapper mapper = new ArrayMapper(dummy);

    assertThrows(
        ArrayIndexOutOfBoundsException.class, () -> mapper.updateObjects(new double[] {1.0, 2.0}));
  }

  @Test
  void manageMappable_whenNullObject_expectNullPointerException() {
    ArrayMapper mapper = new ArrayMapper();

    assertThrows(NullPointerException.class, () -> mapper.manageMappable(null));
  }

  @Test
  void updateArray_whenProvidedArray_expectCallsForAllObjectsInOrder() {
    when(mock1.getStateDimension()).thenReturn(1);
    when(mock2.getStateDimension()).thenReturn(1);

    ArrayMapper mapper = new ArrayMapper();
    mapper.manageMappable(mock1);
    mapper.manageMappable(mock2);

    double[] target = new double[2];
    mapper.updateArray(target);

    verify(mock1, times(1)).mapStateToArray(0, target);
    verify(mock2, times(1)).mapStateToArray(1, target);
  }

  private static final class DummyMappable implements ArraySliceMappable {
    private final int dimension;
    private final double[] state;

    private DummyMappable(int dimension) {
      this.dimension = dimension;
      this.state = new double[dimension];
    }

    @Override
    public int getStateDimension() {
      return dimension;
    }

    @Override
    public void mapStateFromArray(int start, double[] array) {
      System.arraycopy(array, start, state, 0, dimension);
    }

    @Override
    public void mapStateToArray(int start, double[] array) {
      System.arraycopy(state, 0, array, start, dimension);
    }

    private void setState(double... values) {
      System.arraycopy(values, 0, state, 0, dimension);
    }

    private double[] getState() {
      return state.clone();
    }
  }
}
