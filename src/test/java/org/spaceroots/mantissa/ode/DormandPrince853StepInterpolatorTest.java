package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DormandPrince853StepInterpolatorTest {

  @Mock private FirstOrderDifferentialEquations equations;

  @Test
  void
      setInterpolatedTime_whenCalledMultipleTimes_doesNotRecomputeDerivativesAfterFirstInitialization()
          throws Exception {
    double[] state = {1.0};
    double[][] yDotK = createStageSlopes(1.0);

    AtomicInteger derivativeValue = new AtomicInteger(14);
    doAnswer(
            invocation -> {
              double[] target = invocation.getArgument(2);
              Arrays.fill(target, derivativeValue.getAndIncrement());
              return null;
            })
        .when(equations)
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));

    DormandPrince853StepInterpolator interpolator = new DormandPrince853StepInterpolator();
    interpolator.reinitialize(equations, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(0.5);
    double firstValue = interpolator.getInterpolatedState()[0];

    interpolator.setInterpolatedTime(0.25);
    double secondValue = interpolator.getInterpolatedState()[0];

    verify(equations, times(3))
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));
    assertNotEquals(firstValue, secondValue);
  }

  @Test
  void setInterpolatedTime_afterStoreTime_recomputesDerivativesForNewStep() throws Exception {
    double[] state = {1.0};
    double[][] yDotK = createStageSlopes(2.0);

    AtomicInteger derivativeValue = new AtomicInteger(20);
    doAnswer(
            invocation -> {
              double[] target = invocation.getArgument(2);
              Arrays.fill(target, derivativeValue.getAndIncrement());
              return null;
            })
        .when(equations)
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));

    DormandPrince853StepInterpolator interpolator = new DormandPrince853StepInterpolator();
    interpolator.reinitialize(equations, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);
    interpolator.setInterpolatedTime(0.5);

    verify(equations, times(3))
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));

    clearInvocations(equations);
    interpolator.shift();
    interpolator.storeTime(2.0);
    interpolator.setInterpolatedTime(1.5);

    verify(equations, times(3))
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));
  }

  @Test
  void doFinalize_whenCalled_usesExpectedEvaluationTimes() throws Exception {
    double[] state = {2.0};
    double[][] yDotK = createStageSlopes(3.0);

    List<Double> evaluationTimes = new ArrayList<>();
    doAnswer(
            invocation -> {
              evaluationTimes.add(invocation.getArgument(0));
              double[] target = invocation.getArgument(2);
              Arrays.fill(target, 1.0);
              return null;
            })
        .when(equations)
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));

    DormandPrince853StepInterpolator interpolator = new DormandPrince853StepInterpolator();
    interpolator.reinitialize(equations, state, yDotK, true);
    interpolator.previousTime = 2.0;
    interpolator.storeTime(5.0);

    interpolator.setInterpolatedTime(4.0);

    assertEquals(3, evaluationTimes.size());
    assertEquals(2.0 + (1.0 / 10.0) * 3.0, evaluationTimes.get(0), 1.0e-12);
    assertEquals(2.0 + (1.0 / 5.0) * 3.0, evaluationTimes.get(1), 1.0e-12);
    assertEquals(2.0 + (7.0 / 9.0) * 3.0, evaluationTimes.get(2), 1.0e-12);
  }

  @Test
  void writeExternalAndReadExternal_whenRoundTripped_preservesInterpolationOutcome()
      throws Exception {
    double[] state = {2.5};
    double[][] yDotK = createStageSlopes(1.0);

    AtomicInteger derivativeValue = new AtomicInteger(30);
    doAnswer(
            invocation -> {
              double[] target = invocation.getArgument(2);
              Arrays.fill(target, derivativeValue.getAndIncrement());
              return null;
            })
        .when(equations)
        .computeDerivatives(anyDouble(), any(double[].class), any(double[].class));

    DormandPrince853StepInterpolator original = new DormandPrince853StepInterpolator();
    original.reinitialize(equations, state, yDotK, true);
    original.previousTime = 1.0;
    original.storeTime(1.5);
    original.setInterpolatedTime(1.25);
    double[] expected = original.getInterpolatedState();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      original.writeExternal(oos);
    }

    DormandPrince853StepInterpolator copy = new DormandPrince853StepInterpolator();
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      copy.readExternal(ois);
    }

    copy.setInterpolatedTime(1.25);
    assertArrayEquals(expected, copy.getInterpolatedState(), 1.0e-14);
  }

  private static double[][] createStageSlopes(double startValue) {
    double[][] slopes = new double[13][1];
    for (int k = 0; k < slopes.length; k++) {
      slopes[k][0] = startValue + k;
    }
    return slopes;
  }
}
