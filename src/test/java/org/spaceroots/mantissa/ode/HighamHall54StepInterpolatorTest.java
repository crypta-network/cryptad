package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HighamHall54StepInterpolatorTest {

  private static final double TOLERANCE = 1.0e-13;

  @Test
  void setInterpolatedTime_atCurrentTime_returnsCurrentState() throws Exception {
    double[] state = {1.0};
    double[][] yDotK = createStageSlopes1D();

    HighamHall54StepInterpolator interpolator = new HighamHall54StepInterpolator();
    interpolator.reinitialize(null, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(1.0);

    assertArrayEquals(state, interpolator.getInterpolatedState(), TOLERANCE);
  }

  @ParameterizedTest
  @CsvSource({"0.0, -2.5", "0.25, -2.0556640625", "0.5, -1.3906250000000016"})
  void setInterpolatedTime_withinStep_matchesKnownValues(double time, double expected)
      throws Exception {
    double[] state = {1.0};
    double[][] yDotK = createStageSlopes1D();

    HighamHall54StepInterpolator interpolator = new HighamHall54StepInterpolator();
    interpolator.reinitialize(null, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(time);

    assertEquals(expected, interpolator.getInterpolatedState()[0], TOLERANCE);
  }

  @Test
  void setInterpolatedTime_withVectorState_updatesEachComponent() throws Exception {
    double[] state = {10.0, -10.0};
    double[][] yDotK = createSymmetricStageSlopes2D();

    HighamHall54StepInterpolator interpolator = new HighamHall54StepInterpolator();
    interpolator.reinitialize(null, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(0.25);

    double[] expected = {6.9443359375, -6.9443359375};
    assertArrayEquals(expected, interpolator.getInterpolatedState(), TOLERANCE);
  }

  @Test
  void copy_afterFinalization_isDeepAndIndependent() throws Exception {
    double[] state = {1.0};
    double[][] yDotK = createStageSlopes1D();

    HighamHall54StepInterpolator interpolator = new HighamHall54StepInterpolator();
    interpolator.reinitialize(null, state, yDotK, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);
    interpolator.setInterpolatedTime(0.5);
    double originalValue = interpolator.getInterpolatedState()[0];
    interpolator.finalizeStep();

    HighamHall54StepInterpolator copy = interpolator.copy();

    yDotK[0][0] = 10.0;
    state[0] = 5.0;
    interpolator.setInterpolatedTime(0.5);
    double mutatedOriginalValue = interpolator.getInterpolatedState()[0];

    copy.setInterpolatedTime(0.5);
    double copiedValue = copy.getInterpolatedState()[0];

    assertNotEquals(originalValue, mutatedOriginalValue, TOLERANCE);
    assertEquals(originalValue, copiedValue, TOLERANCE);
  }

  private static double[][] createStageSlopes1D() {
    double[][] slopes = new double[6][1];
    slopes[0][0] = 1.0;
    slopes[2][0] = 2.0;
    slopes[3][0] = 3.0;
    slopes[4][0] = 4.0;
    slopes[5][0] = 5.0;
    return slopes;
  }

  private static double[][] createSymmetricStageSlopes2D() {
    double[][] slopes = new double[6][2];
    slopes[0] = new double[] {1.0, -1.0};
    slopes[2] = new double[] {2.0, -2.0};
    slopes[3] = new double[] {3.0, -3.0};
    slopes[4] = new double[] {4.0, -4.0};
    slopes[5] = new double[] {5.0, -5.0};
    return slopes;
  }
}
