package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GillStepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  @Mock private FirstOrderDifferentialEquations equations;

  @ParameterizedTest
  @CsvSource({"0.0", "0.5", "1.0"})
  void setInterpolatedTime_whenThetaMatchesGillFormula_returnsExpectedValue(double theta)
      throws DerivativeException {

    double[] endState = new double[] {1.0};
    double[][] slopes =
        new double[][] {
          new double[] {10.0}, new double[] {20.0}, new double[] {30.0}, new double[] {40.0}
        };

    GillStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);

    interpolator.setInterpolatedTime(theta);

    double expected =
        computeExpectedState(endState[0], slopes, theta, /* oneMinusThetaH= */ 1.0 - theta);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(expected, interpolated[0], EPS);
  }

  @Test
  void setInterpolatedTime_backwardIntegration_handlesNegativeStepSize()
      throws DerivativeException {

    double[] endState = new double[] {2.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0}, new double[] {2.0}, new double[] {3.0}, new double[] {4.0}
        };

    double previousTime = 1.0;
    double currentTime = 0.0;
    GillStepInterpolator interpolator =
        createInterpolator(endState, slopes, previousTime, currentTime, false);

    double queryTime = 0.5;
    interpolator.setInterpolatedTime(queryTime);

    double h = currentTime - previousTime;
    double oneMinusThetaH = currentTime - queryTime;
    double theta = (h - oneMinusThetaH) / h;
    double expected = computeExpectedState(endState[0], slopes, theta, oneMinusThetaH);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(expected, interpolated[0], EPS);
  }

  @Test
  void copy_whenOriginalMutated_preservesIndependentData() throws DerivativeException {

    double[] endState = new double[] {4.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0}, new double[] {2.0}, new double[] {3.0}, new double[] {4.0}
        };

    GillStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);
    interpolator.setInterpolatedTime(0.5);
    interpolator.finalizeStep();

    double[][] originalSlopes = new double[slopes.length][];
    for (int i = 0; i < slopes.length; i++) {
      originalSlopes[i] = slopes[i].clone();
    }

    GillStepInterpolator copy = interpolator.copy();

    // mutate original references after the copy
    endState[0] = 99.0;
    slopes[0][0] = 99.0;

    copy.setInterpolatedTime(0.5);

    double expected =
        computeExpectedState(
            /* currentState= */ 4.0, originalSlopes, /* theta= */ 0.5, /* oneMinusThetaH= */ 0.5);

    double[] copiedState = copy.getInterpolatedState();
    assertEquals(expected, copiedState[0], EPS);
    assertEquals(1.0, copy.yDotK[0][0], EPS);
    assertEquals(4.0, copy.currentState[0], EPS);
  }

  @Test
  void getInterpolatedState_returnsDefensiveCopy() throws DerivativeException {

    double[] endState = new double[] {3.0};
    double[][] slopes =
        new double[][] {
          new double[] {2.0}, new double[] {2.0}, new double[] {2.0}, new double[] {2.0}
        };

    GillStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);

    interpolator.setInterpolatedTime(0.25);

    double[] firstRead = interpolator.getInterpolatedState();
    firstRead[0] = 100.0;

    double[] secondRead = interpolator.getInterpolatedState();
    double expected =
        computeExpectedState(endState[0], slopes, /* theta= */ 0.25, /* oneMinusThetaH= */ 0.75);
    assertEquals(expected, secondRead[0], EPS);
  }

  private GillStepInterpolator createInterpolator(
      double[] endState,
      double[][] slopes,
      double previousTime,
      double currentTime,
      boolean forward) {

    GillStepInterpolator interpolator = new GillStepInterpolator();
    interpolator.reinitialize(equations, endState, slopes, forward);
    interpolator.previousTime = previousTime;
    interpolator.storeTime(currentTime);
    return interpolator;
  }

  private double computeExpectedState(
      double currentState, double[][] slopes, double theta, double oneMinusThetaH) {

    double fourTheta = 4.0 * theta;
    double s = oneMinusThetaH / 6.0;
    double soMt = s * (1.0 - theta);
    double c23 = soMt * (1.0 + 2.0 * theta);
    double coeff1 = soMt * (1.0 - fourTheta);
    double coeff2 = c23 * (2.0 - Math.sqrt(2.0));
    double coeff3 = c23 * (2.0 + Math.sqrt(2.0));
    double coeff4 = s * (1.0 + theta * (1.0 + fourTheta));

    return currentState
        - coeff1 * slopes[0][0]
        - coeff2 * slopes[1][0]
        - coeff3 * slopes[2][0]
        - coeff4 * slopes[3][0];
  }
}
