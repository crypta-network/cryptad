package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class MidpointStepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  @ParameterizedTest
  @ValueSource(doubles = {0.0, 0.25, 0.5, 0.75, 1.0})
  void setInterpolatedTime_withConstantDerivative_matchesLinearSolution(double theta)
      throws DerivativeException {

    double[] startState = new double[] {1.0, -2.0};
    double[] derivative = new double[] {0.5, -1.5};
    double h = 2.0;

    double[] endState =
        new double[] {
          startState[0] + derivative[0] * h, startState[1] + derivative[1] * h,
        };
    double[][] slopes = constantSlopes(derivative);

    MidpointStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* startTime= */ 0.0, /* endTime= */ h, true);

    double time = theta * h;
    interpolator.setInterpolatedTime(time);

    double[] expected =
        new double[] {
          startState[0] + derivative[0] * time, startState[1] + derivative[1] * time,
        };

    assertArrayEquals(expected, interpolator.getInterpolatedState(), EPS);
  }

  @Test
  void setInterpolatedTime_withDistinctSlopes_usesMidpointWeights() throws DerivativeException {

    double startTime = 0.0;
    double endTime = 1.0;
    double h = endTime - startTime;

    double startState = 2.0;
    double yDotStage0 = 1.0;
    double yDotStage1 = 3.0;
    double[] endState = new double[] {startState + h * yDotStage1};
    double[][] slopes = new double[][] {{yDotStage0}, {yDotStage1}};

    MidpointStepInterpolator interpolator =
        createInterpolator(endState, slopes, startTime, endTime, true);

    double theta = 0.3;
    interpolator.setInterpolatedTime(startTime + theta * h);

    double oneMinusThetaH = (1.0 - theta) * h;
    double expected =
        endState[0] + oneMinusThetaH * (theta * yDotStage0 - (1.0 + theta) * yDotStage1);

    assertEquals(expected, interpolator.getInterpolatedState()[0], EPS);
  }

  @Test
  void setInterpolatedTime_backwardIntegration_producesStateInReverseStep()
      throws DerivativeException {

    double startTime = 1.0;
    double endTime = 0.0;
    double h = endTime - startTime; // negative

    double startState = 5.0;
    double derivative = 1.0;
    double[] endState = new double[] {startState + h * derivative};
    double[][] slopes = constantSlopes(new double[] {derivative});

    MidpointStepInterpolator interpolator =
        createInterpolator(endState, slopes, startTime, endTime, false);

    double targetTime = 0.5;
    interpolator.setInterpolatedTime(targetTime);

    double expected = startState + derivative * (targetTime - startTime);
    assertEquals(expected, interpolator.getInterpolatedState()[0], EPS);
  }

  @Test
  void copy_whenOriginalMutated_keepsDeepClonedData() throws DerivativeException {

    double[] startState = new double[] {1.0};
    double[] derivative = new double[] {2.0};
    double h = 1.0;

    double[] endState = new double[] {startState[0] + derivative[0] * h};
    double[][] slopes = constantSlopes(derivative);

    MidpointStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* startTime= */ 0.0, /* endTime= */ h, true);
    interpolator.setInterpolatedTime(0.5 * h);
    interpolator.finalizeStep();

    MidpointStepInterpolator copy = interpolator.copy();

    endState[0] = 99.0;
    slopes[0][0] = 99.0;
    slopes[1][0] = 99.0;

    double targetTime = 0.5 * h;
    copy.setInterpolatedTime(targetTime);

    double expected = startState[0] + derivative[0] * targetTime;
    assertEquals(expected, copy.getInterpolatedState()[0], EPS);
  }

  private static MidpointStepInterpolator createInterpolator(
      double[] endState, double[][] slopes, double startTime, double endTime, boolean forward) {

    MidpointStepInterpolator interpolator = new MidpointStepInterpolator();
    interpolator.reinitialize(new DummyEquations(endState.length), endState, slopes, forward);
    interpolator.previousTime = startTime;
    interpolator.storeTime(endTime);
    return interpolator;
  }

  private static double[][] constantSlopes(double[] derivative) {
    double[][] slopes = new double[2][];
    for (int i = 0; i < slopes.length; i++) {
      slopes[i] = derivative.clone();
    }
    return slopes;
  }

  private static final class DummyEquations implements FirstOrderDifferentialEquations {

    private final int dimension;

    DummyEquations(int dimension) {
      this.dimension = dimension;
    }

    @Override
    public int getDimension() {
      return dimension;
    }

    @Override
    @SuppressWarnings("RedundantThrows")
    public void computeDerivatives(double t, double[] y, double[] yDot) throws DerivativeException {
      Arrays.fill(yDot, 0.0);
    }
  }
}
