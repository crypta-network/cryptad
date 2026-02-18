package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class ClassicalRungeKuttaStepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  @ParameterizedTest
  @ValueSource(doubles = {0.0, 0.25, 0.5, 0.75, 1.0})
  void setInterpolatedTime_withConstantDerivative_matchesAnalyticSolution(double theta)
      throws DerivativeException {

    double[] startState = new double[] {1.0, -2.0};
    double[] constantDerivative = new double[] {0.5, -1.0};
    double h = 2.0;

    double[] endState =
        new double[] {
          startState[0] + constantDerivative[0] * h, startState[1] + constantDerivative[1] * h
        };
    double[][] slopes = constantSlopes(constantDerivative);

    ClassicalRungeKuttaStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* startTime= */ 0.0, /* endTime= */ h, true);

    double time = theta * h;
    interpolator.setInterpolatedTime(time);

    double[] expected =
        new double[] {
          startState[0] + constantDerivative[0] * theta * h,
          startState[1] + constantDerivative[1] * theta * h
        };

    assertArrayEquals(expected, interpolator.getInterpolatedState(), EPS);
  }

  @Test
  void setInterpolatedTime_withDistinctSlopes_appliesRungeKuttaWeights()
      throws DerivativeException {

    double[] endState = new double[] {2.0};
    double[][] slopes = new double[][] {{1.0}, {2.0}, {3.0}, {4.0}};

    ClassicalRungeKuttaStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* startTime= */ 1.5, /* endTime= */ 2.5, true);

    interpolator.setInterpolatedTime(1.8);

    // Expected value computed analytically from the published RK4 dense output weights.
    // For theta = 0.3 the coefficients give an adjustment of -13/200.
    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(-0.065, interpolated[0], EPS);
  }

  @Test
  void copy_whenOriginalMutated_preservesDeepCopiedData() throws DerivativeException {

    double[] startState = new double[] {1.0};
    double[] constantDerivative = new double[] {0.2};
    double h = 1.0;
    double[] endState = new double[] {startState[0] + constantDerivative[0] * h};
    double[][] slopes = constantSlopes(constantDerivative);

    ClassicalRungeKuttaStepInterpolator original =
        createInterpolator(endState, slopes, /* startTime= */ 0.0, /* endTime= */ h, true);
    original.finalizeStep();

    ClassicalRungeKuttaStepInterpolator copy = original.copy();

    // Mutate the original after the copy to ensure deep copies are honored.
    original.currentState[0] = 99.0;
    original.yDotK[0][0] = 5.0;

    double midpointTime = 0.5 * h;
    copy.setInterpolatedTime(midpointTime);

    double[] expected = new double[] {startState[0] + constantDerivative[0] * midpointTime};
    assertArrayEquals(expected, copy.getInterpolatedState(), EPS);
  }

  @Test
  void setInterpolatedTime_backwardIntegration_usesNegativeStep() throws DerivativeException {

    double startTime = 2.0;
    double endTime = 0.0;
    double h = endTime - startTime; // negative step

    double[] startState = new double[] {5.0};
    double[] derivative = new double[] {1.0};
    double[] endState = new double[] {startState[0] + derivative[0] * h};
    double[][] slopes = constantSlopes(derivative);

    ClassicalRungeKuttaStepInterpolator interpolator =
        createInterpolator(endState, slopes, startTime, endTime, false);

    interpolator.setInterpolatedTime(1.0);

    double expectedStateAtMidpoint = 4.0; // startState + derivative * (1.0 - startTime)
    assertEquals(expectedStateAtMidpoint, interpolator.getInterpolatedState()[0], EPS);
  }

  private static ClassicalRungeKuttaStepInterpolator createInterpolator(
      double[] endState, double[][] slopes, double startTime, double endTime, boolean forward) {

    ClassicalRungeKuttaStepInterpolator interpolator = new ClassicalRungeKuttaStepInterpolator();
    interpolator.reinitialize(new DummyEquations(endState.length), endState, slopes, forward);
    interpolator.previousTime = startTime;
    interpolator.storeTime(endTime);
    return interpolator;
  }

  private static double[][] constantSlopes(double[] derivative) {
    double[][] slopes = new double[4][];
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
