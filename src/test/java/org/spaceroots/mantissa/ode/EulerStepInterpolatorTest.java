package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EulerStepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  @Mock private FirstOrderDifferentialEquations equations;

  @Test
  void setInterpolatedTime_whenMidStep_returnsLinearlyInterpolatedState()
      throws DerivativeException {
    EulerStepInterpolator interpolator = new EulerStepInterpolator();
    double[] endState = {1.0, -2.0};
    double[][] slopes = {{0.5, -1.0}};

    interpolator.reinitialize(equations, endState, slopes, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);

    interpolator.setInterpolatedTime(0.5);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(0.75, interpolated[0], EPS);
    assertEquals(-1.5, interpolated[1], EPS);
  }

  @Test
  void setInterpolatedTime_backwardIntegration_handlesNegativeStepSize()
      throws DerivativeException {
    EulerStepInterpolator interpolator = new EulerStepInterpolator();
    double[] endState = {2.0, -4.0};
    double[][] slopes = {{1.0, 3.0}};

    interpolator.reinitialize(equations, endState, slopes, false);
    interpolator.previousTime = 1.0;
    interpolator.storeTime(0.0);

    interpolator.setInterpolatedTime(0.5);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(2.5, interpolated[0], EPS);
    assertEquals(-2.5, interpolated[1], EPS);
  }

  @Test
  void copy_whenOriginalMutated_preservesIndependentState() throws DerivativeException {
    EulerStepInterpolator interpolator = new EulerStepInterpolator();
    double[] endState = {4.0};
    double[][] slopes = {{2.0}};

    interpolator.reinitialize(equations, endState, slopes, true);
    interpolator.previousTime = 0.0;
    interpolator.storeTime(1.0);
    interpolator.setInterpolatedTime(0.5);
    interpolator.finalizeStep();

    EulerStepInterpolator copy = interpolator.copy();

    endState[0] = 99.0;
    slopes[0][0] = 99.0;

    copy.setInterpolatedTime(0.5);

    double[] copiedState = copy.getInterpolatedState();
    assertEquals(3.0, copiedState[0], EPS);
  }
}
