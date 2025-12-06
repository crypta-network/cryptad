package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ThreeEighthesStepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  private FirstOrderDifferentialEquations equations;

  @BeforeEach
  void setUp() {
    equations = mock(FirstOrderDifferentialEquations.class);
  }

  @ParameterizedTest
  @CsvSource({"0.0,2.0", "0.5,3.5", "1.0,5.0"})
  void setInterpolatedTime_whenSlopeConstant_returnsLinearInterpolation(
      double theta, double expectedValue) throws DerivativeException {

    double[] endState = new double[] {5.0};
    double[][] slopes =
        new double[][] {
          new double[] {3.0}, new double[] {3.0}, new double[] {3.0}, new double[] {3.0}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);

    //noinspection PointlessArithmeticExpression
    interpolator.setInterpolatedTime(0.0 + theta * 1.0);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(expectedValue, interpolated[0], EPS);
  }

  @Test
  void setInterpolatedTime_whenAtCurrentTime_returnsCurrentState() throws DerivativeException {
    double[] endState = new double[] {10.0, -1.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0, 2.0},
          new double[] {3.0, 4.0},
          new double[] {5.0, 6.0},
          new double[] {7.0, 8.0}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);

    interpolator.setInterpolatedTime(1.0);

    assertArrayEquals(endState, interpolator.getInterpolatedState(), EPS);
  }

  @Test
  void setInterpolatedTime_whenMidStep_usesAllStageDerivatives() throws DerivativeException {
    double[] endState = new double[] {10.0, -5.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0, -1.0},
          new double[] {0.5, 2.0},
          new double[] {-1.0, 4.0},
          new double[] {2.0, -0.5}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 1.0, /* currentTime= */ 3.0, true);

    double theta = 0.25;
    interpolator.setInterpolatedTime(1.0 + theta * 2.0);

    double oneMinusThetaH = 3.0 - (1.0 + theta * 2.0);
    double fourTheta2 = 4.0 * theta * theta;
    double s = oneMinusThetaH / 8.0;
    double coeff1 = s * (1.0 - 7.0 * theta + 2.0 * fourTheta2);
    double coeff2 = 3.0 * s * (1.0 + theta - fourTheta2);
    double coeff3 = 3.0 * s * (1.0 + theta);
    double coeff4 = s * (1.0 + theta + fourTheta2);

    double expected0 =
        endState[0]
            - coeff1 * slopes[0][0]
            - coeff2 * slopes[1][0]
            - coeff3 * slopes[2][0]
            - coeff4 * slopes[3][0];
    double expected1 =
        endState[1]
            - coeff1 * slopes[0][1]
            - coeff2 * slopes[1][1]
            - coeff3 * slopes[2][1]
            - coeff4 * slopes[3][1];

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(expected0, interpolated[0], EPS);
    assertEquals(expected1, interpolated[1], EPS);
  }

  @Test
  void setInterpolatedTime_whenBackwardIntegration_handlesNegativeStep()
      throws DerivativeException {
    double[] endState = new double[] {2.0};
    double[][] slopes =
        new double[][] {
          new double[] {3.0}, new double[] {3.0}, new double[] {3.0}, new double[] {3.0}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(
            endState, slopes, /* previousTime= */ 2.0, /* currentTime= */ 1.0, false);

    interpolator.setInterpolatedTime(1.5);

    double[] interpolated = interpolator.getInterpolatedState();
    assertEquals(3.5, interpolated[0], EPS);
  }

  @Test
  void copy_whenModifiedOriginal_doesNotAffectCopy() throws DerivativeException {
    double[] endState = new double[] {4.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0}, new double[] {2.0}, new double[] {3.0}, new double[] {4.0}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);
    interpolator.setInterpolatedTime(0.5);
    interpolator.finalizeStep();

    ThreeEighthesStepInterpolator copy = interpolator.copy();

    slopes[0][0] = 99.0;
    endState[0] = -10.0;

    assertEquals(1.0, copy.yDotK[0][0], EPS);
    assertEquals(4.0, copy.currentState[0], EPS);
  }

  @Test
  void getInterpolatedState_returnsDefensiveCopy() throws DerivativeException {
    double[] endState = new double[] {2.0, 3.0};
    double[][] slopes =
        new double[][] {
          new double[] {1.0, 1.0},
          new double[] {1.0, 1.0},
          new double[] {1.0, 1.0},
          new double[] {1.0, 1.0}
        };

    ThreeEighthesStepInterpolator interpolator =
        createInterpolator(endState, slopes, /* previousTime= */ 0.0, /* currentTime= */ 1.0, true);

    interpolator.setInterpolatedTime(0.25);

    double[] firstRead = interpolator.getInterpolatedState();
    firstRead[0] = 100.0;

    double[] secondRead = interpolator.getInterpolatedState();
    assertEquals(1.25, secondRead[0], EPS);
  }

  private ThreeEighthesStepInterpolator createInterpolator(
      double[] endState,
      double[][] slopes,
      double previousTime,
      double currentTime,
      boolean forward) {

    ThreeEighthesStepInterpolator interpolator = new ThreeEighthesStepInterpolator();
    interpolator.reinitialize(equations, endState, slopes, forward);
    interpolator.previousTime = previousTime;
    interpolator.storeTime(currentTime);
    return interpolator;
  }
}
