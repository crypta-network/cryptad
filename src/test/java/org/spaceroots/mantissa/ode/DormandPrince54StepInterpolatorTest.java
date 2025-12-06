package org.spaceroots.mantissa.ode;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@SuppressWarnings("java:S100")
class DormandPrince54StepInterpolatorTest {

  private static final double EPS = 1.0e-12;

  private DormandPrince54StepInterpolator interpolator;

  @BeforeEach
  void setUp() {
    interpolator = createUnitSlopeInterpolator();
  }

  @ParameterizedTest
  @CsvSource({"0.0,0.0", "0.25,0.25", "0.5,0.5", "0.75,0.75", "1.0,1.0"})
  @DisplayName("Interpolated state follows linear solution for constant slope")
  void setInterpolatedTime_whenLinearDerivative_matchesAnalyticalSolution(
      double time, double expected) throws DerivativeException {

    // Act
    interpolator.setInterpolatedTime(time);

    // Assert
    assertEquals(expected, interpolator.getInterpolatedState()[0], EPS);
  }

  @Test
  @DisplayName("Cached interpolation vectors are reused within a step")
  void setInterpolatedTime_whenSlopesMutateWithinStep_vectorsAreCached()
      throws DerivativeException {

    // Arrange
    interpolator.setInterpolatedTime(0.5);
    for (double[] stage : interpolator.yDotK) {
      stage[0] = 5.0; // mutate slopes after vectors were initialized
    }

    // Act
    interpolator.setInterpolatedTime(0.25);

    // Assert
    assertEquals(0.25, interpolator.getInterpolatedState()[0], EPS);
  }

  @Test
  @DisplayName("Reinitialization resets cached vectors for the next step")
  void reinitialize_whenNewStepUsesDifferentSlope_recomputesVectors() throws DerivativeException {

    // Arrange: complete an initial interpolation to populate cached vectors
    interpolator.setInterpolatedTime(0.5);

    // Reinitialize for a new step with a different constant slope
    double newSlope = 2.0;
    double startTime = 1.0;
    double endTime = 2.0;
    double startValue = 1.0;
    double endValue = startValue + newSlope * (endTime - startTime);

    interpolator.reinitialize(
        new ConstantEquation(newSlope), new double[] {endValue}, createSlopes(newSlope), true);
    interpolator.previousTime = startTime;
    interpolator.storeTime(endTime);

    // Act
    interpolator.setInterpolatedTime(1.5);

    // Assert
    assertEquals(2.0, interpolator.getInterpolatedState()[0], EPS);
  }

  @Test
  @DisplayName("Copy provides deep clone independent from original state mutations")
  void copy_whenOriginalMutates_preservesSnapshot() throws DerivativeException {

    // Arrange
    interpolator.setInterpolatedTime(0.5);
    DormandPrince54StepInterpolator clone = interpolator.copy();

    // mutate original after cloning
    interpolator.currentState[0] = 10.0;
    for (double[] stage : interpolator.yDotK) {
      stage[0] = 5.0;
    }

    // Act
    clone.setInterpolatedTime(0.25);

    // Assert
    assertEquals(0.25, clone.getInterpolatedState()[0], EPS);
  }

  private DormandPrince54StepInterpolator createUnitSlopeInterpolator() {
    double startTime = 0.0;
    double endTime = 1.0;
    double slope = 1.0;
    double[] endState = new double[] {slope * (endTime - startTime)};
    DormandPrince54StepInterpolator stepInterpolator = new DormandPrince54StepInterpolator();
    stepInterpolator.reinitialize(new ConstantEquation(slope), endState, createSlopes(slope), true);
    stepInterpolator.previousTime = startTime;
    stepInterpolator.storeTime(endTime);
    return stepInterpolator;
  }

  private double[][] createSlopes(double slope) {
    double[][] slopes = new double[7][1];
    for (double[] stage : slopes) {
      stage[0] = slope;
    }
    return slopes;
  }

  private static final class ConstantEquation implements FirstOrderDifferentialEquations {

    private final double slope;

    ConstantEquation(double slope) {
      this.slope = slope;
    }

    @Override
    public int getDimension() {
      return 1;
    }

    @Override
    public void computeDerivatives(double t, double[] y, double[] yDot) {
      yDot[0] = slope;
    }
  }
}
