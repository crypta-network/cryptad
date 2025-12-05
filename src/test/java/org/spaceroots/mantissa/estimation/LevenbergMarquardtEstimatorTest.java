package org.spaceroots.mantissa.estimation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LevenbergMarquardtEstimatorTest {

  @Mock private WeightedMeasurement firstMeasurement;

  @Mock private WeightedMeasurement secondMeasurement;

  @Test
  void getRMS_whenTwoMeasurements_returnsExpectedRootMeanSquare() {
    when(firstMeasurement.getResidual()).thenReturn(3.0);
    when(firstMeasurement.getWeight()).thenReturn(2.0);
    when(secondMeasurement.getResidual()).thenReturn(-1.0);
    when(secondMeasurement.getWeight()).thenReturn(4.0);

    EstimationProblem problem =
        new EstimationProblem() {
          @Override
          public WeightedMeasurement[] getMeasurements() {
            return new WeightedMeasurement[] {firstMeasurement, secondMeasurement};
          }

          @Override
          public EstimatedParameter[] getUnboundParameters() {
            return new EstimatedParameter[0];
          }

          @Override
          public EstimatedParameter[] getAllParameters() {
            return getUnboundParameters();
          }
        };

    LevenbergMarquardtEstimator estimator = new LevenbergMarquardtEstimator();

    double rms = estimator.getRMS(problem);

    // sqrt((2*9 + 4*1)/2) = sqrt(11) ≈ 3.31662
    assertEquals(Math.sqrt(11.0), rms, 1.0e-12);
  }

  @Test
  void estimate_whenLinearModel_convergesAndUpdatesParameter() throws EstimationException {
    double trueSlope = 2.0;
    LinearProblem problem = new LinearProblem(trueSlope, 0.1);
    LevenbergMarquardtEstimator estimator = new LevenbergMarquardtEstimator();

    estimator.estimate(problem);

    assertEquals(trueSlope, problem.parameter.getEstimate(), 1.0e-6);
    assertTrue(estimator.getCostEvaluations() > 0, "cost evaluations should be recorded");
    assertTrue(estimator.getJacobianEvaluations() > 0, "jacobian evaluations should be recorded");
  }

  @Test
  void estimate_whenMaxEvaluationsIsZero_throwsEstimationException() {
    LinearProblem problem = new LinearProblem(1.0, 0.0);
    LevenbergMarquardtEstimator estimator = new LevenbergMarquardtEstimator();
    estimator.setMaxCostEval(0);

    EstimationException exception =
        assertThrows(EstimationException.class, () -> estimator.estimate(problem));

    assertTrue(
        exception.getMessage().contains("maximal number of evaluations exceeded"),
        "exception message should mention evaluation limit");
  }

  private static final class LinearProblem implements EstimationProblem {

    private final LinearMeasurement[] measurements;
    private final EstimatedParameter parameter;

    LinearProblem(double trueSlope, double initialEstimate) {
      parameter = new EstimatedParameter("slope", initialEstimate);
      measurements =
          new LinearMeasurement[] {
            new LinearMeasurement(1.0, 1.0, trueSlope, parameter),
            new LinearMeasurement(1.0, 2.0, trueSlope, parameter),
            new LinearMeasurement(1.0, 3.0, trueSlope, parameter)
          };
    }

    @Override
    public WeightedMeasurement[] getMeasurements() {
      return measurements;
    }

    @Override
    public EstimatedParameter[] getUnboundParameters() {
      return new EstimatedParameter[] {parameter};
    }

    @Override
    public EstimatedParameter[] getAllParameters() {
      return getUnboundParameters();
    }
  }

  private static final class LinearMeasurement extends WeightedMeasurement {

    private final double x;
    private final double trueSlope;
    private final EstimatedParameter parameter;

    LinearMeasurement(double weight, double x, double trueSlope, EstimatedParameter parameter) {
      super(weight, trueSlope * x);
      this.x = x;
      this.trueSlope = trueSlope;
      this.parameter = parameter;
    }

    @Override
    public double getTheoreticalValue() {
      return parameter.getEstimate() * x;
    }

    @Override
    public double getPartial(EstimatedParameter parameter) {
      return this.parameter == parameter ? x : 0.0;
    }

    @Override
    public double getResidual() {
      return (trueSlope * x) - getTheoreticalValue();
    }
  }
}
