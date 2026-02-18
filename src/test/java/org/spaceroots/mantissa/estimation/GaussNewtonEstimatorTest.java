package org.spaceroots.mantissa.estimation;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GaussNewtonEstimatorTest {

  @Test
  void linearEstimate_whenLinearSystemExact_updatesParametersToLeastSquaresSolution()
      throws EstimationException {
    EstimatedParameter p0 = new EstimatedParameter("p0", 0.0);
    EstimatedParameter p1 = new EstimatedParameter("p1", 0.0);
    LinearProblem problem =
        new LinearProblem(
            new EstimatedParameter[] {p0, p1},
            new LinearMeasurement(1.0, 7.0, new double[] {1.0, 2.0}, false, p0, p1),
            new LinearMeasurement(1.0, 3.0, new double[] {2.0, -1.0}, false, p0, p1));

    GaussNewtonEstimator estimator = new GaussNewtonEstimator(5, 1.0e-12, 1.0e-8, 1.0e-12);

    estimator.linearEstimate(problem);

    assertEquals(2.6, p0.getEstimate(), 1.0e-12);
    assertEquals(2.2, p1.getEstimate(), 1.0e-12);
  }

  @Test
  void linearEstimate_whenMeasurementIgnored_doesNotAffectUpdate() throws EstimationException {
    EstimatedParameter p0 = new EstimatedParameter("p0", 0.0);
    EstimatedParameter p1 = new EstimatedParameter("p1", 0.0);
    LinearMeasurement informative1 =
        new LinearMeasurement(1.0, 7.0, new double[] {1.0, 2.0}, false, p0, p1);
    LinearMeasurement informative2 =
        new LinearMeasurement(1.0, 3.0, new double[] {2.0, -1.0}, false, p0, p1);
    LinearMeasurement ignored =
        new LinearMeasurement(1.0, 100.0, new double[] {10.0, 0.0}, true, p0, p1);
    LinearProblem problem =
        new LinearProblem(new EstimatedParameter[] {p0, p1}, informative1, informative2, ignored);

    GaussNewtonEstimator estimator = new GaussNewtonEstimator(5, 1.0e-12, 1.0e-8, 1.0e-12);

    estimator.linearEstimate(problem);

    assertEquals(2.6, p0.getEstimate(), 1.0e-12);
    assertEquals(2.2, p1.getEstimate(), 1.0e-12);
  }

  @Test
  void linearEstimate_whenMatrixSingular_throwsEstimationException() {
    EstimatedParameter p0 = new EstimatedParameter("p0", 1.0);
    LinearMeasurement singular = new LinearMeasurement(1.0, 5.0, new double[] {0.0}, false, p0);
    LinearProblem problem = new LinearProblem(new EstimatedParameter[] {p0}, singular);

    GaussNewtonEstimator estimator = new GaussNewtonEstimator(3, 1.0e-12, 1.0e-8, 1.0e-12);

    assertThrows(EstimationException.class, () -> estimator.linearEstimate(problem));
  }

  @Test
  void estimate_whenConvergesWithinMaxIterations_updatesParameters() throws EstimationException {
    EstimatedParameter p0 = new EstimatedParameter("p0", 0.0);
    EstimatedParameter p1 = new EstimatedParameter("p1", 0.0);
    LinearProblem problem =
        new LinearProblem(
            new EstimatedParameter[] {p0, p1},
            new LinearMeasurement(1.0, 7.0, new double[] {1.0, 2.0}, false, p0, p1),
            new LinearMeasurement(1.0, 3.0, new double[] {2.0, -1.0}, false, p0, p1));

    GaussNewtonEstimator estimator = new GaussNewtonEstimator(10, 1.0e-15, 1.0e-12, 1.0e-12);

    estimator.estimate(problem);

    assertEquals(2.6, p0.getEstimate(), 1.0e-10);
    assertEquals(2.2, p1.getEstimate(), 1.0e-10);
  }

  @Test
  void getRMS_whenResidualsPresent_computesRootMeanSquare() {
    EstimatedParameter p0 = new EstimatedParameter("p0", 2.0);
    EstimatedParameter p1 = new EstimatedParameter("p1", 4.0);

    LinearMeasurement m1 =
        new LinearMeasurement(2.0, 5.0, new double[] {1.0, 0.0}, false, p0, p1); // residual = 3
    LinearMeasurement m2 =
        new LinearMeasurement(1.0, 3.0, new double[] {0.0, 1.0}, false, p0, p1); // residual = -1
    LinearProblem problem = new LinearProblem(new EstimatedParameter[] {p0, p1}, m1, m2);

    GaussNewtonEstimator estimator = new GaussNewtonEstimator(3, 1.0e-12, 1.0e-8, 1.0e-12);

    double rms = estimator.getRMS(problem);

    assertEquals(Math.sqrt(19.0 / 2.0), rms, 1.0e-12);
  }

  private static final class LinearProblem implements EstimationProblem {
    private final EstimatedParameter[] parameters;
    private final WeightedMeasurement[] measurements;

    LinearProblem(EstimatedParameter[] parameters, WeightedMeasurement... measurements) {
      this.parameters = parameters;
      this.measurements = measurements;
    }

    @Override
    public WeightedMeasurement[] getMeasurements() {
      return measurements;
    }

    @Override
    public EstimatedParameter[] getUnboundParameters() {
      return parameters;
    }

    @Override
    public EstimatedParameter[] getAllParameters() {
      return Arrays.copyOf(parameters, parameters.length);
    }
  }

  private static final class LinearMeasurement extends WeightedMeasurement {
    private final EstimatedParameter[] parameters;
    private final double[] coefficients;

    LinearMeasurement(
        double weight,
        double measuredValue,
        double[] coefficients,
        boolean ignored,
        EstimatedParameter... parameters) {
      super(weight, measuredValue, ignored);
      this.parameters = parameters;
      this.coefficients = coefficients;
    }

    @Override
    public double getTheoreticalValue() {
      double value = 0.0;
      for (int i = 0; i < parameters.length; i++) {
        value += coefficients[i] * parameters[i].getEstimate();
      }
      return value;
    }

    @Override
    public double getPartial(EstimatedParameter parameter) {
      for (int i = 0; i < parameters.length; i++) {
        if (parameters[i] == parameter) {
          return coefficients[i];
        }
      }
      return 0.0;
    }
  }
}
