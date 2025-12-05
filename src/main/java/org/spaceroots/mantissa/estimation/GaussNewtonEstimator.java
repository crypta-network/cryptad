package org.spaceroots.mantissa.estimation;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.linalg.GeneralMatrix;
import org.spaceroots.mantissa.linalg.Matrix;
import org.spaceroots.mantissa.linalg.SingularMatrixException;
import org.spaceroots.mantissa.linalg.SymetricalMatrix;

/**
 * Gauss-Newton implementation of a weighted least squares estimator.
 *
 * <p>The estimator iteratively refines a set of {@link EstimatedParameter estimated parameters} so
 * that the weighted residuals of the provided {@link WeightedMeasurement measurements} are
 * minimized in the least squares sense. It follows the classical Gauss-Newton scheme: linearize the
 * model around the current parameters, solve the normal equations, and update the parameters.
 * Convergence is governed by configurable thresholds that balance numerical stability against
 * runtime cost. The class is mutable during an estimation run but not thread-safe; callers should
 * isolate instances per estimation session or provide external synchronization if shared. Typical
 * usage builds an instance with problem-specific tolerances, calls {@link
 * #estimate(EstimationProblem)} repeatedly for different problems, and inspects derived metrics
 * such as {@link #getRMS(EstimationProblem)} to judge fit quality.
 *
 * <ul>
 *   <li>Iterative nonlinear least squares with Gauss-Newton updates
 *   <li>Configurable iteration cap, steady-state detection, and singularity guard
 *   <li>Convenience path for fully linear problems via {@link #linearEstimate(EstimationProblem)}
 * </ul>
 *
 * @version $Id: GaussNewtonEstimator.java 1678 2005-12-16 11:11:40Z luc $
 * @author L. Maisonobe
 */
public class GaussNewtonEstimator implements Estimator, Serializable {

  /**
   * Build an estimator with explicit convergence and stability thresholds.
   *
   * <p>The constructor captures the stopping rules used by every subsequent estimation run. An
   * iteration stops early when the criterion falls under the {@code convergence} floor or when two
   * consecutive criteria differ by less than {@code steadyStateThreshold} times the current value
   * ({@code Math.abs(Jn - JnMinus1) &lt; Jn * steadyStateThreshold}). A failure to satisfy either
   * rule within {@code maxIterations} iterations results in an {@link EstimationException} during
   * execution. The {@code epsilon} parameter defines the minimal pivot magnitude accepted by the
   * linear solver; values below it are treated as singular to avoid unstable updates. Choose
   * thresholds based on measurement noise level and acceptable runtime.
   *
   * @param maxIterations maximum number of Gauss-Newton iterations permitted before failure
   * @param convergence absolute criterion floor; values below stop further refinements
   * @param steadyStateThreshold relative change limit detecting stalled improvement between steps
   * @param epsilon smallest allowed diagonal pivot before the normal matrix is considered singular
   */
  public GaussNewtonEstimator(
      int maxIterations, double convergence, double steadyStateThreshold, double epsilon) {
    this.maxIterations = maxIterations;
    this.steadyStateThreshold = steadyStateThreshold;
    this.convergence = convergence;
    this.epsilon = epsilon;
  }

  /**
   * Solve an estimation problem using iterative Gauss-Newton updates.
   *
   * <p>The method starts from the current estimates stored in the {@code problem} and repeatedly
   * linearizes the model, solves the associated normal equations, and shifts the parameters toward
   * the least squares minimum. Iterations end when either the criterion falls below the configured
   * {@code convergence} floor or changes less than {@code steadyStateThreshold} relative to its
   * current value, indicating steady state. Failure to satisfy these conditions within {@code
   * maxIterations} steps triggers an {@link EstimationException}. Parameter arrays and measurement
   * collections provided by the problem instance are mutated in place.
   *
   * <p>The routine is not thread-safe and assumes the problem is consistent across iterations. The
   * caller should ensure residuals and partial derivatives are recomputed on each invocation of
   * {@link WeightedMeasurement} accessors.
   *
   * @param problem estimation problem supplying measurements and adjustable parameters; must be
   *     non-null and return consistent residuals for each iteration
   * @exception EstimationException if convergence fails or the linear subproblem becomes singular
   * @see EstimationProblem
   */
  public void estimate(EstimationProblem problem) throws EstimationException {
    int iterations = 0;
    double previous = evaluateCriterion(problem);
    double current;
    double difference;

    // iterate until convergence is reached
    do {

      if (++iterations > maxIterations) {
        throw new EstimationException(
            "unable to converge in {0} iterations", new String[] {Integer.toString(maxIterations)});
      }

      // perform one iteration
      linearEstimate(problem);

      current = evaluateCriterion(problem);
      difference = Math.abs(previous - current);
      previous = current;

    } while ((iterations < 2)
        || (difference > (current * steadyStateThreshold) && (Math.abs(current) > convergence)));
  }

  /**
   * Perform one linearized Gauss-Newton step or solve a purely linear problem.
   *
   * <p>The routine constructs the normal matrix and right-hand side from the measurement residuals
   * and partial derivatives, solves the resulting linear system, and applies the increment to each
   * unbound parameter. For a truly linear model this single call completes the estimation; for
   * nonlinear models it represents one iteration of {@link #estimate(EstimationProblem)}. The
   * method relies on {@link WeightedMeasurement} to provide up-to-date residuals and partials at
   * the current parameter values.
   *
   * @param problem estimation problem whose measurements define residuals and Jacobian entries; it
   *     must expose unbound parameters that can be updated in place
   * @exception EstimationException if the normal matrix is singular or the solver cannot progress
   */
  public void linearEstimate(EstimationProblem problem) throws EstimationException {

    EstimatedParameter[] parameters = problem.getUnboundParameters();
    WeightedMeasurement[] measurements = problem.getMeasurements();

    // build the linear problem
    GeneralMatrix b = new GeneralMatrix(parameters.length, 1);
    SymetricalMatrix a = new SymetricalMatrix(parameters.length);
    for (WeightedMeasurement measurement : measurements) {
      if (!measurement.isIgnored()) {
        double weight = measurement.getWeight();
        double residual = measurement.getResidual();

        // compute the normal equation
        double[] grad = new double[parameters.length];
        Matrix bDecrement = new GeneralMatrix(parameters.length, 1);
        for (int j = 0; j < parameters.length; ++j) {
          grad[j] = measurement.getPartial(parameters[j]);
          bDecrement.setElement(j, 0, weight * residual * grad[j]);
        }

        // update the matrices
        a.selfAddWAAt(weight, grad);
        b.selfAdd(bDecrement);
      }
    }

    try {

      // solve the linearized least squares problem
      Matrix dX = a.solve(b, epsilon);

      // update the estimated parameters
      for (int i = 0; i < parameters.length; ++i) {
        parameters[i].setEstimate(parameters[i].getEstimate() + dX.getElement(i, 0));
      }

    } catch (SingularMatrixException e) {
      throw new EstimationException(e);
    }
  }

  private double evaluateCriterion(EstimationProblem problem) {
    double criterion = 0.0;
    WeightedMeasurement[] measurements = problem.getMeasurements();

    for (WeightedMeasurement measurement : measurements) {
      double residual = measurement.getResidual();
      criterion += measurement.getWeight() * residual * residual;
    }

    return criterion;
  }

  /**
   * Compute the root-mean-square of the weighted residuals for a problem.
   *
   * <p>The RMS equals {@code sqrt(criterion / n)} where {@code criterion} is the sum of weighted
   * squared residuals across the measurements and {@code n} is their count. It provides a
   * normalized measure of fit quality that is directly comparable across problems with different
   * numbers of measurements. The method does not alter the problem or the estimator state and can
   * be invoked between iterations to monitor convergence progress.
   *
   * @param problem estimation problem supplying residuals and weights; must be consistent with the
   *     most recent parameter estimates
   * @return RMS value derived from current residuals; {@code Double.NaN} is never returned
   */
  public double getRMS(EstimationProblem problem) {
    double criterion = evaluateCriterion(problem);
    int n = problem.getMeasurements().length;
    return Math.sqrt(criterion / n);
  }

  /**
   * Maximum count of Gauss-Newton iterations permitted for any estimation run. Exceeding this cap
   * indicates the algorithm stalled or diverged and results in an {@link EstimationException}.
   */
  private final int maxIterations;

  /**
   * Relative threshold used to detect steady-state behaviour between successive criteria values.
   * When the absolute delta falls below this fraction of the current criterion, iterations stop.
   */
  private final double steadyStateThreshold;

  /**
   * Absolute criterion floor that short-circuits further refinement once reached, representing the
   * minimum useful objective value given measurement noise and model fidelity.
   */
  private final double convergence;

  /**
   * Pivot magnitude cutoff passed to the linear solver; smaller values flag the normal matrix as
   * numerically singular to prevent unstable parameter updates.
   */
  private final double epsilon;

  @Serial private static final long serialVersionUID = -7606628156644194170L;
}
