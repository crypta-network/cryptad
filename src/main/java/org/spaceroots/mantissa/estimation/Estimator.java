package org.spaceroots.mantissa.estimation;

/**
 * Strategy interface for solvers that adjust model parameters to fit measured data.
 *
 * <p>Implementations orchestrate the life cycle of an {@link EstimationProblem}, driving iterations
 * that refine parameter values until a stopping criterion is met or a failure condition is reached.
 * The contract is deliberately minimal so algorithms such as least-squares, Kalman filtering, or
 * other domain-specific estimators can plug in while exposing a consistent entry point to callers.
 * Clients typically create a problem instance that carries parameters, measurements, and residual
 * computation hooks, then pass it to an {@code Estimator} implementation to perform the solve step.
 *
 * <p>Responsibility highlights:
 *
 * <ul>
 *   <li>Runs an estimation routine over the supplied problem and updates its parameters in place.
 *   <li>Provides access to quality metrics, such as the Root Mean Square (RMS) of residuals.
 *   <li>Leaves algorithm-specific policy decisions (tolerances, iteration caps, damping) to
 *       implementations.
 * </ul>
 *
 * <p>Unless otherwise documented by a concrete implementation, instances are not guaranteed to be
 * thread-safe. Callers should avoid sharing a single estimator across concurrent solve operations
 * or protect access externally.
 *
 * @see EstimationProblem
 * @version $Id: Estimator.java 1677 2005-12-16 11:10:48Z luc $
 * @author L. Maisonobe
 */
public interface Estimator {

  /**
   * Solve the supplied estimation problem until convergence or an unrecoverable error occurs.
   *
   * <p>The method drives the iterative loop that probes candidate parameter sets, evaluates
   * residuals, and applies the algorithm-specific update rule. When the call returns normally, the
   * {@link EstimationProblem} instance is expected to hold its best-known parameter estimates,
   * which callers can inspect via {@link EstimationProblem#getAllParameters()}. Implementations may
   * stop early when tolerances are met, a maximum iteration count is exceeded, or a numerical issue
   * is detected. No internal synchronization is implied; callers should supply a distinct problem
   * per thread or synchronize externally.
   *
   * <pre>{@code
   * EstimationProblem problem = ...; // populate measurements and initial parameters
   * estimator.estimate(problem);
   * var params = problem.getAllParameters();
   * }</pre>
   *
   * @param problem estimation problem that provides parameters, measurements, and residual model;
   *     must be non-null and initialized before invocation
   * @throws EstimationException if convergence cannot be reached or the problem definition is
   *     inconsistent
   */
  void estimate(EstimationProblem problem) throws EstimationException;

  /**
   * Compute the Root Mean Square (RMS) of the weighted residuals for a problem.
   *
   * <p>The RMS is the square root of the arithmetic mean of squared, weighted residual values
   * produced by the most recent estimation pass. It mirrors the minimized criterion: given
   * criterion {@code c} and {@code n} measurements, RMS equals {@code sqrt(c / n)}. Implementations
   * should rely on the residuals stored in the provided problem and must not modify its state.
   * Calling this method before a solve may yield stale or undefined values, depending on the
   * underlying implementation.
   *
   * @param problem estimation problem whose current residuals are used to compute the RMS; must
   *     match the problem previously processed by the estimator
   * @return RMS value as a non-negative double; specific implementations may return {@code NaN}
   *     when residuals are unavailable
   */
  @SuppressWarnings("unused")
  double getRMS(EstimationProblem problem);
}
