package org.spaceroots.mantissa.estimation;

/**
 * Defines the contract for an estimation problem consumed by numerical estimators.
 *
 * <p>An estimation problem groups a set of adjustable parameters and a collection of weighted
 * measurements describing how well a proposed parameter vector matches observed reality. Concrete
 * implementations typically assemble immutable model metadata at construction time, then expose
 * mutable parameter state to the solver so it can iterate toward a minimum residual. The estimator
 * drives the life-cycle: it repeatedly queries the problem for the current measurements and free
 * parameters, updates parameter estimates based on residuals, and may re-evaluate model predictions
 * between iterations.
 *
 * <p>Typical usage follows this sequence: a client builds an {@code EstimationProblem} carrying the
 * model-specific {@link EstimatedParameter} instances and {@link WeightedMeasurement} entries,
 * passes it to {@link Estimator#estimate(EstimationProblem)}, and lets the estimator perform the
 * optimization loop. Implementations should keep array ordering stable so solvers can cache
 * intermediate state, and should document whether returned arrays are defensive copies or
 * live-backed. This interface itself is agnostic to concurrency; unless an implementation states
 * otherwise, callers should treat instances as not thread-safe and confine access to the estimating
 * thread.
 *
 * <ul>
 *   <li>Provides read access to all parameters, whether currently bound or free.
 *   <li>Separates unbound parameters so solvers know which elements may be updated.
 *   <li>Supplies weighted measurements used to compute residuals and drive corrections.
 * </ul>
 *
 * @see Estimator
 * @see WeightedMeasurement
 * @version $Id: EstimationProblem.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public interface EstimationProblem {
  /**
   * Returns the weighted measurements contributing to the objective being minimized.
   *
   * <p>The returned array represents the complete measurement set known to the problem at the
   * moment of the call. Implementations are encouraged to preserve element ordering across calls so
   * estimators can reuse residual caches or Jacobians. Unless otherwise documented, callers should
   * treat both the array structure and the contained measurement instances as read-only to avoid
   * invalidating the solver’s internal state. Measurement objects typically carry a fixed observed
   * value and a model-computed theoretical value; the theoretical portion will be recomputed by the
   * solver as parameters change, so callers do not need to trigger refreshes manually.
   *
   * @return an array of {@link WeightedMeasurement} instances, never {@code null}; element order is
   *     stable per implementation contract and should not be mutated by callers
   */
  WeightedMeasurement[] getMeasurements();

  /**
   * Returns parameters that are currently free to vary during estimation.
   *
   * <p>The array lists only the subset of parameters the solver is allowed to modify while seeking
   * a solution. Implementations should ensure each entry is also present in the full parameter set
   * returned by {@link #getAllParameters()} so solvers can correlate derivatives and constraints.
   * Callers must not replace or remove elements from the returned array unless the implementation
   * explicitly supports such modifications; most solvers expect structural stability and will write
   * updated estimates via {@link EstimatedParameter#setEstimate(double)} on the existing objects.
   *
   * @return an array of adjustable {@link EstimatedParameter} objects representing free variables;
   *     array and entries are expected to be non-null and reused across iterations
   */
  EstimatedParameter[] getUnboundParameters();

  /**
   * Returns all parameters that describe the model, including bound and unbound ones.
   *
   * <p>This view allows callers to examine every parameter contributing to the model, even if some
   * are held fixed during the current solve. The ordering should be consistent with the unbound
   * subset so derivative arrays and constraint matrices can be indexed predictably. Implementations
   * may include derived or informational parameters; solvers should only alter those that also
   * appear in {@link #getUnboundParameters()}. Unless otherwise stated, treat the array as a live
   * view owned by the problem to avoid desynchronizing parameter state from the underlying model.
   *
   * @return an array containing every {@link EstimatedParameter} instance known to the problem,
   *     typically non-null with stable ordering; callers should avoid structural mutation
   */
  EstimatedParameter[] getAllParameters();
}
