package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Step interpolator for the classical 3/8 fourth-order Runge-Kutta scheme.
 *
 * <p>The interpolator computes a dense output over the last accepted integration step so callers
 * can query intermediate states without re-integrating. It reconstructs the state using the same
 * Butcher tableau as {@link ThreeEighthesIntegrator}, combining the four already-computed
 * derivative evaluations and the normalized abscissa {@code theta} to achieve fourth-order accuracy
 * between grid points.
 *
 * <p>Typical usage is internal to the Runge-Kutta framework: the integrator clones a prototype of
 * this class, initializes it with step data, and then delegates to it when a user requests an
 * interpolated state. The instance is mutable between steps but not thread-safe; it is intended to
 * be used by a single integration thread and discarded or reinitialized after each step. The
 * interpolation preserves the integrator invariants—continuity of the state vector across the step
 * and consistency with the discrete solution at {@code theta = 0} and {@code theta = 1}—while
 * avoiding additional derivative evaluations, keeping the cost bounded to inexpensive linear
 * combinations. The quality of the dense output matches the global order of the 3/8 method, which
 * makes it suitable for event detection or output sampling that requires sub-step resolution.
 *
 * <ul>
 *   <li>Responsibility: provide {@link #computeInterpolatedState(double, double)} consistent with
 *       the 3/8 tableau.
 *   <li>Lifecycle: reinitialize from a base step, interpolate multiple times within that step, then
 *       replace or reinitialize for the next step.
 *   <li>Threading: no internal synchronization; callers must confine instances to one thread.
 * </ul>
 *
 * @see ThreeEighthesIntegrator
 * @version $Id: ThreeEighthesStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class ThreeEighthesStepInterpolator extends RungeKuttaStepInterpolator implements StepInterpolator {

  /**
   * Simple constructor that creates a yet-to-be-initialized interpolator instance.
   *
   * <p>The newly created object does not contain step data until {@link
   * AbstractStepInterpolator#reinitialize(double[], boolean)} is invoked by the owning integrator.
   * This delayed initialization lets {@link RungeKuttaIntegrator} clone a lightweight prototype per
   * step without allocating work arrays eagerly. Callers should treat the instance as unusable
   * until after reinitialization has completed; thereafter it may be queried repeatedly within the
   * same step for dense output and then discarded or reconfigured for subsequent steps.
   */
  public ThreeEighthesStepInterpolator() {}

  /**
   * Copy constructor producing an independent interpolator with the same step data.
   *
   * <p>The copy performs a deep duplication of the state vectors and derivative arrays so that the
   * original and the clone can be used independently without shared mutable state. This is used by
   * the integrator's prototype pattern when handing interpolators to user code while keeping an
   * internal copy for continued integration.
   *
   * @param interpolator interpolator to copy from; its current step data and configuration are
   *     replicated into the new instance while preserving value equality and separation of backing
   *     arrays.
   */
  public ThreeEighthesStepInterpolator(ThreeEighthesStepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Create a deep copy of this interpolator carrying the current step data.
   *
   * <p>The returned instance has the same interpolated time, state, derivatives, and direction, but
   * all internal arrays are detached so mutations on one interpolator do not affect the other. This
   * method is typically called by the integrator when it needs to expose the interpolator to user
   * listeners while retaining an internal copy for continued computation.
   *
   * @return a new {@code ThreeEighthesStepInterpolator} initialized with identical data but backed
   *     by independent arrays, suitable for concurrent read-only use during the same integration
   *     step.
   */
  @Override
  public ThreeEighthesStepInterpolator copy() {
    return new ThreeEighthesStepInterpolator(this);
  }

  /**
   * Compute the interpolated state vector for a normalized position inside the current step.
   *
   * <p>The method evaluates the dense output polynomial associated with the 3/8 Runge-Kutta tableau
   * using the already-computed derivative stages {@code yDotK}. The parameter {@code theta}
   * represents the normalized abscissa in {@code [0, 1]}, where {@code 0} returns the previous grid
   * point, {@code 1} returns the current grid point, and intermediate values yield a smooth
   * fourth-order approximation. No new derivative evaluations occur; the computation is a weighted
   * linear combination of stored slopes and therefore inexpensive and deterministic.
   *
   * <pre>{@code
   * // Example: interpolate halfway through the step
   * interpolator.computeInterpolatedState(0.5, h * 0.5);
   * var midState = interpolator.getInterpolatedState();
   * }</pre>
   *
   * @param theta normalized interpolation abscissa within the step; values outside {@code [0, 1]}
   *     yield an extrapolation consistent with the polynomial but may reduce accuracy.
   * @param oneMinusThetaH signed time difference between the interpolated time and the current step
   *     end; typically equals {@code (1 - theta) * h} and may be negative for backward integration.
   * @throws DerivativeException propagated if user-provided derivative computation fails while
   *     evaluating stored slopes for interpolation.
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    double fourTheta2 = 4 * theta * theta;
    double s = oneMinusThetaH / 8.0;
    double coeff1 = s * (1 - 7 * theta + 2 * fourTheta2);
    double coeff2 = 3 * s * (1 + theta - fourTheta2);
    double coeff3 = 3 * s * (1 + theta);
    double coeff4 = s * (1 + theta + fourTheta2);

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i]
              - coeff1 * yDotK[0][i]
              - coeff2 * yDotK[1][i]
              - coeff3 * yDotK[2][i]
              - coeff4 * yDotK[3][i];
    }
  }

  /**
   * Serialization identifier preserving compatibility for serialized interpolators created with
   * this implementation; remains stable across documentation-only changes.
   */
  @Serial private static final long serialVersionUID = -3345024435978721931L;
}
