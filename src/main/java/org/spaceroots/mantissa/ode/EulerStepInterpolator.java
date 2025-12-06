package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Linear dense-output helper tailored to explicit Euler steps.
 *
 * <p>An {@code EulerStepInterpolator} reconstructs intermediate states for the most recent step of
 * an {@link EulerIntegrator} without re-evaluating user derivatives. It stores the terminal state
 * and the single Euler slope {@code yDotK[0]} computed by the integrator, then answers
 * interpolation queries using the scheme-consistent relation {@code y(t_n + theta*h) = y(t_n + h) -
 * (1 - theta)*h * y'}. The instance is mutable and reused by the integrator across steps; callers
 * should finalize and copy when they need to keep a snapshot beyond the current handler callback.
 *
 * <p>Lifecycle expectations:
 *
 * <ul>
 *   <li>Construct (or clone) an uninitialized prototype.
 *   <li>{@link #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)}
 *       supplies step data before storage.
 *   <li>{@link #storeTime(double)} records the step end; {@link #setInterpolatedTime(double)}
 *       answers dense-output queries.
 *   <li>{@link #copy()} creates deep, independent snapshots once {@link #finalizeStep()} has been
 *       executed.
 * </ul>
 *
 * <p>The class is not thread-safe and assumes single-threaded integrator access. Interpolation is
 * valid in either forward or backward integration direction; extrapolation outside the step is
 * permitted but may reduce accuracy.
 *
 * @see EulerIntegrator
 * @see RungeKuttaStepInterpolator
 * @version $Id: EulerStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class EulerStepInterpolator extends RungeKuttaStepInterpolator implements StepInterpolator {

  /**
   * Create an uninitialized prototype ready for later reuse.
   *
   * <p>The instance contains no allocated state buffers until {@link
   * AbstractStepInterpolator#reinitialize(double[], boolean)} or its Runge-Kutta specific overload
   * is invoked. Integrators use this constructor when applying the prototype/clone pattern to limit
   * allocation churn during long integrations.
   */
  public EulerStepInterpolator() {}

  /**
   * Copy constructor creating a deep, detached interpolator.
   *
   * <p>Use this when an already finalized interpolator must be retained after the integrator moves
   * to the next step. Arrays storing state and derivatives are duplicated so the new instance
   * cannot be mutated by future integration activity, and references to the equations are
   * intentionally cleared.
   *
   * @param interpolator source instance that has been finalized; its arrays are deep-copied and the
   *     equations reference intentionally dropped.
   */
  public EulerStepInterpolator(EulerStepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Create a deep copy preserving the finalized step data.
   *
   * <p>The returned interpolator shares no array references with the original, so subsequent
   * integrator mutations or slope updates cannot affect the copy. Callers should ensure {@link
   * #finalizeStep()} has run on the source before invoking this method so derivative data is
   * complete when stored.
   *
   * @return a new {@code EulerStepInterpolator} holding identical step bounds, direction flags, and
   *     cached interpolated state that are safe to keep beyond the current integration step.
   */
  @Override
  public EulerStepInterpolator copy() {
    return new EulerStepInterpolator(this);
  }

  /**
   * Compute the interpolated state for a requested time inside or near the current step.
   *
   * <p>This Euler-specific implementation applies linear reconstruction using the single stored
   * slope. It writes results into {@link #interpolatedState} without allocating new arrays and does
   * not modify {@link #currentState}. Callers may request times outside the nominal step bounds; in
   * that case the same linear relation is used for extrapolation.
   *
   * @param theta normalized position in the step, where {@code 0} maps to the previous grid point
   *     and {@code 1} to the current grid point; values outside [0, 1] request extrapolation.
   * @param oneMinusThetaH signed time offset {@code currentTime - interpolatedTime}; positive when
   *     integrating forward, negative when stepping backward.
   * @throws DerivativeException propagated if underlying derivative computations deferred to
   *     finalization fail before interpolation proceeds.
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] = currentState[i] - oneMinusThetaH * yDotK[0][i];
    }
  }

  /**
   * Serialization identifier preserving compatibility across releases of the interpolator class.
   *
   * <p>The value remains stable so dense-output snapshots stored by integrators can be safely
   * deserialized in later runs without violating {@link java.io.Serializable} contracts. It does
   * not influence interpolation logic or runtime behavior.
   */
  @Serial private static final long serialVersionUID = -7179861704951334960L;
}
