package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Step interpolator dedicated to the explicit midpoint Runge-Kutta scheme.
 *
 * <p>The interpolator recreates a continuous approximation of the solution between the last two
 * integration nodes computed by {@link MidpointIntegrator}. It relies on the two derivative
 * evaluations already produced during the step and applies the scheme-consistent interpolation
 * formula:
 *
 * <pre>
 *   y(t_n + θh) = y(t_n + h) + (1 - θ) h [ θ y'₁ - (1 + θ) y'₂ ]
 * </pre>
 *
 * where {@code θ} is in the inclusive range {@code [0, 1]}. This makes it suitable for dense output
 * generation, event detection logic that requires accurately located zero crossings, and clients
 * that need intermediate values without re-evaluating derivatives. Instances are mutable and reused
 * by the integrator; they are not thread-safe and should not be shared across concurrent
 * integrations. Typical usage is internal: callers obtain an instance from the integrator callback,
 * set the target time with {@link AbstractStepInterpolator#setInterpolatedTime}, and then read the
 * state arrays that the base class exposes.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> interpolate state values within the current step using
 *       precomputed derivatives.
 *   <li><strong>Notable behaviors:</strong> assumes a two-stage scheme; reuses cached arrays to
 *       reduce allocations.
 * </ul>
 *
 * @see MidpointIntegrator
 * @see RungeKuttaStepInterpolator
 * @see StepInterpolator
 * @version $Id: MidpointStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class MidpointStepInterpolator extends RungeKuttaStepInterpolator implements StepInterpolator {

  /**
   * Simple constructor.
   *
   * <p>The instance created by this constructor intentionally starts uninitialized so that a {@link
   * RungeKuttaIntegrator} can clone it as a prototype and defer array allocation until the actual
   * problem size is known. Call {@link AbstractStepInterpolator#reinitialize} before first use to
   * wire step data, derivatives, and the reference to the equations. This mirrors the design of
   * other step interpolators in the library and helps avoid repeated allocations during long
   * integrations.
   */
  public MidpointStepInterpolator() {}

  /**
   * Copy constructor used by the prototyping pattern.
   *
   * <p>The newly built interpolator receives deep copies of the state and derivative arrays so that
   * it can evolve independently of the original instance while keeping the same interpolation logic
   * and current step metadata.
   *
   * @param interpolator source interpolator providing current step data to duplicate; must not be
   *     {@code null}.
   */
  public MidpointStepInterpolator(MidpointStepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Create an independent copy of this interpolator.
   *
   * <p>The returned instance carries cloned state and derivative arrays that capture the current
   * interpolation context, making it safe to store beyond the lifetime of the original object
   * managed by the integrator. Later updates to either instance do not affect the other.
   *
   * @return a deep copy containing the same step data and interpolation coefficients as this
   *     instance.
   */
  @Override
  public MidpointStepInterpolator copy() {
    return new MidpointStepInterpolator(this);
  }

  /**
   * Compute the state at the currently selected interpolated time.
   *
   * <p>This method applies the midpoint-specific dense output formula using the normalized abscissa
   * {@code theta} and the cached derivative evaluations. It populates the {@code interpolatedState}
   * array provided by the base class without allocating new storage. Callers must have set the
   * target time via {@link AbstractStepInterpolator#setInterpolatedTime} before this method is
   * invoked. Input values are expected to be within the unit interval; values outside may still be
   * processed but represent extrapolation beyond the current step.
   *
   * @param theta normalized interpolation abscissa within the step; {@code 0} is start and {@code
   *     1} is end of the step; values outside perform extrapolation.
   * @param oneMinusThetaH time gap {@code (1 - theta) * h} between the interpolated time and the
   *     current step end; expressed in integration time units.
   * @throws DerivativeException if user-supplied derivative computation signaled an error while
   *     producing the stored stage values used for interpolation.
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    double coeff1 = oneMinusThetaH * theta;
    double coeff2 = oneMinusThetaH * (1.0 + theta);

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] = currentState[i] + coeff1 * yDotK[0][i] - coeff2 * yDotK[1][i];
    }
  }

  /**
   * Serialization version identifier ensuring compatibility across serialized interpolator
   * instances created with the same class definition.
   */
  @Serial private static final long serialVersionUID = -865524111506042509L;
}
