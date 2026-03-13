package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Dense-output interpolator tailored for the classical fourth-order Runge-Kutta scheme.
 *
 * <p>The interpolator reconstructs intermediate states inside the most recently completed
 * integration step, making it possible to evaluate the continuous trajectory without reducing the
 * solver step size. It applies the closed-form dense-output polynomial associated with the RK4
 * tableau, using the already computed stage derivatives {@code y'_1} through {@code y'_4} to avoid
 * any additional function calls. Clients typically obtain instances from {@link
 * ClassicalRungeKuttaIntegrator} via the standard step handler API and invoke {@link
 * #setInterpolatedTime(double)} to position the interpolation cursor within the step. The state
 * returned by {@link #getInterpolatedState()} is immutable to callers but backed by internal
 * buffers reused across calls; copy the array if retaining it beyond the current notification.
 *
 * <p>Invariants and notable behaviors:
 *
 * <ul>
 *   <li>Interpolation is defined for {@code 0 ≤ theta ≤ 1}, where {@code theta} measures progress
 *       from the previous grid point to the current one.
 *   <li>Instances are reused by the integrator; {@link #copy()} provides an isolated snapshot when
 *       step handlers need to preserve state across callbacks.
 *   <li>The class is not thread-safe; use distinct instances per integrator thread.
 * </ul>
 *
 * @see ClassicalRungeKuttaIntegrator
 * @version $Id: ClassicalRungeKuttaStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class ClassicalRungeKuttaStepInterpolator extends RungeKuttaStepInterpolator
    implements StepInterpolator {

  /**
   * Simple constructor used by the integrator's prototype mechanism to create fresh interpolators.
   * The instance starts in an uninitialized state; callers must invoke {@link
   * RungeKuttaStepInterpolator#reinitialize(FirstOrderDifferentialEquations,double[],double[][],boolean)}
   * before the first use so that the internal state buffers point to the step data managed by the
   * integrator. This deferred initialization keeps allocation costs low when many interpolators are
   * cloned for event or handler chains.
   */
  public ClassicalRungeKuttaStepInterpolator() {}

  /**
   * Copy constructor that performs a deep copy of all mutable interpolation buffers.
   *
   * <p>The copied instance shares no arrays with the source, allowing step handlers to retain the
   * duplicate safely after the integrator proceeds to the next step. Scalar configuration such as
   * direction flags are copied verbatim.
   *
   * @param interpolator interpolator to copy from; must be already initialized for meaningful data.
   */
  public ClassicalRungeKuttaStepInterpolator(ClassicalRungeKuttaStepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Create an independent clone of this interpolator with detached state arrays.
   *
   * <p>Use this method when a step handler needs to retain interpolation results beyond the current
   * callback. The returned instance can be moved to different interpolation times without affecting
   * the original, because all internal buffers are duplicated during cloning.
   *
   * @return a new {@code ClassicalRungeKuttaStepInterpolator} holding copies of the current state
   *     arrays and configuration flags.
   */
  @Override
  public ClassicalRungeKuttaStepInterpolator copy() {
    return new ClassicalRungeKuttaStepInterpolator(this);
  }

  /**
   * Compute the state vector corresponding to the current interpolated time within the step.
   *
   * <p>The implementation evaluates the dense-output polynomial associated with the RK4 tableau
   * using the four stored derivative evaluations {@code yDotK}. The {@code theta} argument defines
   * where the interpolation point lies between the previous grid point and the current one, while
   * {@code oneMinusThetaH} supplies the precomputed time offset in seconds. The method overwrites
   * the internal {@code interpolatedState} buffer; callers should access it via {@link
   * #getInterpolatedState()} after invocation.
   *
   * @param theta normalized abscissa in {@code [0, 1]} representing progress across the current
   *     integration step; values outside the range lead to extrapolation.
   * @param oneMinusThetaH signed time gap between the interpolated instant and the current step end
   *     time, typically {@code (1 - theta) * h} where {@code h} is the step size.
   * @throws DerivativeException propagated if a user-supplied derivative function triggers it
   *     during interpolation support logic in the parent class.
   */
  @Override
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    double fourTheta = 4 * theta;
    double s = oneMinusThetaH / 6.0;
    double coeff1 = s * ((-fourTheta + 5) * theta - 1);
    double coeff23 = s * ((fourTheta - 2) * theta - 2);
    double coeff4 = s * ((-fourTheta - 1) * theta - 1);

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i]
              + coeff1 * yDotK[0][i]
              + coeff23 * (yDotK[1][i] + yDotK[2][i])
              + coeff4 * yDotK[3][i];
    }
  }

  /**
   * Serialization version identifier preserving compatibility for persisted interpolator snapshots
   * across library releases that retain the same field layout.
   */
  @Serial private static final long serialVersionUID = -6576285612589783992L;
}
