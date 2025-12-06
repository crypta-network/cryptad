package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Interpolates states inside the last accepted step of the 5(4) Higham and Hall Runge-Kutta scheme.
 *
 * <p>Instances are created by {@link HighamHall54Integrator} as part of the dense output mechanism.
 * The interpolator stores the step derivatives produced by the integrator and rebuilds an
 * intermediate state for any normalized abscissa {@code theta} in {@code [0, 1]} without
 * re-evaluating user derivatives. Callers typically receive a fully initialized instance from the
 * integrator and then query it repeatedly while {@link StepHandler} callbacks are executing. The
 * interpolator is mutable during initialization and reuse, but once {@link
 * org.spaceroots.mantissa.ode.AbstractStepInterpolator#finalizeStep finalizeStep} has been called
 * for a step it can be safely read by a single thread until the next step replaces its buffers. It
 * does not perform synchronization and should therefore not be shared across threads without
 * external coordination.
 *
 * <p>Notable characteristics include:
 *
 * <ul>
 *   <li>Uses a quintic polynomial tailored to the Higham–Hall tableau to achieve 4th order accuracy
 *       between grid points.
 *   <li>Avoids additional ODE function evaluations by reusing stored stage derivatives.
 *   <li>Supports cloning via {@link #copy()} so integrators can prototype and duplicate instances
 *       efficiently.
 * </ul>
 *
 * @see HighamHall54Integrator
 * @see RungeKuttaStepInterpolator
 * @version $Id: HighamHall54StepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class HighamHall54StepInterpolator extends RungeKuttaStepInterpolator implements StepInterpolator {

  /**
   * Builds an uninitialized interpolator shell for later reuse.
   *
   * <p>The instance created by this constructor does not yet contain any step data. Callers must
   * invoke {@link AbstractStepInterpolator#reinitialize(double[], boolean)} (indirectly through the
   * owning integrator) before requesting interpolated states. This lazy construction is used by
   * integrators that clone a prototype per step to avoid repeatedly allocating storage. Until
   * reinitialized, accessing interpolation values is unsupported.
   */
  public HighamHall54StepInterpolator() {
    super();
  }

  /**
   * Creates a deep copy of another interpolator instance.
   *
   * <p>All internal arrays are duplicated so that subsequent mutations of the source or the copy do
   * not interfere. This constructor is primarily used by the prototype pattern inside Runge Kutta
   * integrators when they need to supply a fresh interpolator for a new step while retaining
   * previously computed data in the original.
   *
   * @param interpolator interpolator to copy from; must already be initialized for the step being
   *     cloned so the new instance has consistent derivative buffers
   */
  public HighamHall54StepInterpolator(HighamHall54StepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Returns a cloned interpolator carrying the same step data.
   *
   * <p>The returned instance owns its own arrays and can be mutated independently of the original.
   * It is typically used by integrators when they need to preserve the state of the current step
   * while preparing the next one.
   *
   * @return a new {@code HighamHall54StepInterpolator} with duplicated internal buffers and step
   *     parameters
   */
  @Override
  public HighamHall54StepInterpolator copy() {
    return new HighamHall54StepInterpolator(this);
  }

  /**
   * Compute the state vector at a normalized abscissa inside the current step.
   *
   * <p>This method evaluates the Higham–Hall dense output polynomial using the stage derivatives
   * from the last completed step. It assumes all interpolation arrays have already been set up by
   * {@link org.spaceroots.mantissa.ode.AbstractStepInterpolator#reinitialize(double[], boolean)}
   * and {@link org.spaceroots.mantissa.ode.AbstractStepInterpolator#finalizeStep()} before
   * invocation. No additional derivative evaluations occur; only stored values are combined. The
   * computation is linear in the dimension of the state vector and produces results consistent with
   * a 4th order polynomial in {@code theta}.
   *
   * @param theta normalized abscissa in the current step; {@code 0} targets the start and {@code 1}
   *     targets the end of the step, with intermediate values yielding interpolated states
   * @param oneMinusThetaH current step size multiplied by {@code (1 - theta)}; retained for API
   *     compatibility although not used by this implementation
   * @throws DerivativeException if user-supplied derivative code raised an exception during step
   *     preparation; propagated unchanged to preserve caller handling
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    double theta2 = theta * theta;

    double b0 =
        h
            * (-1.0 / 12.0
                + theta
                    * (1.0 + theta * (-15.0 / 4.0 + theta * (16.0 / 3.0 + theta * -5.0 / 2.0))));
    double b2 =
        h * (-27.0 / 32.0 + theta2 * (459.0 / 32.0 + theta * (-243.0 / 8.0 + theta * 135.0 / 8.0)));
    double b3 = h * (4.0 / 3.0 + theta2 * (-22.0 + theta * (152.0 / 3.0 + theta * -30.0)));
    double b4 =
        h
            * (-125.0 / 96.0
                + theta2 * (375.0 / 32.0 + theta * (-625.0 / 24.0 + theta * 125.0 / 8.0)));
    double b5 = h * (-5.0 / 48.0 + theta2 * (-5.0 / 16.0 + theta * 5.0 / 12.0));

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i]
              + b0 * yDotK[0][i]
              + b2 * yDotK[2][i]
              + b3 * yDotK[3][i]
              + b4 * yDotK[4][i]
              + b5 * yDotK[5][i];
    }
  }

  /**
   * Serialization identifier preserving compatibility of interpolator instances across versions.
   * The value is constant and does not participate in runtime interpolation behavior.
   */
  @Serial private static final long serialVersionUID = -3583240427587318654L;
}
