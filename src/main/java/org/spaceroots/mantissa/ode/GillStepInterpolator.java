package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Step interpolator specialized for the Gill fourth-order Runge–Kutta scheme.
 *
 * <p>This interpolator reconstructs a continuous state estimate inside the most recently accepted
 * integration step by reusing the four derivative evaluations produced by the Gill integrator. It
 * is intended to be instantiated by {@link GillIntegrator}, passed to step handlers, and queried by
 * callers that need values at arbitrary intermediate times without triggering extra derivative
 * evaluations. The life cycle follows the pattern of this package: create an empty instance, {@link
 * AbstractStepInterpolator#reinitialize reinitialize} it once step data is available, clone it when
 * snapshots must be retained, and then interpolate repeatedly while the cached step remains valid.
 *
 * <p>Instances are mutable and not thread-safe; each thread should work with its own copy to avoid
 * races while reading and writing internal arrays. The interpolation formula preserves the Gill
 * method invariants, assumes {@code theta} is within {@code [0, 1]}, and performs purely algebraic
 * combinations of the stored stages, so performance is dominated by array arithmetic rather than
 * additional function calls. Accuracy matches the parent integrator’s fourth-order dense output for
 * interior points of the current step.
 *
 * <ul>
 *   <li>Provides dense output aligned with the Gill Runge–Kutta tableau.
 *   <li>Supports cloning so multiple consumers can safely hold step snapshots.
 *   <li>Requires explicit reinitialization before any interpolation call.
 * </ul>
 *
 * @see GillIntegrator
 * @see RungeKuttaStepInterpolator
 * @author L. Maisonobe
 * @version $Id: GillStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 */
class GillStepInterpolator extends RungeKuttaStepInterpolator implements StepInterpolator {

  /**
   * Creates an uninitialized interpolator ready for deferred setup.
   *
   * <p>The instance does not yet contain step data or allocated buffers for the interpolated state.
   * Callers must invoke {@link AbstractStepInterpolator#reinitialize} to bind the current step
   * arrays, otherwise any attempt to interpolate will be invalid. {@link RungeKuttaIntegrator} uses
   * this constructor to create a prototype that it clones and initializes lazily as steps are
   * accepted.
   */
  public GillStepInterpolator() {}

  /**
   * Copy constructor.
   *
   * <p>The new interpolator duplicates state, derivative stages, and timing metadata from the
   * source so later mutations do not affect the original. Step handlers typically use this to cache
   * a snapshot while the integrator advances.
   *
   * @param interpolator interpolator to copy from; should be initialized to capture meaningful
   *     state.
   */
  public GillStepInterpolator(GillStepInterpolator interpolator) {
    super(interpolator);
  }

  @Override
  public GillStepInterpolator copy() {
    return new GillStepInterpolator(this);
  }

  /**
   * Computes the interpolated state inside the current Gill step.
   *
   * <p>This method applies the dense-output polynomial tied to the Gill RK4 tableau. It consumes
   * the precomputed stage derivatives in {@code yDotK}, combines them with the normalized position
   * {@code theta}, and writes the resulting coordinates into {@code interpolatedState} without
   * altering the original step data. No additional derivative evaluations occur; the computation is
   * deterministic given the stored stages and the supplied interpolation abscissa.
   *
   * @param theta normalized position in the step, {@code 0} at start and {@code 1} at end; callers
   *     should keep it within the closed interval {@code [0, 1]}.
   * @param oneMinusThetaH time offset from the interpolation instant to the step end, using the
   *     same units as the integrator step size; typically {@code (1 - theta) * h}.
   * @throws DerivativeException if previously computed derivatives could not be reused to form a
   *     consistent interpolated state.
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    double fourTheta = 4 * theta;
    double s = oneMinusThetaH / 6.0;
    double soMt = s * (1 - theta);
    double c23 = soMt * (1 + 2 * theta);
    double coeff1 = soMt * (1 - fourTheta);
    double coeff2 = c23 * TMQ;
    double coeff3 = c23 * TPQ;
    double coeff4 = s * (1 + theta * (1 + fourTheta));

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i]
              - coeff1 * yDotK[0][i]
              - coeff2 * yDotK[1][i]
              - coeff3 * yDotK[2][i]
              - coeff4 * yDotK[3][i];
    }
  }

  /** First Gill coefficient. */
  private static final double TMQ = 2 - Math.sqrt(2.0);

  /** Second Gill coefficient. */
  private static final double TPQ = 2 + Math.sqrt(2.0);

  /**
   * Serialization identifier ensuring compatible stream representation across versions of this
   * interpolator implementation.
   */
  @Serial private static final long serialVersionUID = -107804074496313322L;
}
