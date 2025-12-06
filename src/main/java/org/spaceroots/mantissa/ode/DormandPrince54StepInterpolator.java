package org.spaceroots.mantissa.ode;

import java.io.Serial;

/**
 * Interpolator that provides dense output for a Dormand-Prince 5(4) Runge-Kutta step.
 *
 * <p>The instance is created by {@link DormandPrince54Integrator} and reused between successive
 * steps so that intermediate states can be queried at arbitrary normalized positions inside the
 * current step. The interpolator computes the Shampine dense-output polynomial once per step,
 * caches its intermediate vectors, and exposes the interpolated state without altering the
 * underlying integrator state. Instances are mutable and stateful: callers must invoke {@link
 * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)} and {@link
 * #storeTime(double)} as the integrator progresses. No internal synchronization is provided; a
 * single instance must be confined to the integration thread that owns it.
 *
 * <p>Typical usage links the interpolator lifetime to a single integration run. The integrator
 * calls {@code reinitialize} when a step starts, {@code storeTime} when a step ends, and the client
 * invokes {@code computeInterpolatedState} with a normalized abscissa to obtain a continuous view
 * of the solution across the accepted step. The class assumes the step size and stage derivatives
 * remain unchanged between these calls.
 *
 * <ul>
 *   <li>Responsibility: assemble dense-output coefficients specific to the Dormand-Prince 5(4)
 *       tableau.
 *   <li>Behavior: lazily initializes and reuses interpolation vectors to limit allocations.
 *   <li>Thread-safety: not thread-safe; intended for single-threaded integration pipelines.
 * </ul>
 *
 * @see DormandPrince54Integrator
 * @version $Id: DormandPrince54StepInterpolator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
class DormandPrince54StepInterpolator extends RungeKuttaStepInterpolator
    implements StepInterpolator {

  /**
   * Create an uninitialized interpolator ready to be wired into an integrator.
   *
   * <p>The constructor intentionally leaves the internal interpolation vectors {@code null} so that
   * allocation can be delayed until the owning integrator knows the problem dimension. Call {@link
   * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)} before
   * requesting any interpolated state; otherwise the instance does not contain valid buffers. This
   * pattern enables prototype-based creation, where the integrator clones a blank model for each
   * integration run.
   */
  public DormandPrince54StepInterpolator() {
    super();
    v1 = null;
    v2 = null;
    v3 = null;
    v4 = null;
    vectorsInitialized = false;
  }

  /**
   * Build a new interpolator by deeply copying another instance.
   *
   * <p>All cached interpolation vectors are cloned so that the returned object evolves
   * independently from {@code interpolator}. Scalar state such as the step size, direction flag,
   * and stored times are propagated as well, mirroring the snapshot used by the parent integrator
   * when it needs a safe duplicate for event detection or user callbacks.
   *
   * @param interpolator source interpolator providing the cached stage data and runtime state; may
   *     be partially uninitialized when constructed by the integrator.
   */
  public DormandPrince54StepInterpolator(DormandPrince54StepInterpolator interpolator) {

    super(interpolator);

    if (interpolator.v1 == null) {

      v1 = null;
      v2 = null;
      v3 = null;
      v4 = null;
      vectorsInitialized = false;

    } else {

      v1 = interpolator.v1.clone();
      v2 = interpolator.v2.clone();
      v3 = interpolator.v3.clone();
      v4 = interpolator.v4.clone();
      vectorsInitialized = interpolator.vectorsInitialized;
    }
  }

  @Override
  public DormandPrince54StepInterpolator copy() {
    return new DormandPrince54StepInterpolator(this);
  }

  /**
   * Reinitialize the interpolator for a new Dormand-Prince 5(4) step.
   *
   * <p>The method resets cached interpolation vectors and records references to the integrator
   * arrays that hold the current step data. Array references are borrowed, not copied, so the
   * caller must ensure they remain stable until the step is finalized. After calling this method,
   * invoke {@link #storeTime(double)} for the step end time and call {@link
   * #computeInterpolatedState(double, double)} to obtain dense output.
   *
   * @param equations set of differential equations defining {@code y'}; used only for dimension
   *     consistency.
   * @param y reference to the state vector at the end of the current step; must match dimension.
   * @param yDotK stage derivatives for the step, indexed by stage then component; reused in-place.
   * @param forward {@code true} if time increases during integration; influences interpolation
   *     direction handling.
   */
  @Override
  public void reinitialize(
      FirstOrderDifferentialEquations equations, double[] y, double[][] yDotK, boolean forward) {
    super.reinitialize(equations, y, yDotK, forward);
    v1 = null;
    v2 = null;
    v3 = null;
    v4 = null;
    vectorsInitialized = false;
  }

  /**
   * Store the current step end time and clear cached interpolation vectors.
   *
   * <p>The integrator invokes this method once per accepted step to record the step boundary. Any
   * previously computed interpolation vectors become invalid because the step size or slope data
   * may have changed. Subsequent calls to {@link #computeInterpolatedState(double, double)} will
   * lazily rebuild the vectors for the new step before returning an interpolated state.
   *
   * @param t current step end time in the integrator's time unit; reused for interpolation bounds.
   */
  @Override
  public void storeTime(double t) {
    super.storeTime(t);
    vectorsInitialized = false;
  }

  /**
   * Compute the state vector at an interpolated point inside the current step.
   *
   * <p>The method lazily builds the dense-output polynomial coefficients for the Dormand-Prince
   * 5(4) tableau the first time it is invoked after {@link #storeTime(double)}. It then evaluates
   * the polynomial using the normalized position {@code theta} and the already-computed stage
   * derivatives. Inputs are treated as dimensionless fractions of the current step: {@code theta}
   * equals {@code 0} at the previous grid point and {@code 1} at the current one, while {@code
   * oneMinusThetaH} conveys the scaled distance to the end of the step. No derivative evaluations
   * occur inside this method; it strictly combines cached data.
   *
   * @param theta normalized interpolation abscissa in [0, 1]; values outside range extrapolate.
   * @param oneMinusThetaH signed gap between the interpolated time and the current step end, in the
   *     same units as the integrator step size.
   * @throws DerivativeException if the parent integration infrastructure needs derivatives and
   *     their evaluation fails or is refused by the user function.
   */
  @Override
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    if (!vectorsInitialized) {

      if (v1 == null) {
        v1 = new double[interpolatedState.length];
        v2 = new double[interpolatedState.length];
        v3 = new double[interpolatedState.length];
        v4 = new double[interpolatedState.length];
      }

      // no step finalization is needed for this interpolator

      // we need to compute the interpolation vectors for this time step
      for (int i = 0; i < interpolatedState.length; ++i) {
        v1[i] =
            h
                * (A70 * yDotK[0][i]
                    + A72 * yDotK[2][i]
                    + A73 * yDotK[3][i]
                    + A74 * yDotK[4][i]
                    + A75 * yDotK[5][i]);
        v2[i] = h * yDotK[0][i] - v1[i];
        v3[i] = v1[i] - v2[i] - h * yDotK[6][i];
        v4[i] =
            h
                * (D0 * yDotK[0][i]
                    + D2 * yDotK[2][i]
                    + D3 * yDotK[3][i]
                    + D4 * yDotK[4][i]
                    + D5 * yDotK[5][i]
                    + D6 * yDotK[6][i]);
      }

      vectorsInitialized = true;
    }

    // interpolate
    double eta = oneMinusThetaH / h;
    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i] - eta * (v1[i] - theta * (v2[i] + theta * (v3[i] + eta * v4[i])));
    }
  }

  /** First vector for interpolation. */
  private double[] v1;

  /** Second vector for interpolation. */
  private double[] v2;

  /** Third vector for interpolation. */
  private double[] v3;

  /** Fourth vector for interpolation. */
  private double[] v4;

  /** Initialization indicator for the interpolation vectors. */
  private boolean vectorsInitialized;

  // last row of the Butcher-array internal weights, note that a71 is null
  private static final double A70 = 35.0 / 384.0;
  private static final double A72 = 500.0 / 1113.0;
  private static final double A73 = 125.0 / 192.0;
  private static final double A74 = -2187.0 / 6784.0;
  private static final double A75 = 11.0 / 84.0;

  // dense output of Shampine (1986), note that d1 is null
  private static final double D0 = -12715105075.0 / 11282082432.0;
  private static final double D2 = 87487479700.0 / 32700410799.0;
  private static final double D3 = -10690763975.0 / 1880347072.0;
  private static final double D4 = 701980252875.0 / 199316789632.0;
  private static final double D5 = -1453857185.0 / 822651844.0;
  private static final double D6 = 69997945.0 / 29380423.0;

  @Serial private static final long serialVersionUID = 4104157279605906956L;
}
