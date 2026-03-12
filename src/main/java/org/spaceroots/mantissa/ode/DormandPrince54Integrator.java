package org.spaceroots.mantissa.ode;

/**
 * Implements the 5(4) Dormand–Prince embedded Runge–Kutta integrator for systems of ordinary
 * differential equations.
 *
 * <p>Instances provide adaptive step size control, automatic initial step estimation, dense output
 * through a step interpolator, and the <i>first same as last</i> (FSAL) optimization that reuses
 * the final derivative of a successful step as the initial derivative of the next one. The method
 * evaluates seven intermediate stages per attempted step, but the FSAL property lowers the cost of
 * accepted steps to six function evaluations. Step acceptance is driven by the embedded 5th/4th
 * order pair, allowing the higher-order estimate to propagate while the lower-order estimate bounds
 * the local truncation error. Typical usage constructs the integrator with bounds and tolerances,
 * registers any {@link StepHandler}, and calls {@link #integrate(FirstOrderDifferentialEquations,
 * double, double[], double, double[])} to evolve state toward the target time.
 *
 * <p>Lifecycle considerations:
 *
 * <ul>
 *   <li>Instances are mutable and not thread-safe; confine one integrator to a single integration
 *       run at a time.
 *   <li>Step sizes remain within {@code minStep} and {@code maxStep}; the last step may be shorter
 *       to land exactly on the target time or an event.
 *   <li>Tolerances may be scalar or per-component vectors; callers must provide vectors matching
 *       the equation dimension.
 * </ul>
 *
 * <p>Historically, this scheme was published by Dormand and Prince (1980) and extended with
 * continuous output by Shampine (1986); see the original paper for coefficient derivations.
 */
public class DormandPrince54Integrator extends RungeKuttaFehlbergIntegrator {

  private static final String METHOD_NAME = "Dormand-Prince 5(4)";

  private static final double[] C = {1.0 / 5.0, 3.0 / 10.0, 4.0 / 5.0, 8.0 / 9.0, 1.0, 1.0};

  private static final double[][] A = {
    {1.0 / 5.0},
    {3.0 / 40.0, 9.0 / 40.0},
    {44.0 / 45.0, -56.0 / 15.0, 32.0 / 9.0},
    {19372.0 / 6561.0, -25360.0 / 2187.0, 64448.0 / 6561.0, -212.0 / 729.0},
    {9017.0 / 3168.0, -355.0 / 33.0, 46732.0 / 5247.0, 49.0 / 176.0, -5103.0 / 18656.0},
    {35.0 / 384.0, 0.0, 500.0 / 1113.0, 125.0 / 192.0, -2187.0 / 6784.0, 11.0 / 84.0}
  };

  private static final double[] B = {
    35.0 / 384.0, 0.0, 500.0 / 1113.0, 125.0 / 192.0, -2187.0 / 6784.0, 11.0 / 84.0, 0.0
  };

  private static final double E1 = 71.0 / 57600.0;
  private static final double E3 = -71.0 / 16695.0;
  private static final double E4 = 71.0 / 1920.0;
  private static final double E5 = -17253.0 / 339200.0;
  private static final double E6 = 22.0 / 525.0;
  private static final double E7 = -1.0 / 40.0;

  /**
   * Creates an integrator with scalar error tolerances and explicit step size bounds.
   *
   * <p>Use this constructor when all state components should share the same absolute and relative
   * tolerances. The integrator automatically chooses an initial step respecting the supplied
   * bounds, adapts step sizes to maintain the requested accuracy, and reuses the FSAL derivative
   * shortcut on accepted steps. Step sizes remain positive in magnitude regardless of the chosen
   * integration direction, and the last step may be shorter to reach the exact target time.
   *
   * @param minStep minimum allowed positive step size, applied even during backward integration.
   * @param maxStep maximum allowed positive step size, not smaller than {@code minStep}.
   * @param scalAbsoluteTolerance uniform absolute error bound applied to every state component.
   * @param scalRelativeTolerance uniform relative error bound scaled by each component magnitude.
   */
  public DormandPrince54Integrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {
    super(
        new RungeKuttaFehlbergMethod(true, C, A, B, new DormandPrince54StepInterpolator()),
        minStep,
        maxStep,
        scalAbsoluteTolerance,
        scalRelativeTolerance);
  }

  /**
   * Creates an integrator with per-component error tolerances and step size bounds.
   *
   * <p>Use this overload when different state coordinates require distinct absolute or relative
   * tolerances. The provided vectors must match the dimension reported by the underlying equations;
   * values are consumed as-is and must be non-negative. Step sizes adapt between {@code minStep}
   * and {@code maxStep}, and the final step may be shorter to align with the target time or an
   * event located by the switching functions handler.
   *
   * @param minStep minimum allowed positive step size, reused for forward and backward runs.
   * @param maxStep maximum allowed positive step size that caps automatic growth.
   * @param vecAbsoluteTolerance absolute error bounds per component; length equals problem
   *     dimension.
   * @param vecRelativeTolerance relative error bounds per component; length equals problem
   *     dimension.
   */
  public DormandPrince54Integrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {
    super(
        new RungeKuttaFehlbergMethod(true, C, A, B, new DormandPrince54StepInterpolator()),
        minStep,
        maxStep,
        vecAbsoluteTolerance,
        vecRelativeTolerance);
  }

  /**
   * Returns the short human-readable identifier of this integration method.
   *
   * <p>The name can be used in logs, diagnostics, or UI surfaces to indicate which embedded
   * Runge–Kutta scheme produced a particular integration result. The returned string is constant
   * across instances and does not include tolerance or step-size configuration.
   *
   * @return a stable method name describing the Dormand–Prince 5(4) scheme.
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }

  /**
   * Reports the algebraic order of the propagated solution.
   *
   * <p>The Dormand–Prince 5(4) pair uses the fifth-order estimate for the accepted state and the
   * embedded fourth-order estimate to control local error. This method exposes the propagated order
   * so callers can reason about expected convergence rates or select schemes dynamically.
   *
   * @return the integer order (five) of the accepted solution estimate.
   */
  @Override
  public int getOrder() {
    return 5;
  }

  /**
   * Computes the normalized root-mean-square local error estimate for a tentative step.
   *
   * <p>The implementation combines the Dormand–Prince error coefficients with the stage derivatives
   * to form the embedded fourth-order estimate, scales each component by the greater scale of the
   * start and end state, and divides by either scalar or per-component tolerances. The returned
   * value is compared against {@code 1.0}; values above one trigger a rejected step and step-size
   * reduction, while values below one permit acceptance. The calculation is deterministic and
   * agnostic to the integration direction.
   *
   * @param yDotK derivatives for all Runge–Kutta stages; index {@code [k][j]} stores stage {@code
   *     k} for component {@code j}.
   * @param y0 state estimate at the beginning of the step; used for scaling each component.
   * @param y1 state estimate at the end of the step produced by the higher-order formula.
   * @param h signed step size that was attempted when computing {@code yDotK}.
   * @return error ratio; values greater than one cause step rejection and resizing.
   */
  @Override
  protected double estimateError(double[][] yDotK, double[] y0, double[] y1, double h) {

    double error = 0;

    for (int j = 0; j < y0.length; ++j) {
      double errSum =
          E1 * yDotK[0][j]
              + E3 * yDotK[2][j]
              + E4 * yDotK[3][j]
              + E5 * yDotK[4][j]
              + E6 * yDotK[5][j]
              + E7 * yDotK[6][j];

      double yScale = Math.max(Math.abs(y0[j]), Math.abs(y1[j]));
      double tol =
          (vecAbsoluteTolerance == null)
              ? (scalAbsoluteTolerance + scalRelativeTolerance * yScale)
              : (vecAbsoluteTolerance[j] + vecRelativeTolerance[j] * yScale);
      double ratio = h * errSum / tol;
      error += ratio * ratio;
    }

    return Math.sqrt(error / y0.length);
  }
}
