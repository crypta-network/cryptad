package org.spaceroots.mantissa.ode;

/**
 * Higham and Hall 5(4) embedded Runge-Kutta integrator with adaptive steps and continuous output.
 *
 * <p>This implementation follows the 5(4) scheme described by Higham and Hall and is wired for
 * local extrapolation: the fifth-order solution is returned while the embedded fourth-order
 * estimate drives the adaptive step-size controller. The integrator is stateful only for
 * configuration; it is otherwise thread-confined and should be created per integration run. It
 * evaluates the differential equations seven times per accepted step, balancing accuracy and
 * computational cost.
 *
 * <p>Typical usage is to instantiate the integrator with absolute and relative tolerances matching
 * the scale of the problem, then call {@link #integrate(FirstOrderDifferentialEquations, double,
 * double[], double, double[])} inherited from {@code RungeKuttaFehlbergIntegrator}. Step sizes are
 * initialized automatically within the provided bounds and may shrink when error estimates exceed
 * tolerance. The interpolator supports dense output queries between grid points.
 *
 * <p><strong>Responsibilities</strong>:
 *
 * <ul>
 *   <li>Provide coefficients for the Higham-Hall tableau and embedded error estimator.
 *   <li>Compute root-mean-square scaled error norms for adaptive control.
 *   <li>Expose metadata such as method name and formal order.
 * </ul>
 *
 * @version $Id: HighamHall54Integrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class HighamHall54Integrator extends RungeKuttaFehlbergIntegrator {

  private static final String METHOD_NAME = "Higham-Hall 5(4)";

  private static final double[] c = {2.0 / 9.0, 1.0 / 3.0, 1.0 / 2.0, 3.0 / 5.0, 1.0, 1.0};

  private static final double[][] a = {
    {2.0 / 9.0},
    {1.0 / 12.0, 1.0 / 4.0},
    {1.0 / 8.0, 0.0, 3.0 / 8.0},
    {91.0 / 500.0, -27.0 / 100.0, 78.0 / 125.0, 8.0 / 125.0},
    {-11.0 / 20.0, 27.0 / 20.0, 12.0 / 5.0, -36.0 / 5.0, 5.0},
    {1.0 / 12.0, 0.0, 27.0 / 32.0, -4.0 / 3.0, 125.0 / 96.0, 5.0 / 48.0}
  };

  private static final double[] b = {
    1.0 / 12.0, 0.0, 27.0 / 32.0, -4.0 / 3.0, 125.0 / 96.0, 5.0 / 48.0, 0.0
  };

  private static final double[] e = {
    -1.0 / 20.0, 0.0, 81.0 / 160.0, -6.0 / 5.0, 25.0 / 32.0, 1.0 / 16.0, -1.0 / 10.0
  };

  /**
   * Create an integrator configured with scalar error tolerances and bounded step sizes.
   *
   * <p>The provided absolute and relative tolerances are applied uniformly across all state
   * components. The step-size controller respects the {@code minStep} floor and {@code maxStep}
   * ceiling, but the final step may be shorter to land exactly on the target time. All parameters
   * must be strictly positive to allow both forward and backward integration.
   *
   * @param minStep the smallest step the controller will attempt before potentially failing, in the
   *     integration time units; must be greater than zero.
   * @param maxStep the largest step the controller may take; must exceed {@code minStep} and be
   *     positive even when integrating backward in time.
   * @param scalAbsoluteTolerance uniform absolute error tolerance applied to every state component;
   *     must be non-negative but typically small compared to expected state magnitudes.
   * @param scalRelativeTolerance uniform relative error tolerance used to scale with state size;
   *     must be non-negative and combined with the absolute term.
   */
  @SuppressWarnings("unused")
  public HighamHall54Integrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {
    super(
        new RungeKuttaFehlbergMethod(false, c, a, b, new HighamHall54StepInterpolator()),
        minStep,
        maxStep,
        scalAbsoluteTolerance,
        scalRelativeTolerance);
  }

  /**
   * Create an integrator configured with per-component error tolerances and bounded step sizes.
   *
   * <p>Vector tolerances let callers tune accuracy differently for each state dimension. Arrays
   * must match the problem dimension supplied to {@code integrate}. Bounds on step sizes mirror the
   * scalar constructor: they constrain the adaptive controller but do not guarantee fixed step
   * lengths. A final step may still be shortened to land exactly at the integration endpoint.
   *
   * @param minStep the smallest admissible step in time units; must be positive for both forward
   *     and backward integration scenarios.
   * @param maxStep largest admissible step; must be positive and not smaller than {@code minStep}.
   * @param vecAbsoluteTolerance element-wise absolute tolerances; each entry must be non-negative,
   *     and the array length must equal the equations dimension.
   * @param vecRelativeTolerance element-wise relative tolerances; each entry must be non-negative
   *     and combined with the absolute tolerances for scaling.
   */
  @SuppressWarnings("unused")
  public HighamHall54Integrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {
    super(
        new RungeKuttaFehlbergMethod(false, c, a, b, new HighamHall54StepInterpolator()),
        minStep,
        maxStep,
        vecAbsoluteTolerance,
        vecRelativeTolerance);
  }

  /**
   * Get a human-readable identifier for this integration method.
   *
   * <p>The returned name follows the canonical spelling used throughout the library and can be used
   * in logs, metrics, or UI labels to differentiate integrators at runtime.
   *
   * @return descriptive method name; immutable and safe for repeated calls
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }

  /**
   * Get the formal order of accuracy of the primary solution formula.
   *
   * <p>This value reflects the order used for the accepted solution (fifth order). The embedded
   * fourth-order estimate is used internally for error control and is not returned to callers.
   *
   * @return integration order of the returned solution; always {@code 5}
   */
  @Override
  public int getOrder() {
    return 5;
  }

  /**
   * Compute the scaled root-mean-square error estimate for one trial step.
   *
   * <p>The method combines stage derivatives from the embedded tableau with absolute/relative
   * tolerances to produce a dimensionless norm. The controller interprets values greater than one
   * as exceeding tolerance and will reduce the step size; values below one typically accept the
   * step. Inputs are neither validated nor copied for performance reasons, so callers must supply
   * arrays consistent with the current problem dimension.
   *
   * @param yDotK stage derivatives produced during the seven Runge-Kutta evaluations; the outer
   *     array index is the stage, and the inner index is the state component.
   * @param y0 estimate of the state at the beginning of the step; array length must equal the
   *     problem dimension.
   * @param y1 estimate of the state at the end of the step before error correction; must align with
   *     {@code y0} in length and ordering.
   * @param h current step size in integration time units; may be positive or negative depending on
   *     the integration direction.
   * @return dimensionless error ratio; values above one suggest rejecting or shrinking the step
   */
  @Override
  protected double estimateError(double[][] yDotK, double[] y0, double[] y1, double h) {

    double error = 0;

    for (int j = 0; j < y0.length; ++j) {
      double errSum = e[0] * yDotK[0][j];
      for (int l = 1; l < e.length; ++l) {
        errSum += e[l] * yDotK[l][j];
      }

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
