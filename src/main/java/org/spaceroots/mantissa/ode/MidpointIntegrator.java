package org.spaceroots.mantissa.ode;

/**
 * Second-order explicit Runge–Kutta (midpoint) integrator for first-order ordinary differential
 * equations using a constant step size.
 *
 * <p>This implementation executes the classical midpoint tableau:
 *
 * <pre>
 *    0  |  0    0
 *   1/2 | 1/2   0
 *       |----------
 *       |  0    1
 * </pre>
 *
 * and wires it into the shared fixed-step control flow provided by {@link RungeKuttaIntegrator}.
 * The instance is mutable but intended for single-threaded reuse across multiple integration runs;
 * create one instance per concurrent integration to avoid shared mutable state. Dense output is
 * available through {@link MidpointStepInterpolator} when the registered {@link StepHandler}
 * requests it. The nominal step size is never adapted automatically, but individual steps can be
 * shortened when switching functions signal an event, after which the original cadence resumes.
 *
 * <p>Typical usage follows a "create–configure–integrate" pattern:
 *
 * <ul>
 *   <li>Construct the integrator with a positive step size matching the equation time units.
 *   <li>Optionally install a {@link StepHandler} and switching functions to observe or stop runs.
 *   <li>Call {@link #integrate(FirstOrderDifferentialEquations, double, double[], double,
 *       double[])} with matching state vectors for each trajectory.
 * </ul>
 *
 * <p>Use this integrator when a lightweight, fixed-step scheme suffices and the modest accuracy of
 * a second-order method meets requirements. For stiffer problems or tighter tolerances, prefer the
 * higher-order Runge–Kutta variants in this package.
 *
 * @see EulerIntegrator
 * @see ClassicalRungeKuttaIntegrator
 * @see GillIntegrator
 * @version $Id: MidpointIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class MidpointIntegrator extends RungeKuttaIntegrator {

  private static final String METHOD_NAME = "midpoint";

  private static final double[] c = {1.0 / 2.0};

  private static final double[][] a = {{1.0 / 2.0}};

  private static final double[] b = {0.0, 1.0};

  /**
   * Build a midpoint integrator configured with the provided fixed step size.
   *
   * <p>The created instance is ready for immediate use and may be reused sequentially across
   * multiple integration runs. The {@code step} value must be expressed in the same units as the
   * independent variable of the supplied {@link FirstOrderDifferentialEquations}. Negative values
   * are allowed to support backward integration; zero is rejected at runtime by the base class
   * validation. Dense-output interpolation is available when callers install a {@link StepHandler}
   * that requests it.
   *
   * @param step constant integration step size, in equation time units; positive for forward
   *     traversal, negative for backward traversal; must be non-zero.
   */
  public MidpointIntegrator(double step) {
    super(false, c, a, b, new MidpointStepInterpolator(), step);
  }

  /**
   * Return the human-readable identifier for this integration scheme.
   *
   * <p>The name is stable across releases and matches the conventional label used in logs, user
   * interfaces, and algorithm selection helpers inside the library. The value is independent of any
   * runtime configuration such as step size and is suitable for display or switch-based dispatch.
   *
   * @return constant string {@code "midpoint"} identifying this Runge–Kutta variant; the caller
   *     must not modify or cache assumptions about capitalization beyond this literal.
   */
  public String getName() {
    return METHOD_NAME;
  }
}
