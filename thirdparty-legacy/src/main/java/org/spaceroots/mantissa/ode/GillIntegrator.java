package org.spaceroots.mantissa.ode;

/**
 * Fourth-order Gill Runge–Kutta integrator with fixed step size.
 *
 * <p>This explicit Runge–Kutta flavor balances round-off error by mixing the classical RK4 stages
 * with {@code sqrt(2)} coefficients. It is suited to smooth first-order systems where a constant
 * step is acceptable and dense output is either unnecessary or provided by {@link
 * GillStepInterpolator}. Typical usage creates an instance with a chosen step, optionally installs
 * a {@link StepHandler} or switching functions, and then calls {@link #integrate
 * RungeKuttaIntegrator.integrate} for each trajectory. Instances are mutable but intended for
 * sequential reuse; they are <em>not</em> thread-safe.
 *
 * <p>Notable characteristics:
 *
 * <ul>
 *   <li>Fixed step; events may truncate individual steps without changing the nominal step size.
 *   <li>Explicit tableau with four stages; no FSAL optimisation is used.
 *   <li>Accuracy comparable to classical RK4 but with improved error damping on some problems.
 * </ul>
 *
 * <p>The underlying Butcher tableau is:
 *
 * <pre>
 *    0  |    0        0       0      0
 *   1/2 |   1/2       0       0      0
 *   1/2 | (q-1)/2  (2-q)/2    0      0
 *    1  |    0       -q/2  (2+q)/2   0
 *       |-------------------------------
 *       |   1/6    (2-q)/6 (2+q)/6  1/6
 * </pre>
 *
 * with {@code q = sqrt(2)}. See {@link RungeKuttaIntegrator} for lifecycle, event handling, and
 * dense-output integration contract details.
 *
 * @see EulerIntegrator
 * @see ClassicalRungeKuttaIntegrator
 * @see MidpointIntegrator
 * @see ThreeEighthesIntegrator
 * @version $Id: GillIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class GillIntegrator extends RungeKuttaIntegrator {

  private static final String METHOD_NAME = "Gill";

  private static final double SQRT_2 = Math.sqrt(2.0);

  private static final double[] c = {1.0 / 2.0, 1.0 / 2.0, 1.0};

  private static final double[][] a = {
    {1.0 / 2.0},
    {(SQRT_2 - 1.0) / 2.0, (2.0 - SQRT_2) / 2.0},
    {0.0, -SQRT_2 / 2.0, (2.0 + SQRT_2) / 2.0}
  };

  private static final double[] b = {
    1.0 / 6.0, (2.0 - SQRT_2) / 6.0, (2.0 + SQRT_2) / 6.0, 1.0 / 6.0
  };

  /**
   * Creates a Gill integrator configured with a constant step size.
   *
   * <p>The instance may be reused across multiple {@link #integrate} calls; internal state is
   * cleared automatically after each run. Switching functions can shorten individual steps, but the
   * nominal step size provided here governs staging and output cadence.
   *
   * @param step fixed integration step expressed in the same time units as the differential
   *     equations; must be a non-zero finite value to avoid {@link IntegratorException} at runtime.
   */
  public GillIntegrator(double step) {
    super(false, c, a, b, new GillStepInterpolator(), step);
  }

  /**
   * Returns the human-readable name of this integration method.
   *
   * <p>The returned string is stable and can be logged or displayed in diagnostics to identify the
   * chosen Runge–Kutta flavor. It does not vary with step size or runtime configuration.
   *
   * @return method name string, always {@code "Gill"} for this integrator.
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }
}
