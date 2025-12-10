package org.spaceroots.mantissa.ode;

/**
 * Fixed-step explicit Euler integrator for first-order ordinary differential equations.
 *
 * <p>This class implements the canonical forward-Euler scheme, updating the state as {@code
 * y(t+h)=y(t)+h*y'(t)} using a single derivative evaluation per step. It deliberately favors
 * simplicity over accuracy and stability, which makes it useful as a pedagogical baseline or as a
 * quick comparator against higher-order methods when profiling algorithms or validating test
 * infrastructure. Dense output reuses the same linear interpolation already implied by the Euler
 * step, ensuring predictable mid-step values without extra derivative calls.
 *
 * <p>The integrator maintains a constant step size across the interval, truncating only when a
 * registered {@link SwitchingFunction} signals an event. It is mutable and not thread-safe; create
 * one instance per concurrent integration and reuse it sequentially for minimal allocation churn.
 * Typical usage wires a {@link StepHandler} to collect samples, then calls {@link
 * #integrate(FirstOrderDifferentialEquations, double, double[], double, double[])} with the desired
 * times and state arrays.
 *
 * <ul>
 *   <li><strong>Strengths:</strong> single derivative per step, straightforward dense output.
 *   <li><strong>Limitations:</strong> first-order accuracy, sensitive to stiffness, and requires
 *       very small steps for precision.
 * </ul>
 *
 * @see MidpointIntegrator
 * @see ClassicalRungeKuttaIntegrator
 * @see GillIntegrator
 * @see ThreeEighthesIntegrator
 * @version $Id: EulerIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class EulerIntegrator extends RungeKuttaIntegrator {

  private static final String METHOD_NAME = "Euler";

  private static final double[] c = {};

  private static final double[][] a = {};

  private static final double[] b = {1.0};

  /**
   * Create an Euler integrator configured with a fixed step size.
   *
   * <p>The step size controls both integration spacing and the linear dense-output interval. A
   * smaller value increases accuracy but raises the number of derivative evaluations; a larger
   * value reduces work but may introduce instability or miss fast dynamics. The instance may be
   * reused across runs; change the step size by creating a new integrator rather than mutating
   * internal state.
   *
   * @param step strictly positive step size in integration time units; values near zero may cause
   *     excessive steps or overflow, while negative values are unsupported.
   */
  public EulerIntegrator(double step) {
    super(false, c, a, b, new EulerStepInterpolator(), step);
  }

  /**
   * Return the user-friendly name of this integration scheme.
   *
   * <p>The name is stable across versions and may be used for logging, configuration displays, or
   * diagnostics that distinguish integrator types at runtime without relying on class names.
   *
   * @return immutable method identifier string, currently {@code \"Euler\"}, suitable for display
   *     and equality checks.
   */
  public String getName() {
    return METHOD_NAME;
  }
}
