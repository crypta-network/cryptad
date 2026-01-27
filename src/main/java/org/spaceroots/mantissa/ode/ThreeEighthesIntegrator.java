package org.spaceroots.mantissa.ode;

/**
 * Fixed-step 3/8 Runge–Kutta integrator for first-order ordinary differential equations.
 *
 * <p>This explicit fourth-order scheme advances the state using the classical 3/8 Butcher tableau,
 * striking a balance between accuracy and computational cost for problems where a uniform step size
 * is acceptable. It is suitable when callers control the step externally (e.g., to align with event
 * grids) or when a predictable number of function evaluations per step is desired. The integrator
 * keeps a constant nominal step, delegates dense output to {@link ThreeEighthesStepInterpolator},
 * and honors event detection via the shared {@link RungeKuttaIntegrator} infrastructure.
 *
 * <p>Lifecycle: create one instance per concurrent integration, configure optional {@link
 * StepHandler} or switching functions, then call {@link #integrate} inherited from the base class.
 * The integrator is not thread-safe; reuse it sequentially across runs. Accuracy within a step
 * matches fourth-order expectations as long as the supplied derivatives are smooth over the step
 * span. For stiff systems or cases requiring adaptive control, prefer an adaptive integrator
 * instead.
 *
 * <ul>
 *   <li>Responsibilities: supply the 3/8 tableau and a matching step interpolator.
 *   <li>Notable behaviors: constant step size, no FSAL reuse, dense output supported when
 *       requested.
 *   <li>Interoperability: shares event handling, state validation, and handler wiring with other
 *       {@link RungeKuttaIntegrator} subclasses.
 * </ul>
 *
 * <pre>
 *    0  |  0    0    0    0
 *   1/3 | 1/3   0    0    0
 *   2/3 |-1/3   1    0    0
 *    1  |  1   -1    1    0
 *       |--------------------
 *       | 1/8  3/8  3/8  1/8
 * </pre>
 *
 * @see EulerIntegrator
 * @see ClassicalRungeKuttaIntegrator
 * @see GillIntegrator
 * @see MidpointIntegrator
 * @version $Id: ThreeEighthesIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class ThreeEighthesIntegrator extends RungeKuttaIntegrator {

  private static final String METHOD_NAME = "3/8";

  private static final double[] C = {1.0 / 3.0, 2.0 / 3.0, 1.0};

  private static final double[][] A = {{1.0 / 3.0}, {-1.0 / 3.0, 1.0}, {1.0, -1.0, 1.0}};

  private static final double[] B = {1.0 / 8.0, 3.0 / 8.0, 3.0 / 8.0, 1.0 / 8.0};

  /**
   * Create a 3/8 Runge–Kutta integrator configured with a fixed step size.
   *
   * <p>The constructor merely wires the immutable Butcher tableau into the shared {@link
   * RungeKuttaIntegrator} machinery and keeps the provided step for all subsequent {@link
   * #integrate} calls. Step size must already reflect the desired integration direction; negative
   * values are allowed for backward sweeps. The instance is reusable across runs as long as it is
   * not accessed concurrently.
   *
   * @param step signed integration step in the same units as the independent variable; must be
   *     non-zero to avoid validation failures at integration time.
   */
  public ThreeEighthesIntegrator(double step) {
    super(false, C, A, B, new ThreeEighthesStepInterpolator(), step);
  }

  /**
   * Return the short display name of this integration scheme.
   *
   * <p>The name is a stable identifier ({@code "3/8"}) suitable for logs, configuration displays,
   * or comparative reporting across available integrators. The value does not change during the
   * lifetime of the instance.
   *
   * @return constant string identifying the 3/8 Runge–Kutta method for user-facing display.
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }
}
