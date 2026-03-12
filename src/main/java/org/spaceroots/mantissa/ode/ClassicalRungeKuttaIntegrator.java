package org.spaceroots.mantissa.ode;

/**
 * Classic fourth-order explicit Runge–Kutta integrator for first-order ordinary differential
 * equations.
 *
 * <p>This implementation keeps a constant, user-specified step size and wires the canonical RK4
 * Butcher tableau shown below. It is a good general-purpose choice when the right-hand side is
 * smooth, accuracy requirements are moderate, and an adaptive scheme is unnecessary or too costly.
 * The integrator is mutable and not thread-safe; create one instance per concurrent integration and
 * reuse it sequentially to avoid repeated allocation of stage buffers and interpolators.
 *
 * <p>Butcher tableau used by this class:
 *
 * <pre>
 *    0  |  0    0    0    0
 *   1/2 | 1/2   0    0    0
 *   1/2 |  0   1/2   0    0
 *    1  |  0    0    1    0
 *       |--------------------
 *       | 1/6  1/3  1/3  1/6
 * </pre>
 *
 * <ul>
 *   <li>Uses the shared {@link RungeKuttaIntegrator} control flow for event handling and dense
 *       output.
 *   <li>Pairs with {@link ClassicalRungeKuttaStepInterpolator} to expose continuous trajectories
 *       across each fixed step.
 *   <li>Requires callers to choose a step small enough for stability; no error control is performed
 *       internally.
 * </ul>
 *
 * @see EulerIntegrator
 * @see GillIntegrator
 * @see MidpointIntegrator
 * @see ThreeEighthesIntegrator
 * @version $Id: ClassicalRungeKuttaIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class ClassicalRungeKuttaIntegrator extends RungeKuttaIntegrator {

  private static final String METHOD_NAME = "classical Runge-Kutta";

  private static final double[] c = {1.0 / 2.0, 1.0 / 2.0, 1.0};

  private static final double[][] a = {{1.0 / 2.0}, {0.0, 1.0 / 2.0}, {0.0, 0.0, 1.0}};

  private static final double[] b = {1.0 / 6.0, 1.0 / 3.0, 1.0 / 3.0, 1.0 / 6.0};

  /**
   * Build a fourth-order Runge–Kutta integrator that advances with a fixed time step.
   *
   * <p>The provided step size is applied unchanged for every attempted step; event handling may
   * temporarily shorten a single step to land exactly on an event boundary, after which the nominal
   * size is restored. Choose the value based on problem smoothness and desired accuracy, bearing in
   * mind that RK4 has local error on the order of {@code O(h^5)} and global error on the order of
   * {@code O(h^4)}.
   *
   * @param step positive, fixed integration step expressed in the same time units as the underlying
   *     differential equations; values that are zero or excessively large may lead to {@link
   *     IntegratorException} during a run.
   */
  public ClassicalRungeKuttaIntegrator(double step) {
    super(false, c, a, b, new ClassicalRungeKuttaStepInterpolator(), step);
  }

  /**
   * Return the human-readable identifier for this integration method.
   *
   * <p>The name is stable across versions and can be used in logs, user interfaces, or selection
   * menus where multiple fixed-step schemes are exposed. It does not change with step size or other
   * runtime configuration.
   *
   * @return immutable string {@code "classical Runge-Kutta"} describing this RK4 implementation.
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }
}
