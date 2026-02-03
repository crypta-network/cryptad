package org.spaceroots.mantissa.ode;

/**
 * Holds reusable work arrays for the initial step-size estimate.
 *
 * <p>This class stores the mutable buffers used during the Euler probe that refines the initial
 * step size. Integrators typically create a workspace alongside {@link StepInitializationInputs}
 * and pass both into {@link StepInitializationContext}. The buffers are shared with the integrator
 * and are written in-place when computing the Euler trial state and its derivative.
 *
 * <p>The instance is immutable, but it retains references to mutable arrays owned by the caller. No
 * defensive copies are made. Callers must ensure that both arrays have the same length as the state
 * vector and that they are safe to overwrite during initialization. The class is not thread-safe
 * because it exposes mutable arrays that the integrator is expected to reuse.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Providing a buffer for the Euler-predicted trial state.
 *   <li>Providing a buffer for derivatives at the trial state.
 * </ul>
 *
 * @see StepInitializationContext
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class StepInitializationWorkspace {
  private final double[] y1;
  private final double[] yDot1;

  /**
   * Creates a workspace holding the mutable buffers used during initialization.
   *
   * <p>This constructor stores references to the supplied arrays without validation. Callers must
   * ensure the arrays are non-null, have the correct length for the problem dimension, and can be
   * overwritten during the Euler probe. The resulting instance is intended for immediate use by a
   * single integrator and should not be shared across threads.
   *
   * @param y1 workspace for the Euler-predicted trial state; must be mutable and correctly sized
   * @param yDot1 workspace for derivatives at the trial state; must be mutable and correctly sized
   */
  public StepInitializationWorkspace(double[] y1, double[] yDot1) {
    this.y1 = y1;
    this.yDot1 = yDot1;
  }

  /**
   * Returns the workspace array for the Euler-predicted trial state.
   *
   * <p>The integrator writes the Euler trial state into this array and then uses it as input for
   * derivative evaluation at the trial time. The contents are transient and may be overwritten on
   * each initialization attempt. Callers should not assume the values persist beyond the step-size
   * estimation.
   *
   * @return workspace array holding the Euler trial state, shared and mutable
   */
  public double[] y1() {
    return y1;
  }

  /**
   * Returns the workspace array for derivatives at the Euler trial state.
   *
   * <p>The derivative provider writes into this array when evaluating the Euler trial point. The
   * values are consumed immediately by the heuristic to estimate curvature and are not retained.
   * The array is shared with the caller and may be overwritten in further initialization steps.
   *
   * @return workspace array for derivatives at the trial state, shared and mutable
   */
  public double[] yDot1() {
    return yDot1;
  }
}
