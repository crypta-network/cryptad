package org.spaceroots.mantissa.ode;

import java.io.Serializable;

/**
 * Describes a user-supplied switching function that signals discrete events to an ODE integrator.
 *
 * <p>A switching function evaluates a continuous scalar predicate {@link #g(double, double[])}
 * alongside numerical integration. When the function crosses zero, the integrator treats the
 * crossing as an event boundary and delegates to {@link #eventOccurred(double, double[])} to decide
 * whether to stop, continue, or reset state or derivatives. This interface is intentionally small
 * so implementations can be lightweight, stateless, or capture only the external state they need.
 *
 * <p>Typical usage pairs a switching function with a step handler: the integrator brackets a root
 * of {@code g(t, y)} inside a step, reduces the step size so the root lands at the end of the step,
 * and then triggers {@link #eventOccurred(double, double[])} before invoking the handler. The
 * integrator guarantees that interpolation within the accepted step is still valid, which makes
 * this mechanism suitable for domain boundaries (e.g., altitude crossing), guard conditions, or
 * reacting to derivative discontinuities.
 *
 * <p>Implementations should be thread-confinement friendly: instances are typically used by a
 * single integrator run, so they may keep mutable detection state as long as they are not shared
 * across concurrent integrations. Returning reset indicators obligates the implementation to supply
 * the new state in {@link #resetState(double, double[])}; failing to do so may produce inconsistent
 * trajectories. Constants in this interface map directly to the contract expected by the integrator
 * and by downstream tools built on the Mantissa ODE package.
 *
 * @see FirstOrderIntegrator
 * @see StepHandler
 * @version $Id: SwitchingFunction.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface SwitchingFunction extends Serializable {

  /**
   * Stop indicator used when integration must halt after handling the current step.
   *
   * <p>Return this constant from {@link #eventOccurred(double, double[])} to request that the
   * integrator mark the current step as the last one, call the configured {@link StepHandler}, and
   * then terminate without attempting further steps. Use it when crossing the switching surface
   * represents a terminal condition for the model (for example, hitting the ground or violating a
   * safety constraint).
   */
  int STOP = 0;

  /**
   * Reset state indicator requesting continuation with a new state vector.
   *
   * <p>Return this constant from {@link #eventOccurred(double, double[])} when integration should
   * continue after the event, but with the state vector replaced. The integrator will invoke {@link
   * #resetState(double, double[])} after the current {@link StepHandler} finishes, and it will
   * recompute derivatives before advancing. Use this when the event represents a discontinuity that
   * requires a jump in state, such as toggling a mechanical constraint or applying an impulse.
   */
  int RESET_STATE = 1;

  /**
   * Reset derivatives indicator requesting recomputation without altering the state vector.
   *
   * <p>Return this constant from {@link #eventOccurred(double, double[])} when the event only
   * changes the derivative function, not the current state. The integrator will keep the state
   * unchanged but recompute derivatives before stepping again. This is useful for piecewise-defined
   * dynamics where the slope switches at known manifolds while the state remains continuous.
   */
  int RESET_DERIVATIVES = 2;

  /**
   * Continue indicator used when no special action is required after the event.
   *
   * <p>Return this constant from {@link #eventOccurred(double, double[])} to acknowledge the event
   * while letting the integrator proceed normally. Neither state nor derivatives will be reset, and
   * the step sequence continues. Choose this when the sign change is merely informational or when
   * side effects have already been applied elsewhere.
   */
  int CONTINUE = 3;

  /**
   * Evaluate the switching predicate whose zero crossings define discrete events.
   *
   * <p>The integrator samples this function at step endpoints and via root finders inside a step to
   * locate sign changes. Implementations should return a continuous value near expected roots so
   * bisection or similar solvers can converge reliably. Expensive computations should be avoided
   * where possible because this method is called frequently during step refinement. Returning
   * {@code Double.NaN} is discouraged because it prevents reliable root detection.
   *
   * @param t current value of the independent time variable in integration units; finite and
   *     monotonic according to the integrator direction
   * @param y current state vector; elements are owned by the integrator and must not be modified
   * @return scalar predicate value whose sign determines event crossings; negative/positive values
   *     are arbitrary as long as sign changes identify the intended surface
   */
  double g(double t, double[] y);

  /**
   * Decide the post-event action once a sign change has been located at the end of a step.
   *
   * <p>The integrator calls this hook immediately after it positions the step endpoint exactly on
   * an event surface. Implementations may update internal bookkeeping (for example, toggling a mode
   * flag) and must return one of the interface constants to steer the subsequent step schedule. The
   * returned action is applied after the current {@link StepHandler} invocation, and derivative
   * recomputation occurs automatically for reset cases. Avoid performing heavy work here; defer
   * state changes to {@link #resetState(double, double[])} when possible for clarity.
   *
   * @param t event time at the accepted step end; equals the root location determined for {@code
   *     g(t, y)}
   * @param y state vector at the event boundary; callers may use it for decision logic but should
   *     not modify contents
   * @return one of {@link #STOP}, {@link #RESET_STATE}, {@link #RESET_DERIVATIVES}, {@link
   *     #CONTINUE} to indicate stop/continue/reset handling
   */
  int eventOccurred(double t, double[] y);

  /**
   * Supply a replacement state vector before integration continues after a reset event.
   *
   * <p>Invoked only when {@link #eventOccurred(double, double[])} returned {@link #RESET_STATE} (or
   * {@link #RESET_STATE}), this method allows the implementation to write the new state directly
   * into the provided array. The integrator will use the updated values as the starting point for
   * the next step and will recompute derivatives automatically. Implementations may apply
   * discontinuous jumps, enforce constraints, or perform minimal adjustments; callers must ensure
   * the resulting state is finite and consistent with model invariants to avoid integration
   * failure.
   *
   * @param t event time at which the reset takes effect; equals the step end where the root was
   *     detected
   * @param y mutable array containing the current state; replace its contents in place with the new
   *     state vector that should seed the subsequent step
   */
  void resetState(double t, double[] y);
}
