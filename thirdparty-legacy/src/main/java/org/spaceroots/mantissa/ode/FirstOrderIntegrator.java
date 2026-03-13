package org.spaceroots.mantissa.ode;

/**
 * Integrates systems of first order ordinary differential equations.
 *
 * <p>Implementations advance a state vector forward or backward in time while delegating the actual
 * derivative computation to a user-supplied {@link FirstOrderDifferentialEquations} model. The
 * integrator controls step sizes, calls {@link StepHandler} listeners after accepted steps, and
 * monitors {@link SwitchingFunction switching functions} to stop or reset the integration when
 * event surfaces are crossed. A single integrator instance typically carries mutable state (current
 * step size, cached derivatives) and is therefore intended for single-threaded use per integration
 * run.
 *
 * <p>Typical usage follows this sequence:
 *
 * <ol>
 *   <li>Create or configure the integrator implementation.
 *   <li>Install a {@link StepHandler} to record accepted steps or drive downstream computation.
 *   <li>Optionally register one or more {@link SwitchingFunction} instances to detect events.
 *   <li>Call {@link #integrate(FirstOrderDifferentialEquations, double, double[], double,
 *       double[])} with initial state and target time.
 * </ol>
 *
 * <p>Integrators are free to adapt step sizes, but they must respect event detection constraints
 * and guarantee that the provided {@code y} array reflects the state at the last completed step
 * when the call returns.
 *
 * @see FirstOrderDifferentialEquations
 * @see StepHandler
 * @see SwitchingFunction
 * @version $Id: FirstOrderIntegrator.java 1719 2007-09-26 19:46:57Z luc $
 * @author L. Maisonobe
 */
public interface FirstOrderIntegrator {

  /**
   * Get the name of the method.
   *
   * <p>The returned identifier should remain stable across versions of a given implementation so
   * that logging and downstream tooling can attribute results to a concrete integration scheme
   * (e.g., Dormand–Prince 8(5,3), Gragg–Bulirsch–Stoer). The name is purely informational and has
   * no bearing on runtime behavior.
   *
   * @return human-friendly identifier of the integration algorithm currently in use
   */
  String getName();

  /**
   * Set the step handler for this integrator. The handler will be called by the integrator for each
   * accepted step.
   *
   * <p>Only one handler is stored; successive calls replace the previous handler. Step handlers can
   * accumulate results, stream intermediate states elsewhere, or enforce user-defined consistency
   * checks. They are invoked on every accepted step, which may differ from internal trial steps
   * when an adaptive scheme rejects some candidates.
   *
   * @param handler handler for the accepted steps, invoked in chronological order; must not be
   *     {@code null}
   */
  void setStepHandler(StepHandler handler);

  /**
   * Get the step handler for this integrator.
   *
   * <p>This accessor is useful for querying or decorating an existing handler without replacing it.
   * If no handler has been configured, implementations typically return a default noop handler that
   * discards step information.
   *
   * @return the step handler for this integrator, never {@code null}
   */
  @SuppressWarnings("unused")
  StepHandler getStepHandler();

  /**
   * Add a switching function to the integrator.
   *
   * <p>Switching functions detect sign changes of an event indicator and can stop the integration,
   * reset state, or alter step sizes when a zero crossing occurs. Multiple functions may be
   * registered; they are evaluated independently according to the integrator's event handling
   * policy.
   *
   * @param function switching function whose sign changes indicate an event condition
   * @param maxCheckInterval maximal time interval between function evaluations to avoid missing
   *     sign changes during large internal steps
   * @param convergence convergence threshold for locating the event time within the bracketing
   *     interval
   */
  void addSwitchingFunction(
      SwitchingFunction function, double maxCheckInterval, double convergence);

  /**
   * Integrate the differential equations up to the given time.
   *
   * <p>This method solves an Initial Value Problem (IVP).
   *
   * <p>Since this method stores some internal state variables made available in its public
   * interface during integration ({@link #getCurrentStepsize()}), it is <em>not</em> thread-safe.
   *
   * <p>The {@code y} array is updated in place to reflect the state at the end of each accepted
   * step and on return holds the state at {@code t}. Implementations may perform backward
   * integration when {@code t} is less than {@code t0}. All arrays must match the dimensionality
   * declared by {@code equations}.
   *
   * <pre>{@code
   * double[] state = {...};
   * integrator.setStepHandler(myHandler);
   * integrator.integrate(model, 0.0, state, 10.0, state);
   * }</pre>
   *
   * @param equations differential equations to integrate; defines dimension and derivative
   *     function; must not be {@code null}
   * @param t0 initial time expressed in the same units expected by the model
   * @param y0 initial value of the state vector at {@code t0}; length must match problem dimension
   * @param t target time for the integration; may be less than {@code t0} for backward integration
   * @param y placeholder updated with the state after each accepted step and on completion; may be
   *     the same array instance as {@code y0}
   * @throws IntegratorException if the integrator cannot converge or encounters configuration
   *     issues
   * @throws DerivativeException if the user-supplied derivative computation fails or rejects input
   */
  void integrate(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t, double[] y)
      throws DerivativeException, IntegratorException;

  /**
   * Get the current value of the step start time t<sub>i</sub>.
   *
   * <p>This method can be called during integration (typically by the object implementing the
   * {@link FirstOrderDifferentialEquations differential equations} problem) if the value of the
   * current step that is attempted is needed.
   *
   * <p>The result is undefined if the method is called outside of calls to {@link #integrate}
   *
   * @return current value of the step start time t<sub>i</sub>; meaningful only during integration
   */
  @SuppressWarnings("unused")
  double getCurrentStepStart();

  /**
   * Get the current value of the integration stepsize.
   *
   * <p>This method can be called during integration (typically by the object implementing the
   * {@link FirstOrderDifferentialEquations differential equations} problem) if the value of the
   * current stepsize that is tried is needed.
   *
   * <p>The result is undefined if the method is called outside of calls to {@link #integrate}
   *
   * @return current value of the stepsize being attempted for the ongoing step
   */
  @SuppressWarnings("unused")
  double getCurrentStepsize();
}
