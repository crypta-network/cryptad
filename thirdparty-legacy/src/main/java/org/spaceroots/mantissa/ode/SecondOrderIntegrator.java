package org.spaceroots.mantissa.ode;

/**
 * Interface for numerical schemes that integrate systems of second order ordinary differential
 * equations.
 *
 * <p>Implementations advance a state vector and its first derivative from an initial instant to a
 * target instant while respecting the mathematical model supplied by a {@link
 * SecondOrderDifferentialEquations} instance. The integrator coordinates step size control,
 * accuracy management, and event notification through handlers while leaving the derivative
 * computation to user-provided equations. Callers typically configure a step handler and then
 * invoke {@link #integrate(SecondOrderDifferentialEquations, double, double[], double[], double,
 * double[], double[])} once per trajectory. Instances are expected to be stateful with respect to
 * configuration (handlers, tolerances) but to leave ownership of state vectors to the caller so the
 * same integrator can be reused across runs.
 *
 * <p>Unless otherwise documented by an implementation, instances are not guaranteed to be thread
 * safe; clients should confine each instance to a single integration workflow at a time. Most
 * integrators assume finite, well-defined derivatives and may reject ill-conditioned problems or
 * discontinuities without an event handler.
 *
 * <ul>
 *   <li>Responsibility: drive the integration loop for second order systems.
 *   <li>Notable behavior: delegates derivative evaluation to user code at every step.
 *   <li>Common usage: configure a {@link StepHandler}, then call {@link
 *       #integrate(SecondOrderDifferentialEquations, double, double[], double[], double, double[],
 *       double[])}.
 * </ul>
 *
 * @see SecondOrderDifferentialEquations
 * @version $Id: SecondOrderIntegrator.java 1599 2004-08-22 12:43:12Z luc $
 * @author L. Maisonobe
 */
public interface SecondOrderIntegrator {

  /**
   * Get the name of the method.
   *
   * <p>Names are intended for logging, reporting, and selection among multiple integrator
   * strategies. Implementations typically return a short mnemonic such as a scheme identifier or
   * family name (for example, Runge-Kutta or Adams types). The returned value should remain stable
   * for a given implementation so external configuration or diagnostics can rely on it without
   * needing instance-specific metadata.
   *
   * @return name of the integration method, suitable for display or diagnostics
   */
  String getName();

  /**
   * Set the step handler for this integrator. The handler will be called by the integrator for each
   * accepted step.
   *
   * <p>Handlers allow clients to observe intermediate states, perform logging, implement event
   * detection, or stop the integration early. Passing a new handler replaces any previously set
   * handler for subsequent runs; existing integrations are unaffected until the next call to {@link
   * #integrate(SecondOrderDifferentialEquations, double, double[], double[], double, double[],
   * double[])} begins. Implementations are expected to invoke the handler in chronological order of
   * accepted steps.
   *
   * @param handler handler for accepted steps; must not be {@code null} and should be reusable
   */
  void setStepHandler(StepHandler handler);

  /**
   * Get the step handler for this integrator.
   *
   * <p>This accessor is useful for inspection, decoration, or replacement of an existing handler.
   * The returned reference is the same instance previously supplied to {@link #setStepHandler} and
   * remains owned by the caller; integrators do not clone handlers.
   *
   * @return the current step handler used for accepted steps, or {@code null} if none was set
   */
  @SuppressWarnings("unused")
  StepHandler getStepHandler();

  /**
   * Integrate the differential equations up to the given time.
   *
   * <p>The method advances the provided state in place, calling the configured {@link StepHandler}
   * after each accepted step and stopping exactly at the target time (up to integrator accuracy).
   * Integrators may internally allocate temporary storage but must place the final state and first
   * derivative in the supplied output arrays. Backward integration is supported by using a target
   * time smaller than the initial one. Callers should provide arrays of the correct dimension and
   * should not modify them concurrently during the computation.
   *
   * <pre>{@code
   * // Example: integrate from 0.0 to 10.0 seconds
   * integrator.setStepHandler(handler);
   * integrator.integrate(equations, 0.0, y0, yDot0, 10.0, y, yDot);
   * }</pre>
   *
   * @param equations differential equations to integrate; supplies second derivatives on demand
   * @param t0 initial time in integration units (for example, seconds)
   * @param y0 initial value of the state vector at {@code t0}; length must match system dimension
   * @param yDot0 initial value of the first derivative of the state vector at {@code t0}
   * @param t target time for the integration (maybe less than {@code t0} for backward runs)
   * @param y placeholder for state vector at each successful step; may be the same object as {@code
   *     y0}
   * @param yDot placeholder for first derivative of the state vector at {@code t}; may be the same
   *     object as {@code yDot0}
   * @throws IntegratorException if the integrator cannot perform integration or convergence fails
   * @throws DerivativeException if the user-supplied derivatives cannot be evaluated successfully
   */
  void integrate(
      SecondOrderDifferentialEquations equations,
      double t0,
      double[] y0,
      double[] yDot0,
      double t,
      double[] y,
      double[] yDot)
      throws DerivativeException, IntegratorException;
}
