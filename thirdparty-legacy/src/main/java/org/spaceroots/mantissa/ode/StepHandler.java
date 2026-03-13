package org.spaceroots.mantissa.ode;

/**
 * Interface for components notified after each successful numerical integration step.
 *
 * <p>Integrators advance an ODE solution through a sequence of steps whose size depends on their
 * internal error control and algorithmic choices. After finishing a step they pass a {@link
 * StepInterpolator} to registered handlers so that application code can record, transform, or
 * publish the evolving state without coupling to the solver implementation. Typical handlers either
 * extract only end-of-step values, accumulate an ephemeris for later querying, or stream dense
 * interpolated samples to downstream consumers such as visualizers or event detectors. The handler
 * itself remains stateless with respect to the integrator; a fresh run should call {@link #reset()}
 * so caches are cleared and invariants re-established before the first step arrives.
 * Implementations are generally not thread-safe and are invoked on the integrator thread unless
 * explicitly guarded by the caller.
 *
 * <p>Common responsibilities include:
 *
 * <ul>
 *   <li>Deciding whether dense interpolation is required for intermediate evaluations.
 *   <li>Storing or streaming step samples with user-defined precision.
 *   <li>Detecting termination conditions based on the evolving state.
 * </ul>
 *
 * @see FirstOrderIntegrator
 * @see SecondOrderIntegrator
 * @see StepInterpolator
 * @version $Id: StepHandler.java 1444 2003-01-03 19:08:41Z luc $
 * @author L. Maisonobe
 */
public interface StepHandler {

  /**
   * States whether this handler needs dense output across each accepted step.
   *
   * <p>Integrators incur additional work to build a {@link StepInterpolator} capable of evaluating
   * the state at arbitrary points within the step. Handlers that only consume end-of-step values
   * should return {@code false} to let the integrator substitute a lightweight {@link
   * DummyStepInterpolator} and reduce overhead. Handlers that interpolate internal samples,
   * generate continuous output models, or perform fine-grained event checks should return {@code
   * true}. The decision is static for the duration of one integration run and is typically based on
   * how the handler aggregates or publishes results.
   *
   * @return {@code true} when an interpolator with full dense-evaluation capability is required,
   *     {@code false} when end-of-step values alone are sufficient and cheaper dummy data may be
   *     used
   */
  boolean requiresDenseOutput();

  /**
   * Reset the handler to prepare for a new integration sequence.
   *
   * <p>Integrators invoke this method exactly once before delivering the first step of a run. An
   * implementation should clear cached samples, counters, or derived aggregates so that state from
   * a previous integration does not leak into the next. The call happens before any thread starts
   * delivering steps, so implementations may initialize mutable structures without additional
   * synchronization. Handlers that allocate large buffers may choose to reuse them to limit garbage
   * creation but must ensure content reflects only the upcoming run.
   */
  void reset();

  /**
   * Process the last accepted step produced by the integrator.
   *
   * <p>The same interpolator instance is reused across calls for efficiency. Handlers that need a
   * persistent record must clone the interpolator or extract scalar data because retaining the
   * shared object leads to mutated state on subsequent calls. The {@code isLast} flag allows
   * implementations to finalize derived products, flush buffered output, or free resources after
   * the terminal step. Typical implementations pull dense samples for plotting, push summaries to
   * observers, or stop integration early when an application-specific condition is reached. The
   * method may propagate {@link DerivativeException} so that upstream code can react to failures in
   * the user-supplied dynamics function.
   *
   * <pre>{@code
   * // Example: stash samples for later interpolation
   * handler.handleStep(interpolator, interpolator.isForward());
   * }</pre>
   *
   * @param interpolator step interpolator representing the accepted step; must be cloned or copied
   *     before storing beyond the duration of this call
   * @param isLast {@code true} when this invocation corresponds to the terminal step of the current
   *     integration run, {@code false} otherwise
   * @throws DerivativeException if evaluating the derivative through the interpolator triggers a
   *     user function failure that the integrator chooses to propagate
   */
  void handleStep(StepInterpolator interpolator, boolean isLast) throws DerivativeException;
}
