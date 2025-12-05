package org.spaceroots.mantissa.ode;

import java.io.Externalizable;

/**
 * Interface for dense output interpolation across the most recently accepted integration step.
 *
 * <p>An integrator creates a fresh interpolator after each successful step and passes it to
 * configured {@link StepHandler handlers}. Handlers can sample the numerical solution at any time
 * within the step, obtaining a smoothly interpolated state without requesting smaller step sizes.
 * Typical usage follows this pattern: a handler receives the interpolator, calls {@link
 * #setInterpolatedTime(double)} with a target time between {@link #getPreviousTime()} and {@link
 * #getCurrentTime()}, then reads {@link #getInterpolatedState()}. Implementations are usually
 * lightweight views backed by the integrator’s internal state and may be reused between callbacks;
 * they are therefore not guaranteed to be thread-safe.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Exposing the step bounds and natural integration direction.
 *   <li>Allowing callers to pick an arbitrary interpolation time, even slightly outside the nominal
 *       step interval, when exploratory searches are required.
 *   <li>Providing the corresponding state vector with accuracy comparable to the underlying
 *       integrator order within the step.
 * </ul>
 *
 * <p>Implementations must preserve the numerical results produced by the integrator while
 * minimizing additional allocations. Callers should treat returned arrays as read-only snapshots
 * unless the concrete class explicitly documents a defensive copy.
 *
 * @see FirstOrderIntegrator
 * @see SecondOrderIntegrator
 * @see StepHandler
 * @version $Id: StepInterpolator.java 1629 2004-10-07 17:00:18Z luc $
 * @author L. Maisonobe
 */
public interface StepInterpolator extends Externalizable {

  /**
   * Get the previous grid point time for the current interpolated step.
   *
   * <p>The value corresponds to the start of the step accepted by the integrator. It is expressed
   * in the integration variable units (typically seconds) and remains constant until the next step
   * is accepted. Handlers can use it to bound interpolation requests or to detect step rejections
   * when multiple callbacks occur.
   *
   * @return the time coordinate, in integration units, of the step starting point
   */
  double getPreviousTime();

  /**
   * Get the current grid point time for the active step.
   *
   * <p>This is the end time of the step that produced this interpolator. It may be greater or less
   * than {@link #getPreviousTime()} depending on the integration direction. The value does not
   * change while the interpolator instance is in use by handlers, even if subsequent steps are
   * computed later on.
   *
   * @return the time coordinate, in integration units, of the step end point
   */
  double getCurrentTime();

  /**
   * Get the time of the interpolated point. If {@link #setInterpolatedTime} has not been called, it
   * returns the current grid point time.
   *
   * <p>The interpolated time is mutable per interpolator instance and determines which state vector
   * {@link #getInterpolatedState()} will expose. Values are typically constrained to the current
   * step bounds, but implementations may support slight extrapolation for root-finding or event
   * localization algorithms that probe near the boundaries.
   *
   * @return the time, in integration units, used for the next interpolated state retrieval
   */
  @SuppressWarnings("unused")
  double getInterpolatedTime();

  /**
   * Set the time of the interpolated point.
   *
   * <p>Setting the time outside the current step is now allowed (it was not allowed up to version
   * 5.4 of Mantissa), but should be used with care since the accuracy of the interpolator will
   * probably be very poor far from this step. This allowance has been added to simplify
   * implementation of search algorithms near the step endpoints.
   *
   * <p>Calling this method updates the internal interpolation model so the following call to {@link
   * #getInterpolatedState()} returns a state consistent with the specified time. It is idempotent
   * for identical input values and does not advance the integrator itself.
   *
   * <pre>{@code
   * // Sample midway through the accepted step
   * interpolator.setInterpolatedTime(
   *     0.5 * (interpolator.getPreviousTime() + interpolator.getCurrentTime()));
   * double[] midState = interpolator.getInterpolatedState();
   * }</pre>
   *
   * @param time target time, in the integration variable units, for interpolation evaluation
   * @throws DerivativeException if the interpolator must finalize or refresh step data and that
   *     operation triggers a derivative computation failure
   */
  void setInterpolatedTime(double time) throws DerivativeException;

  /**
   * Get the state vector of the interpolated point.
   *
   * <p>The returned array contains one entry per state dimension, aligned with the integrator’s
   * state ordering. Implementations may return an internal buffer for performance; callers should
   * therefore read but not modify its contents unless documentation for the concrete class promises
   * a defensive copy. The values reflect the time last provided to {@link
   * #setInterpolatedTime(double)}.
   *
   * @return state vector matching the last set interpolated time, expressed in state units
   */
  double[] getInterpolatedState();

  /**
   * Check if the natural integration direction is forward (increasing time).
   *
   * <p>This method provides the integration direction as specified by the integrator itself, it
   * avoids some nasty problems in degenerated cases like null steps due to cancellation at step
   * initialization, step control or switching function triggering.
   *
   * <p>The direction remains constant for a given integrator instance even if extrapolation is
   * requested through {@link #setInterpolatedTime(double)}. Consumers can rely on it to select
   * appropriate bracketing logic when scanning for events.
   *
   * @return {@code true} when time grows monotonically during integration; {@code false} otherwise
   */
  boolean isForward();
}
