package org.spaceroots.mantissa.ode;

import java.io.Serial;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;
import org.spaceroots.mantissa.roots.BrentSolver;
import org.spaceroots.mantissa.roots.ConvergenceChecker;
import org.spaceroots.mantissa.roots.RootsFinder;

/**
 * Maintains switching-function state across numerical integration steps.
 *
 * <p>This helper is created for each {@link SwitchingFunction} registered on an integrator and
 * persists between calls so events are detected deterministically. It stores the sign of the
 * function at the start of a step, tracks the last accepted event time, and remembers whether a
 * pending event has already been bracketed. The instance is reused as the integrator iterates over
 * a proposed step, sampling at a bounded interval to ensure no zero crossing is skipped even when
 * the step size grows.
 *
 * <p>The class is intentionally mutable and <strong>not</strong> thread-safe; a single instance
 * must be confined to one integration process. Callers drive the life cycle in a predictable
 * pattern: {@link #reinitializeBegin(double, double[])} at step start, {@link
 * #evaluateStep(StepInterpolator)} during proposal scanning, {@link #stepAccepted(double,
 * double[])} when a step is kept, optionally {@link #reset(double, double[])} if an event fires,
 * and {@link #stop()} to determine termination.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Bracketing and localizing zero crossings with a {@link BrentSolver}-backed root finder.
 *   <li>Exposing event timing and next-action hints for integrator control flow.
 *   <li>Enforcing a maximum check interval to limit missed crossings on oscillatory functions.
 * </ul>
 *
 * @version $Id: SwitchState.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
class SwitchState implements ComputableFunction, ConvergenceChecker {

  @Serial private static final long serialVersionUID = 6944466361876662425L;

  /** Switching function. */
  private final SwitchingFunction function;

  /** Maximal time interval between switching function checks. */
  private final double maxCheckInterval;

  /** Convergence threshold for event localization. */
  private final double convergence;

  /** Time at the beginning of the step. */
  private double t0;

  /** Value of the switching function at the beginning of the step. */
  private double g0;

  /** Simulated sign of g0 (we cheat when crossing events). */
  private boolean g0Positive;

  /** Indicator of event expected during the step. */
  private boolean pendingEvent;

  /** Occurrence time of the pending event. */
  private double pendingEventTime;

  /** Occurrence time of the previous event. */
  private double previousEventTime;

  /**
   * Variation direction around pending event. (this is considered with respect to the integration
   * direction)
   */
  private boolean increasing;

  /** Next action indicator. */
  private int nextAction;

  /** Interpolator valid for the current step. */
  private StepInterpolator interpolator;

  /**
   * Create a state tracker for one switching function.
   *
   * <p>The instance is tied to the provided {@link SwitchingFunction} and to the convergence and
   * sampling policy chosen by the caller. It does not copy the function, so the caller retains
   * ownership and must keep the function valid for the lifetime of the tracker. The maximum check
   * interval bounds how far apart the interpolated evaluations may occur within a step and is
   * applied symmetrically for forward and backward integration.
   *
   * @param function switching function evaluated along the step to detect events reliably
   * @param maxCheckInterval maximal time gap between sign checks to prevent missed crossings
   * @param convergence absolute tolerance used while refining and validating event time estimates
   */
  public SwitchState(SwitchingFunction function, double maxCheckInterval, double convergence) {
    this.function = function;
    this.maxCheckInterval = maxCheckInterval;
    this.convergence = Math.abs(convergence);

    // some dummy values ...
    t0 = Double.NaN;
    g0 = Double.NaN;
    g0Positive = true;
    pendingEvent = false;
    pendingEventTime = Double.NaN;
    previousEventTime = Double.NaN;
    increasing = true;
    nextAction = SwitchingFunction.CONTINUE;

    interpolator = null;
  }

  /**
   * Reinitialize the beginning of the step.
   *
   * <p>This method must be called exactly once at the start of each proposed step, before any
   * evaluation happens. It captures the current time and state, computes the switching-function
   * value, and establishes the reference sign used during subsequent scanning. The stored values
   * remain authoritative until the step is accepted or rejected, so callers should avoid invoking
   * this method mid-step or with stale state arrays.
   *
   * @param t0 value of the independent time variable at the start of the candidate step
   * @param y0 array containing the current state vector at the beginning of the candidate step
   */
  public void reinitializeBegin(double t0, double[] y0) {
    this.t0 = t0;
    g0 = function.g(t0, y0);
    g0Positive = (g0 >= 0);
  }

  /**
   * Evaluate the impact of the proposed step on the switching function.
   *
   * <p>The interpolator is sampled at most every {@code maxCheckInterval} units of the independent
   * variable so that rapidly oscillating functions still surface sign changes. When a crossing is
   * detected, a Brent root finder is invoked to locate the event time within the current step. The
   * method may mark a pending event that forces the caller to shorten or retry the step so the
   * event lands on a boundary rather than in the interior.
   *
   * @param interpolator step interpolator that provides dense state evaluation across the step span
   * @return true if an event is detected inside the proposed step and the step should be rejected
   *     and retried with an adjusted end time
   */
  public boolean evaluateStep(StepInterpolator interpolator) {
    try {
      this.interpolator = interpolator;

      double t1 = interpolator.getCurrentTime();
      int n = Math.max(1, (int) Math.ceil(Math.abs(t1 - t0) / maxCheckInterval));
      double h = (t1 - t0) / n;

      double ta = t0;
      double ga = g0;
      double tb = t0 + ((t1 > t0) ? convergence : -convergence);
      for (int i = 0; i < n; ++i) {
        tb += h;
        interpolator.setInterpolatedTime(tb);
        double gb = function.g(tb, interpolator.getInterpolatedState());

        if (hasSignChanged(gb)) {
          SignChangeHandling handling = handleSignChange(ta, ga, tb, gb, t1);
          if (handling == SignChangeHandling.REJECT_STEP) {
            return true;
          }
          if (handling == SignChangeHandling.ACCEPT_STEP) {
            return false;
          }
        } else {
          ta = tb;
          ga = gb;
        }
      }

      clearPendingEvent();
      return false;

    } catch (DerivativeException e) {
      throw new IllegalStateException("unexpected exception during event evaluation", e);
    }
  }

  private boolean hasSignChanged(double gb) {
    return g0Positive ^ (gb >= 0);
  }

  private enum SignChangeHandling {
    REJECT_STEP,
    ACCEPT_STEP,
    CONTINUE_SCAN
  }

  private SignChangeHandling handleSignChange(
      double ta, double ga, double tb, double gb, double t1) {
    increasing = (gb >= ga);

    RootsFinder solver = new BrentSolver();
    try {
      if (!solver.findRoot(this, this, 1000, ta, ga, tb, gb)) {
        throw new IllegalStateException("failed to locate switching function root");
      }
    } catch (FunctionException e) {
      throw new IllegalStateException("failed to locate switching function root", e);
    }

    double root = solver.getRoot();
    if (Double.isNaN(previousEventTime) || (Math.abs(previousEventTime - root) > convergence)) {
      pendingEventTime = root;
      if (pendingEvent && (Math.abs(t1 - pendingEventTime) <= convergence)) {
        return SignChangeHandling.ACCEPT_STEP;
      }
      pendingEvent = true;
      return SignChangeHandling.REJECT_STEP;
    }
    return SignChangeHandling.CONTINUE_SCAN;
  }

  private void clearPendingEvent() {
    pendingEvent = false;
    pendingEventTime = Double.NaN;
  }

  /**
   * Get the occurrence time of the event triggered in the current step.
   *
   * <p>The value is only meaningful after {@link #evaluateStep(StepInterpolator)} reports an event
   * and before the next {@link #stepAccepted(double, double[])} call updates the internal state.
   * Callers should treat the returned time as immutable and should not reuse it after a reset or a
   * subsequent step begins.
   *
   * @return event occurrence time recorded for the current step, or {@link Double#NaN} when none
   *     has been detected
   */
  public double getEventTime() {
    return pendingEventTime;
  }

  /**
   * Acknowledge the fact the step has been accepted by the integrator.
   *
   * <p>Once the caller decides to keep the proposed step, this method refreshes the stored
   * baseline, recomputes the switching-function sign, and records any event occurrence so the next
   * step can start with consistent context. When a pending event existed, it updates the simulated
   * sign to the post-event side and records the action requested by the {@link SwitchingFunction}.
   *
   * @param t value of the independent time variable at the end of the accepted step
   * @param y array containing the current value of the state vector at the end of the accepted step
   */
  public void stepAccepted(double t, double[] y) {

    t0 = t;
    g0 = function.g(t, y);

    if (pendingEvent) {
      // force the sign to its value "just after the event"
      previousEventTime = t;
      g0Positive = increasing;
      nextAction = function.eventOccurred(t, y);
    } else {
      g0Positive = (g0 >= 0);
      nextAction = SwitchingFunction.CONTINUE;
    }
  }

  /**
   * Check if the integration should be stopped at the end of the current step.
   *
   * <p>The decision reflects the last {@link SwitchingFunction#eventOccurred(double, double[])}
   * result captured by {@link #stepAccepted(double, double[])}. It does not trigger additional
   * computations and can be queried repeatedly without side effects.
   *
   * @return true if the last processed event requested {@link SwitchingFunction#STOP} and the
   *     integrator should terminate gracefully
   */
  public boolean stop() {
    return nextAction == SwitchingFunction.STOP;
  }

  /**
   * Let the switching function reset the state if it wants.
   *
   * <p>Call this immediately after a step containing an event has been accepted to give the
   * switching function a chance to modify the state vector for the next step. The method clears the
   * pending-event flag and returns whether derivative recomputation is required, mirroring the
   * action previously returned by {@link SwitchingFunction#eventOccurred(double, double[])}.
   * Calling it when no event is pending leaves the state untouched and signals that no reset is
   * needed.
   *
   * @param t value of the independent time variable at the beginning of the next step to prepare
   * @param y array where the switching function may write the desired state vector for the restart
   * @return true if the integrator must also recompute derivatives before advancing the solution
   */
  public boolean reset(double t, double[] y) {

    if (!pendingEvent) {
      return false;
    }

    if (nextAction == SwitchingFunction.RESET_STATE) {
      function.resetState(t, y);
    }
    pendingEvent = false;
    pendingEventTime = Double.NaN;

    return (nextAction == SwitchingFunction.RESET_STATE)
        || (nextAction == SwitchingFunction.RESET_DERIVATIVES);
  }

  /**
   * Get the value of the g function at the specified time.
   *
   * <p>This method delegates to the current step interpolator to obtain the interpolated state and
   * then evaluates the switching function. It is primarily used by the root finder while refining
   * an event time, and it assumes the interpolator has been initialized for the step under review.
   *
   * @param t current time within the bounds of the step managed by the stored interpolator
   * @return switching-function value evaluated on the interpolated state at the requested time
   * @exception FunctionException if the interpolator cannot produce a state at the given time or
   *     the switching function signals a computation failure
   */
  public double valueAt(double t) throws FunctionException {
    try {
      interpolator.setInterpolatedTime(t);
      return function.g(t, interpolator.getInterpolatedState());
    } catch (DerivativeException e) {
      throw new FunctionException(e);
    }
  }

  /**
   * Check if the event time has been found.
   *
   * <p>This callback implements the {@link ConvergenceChecker} contract for the configured
   * convergence threshold. It compares the interval width to the tolerance and indicates whether
   * the root finder should keep the lower or upper bracket based on which endpoint is closer to
   * zero. The method is side-effect free and deterministic for the same inputs.
   *
   * @param x0 lower bound of the bracketing interval currently evaluated by the solver
   * @param y0 value of the switching function at {@code x0}, typically already computed
   * @param x1 higher bound of the bracketing interval being refined by the solver
   * @param y1 value of the switching function at {@code x1}, paired with the upper bound
   * @return convergence indicator describing whether the interval is within tolerance and which
   *     endpoint is preferred when both are close to a root
   */
  public int converged(double x0, double y0, double x1, double y1) {
    if (Math.abs(x1 - x0) < convergence) {
      return (Math.abs(y0) < Math.abs(y1)) ? ConvergenceChecker.LOW : ConvergenceChecker.HIGH;
    }
    return ConvergenceChecker.NONE;
  }
}
