package org.spaceroots.mantissa.ode;

import java.util.ArrayList;
import java.util.List;

/**
 * Coordinates multiple {@link SwitchingFunction switching functions} for a single ODE integration
 * run.
 *
 * <p>The handler owns a collection of per-function {@link SwitchState} instances that track the
 * latest sign of each predicate, search for zero crossings inside a candidate step, and remember
 * the earliest event that would force the integrator to shorten that step. A single handler is
 * created for one integration session and is expected to receive callbacks in the same order as the
 * integrator progresses: {@link #evaluateStep(StepInterpolator)} before the step is accepted,
 * {@link #stepAccepted(double, double[])} after acceptance, then {@link #reset(double, double[])}
 * and {@link #stop()} if an event requested additional actions. Instances are mutable and not
 * thread-safe; the integrator must ensure serialized access when dealing with multiple switching
 * functions. Typical usage is one handler per integrator run, populated with application-defined
 * switching functions during setup and reused until the integration completes or is aborted.
 *
 * <ul>
 *   <li>Responsibility: aggregate event detection across all registered switching functions.
 *   <li>Priority rule: earliest event wins when integrating forward; latest when backward.
 *   <li>Lifecycle: initialize once on the first step, then update state after each accepted step.
 * </ul>
 *
 * @see SwitchingFunction
 * @see SwitchState
 * @version $Id: SwitchingFunctionsHandler.java 1707 2006-11-19 20:08:32Z luc $
 * @author L. Maisonobe
 */
public class SwitchingFunctionsHandler {

  /**
   * Creates an empty handler ready to accept switching functions.
   *
   * <p>The new instance starts with no registered functions, a cleared pending-event pointer, and
   * an uninitialized state. Clients typically construct one handler per integrator run, add all
   * required switching functions via {@link #add(SwitchingFunction, double, double)}, and then
   * supply the handler to the integrator. The handler may be reused across steps but should not be
   * shared between concurrent integrations because it stores mutable step-local state.
   */
  public SwitchingFunctionsHandler() {
    functions = new ArrayList<>();
    first = null;
    initialized = false;
  }

  /**
   * Registers a new switching function to be monitored during subsequent steps.
   *
   * <p>The handler wraps the provided {@link SwitchingFunction} into a {@link SwitchState} that
   * stores detection parameters. Registration is additive; functions are checked in insertion order
   * and the earliest event in the integration direction takes precedence when multiple crossings
   * are found. This method does not reset prior state and may be called only during setup, before
   * the first step is evaluated, to avoid undefined interactions with partially initialized state.
   *
   * @param function switching function defining a zero-crossing predicate; must not be {@code null}
   * @param maxCheckInterval maximum predicate spacing within a step, in integration time units
   * @param convergence absolute time tolerance for event localization; smaller values tighten
   *     accuracy
   */
  public void add(SwitchingFunction function, double maxCheckInterval, double convergence) {
    functions.add(new SwitchState(function, maxCheckInterval, convergence));
  }

  /**
   * Reports whether any switching functions have been registered.
   *
   * <p>Callers can use this as a quick guard to skip event-related work when no functions were
   * added. The result reflects the current registration set and ignores runtime state such as
   * pending events or initialization. The method is side-effect free and may be called at any time.
   *
   * @return {@code true} when no switching functions are present; {@code false} otherwise
   */
  public boolean isEmpty() {
    return functions.isEmpty();
  }

  /**
   * Scans all registered switching functions against a proposed integrator step.
   *
   * <p>The handler initializes lazily on the first call by sampling the interpolator at the
   * previous step start. It then delegates to each {@link SwitchState} to detect sign changes,
   * choosing the earliest event time when integrating forward and the latest when integrating
   * backward. The interpolator may be temporarily rewound to bracket events but is left consistent
   * for the caller. If an event is found the integrator should normally reject the step and retry
   * with a shortened interval ending at the detected time.
   *
   * @param interpolator interpolator describing the candidate step; must provide dense output
   * @return {@code true} if any switching function triggers an event inside the proposed step;
   *     {@code false} otherwise
   * @throws IllegalStateException when interpolator sampling raises a {@link DerivativeException}
   *     during initialization
   */
  public boolean evaluateStep(StepInterpolator interpolator) {

    first = null;
    if (functions.isEmpty()) {
      // there is nothing to do, return now to avoid setting the
      // interpolator time (and hence avoid unneeded calls to the
      // user function due to interpolator finalization)
      return false;
    }

    initializeIfNeeded(interpolator);
    checkEvents(interpolator);

    return first != null;
  }

  private void checkEvents(StepInterpolator interpolator) {
    for (SwitchState state : functions) {
      if (!state.evaluateStep(interpolator)) {
        continue;
      }
      if (first == null) {
        first = state;
      } else {
        selectEarlierState(interpolator, state);
      }
    }
  }

  private void selectEarlierState(StepInterpolator interpolator, SwitchState candidate) {
    if (interpolator.isForward()) {
      if (candidate.getEventTime() < first.getEventTime()) {
        first = candidate;
      }
      return;
    }
    if (candidate.getEventTime() > first.getEventTime()) {
      first = candidate;
    }
  }

  private void initializeIfNeeded(StepInterpolator interpolator) {
    if (initialized) {
      return;
    }

    // initialize the switching functions
    double t0 = interpolator.getPreviousTime();
    try {
      interpolator.setInterpolatedTime(t0);
      double[] y = interpolator.getInterpolatedState();
      for (SwitchState state : functions) {
        state.reinitializeBegin(t0, y);
      }
    } catch (DerivativeException e) {
      throw new IllegalStateException("unexpected exception", e);
    }

    initialized = true;
  }

  /**
   * Returns the time of the first event detected in the most recently evaluated step.
   *
   * <p>The returned value is meaningful only after a call to {@link
   * #evaluateStep(StepInterpolator)} that reported an event. When no event has been found since the
   * last initialization, this method returns {@link Double#NaN}. The value is not cleared by {@link
   * #stepAccepted(double, double[])} so callers should always check the {@code evaluateStep} result
   * before using it.
   *
   * @return event time in integration units or {@link Double#NaN} when no event is pending
   */
  public double getEventTime() {
    return (first == null) ? Double.NaN : first.getEventTime();
  }

  /**
   * Notifies all switching functions that the current step was accepted.
   *
   * <p>This call advances internal state to the end of the accepted step, capturing the latest sign
   * of each predicate and recording any event actions requested by {@link
   * SwitchingFunction#eventOccurred(double, double[])}. It must be invoked exactly once per
   * accepted step and before any call to {@link #reset(double, double[])} or {@link #stop()} so
   * that pending actions are visible.
   *
   * @param t time at the end of the accepted step in integration units
   * @param y state vector at step end; must be non-null and sized correctly
   */
  public void stepAccepted(double t, double[] y) {
    for (SwitchState state : functions) {
      state.stepAccepted(t, y);
    }
  }

  /**
   * Indicates whether any switching function requested integration to stop.
   *
   * <p>The method inspects the latest actions recorded during {@link #stepAccepted(double,
   * double[])} and returns {@code true} when at least one function returned {@link
   * SwitchingFunction#STOP}. It performs no additional computation and can be called multiple times
   * per step without side effects.
   *
   * @return {@code true} when a stop action is pending for the current step; {@code false}
   *     otherwise
   */
  public boolean stop() {
    for (SwitchState state : functions) {
      if (state.stop()) {
        return true;
      }
    }
    return false;
  }

  /**
   * Applies pending reset actions requested by switching functions after a step was accepted.
   *
   * <p>If any switching function asked for a state or derivative reset during {@link
   * #stepAccepted(double, double[])}, this method lets it modify the supplied state vector and
   * informs the caller whether derivatives must be recomputed. It must be invoked before starting
   * the next integration step so that resets take effect. When no pending event exists, the method
   * returns {@code false} and leaves the state untouched.
   *
   * @param t start time of the next step where any reset is applied
   * @param y mutable state array for next step; non-null and sized like integration state
   * @return {@code true} if derivatives must be recomputed after a requested reset; {@code false}
   *     otherwise
   */
  public boolean reset(double t, double[] y) {
    boolean resetDerivatives = false;
    for (SwitchState state : functions) {
      if (state.reset(t, y)) {
        resetDerivatives = true;
      }
    }
    return resetDerivatives;
  }

  /** Switching functions. */
  private final List<SwitchState> functions;

  /** First active switching function. */
  private SwitchState first;

  /** Initialization indicator. */
  private boolean initialized;
}
