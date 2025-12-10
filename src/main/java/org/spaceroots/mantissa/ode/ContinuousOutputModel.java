package org.spaceroots.mantissa.ode;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Collects every accepted integration step and exposes a continuous view of the solution.
 *
 * <p>This step handler clones and stores finalized {@link StepInterpolator} instances in time order
 * so that, after integration finishes, callers can move freely through the trajectory using {@link
 * #setInterpolatedTime(double)} and {@link #getInterpolatedState()}. The model is intended for
 * post-processing workflows such as plotting, re-sampling at uniform grids, or comparing numerical
 * output against analytical benchmarks without rerunning the integrator. It remains mutable until
 * the last step is marked, then behaves as a read-mostly buffer of frozen step snapshots.
 *
 * <p>The handler may be reused across multiple contiguous phases that share the same integration
 * direction, enabling complex simulations (for example, coast–burn–coast) to appear as a single
 * continuous record. Memory consumption scales with the number of accepted steps and the state
 * dimension; tight tolerances or long horizons can therefore require considerable storage.
 * Instances are not thread-safe and should be confined to the integration thread.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> capture dense-output steps, provide random interpolation
 *       access, and bridge adjacent integration phases.
 *   <li><strong>Invariants:</strong> step order is preserved, direction is consistent across
 *       appended models, and dense output remains available for every stored step.
 *   <li><strong>Persistence:</strong> implements {@link Serializable}, allowing recorded
 *       trajectories to be saved or transferred without rerunning the solver.
 * </ul>
 *
 * @see StepHandler
 * @see StepInterpolator
 * @version $Id: ContinuousOutputModel.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class ContinuousOutputModel implements StepHandler, Serializable {

  /**
   * Creates an empty continuous output model ready to receive steps.
   *
   * <p>The constructor allocates the internal list and immediately calls {@link #reset()} so all
   * time markers are {@link Double#NaN} and the direction flag is forward. No steps are available
   * until {@link #handleStep(StepInterpolator, boolean)} is invoked by an integrator, but the
   * instance can be created early and passed around safely. Constructing multiple transient models
   * is inexpensive and useful when experimenting with alternative integration settings or when
   * issuing concurrent dry runs in test harnesses.
   */
  public ContinuousOutputModel() {
    steps = new ArrayList<>();
    reset();
  }

  /**
   * Appends the steps of another continuous model directly after this one.
   *
   * <p>The supplied model must describe the same state dimension and integration direction. A gap
   * larger than a small fraction of the preceding step size is rejected to protect continuity.
   * Steps are deep-copied, so later changes to the source model do not affect this instance.
   *
   * @param model another populated {@code ContinuousOutputModel} whose trajectory follows this one
   *     in time and uses identical state dimensionality and direction; must not be {@code null}
   * @throws IllegalArgumentException if vector dimensions differ, integration directions disagree,
   *     or a detectable hole exists between the last local step and the first appended step
   */
  public void append(ContinuousOutputModel model) {

    if (model.steps.isEmpty()) {
      return;
    }

    if (steps.isEmpty()) {
      initialTime = model.initialTime;
      forward = model.forward;
    } else {

      if (getInterpolatedState().length != model.getInterpolatedState().length) {
        throw new IllegalArgumentException("state vector dimension mismatch");
      }

      if (forward ^ model.forward) {
        throw new IllegalArgumentException("propagation direction mismatch");
      }

      StepInterpolator lastInterpolator = (StepInterpolator) steps.get(index);
      double current = lastInterpolator.getCurrentTime();
      double previous = lastInterpolator.getPreviousTime();
      double step = current - previous;
      double gap = model.getInitialTime() - current;
      if (Math.abs(gap) > 1.0e-3 * Math.abs(step)) {
        throw new IllegalArgumentException("hole between time ranges");
      }
    }

    for (AbstractStepInterpolator ai : model.steps) {
      steps.add(ai.copy());
    }

    index = steps.size() - 1;
    finalTime = steps.get(index).getCurrentTime();
  }

  /**
   * Signals that dense output is mandatory for this handler.
   *
   * <p>The model reconstructs intermediate states from stored interpolators; it therefore requires
   * every step to provide dense output. Integrators can check this flag when configuring step
   * handling and enable the extra computations needed to populate dense interpolators. Because the
   * return value is constant, clients may cache the decision and avoid repeated configuration
   * checks during long runs.
   *
   * @return {@code true}, indicating dense output is required for every accepted step
   */
  public boolean requiresDenseOutput() {
    return true;
  }

  /**
   * Clears all stored steps and reinitializes timing metadata.
   *
   * <p>After a reset the model contains no interpolators, the current index is zero, and both
   * boundary times are {@link Double#NaN}. Use this to reuse the same instance for a fresh
   * integration run without reallocating internal structures. This helps reduce garbage creation
   * during parameter sweeps or optimization loops that perform many short integrations in rapid
   * succession.
   */
  public void reset() {
    initialTime = Double.NaN;
    finalTime = Double.NaN;
    forward = true;
    index = 0;
    steps.clear();
  }

  /**
   * Records an accepted integration step.
   *
   * <p>The supplied interpolator is finalized, deep-copied, and appended. On the first invocation
   * the model captures the initial time and integration direction from the step metadata. When
   * {@code isLast} is {@code true}, the method also stores the final time and updates the current
   * index so callers may immediately query interpolated values.
   *
   * @param interpolator dense-output interpolator describing the accepted step; must align with the
   *     integrator’s state vector and direction and must not be {@code null}
   * @param isLast {@code true} when this step terminates the integration run; {@code false} when
   *     more steps will follow
   * @throws DerivativeException if finalizing or copying the interpolator requires derivative
   *     evaluations that fail or propagate user exceptions
   */
  public void handleStep(StepInterpolator interpolator, boolean isLast) throws DerivativeException {

    AbstractStepInterpolator ai = (AbstractStepInterpolator) interpolator;

    if (steps.isEmpty()) {
      initialTime = interpolator.getPreviousTime();
      forward = interpolator.isForward();
    }

    ai.finalizeStep();
    steps.add(ai.copy());

    if (isLast) {
      finalTime = ai.getCurrentTime();
      index = steps.size() - 1;
    }
  }

  /**
   * Returns the initial integration time recorded from the first stored step.
   *
   * <p>Before any steps are handled this value is {@link Double#NaN}. Once set, it reflects the
   * earliest time across all appended models and remains stable.
   *
   * @return starting time of the trajectory, or {@code Double.NaN} when no steps are present
   */
  public double getInitialTime() {
    return initialTime;
  }

  /**
   * Returns the final integration time of the latest recorded step.
   *
   * <p>The value is updated when {@link #handleStep(StepInterpolator, boolean)} is invoked with the
   * last-step flag. Prior to that point it remains {@link Double#NaN}.
   *
   * @return end time of the most recent integration phase, or {@code Double.NaN} until finalized
   */
  @SuppressWarnings("unused")
  public double getFinalTime() {
    return finalTime;
  }

  /**
   * Returns the time associated with the currently selected interpolated state.
   *
   * <p>Until {@link #setInterpolatedTime(double)} is invoked, this method returns the final
   * integration time, matching the end of the last recorded step. When callers adjust interpolation
   * time frequently, this accessor avoids redundant state computations when only the timestamp is
   * needed, for example while logging event brackets or scanning for zero crossings.
   *
   * @return time of the last interpolation request, or the final integration time when unset
   */
  @SuppressWarnings("unused")
  public double getInterpolatedTime() {
    return steps.get(index).getInterpolatedTime();
  }

  /**
   * Selects the target time for subsequent interpolation requests.
   *
   * <p>The method locates the step that brackets the requested time using a mix of quadratic
   * estimation and bounded refinement, then delegates to the underlying interpolator to prepare the
   * state. Calls are intended after integration completes; invoking them earlier can yield
   * incomplete data. Times outside the stored interval are allowed for cautious extrapolation, but
   * fidelity decreases as the request moves away from recorded steps.
   *
   * @param time absolute integration time to evaluate, potentially inside or slightly outside the
   *     recorded interval; extreme extrapolation may reduce accuracy
   */
  public void setInterpolatedTime(double time) {

    int iMin = 0;
    AbstractStepInterpolator sMin = steps.get(iMin);
    double tMin = midpoint(sMin);

    int iMax = steps.size() - 1;
    AbstractStepInterpolator sMax = steps.get(iMax);
    double tMax = midpoint(sMax);

    if (locatePoint(time, sMin) <= 0) {
      index = iMin;
      safeSetInterpolatedTime(sMin, time);
      return;
    }
    if (locatePoint(time, sMax) >= 0) {
      index = iMax;
      safeSetInterpolatedTime(sMax, time);
      return;
    }

    index = findIndex(time, iMin, iMax, tMin, tMax);
    safeSetInterpolatedTime(steps.get(index), time);
  }

  /**
   * Returns the state vector corresponding to the current interpolated time.
   *
   * <p>The returned array may be backed by an internal buffer owned by the underlying interpolator.
   * Treat it as read-only or make a defensive copy before modification or long-term retention.
   * Subsequent calls after changing {@link #setInterpolatedTime(double)} will update the contents
   * of the same backing array, keeping allocations low when sampling many points along the
   * trajectory.
   *
   * @return state components evaluated at {@link #getInterpolatedTime()}, possibly backed by a
   *     mutable buffer reused between calls
   */
  public double[] getInterpolatedState() {
    return steps.get(index).getInterpolatedState();
  }

  /**
   * Compare a step interval and a double.
   *
   * @param time point to locate
   * @param interval step interval
   * @return -1 if the double is before the interval, 0 if it is in the interval, and +1 if it is
   *     after the interval, according to the interval direction
   */
  private int locatePoint(double time, AbstractStepInterpolator interval) {
    if (forward) {
      if (time < interval.getPreviousTime()) {
        return -1;
      } else if (time > interval.getCurrentTime()) {
        return +1;
      } else {
        return 0;
      }
    }
    if (time > interval.getPreviousTime()) {
      return -1;
    } else if (time < interval.getCurrentTime()) {
      return +1;
    } else {
      return 0;
    }
  }

  /** Initial integration time. */
  private double initialTime;

  /** Final integration time. */
  private double finalTime;

  /** Integration direction indicator. */
  private boolean forward;

  /** Current interpolator index. */
  private int index;

  /** Steps table. */
  private final List<AbstractStepInterpolator> steps;

  private int findIndex(double time, int iMin, int iMax, double tMin, double tMax) {

    while (iMax - iMin > 5) {

      AbstractStepInterpolator si = steps.get(index);
      int location = locatePoint(time, si);
      if (location < 0) {
        iMax = index;
        tMax = midpoint(si);
      } else if (location > 0) {
        iMin = index;
        tMin = midpoint(si);
      } else {
        return index;
      }

      int iMed = (iMin + iMax) / 2;
      AbstractStepInterpolator sMed = steps.get(iMed);
      double tMed = midpoint(sMed);

      if ((Math.abs(tMed - tMin) < 1e-6) || (Math.abs(tMax - tMed) < 1e-6)) {
        index = iMed;
      } else {
        double d12 = tMax - tMed;
        double d23 = tMed - tMin;
        double d13 = tMax - tMin;
        double dt1 = time - tMax;
        double dt2 = time - tMed;
        double dt3 = time - tMin;
        double iLagrange =
            ((dt2 * dt3 * d23) * iMax - (dt1 * dt3 * d13) * iMed + (dt1 * dt2 * d12) * iMin)
                / (d12 * d23 * d13);
        index = (int) Math.rint(iLagrange);
      }

      int low = Math.max(iMin + 1, (9 * iMin + iMax) / 10);
      int high = Math.min(iMax - 1, (iMin + 9 * iMax) / 10);
      if (index < low) {
        index = low;
      } else if (index > high) {
        index = high;
      }
    }

    index = iMin;
    while ((index <= iMax) && (locatePoint(time, steps.get(index)) > 0)) {
      ++index;
    }

    return index;
  }

  private double midpoint(AbstractStepInterpolator interpolator) {
    return 0.5 * (interpolator.getPreviousTime() + interpolator.getCurrentTime());
  }

  private void safeSetInterpolatedTime(AbstractStepInterpolator interpolator, double time) {
    try {
      interpolator.setInterpolatedTime(time);
    } catch (DerivativeException e) {
      throw new IllegalStateException("unexpected DerivativeException caught", e);
    }
  }

  @Serial private static final long serialVersionUID = 2259286184268533249L;
}
