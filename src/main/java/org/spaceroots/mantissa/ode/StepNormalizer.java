package org.spaceroots.mantissa.ode;

/**
 * Normalizes calls from variable-step integrators so a fixed-step handler receives evenly spaced
 * samples.
 *
 * <p>Integrators in this library expose state through {@link StepHandler} callbacks whose cadence
 * is dictated by the adaptive step-size algorithm. {@code StepNormalizer} adapts that variable
 * cadence to a user-supplied {@link FixedStepHandler} by generating synthetic callbacks on a
 * constant grid decided at construction time. The first sample is always taken at the start of the
 * integration interval and further samples are emitted every {@code h} units until the end of the
 * last accepted step. The final emitted point is flagged with {@code isLast}, even when the last
 * segment is shorter than {@code h}.
 *
 * <p>State is cached between invocations, so a single instance is intended to be used for one
 * integration run and must be {@link #reset() reset} before reuse. Instances are mutable and not
 * thread-safe; callers should confine them to the integrator thread. This helper does not constrain
 * the underlying integrator: noninteger step ratios, overshoots, and backward integrations are all
 * supported transparently.
 *
 * <ul>
 *   <li>Maintains direction automatically by negating the step when time decreases.
 *   <li>Requires dense output from the integrator to interpolate intermediate grid points.
 *   <li>Delegates array ownership to the caller; handlers should copy if they retain state.
 * </ul>
 *
 * @see StepHandler
 * @see FixedStepHandler
 * @version $Id: StepNormalizer.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class StepNormalizer implements StepHandler {

  /**
   * Creates a normalizer that feeds a fixed-step handler using a constant spacing.
   *
   * <p>The supplied step size is converted to its absolute value; integration direction is inferred
   * from the first received {@link StepInterpolator}. The wrapped {@link FixedStepHandler} is
   * invoked immediately at the integration start time and then on each normalized grid point until
   * the end of the last accepted step.
   *
   * @param h desired fixed spacing between emitted samples, in integration time units; sign is
   *     ignored and zero is legal but produces no internal movement.
   * @param handler delegate that receives normalized steps; must not be {@code null} and should
   *     tolerate repeated array reuse by the normalizer.
   */
  public StepNormalizer(double h, FixedStepHandler handler) {
    this.h = Math.abs(h);
    this.handler = handler;
    reset();
  }

  /**
   * Indicates that dense output is required from the driving integrator.
   *
   * <p>The normalizer evaluates the provided {@link StepInterpolator} at arbitrary points inside
   * each accepted step to align results with its fixed grid. Consequently, integrators using this
   * handler must provide interpolators capable of returning accurate intermediate states.
   *
   * @return {@code true} because intermediate interpolation is mandatory for normalization
   */
  public boolean requiresDenseOutput() {
    return true;
  }

  /**
   * Clears cached state so the instance can serve a new integration run.
   *
   * <p>This method forgets the last time, state vector, and detected direction. It should be called
   * before reusing the handler with a different integrator or after an integration that terminated
   * prematurely. Calling it between successive {@link #handleStep(StepInterpolator, boolean)} calls
   * inside one integration would corrupt the normalization sequence.
   */
  public void reset() {
    lastTime = Double.NaN;
    lastState = null;
    forward = true;
  }

  /**
   * Emits fixed-interval samples that fall within the accepted step.
   *
   * <p>When first invoked, the method records the start of the interpolation interval and primes
   * the grid based on the detected integration direction. On each call it walks forward or backward
   * in {@code h}-sized increments, asking the interpolator for intermediate states and forwarding
   * them to the wrapped {@link FixedStepHandler}. If {@code isLast} is {@code true}, the final
   * emitted point is flagged so downstream logic can finalize any accumulation.
   *
   * @param interpolator provider for the current accepted step; must support repeated calls to
   *     {@link StepInterpolator#setInterpolatedTime(double)} within the step bounds.
   * @param isLast {@code true} when no more steps will arrive from the integrator; marks the final
   *     delegated callback accordingly.
   * @throws DerivativeException if the interpolator triggers derivative evaluation while preparing
   *     an intermediate state and the user function signals a failure.
   */
  public void handleStep(StepInterpolator interpolator, boolean isLast) throws DerivativeException {

    double nextTime;

    if (lastState == null) {

      lastTime = interpolator.getPreviousTime();
      interpolator.setInterpolatedTime(lastTime);

      double[] state = interpolator.getInterpolatedState();
      lastState = state.clone();

      // take the integration direction into account
      forward = (interpolator.getCurrentTime() >= lastTime);
      if (!forward) {
        h = -h;
      }
    }

    nextTime = lastTime + h;
    boolean nextInStep = forward ^ (nextTime > interpolator.getCurrentTime());
    while (nextInStep) {

      // output the stored previous step
      handler.handleStep(lastTime, lastState, false);

      // store the next step
      lastTime = nextTime;
      interpolator.setInterpolatedTime(lastTime);
      System.arraycopy(interpolator.getInterpolatedState(), 0, lastState, 0, lastState.length);

      nextTime += h;
      nextInStep = forward ^ (nextTime > interpolator.getCurrentTime());
    }

    if (isLast) {
      // there will be no more steps,
      // the stored one should be flagged as being the last
      handler.handleStep(lastTime, lastState, true);
    }
  }

  /** Fixed time step. */
  private double h;

  /** Underlying step handler. */
  private final FixedStepHandler handler;

  /** Last step time. */
  private double lastTime;

  /** Last State vector. */
  private double[] lastState;

  /** Integration direction indicator. */
  private boolean forward;
}
