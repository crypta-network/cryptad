package org.spaceroots.mantissa.ode;

/**
 * Base class for integrators that adapt their step size while solving ordinary differential
 * equations.
 *
 * <p>The class centralizes step bounds, tolerance bookkeeping, and initialization so concrete
 * algorithms can focus on method-specific interpolation and local error estimation. For each state
 * component {@code i}, the error threshold is {@code absTol_i + relTol_i * max(|y_m|, |y_{m+1}|)};
 * scalar tolerances are broadcast when vector forms are not provided. A tentative step is accepted
 * when {@code sqrt(sum((errEst_i / threshold_i)^2) / n) < 1}, where {@code n} is the state
 * dimension, otherwise the step is rejected and retried with a modified size.
 *
 * <p>Instances are mutable and not thread-safe; each integrator should be confined to one
 * integration sequence at a time. Typical usage:
 *
 * <ul>
 *   <li>Construct a subclass with minimum/maximum step bounds and tolerances.
 *   <li>Optionally set an initial step, register step handlers, and add switching functions for
 *       event detection.
 *   <li>Call the subclass implementation of {@code integrate(...)} to evolve from {@code t0} to the
 *       target time, allowing the integrator to grow or shrink steps as needed.
 * </ul>
 *
 * <p>During integration the instance tracks the current step start and signed step size to support
 * dense output and event location. Call {@link #resetInternalState()} before reusing an integrator
 * for a new run to avoid leaking previous state.
 *
 * @see FirstOrderIntegrator
 * @see SwitchingFunction
 * @version $Id: AdaptiveStepsizeIntegrator.java 1719 2007-09-26 19:46:57Z luc $
 * @author L. Maisonobe
 */
public abstract class AdaptiveStepsizeIntegrator implements FirstOrderIntegrator {

  /**
   * Build an integrator with scalar tolerances and explicit step size bounds.
   *
   * <p>The created instance installs a no-op step handler and immediately resets its internal
   * bookkeeping. Step bounds must be strictly positive even for backward integration. Scalar
   * tolerances are applied to every component when estimating local truncation error.
   *
   * @param minStep minimal allowed step magnitude; positive even when integrating backward.
   * @param maxStep maximal allowed step magnitude; positive and not smaller than {@code minStep}.
   * @param scalAbsoluteTolerance uniform absolute error tolerance applied to all components.
   * @param scalRelativeTolerance uniform relative error tolerance applied to all components.
   */
  protected AdaptiveStepsizeIntegrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {

    this.minStep = minStep;
    this.maxStep = maxStep;
    this.initialStep = -1.0;

    this.scalAbsoluteTolerance = scalAbsoluteTolerance;
    this.scalRelativeTolerance = scalRelativeTolerance;
    this.vecAbsoluteTolerance = null;
    this.vecRelativeTolerance = null;

    // set the default step handler
    handler = DummyStepHandler.getInstance();

    switchesHandler = new SwitchingFunctionsHandler();

    resetInternalState();
  }

  /**
   * Build an integrator with per-component tolerances and step size bounds.
   *
   * <p>Vector tolerances let callers adapt admissible error to the scale of each state coordinate.
   * Arrays are used as provided; callers must ensure their length matches the problem dimension.
   * The default step handler performs no action until replaced.
   *
   * @param minStep minimal allowed step magnitude; positive even when integrating backward.
   * @param maxStep maximal allowed step magnitude; positive and not smaller than {@code minStep}.
   * @param vecAbsoluteTolerance absolute error tolerance for each component; must align with the
   *     state dimension and contain non-negative entries.
   * @param vecRelativeTolerance relative error tolerance for each component; must align with the
   *     state dimension and contain non-negative entries.
   */
  protected AdaptiveStepsizeIntegrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {

    this.minStep = minStep;
    this.maxStep = maxStep;
    this.initialStep = -1.0;

    this.scalAbsoluteTolerance = 0;
    this.scalRelativeTolerance = 0;
    this.vecAbsoluteTolerance = vecAbsoluteTolerance;
    this.vecRelativeTolerance = vecRelativeTolerance;

    // set the default step handler
    handler = DummyStepHandler.getInstance();

    switchesHandler = new SwitchingFunctionsHandler();

    resetInternalState();
  }

  /**
   * Set an explicit initial step size to be reused by the next integration run.
   *
   * <p>A positive value inside {@code [minStep, maxStep]} is honored directly by {@link
   * #initializeStep(StepInitializationContext)}. Negative or out-of-range values instruct the
   * integrator to estimate an initial step from the derivatives instead. The stored value is not
   * persisted across calls to {@link #resetInternalState()}.
   *
   * @param initialStepSize the desired starting step must be positive and within configured bounds,
   *     or it is ignored in favor of automatic estimation.
   */
  @SuppressWarnings("unused")
  public void setInitialStepSize(double initialStepSize) {
    if ((initialStepSize < minStep) || (initialStepSize > maxStep)) {
      initialStep = -1.0;
    } else {
      initialStep = initialStepSize;
    }
  }

  /**
   * Set the step handler that will be invoked after each accepted step.
   *
   * <p>Handlers receive interpolated state information from the concrete integrator implementation.
   * Passing {@code null} is unsupported; use {@link DummyStepHandler#getInstance()} when no output
   * is needed. The supplied instance remains active until replaced by another call.
   *
   * @param handler non-null callback used to process or observe accepted steps during integration.
   */
  @Override
  public void setStepHandler(StepHandler handler) {
    this.handler = handler;
  }

  /**
   * Get the currently registered step handler.
   *
   * <p>The returned instance is the same object supplied via {@link #setStepHandler(StepHandler)}
   * or the default dummy handler if none was set. Callers should treat the handler according to its
   * own thread-safety guarantees.
   *
   * @return active handler invoked after each accepted step; never {@code null}.
   */
  @Override
  public StepHandler getStepHandler() {
    return handler;
  }

  /**
   * Add a switching function that will be monitored during integration.
   *
   * <p>Switching functions usually represent zero-crossing events. They are sampled at least every
   * {@code maxCheckInterval} units of the independent variable to avoid missed sign changes, and
   * event times are refined until successive estimates differ by less than {@code convergence}.
   * Functions are processed in the order they are registered.
   *
   * @param function event function to monitor; must not be {@code null}.
   * @param maxCheckInterval maximum time between evaluations of the function; must be positive and
   *     expressed in the same units as the integration variable.
   * @param convergence absolute convergence threshold for event time search; must be positive and
   *     appropriate for the problem scale.
   */
  @Override
  public void addSwitchingFunction(
      SwitchingFunction function, double maxCheckInterval, double convergence) {
    switchesHandler.add(function, maxCheckInterval, convergence);
  }

  /**
   * Estimate an initial step size using scaling factors and derivative information.
   *
   * <p>If a valid explicit value was supplied via {@link #setInitialStepSize(double)}, it is
   * returned immediately with the correct sign for the requested direction. Otherwise, a heuristic
   * step is derived from the ratio of scaled state and derivative norms, refined with a trial Euler
   * step, and finally clamped to the configured minimum and maximum step sizes.
   *
   * @param context bundled initialization parameters for the step size heuristic.
   * @return signed initial step size bounded by configured limits and oriented according to {@code
   *     context.forward()}.
   * @throws DerivativeException if derivative evaluation fails while probing the trial point.
   */
  public double initializeStep(StepInitializationContext context) throws DerivativeException {

    if (initialStep > 0) {
      // use the user-provided value
      return context.forward() ? initialStep : -initialStep;
    }

    // very rough first guess: h = 0.01 * ||y/scale|| / ||y'/scale||
    // this guess will be used to perform an Euler step
    double ratio;
    double yOnScale2 = 0;
    double yDotOnScale2 = 0;
    for (int j = 0; j < context.y0().length; ++j) {
      ratio = context.y0()[j] / context.scale()[j];
      yOnScale2 += ratio * ratio;
      ratio = context.yDot0()[j] / context.scale()[j];
      yDotOnScale2 += ratio * ratio;
    }

    double h =
        ((yOnScale2 < 1.0e-10) || (yDotOnScale2 < 1.0e-10))
            ? 1.0e-6
            : (0.01 * Math.sqrt(yOnScale2 / yDotOnScale2));
    if (!context.forward()) {
      h = -h;
    }

    // perform an Euler step using the preceding rough guess
    for (int j = 0; j < context.y0().length; ++j) {
      context.y1()[j] = context.y0()[j] + h * context.yDot0()[j];
    }
    context.equations().computeDerivatives(context.t0() + h, context.y1(), context.yDot1());

    // estimate the second derivative of the solution
    double yDDotOnScale = 0;
    for (int j = 0; j < context.y0().length; ++j) {
      ratio = (context.yDot1()[j] - context.yDot0()[j]) / context.scale()[j];
      yDDotOnScale += ratio * ratio;
    }
    yDDotOnScale = Math.sqrt(yDDotOnScale) / h;

    // step size is computed such that
    // h^order * max (||y'/tol||, ||y''/tol||) = 0.01
    double maxInv2 = Math.max(Math.sqrt(yDotOnScale2), yDDotOnScale);
    double h1 =
        (maxInv2 < 1.0e-15)
            ? Math.max(1.0e-6, 0.001 * Math.abs(h))
            : Math.pow(0.01 / maxInv2, 1.0 / context.order());
    h = Math.min(100.0 * Math.abs(h), h1);
    h = Math.max(h, 1.0e-12 * Math.abs(context.t0()));
    if (h < getMinStep()) {
      h = getMinStep();
    }
    if (h > getMaxStep()) {
      h = getMaxStep();
    }
    if (!context.forward()) {
      h = -h;
    }

    return h;
  }

  /**
   * Clamp a proposed step size to configured bounds, optionally rejecting undersized values.
   *
   * <p>The returned value preserves the sign of {@code h} while ensuring its magnitude lies inside
   * {@code [minStep, maxStep]}. When {@code acceptSmall} is {@code false} and the proposed
   * magnitude is smaller than {@code minStep}, an {@link IntegratorException} is raised; otherwise
   * the step is increased to exactly the minimum magnitude.
   *
   * @param h candidate signed step size before bounding; may be positive or negative.
   * @param acceptSmall {@code true} to silently clamp values below {@code minStep}, {@code false}
   *     to throw instead of enlarging them.
   * @return bounded step size that respects configured limits while keeping the original sign.
   * @throws IntegratorException if {@code acceptSmall} is {@code false} and {@code |h| < minStep}.
   */
  protected double filterStep(double h, boolean acceptSmall) throws IntegratorException {

    if (Math.abs(h) < minStep) {
      if (acceptSmall) {
        h = (h < 0) ? -minStep : minStep;
      } else {
        throw new IntegratorException(
            "minimal step size ({0}) reached," + " integration needs {1}",
            new String[] {Double.toString(minStep), Double.toString(Math.abs(h))});
      }
    }

    if (h > maxStep) {
      h = maxStep;
    } else if (h < -maxStep) {
      h = -maxStep;
    }

    return h;
  }

  /**
   * Get the start time of the current integration step.
   *
   * <p>Before any integration or after a reset the value is {@link Double#NaN}, indicating no
   * active step is in progress. Concrete integrators update this value whenever they propose or
   * accept a step so that step handlers and switching functions can access the accurate origin of
   * the interpolation interval.
   *
   * @return time coordinate at the beginning of the current step, or {@code NaN} when unset.
   */
  @Override
  public double getCurrentStepStart() {
    return stepStart;
  }

  /**
   * Get the signed size of the current integration step.
   *
   * <p>The sign reflects the integration direction. Immediately after construction or reset, the
   * value is initialized to the geometric mean of the minimum and maximum step bounds. During
   * integration, it contains the step length last computed by the adaptive controller, which is
   * useful for diagnostic logging or for dense output interpolation that needs the current step
   * width.
   *
   * @return current signed step size chosen by the integrator, or the initial guess when unset.
   */
  @Override
  public double getCurrentStepsize() {
    return stepSize;
  }

  /**
   * Reset internal step-related state to sentinel values.
   *
   * <p>This method should be called before reusing the integrator for a new problem to avoid mixing
   * state between runs. It clears the current step start to {@link Double#NaN} and reinitializes
   * the step size to a neutral guess derived from the configured bounds, giving subclasses a clean
   * baseline for their next initialization phase.
   */
  protected void resetInternalState() {
    stepStart = Double.NaN;
    stepSize = Math.sqrt(minStep * maxStep);
  }

  /**
   * Get the minimal admissible step magnitude configured for this integrator.
   *
   * <p>This lower bound prevents the adaptive controller from shrinking steps to values that would
   * make progress numerically insignificant or cause excessive round-off errors.
   *
   * @return strictly positive lower bound applied when filtering proposed steps.
   */
  public double getMinStep() {
    return minStep;
  }

  /**
   * Get the maximal admissible step magnitude configured for this integrator.
   *
   * <p>This upper bound caps aggressive growth of the step size so that event detection and local
   * truncation error estimates remain reliable even when the solution behaves smoothly.
   *
   * @return strictly positive upper bound applied when filtering proposed steps.
   */
  public double getMaxStep() {
    return maxStep;
  }

  /**
   * Lower bound for step magnitudes; used by {@link #filterStep(double, boolean)} and step
   * initialization heuristics. The value is fixed at construction time and remains constant for the
   * lifetime of the integrator instance.
   */
  private final double minStep;

  /**
   * Upper bound for step magnitudes; prevents adaptive schemes from growing beyond safe limits for
   * the problem scale. The value is immutable after construction to keep filtering logic
   * predictable.
   */
  private final double maxStep;

  /**
   * Optional user-supplied initial step size; a negative value signals that automatic estimation
   * should be used instead. The value is mutable between runs and is consumed by {@link
   * #initializeStep(StepInitializationContext)}.
   */
  private double initialStep;

  /**
   * Absolute error tolerance applied uniformly when vector tolerances are not provided. Subclasses
   * consult this value while computing normalized error estimates, ensuring each component is
   * measured against a consistent absolute scale.
   */
  protected double scalAbsoluteTolerance;

  /**
   * Relative error tolerance applied uniformly when vector tolerances are not provided. It scales
   * the acceptable error proportionally to the scale of each state component during adaptive
   * control.
   */
  protected double scalRelativeTolerance;

  /**
   * Per-component absolute error tolerances aligned with the problem dimension, if configured.
   * Concrete integrators use these values directly when available to refine normalized error
   * metrics.
   */
  protected double[] vecAbsoluteTolerance;

  /**
   * Per-component relative error tolerances aligned with the problem dimension, if configured.
   * Enables heterogeneous scaling so larger-magnitude components do not dominate the adaptive
   * controller.
   */
  protected double[] vecRelativeTolerance;

  /**
   * Callback invoked after each accepted step; defaults to a no-op handler. Concrete integrators
   * call the handler to expose interpolated state values, enabling users to collect dense output or
   * drive side effects such as logging.
   */
  protected StepHandler handler;

  /**
   * Aggregates registered switching functions and coordinates event detection. It controls sampling
   * frequency, root finding, and state changes triggered by events encountered during the adaptive
   * integration process.
   */
  protected SwitchingFunctionsHandler switchesHandler;

  /**
   * Time coordinate of the current step start; {@link Double#NaN} when uninitialized. Updated by
   * concrete integrators as they progress through the domain.
   */
  protected double stepStart;

  /**
   * Signed length of the current step; initialized to the geometric mean of configured bounds.
   * Values are adapted continuously by concrete integrators in response to local error estimates.
   */
  protected double stepSize;
}
