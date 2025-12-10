package org.spaceroots.mantissa.ode;

/**
 * Fixed-step Runge–Kutta base integrator for first-order ordinary differential equations.
 *
 * <p>Instances provide the shared control-flow, event processing, and dense-output wiring used by
 * all explicit Runge–Kutta schemes in this package. Callers supply a Butcher tableau and a step
 * interpolator prototype; subclasses only define the coefficients and the public name. The class
 * maintains a fixed step size throughout an {@link #integrate(FirstOrderDifferentialEquations,
 * double, double[], double, double[]) integration} and supports optional “first same as last”
 * (FSAL) methods where the final stage slope of one step seeds the next. It is <strong>not</strong>
 * thread-safe; create one integrator instance per concurrent integration and reuse it sequentially
 * to avoid allocation churn.
 *
 * <p>Lifecycle highlights:
 *
 * <ul>
 *   <li>Validate dimensions and interval, allocate stage arrays, and configure dense output.
 *   <li>Advance a fixed number of equal steps, detecting switching functions and re-aligning step
 *       boundaries when events occur.
 *   <li>Expose intermediate states via the configured {@link StepHandler} and optional dense
 *       interpolator.
 * </ul>
 *
 * <p>Use this base when implementing new explicit Runge–Kutta flavors with constant step sizes.
 * Prefer higher-level adaptative integrators when variable step control or error estimates are
 * required. Switching functions are evaluated deterministically and may shorten individual steps,
 * but the nominal step size and FSAL reuse remain intact between events.
 *
 * @see EulerIntegrator
 * @see ClassicalRungeKuttaIntegrator
 * @see GillIntegrator
 * @see MidpointIntegrator
 * @version $Id: RungeKuttaIntegrator.java 1719 2007-09-26 19:46:57Z luc $
 * @author L. Maisonobe
 */
public abstract class RungeKuttaIntegrator implements FirstOrderIntegrator {

  /**
   * Build a Runge–Kutta integrator with constant step size and default no-op step handler.
   *
   * <p>The caller supplies the Butcher tableau rows and an interpolator prototype appropriate for
   * the specific Runge–Kutta scheme. The integrator clones the interpolator per step and may reuse
   * the final slope of each step when {@code fsal} is {@code true}. The instance is ready for reuse
   * across multiple integration runs; state is cleared automatically after each {@link #integrate}
   * call.
   *
   * @param fsal {@code true} to enable FSAL reuse where the last slope equals the next first slope.
   * @param c time-step offsets (excluding the initial zero) matching the Butcher tableau rows.
   * @param a internal stage weights (tableau without the leading empty row); each row length equals
   *     its stage index.
   * @param b external weights for the final state update; length must equal {@code c.length + 1}.
   * @param prototype dense-output interpolator prototype copied for each accepted step; must be a
   *     {@link RungeKuttaStepInterpolator}.
   * @param step fixed integration step size in the same time units as equation evaluation.
   */
  protected RungeKuttaIntegrator(
      boolean fsal,
      double[] c,
      double[][] a,
      double[] b,
      AbstractStepInterpolator prototype,
      double step) {
    this.fsal = fsal;
    this.c = c;
    this.a = a;
    this.b = b;
    this.prototype = checkPrototype(prototype);
    this.step = step;
    handler = DummyStepHandler.getInstance();
    switchesHandler = new SwitchingFunctionsHandler();
    resetInternalState();
  }

  /**
   * Set the step handler invoked after every accepted step.
   *
   * <p>The handler receives a {@link StepInterpolator} positioned at the end of the step and may
   * request dense output. Providing a custom handler allows callers to log progress, accumulate
   * solution samples, or abort integration via exception. Passing {@code null} is unsupported; use
   * {@link DummyStepHandler#getInstance()} to ignore callbacks.
   *
   * @param handler non-null consumer for accepted steps; must tolerate reuse across many steps.
   */
  public void setStepHandler(StepHandler handler) {
    this.handler = handler;
  }

  /**
   * Return the current step handler used for accepted steps.
   *
   * <p>The returned instance is the same object supplied via {@link #setStepHandler}. The default
   * value is {@link DummyStepHandler#getInstance()}, which performs no work. Callers may replace it
   * before each integration run to collect step data in different ways.
   *
   * @return mutable step handler instance currently registered with this integrator.
   */
  public StepHandler getStepHandler() {
    return handler;
  }

  /**
   * Register a switching function used to detect events during integration.
   *
   * <p>Each function is polled at most every {@code maxCheckInterval} along the independent
   * variable, regardless of the nominal step size, to avoid missing sign changes. When an event is
   * detected, the integrator shortens the current step so the accepted step ends exactly at the
   * event time within the given {@code convergence} tolerance.
   *
   * @param function user-supplied switching function that returns signed values across the domain.
   * @param maxCheckInterval maximum interval, in integration time units, between event evaluations.
   * @param convergence absolute time accuracy used when refining the event occurrence instant.
   */
  public void addSwitchingFunction(
      SwitchingFunction function, double maxCheckInterval, double convergence) {
    switchesHandler.add(function, maxCheckInterval, convergence);
  }

  /**
   * Integrate the set of differential equations over a fixed number of equal steps.
   *
   * <p>The initial state {@code y0} is copied into {@code y} if they differ; the final state is
   * always stored in {@code y}. The method enforces dimension compatibility, rejects near-zero
   * intervals, and processes switching functions that may truncate individual steps while
   * preserving the nominal step size thereafter. Dense-output handlers receive an interpolator
   * pointing to the end of each accepted step.
   *
   * <p>Typical usage:
   *
   * <pre>{@code
   * double[] state = initial.clone();
   * integrator.integrate(equations, t0, state, tEnd, state);
   * }</pre>
   *
   * @param equations system of first-order equations to evaluate; dimension must match {@code y0}.
   * @param t0 initial integration time; also used as the start of the first step.
   * @param y0 initial state vector at {@code t0}; never modified when equal to {@code y}.
   * @param t target time for integration end; may be greater or less than {@code t0}.
   * @param y output state vector; receives the final state and may alias {@code y0}.
   * @throws DerivativeException if equation evaluation fails at any step or intermediate stage.
   * @throws IntegratorException if dimensions mismatch or the interval length is too small.
   */
  public void integrate(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t, double[] y)
      throws DerivativeException, IntegratorException {

    validateIntegrationRange(equations, y0, t0, t);

    boolean forward = (t > t0);
    int stages = c.length + 1;
    if (y != y0) {
      System.arraycopy(y0, 0, y, 0, y0.length);
    }

    double[][] yDotK = createDerivativesArray(stages, y0.length);
    double[] yTmp = new double[y0.length];
    AbstractStepInterpolator interpolator = createInterpolator(equations, yTmp, yDotK, forward);

    long nbStep = computeNumberOfSteps(t0, t);
    boolean firstEvaluationPending = true;
    boolean lastStep = false;
    long stepIndex = 0;
    stepStart = t0;
    stepSize = computeStepSize(t0, t, nbStep);
    handler.reset();
    interpolator.storeTime(t0);

    while (!lastStep) {
      interpolator.shift();

      StepComputationResult stepResult =
          computeProvisionalStep(
              equations, y, yTmp, yDotK, stages, firstEvaluationPending, interpolator);
      firstEvaluationPending = false;

      acceptStep(y, yTmp);
      boolean stopRequested = switchesHandler.stop();
      boolean lastStepCandidate = stopRequested || isLastStep(stepIndex, nbStep);

      if (stepResult.needStepAdjustment && !stopRequested) {
        nbStep = computeNumberOfSteps(stepStart, t);
        stepSize = computeStepSize(stepStart, t, nbStep);
        stepIndex = 0;
        lastStepCandidate = false;
      } else {
        ++stepIndex;
      }

      lastStep = lastStepCandidate;

      interpolator.storeTime(stepStart);
      handler.handleStep((StepInterpolator) interpolator, lastStep);

      updateFsalState(yDotK, stages, y.length);

      if (switchesHandler.reset(stepStart, y) && !lastStep) {
        equations.computeDerivatives(stepStart, y, yDotK[0]);
      }
    }

    resetInternalState();
  }

  /**
   * Get the start time of the last processed step.
   *
   * <p>Returns {@link Double#NaN} before the first call to {@link #integrate} and immediately after
   * a run completes, because {@link #resetInternalState()} clears the cached value. During
   * integration, it reflects the time at which the current step began, even if that step was
   * shortened by an event.
   *
   * @return time coordinate for the start of the last accepted step, or {@code NaN} when undefined.
   */
  public double getCurrentStepStart() {
    return stepStart;
  }

  /**
   * Get the size of the current integration step.
   *
   * <p>During integration this value is the actual step size being taken, which may differ from the
   * nominal constructor step if an event truncated the current step. Outside an integration run the
   * value is {@link Double#NaN}.
   *
   * @return length of the current step in integration time units, or {@code NaN} when not running.
   */
  public double getCurrentStepsize() {
    return stepSize;
  }

  /** Reset internal state to dummy values. */
  private void resetInternalState() {
    stepStart = Double.NaN;
    stepSize = Double.NaN;
  }

  /** Indicator for <i>fsal</i> methods. */
  private final boolean fsal;

  /** Time steps from Butcher array (without the first zero). */
  private final double[] c;

  /** Internal weights from Butcher array (without the first empty row). */
  private final double[][] a;

  /** External weights for the high order method from Butcher array. */
  private final double[] b;

  /** Prototype of the step interpolator. */
  private final RungeKuttaStepInterpolator prototype;

  /** Integration step. */
  private final double step;

  /** Step handler. */
  private StepHandler handler;

  /** Switching functions handler. */
  protected SwitchingFunctionsHandler switchesHandler;

  /** Current step start time. */
  private double stepStart;

  /** Current stepsize. */
  private double stepSize;

  private RungeKuttaStepInterpolator checkPrototype(AbstractStepInterpolator prototype) {
    if (prototype instanceof RungeKuttaStepInterpolator rungeKuttaPrototype) {
      return rungeKuttaPrototype;
    }
    throw new IllegalArgumentException("Prototype must be a RungeKuttaStepInterpolator");
  }

  private void validateIntegrationRange(
      FirstOrderDifferentialEquations equations, double[] y0, double t0, double t)
      throws IntegratorException {
    if (equations.getDimension() != y0.length) {
      throw new IntegratorException(
          "dimensions mismatch: ODE problem has dimension {0}," + " state vector has dimension {1}",
          new String[] {Integer.toString(equations.getDimension()), Integer.toString(y0.length)});
    }
    if (Math.abs(t - t0) <= 1.0e-12 * Math.max(Math.abs(t0), Math.abs(t))) {
      throw new IntegratorException(
          "too small integration interval: length = {0}",
          new String[] {Double.toString(Math.abs(t - t0))});
    }
  }

  private double[][] createDerivativesArray(int stages, int dimension) {
    double[][] yDotK = new double[stages][];
    for (int i = 0; i < stages; ++i) {
      yDotK[i] = new double[dimension];
    }
    return yDotK;
  }

  private AbstractStepInterpolator createInterpolator(
      FirstOrderDifferentialEquations equations, double[] yTmp, double[][] yDotK, boolean forward) {
    if (handler.requiresDenseOutput() || (!switchesHandler.isEmpty())) {
      RungeKuttaStepInterpolator rki = (RungeKuttaStepInterpolator) prototype.copy();
      rki.reinitialize(equations, yTmp, yDotK, forward);
      return rki;
    }
    return new DummyStepInterpolator(yTmp, forward);
  }

  private long computeNumberOfSteps(double start, double target) {
    return Math.max(1L, Math.abs(Math.round((target - start) / step)));
  }

  private double computeStepSize(double start, double target, long numberOfSteps) {
    return (target - start) / numberOfSteps;
  }

  private StepComputationResult computeProvisionalStep(
      FirstOrderDifferentialEquations equations,
      double[] y,
      double[] yTmp,
      double[][] yDotK,
      int stages,
      boolean firstEvaluationPending,
      AbstractStepInterpolator interpolator)
      throws DerivativeException {

    boolean adjusted = false;
    boolean needUpdate;
    do {
      computeFirstDerivativesIfNeeded(equations, y, yDotK, firstEvaluationPending);
      firstEvaluationPending = false;
      computeIntermediateStages(equations, y, yTmp, yDotK, stages);
      estimateStepEndState(y, yTmp, yDotK, stages);
      needUpdate = handleSwitchingFunctions(interpolator);
      adjusted |= needUpdate;
    } while (needUpdate);

    return new StepComputationResult(adjusted);
  }

  private void computeFirstDerivativesIfNeeded(
      FirstOrderDifferentialEquations equations, double[] y, double[][] yDotK, boolean pending)
      throws DerivativeException {
    if (pending || !fsal) {
      equations.computeDerivatives(stepStart, y, yDotK[0]);
    }
  }

  private void computeIntermediateStages(
      FirstOrderDifferentialEquations equations,
      double[] y,
      double[] yTmp,
      double[][] yDotK,
      int stages)
      throws DerivativeException {
    for (int k = 1; k < stages; ++k) {
      for (int j = 0; j < y.length; ++j) {
        double sum = a[k - 1][0] * yDotK[0][j];
        for (int l = 1; l < k; ++l) {
          sum += a[k - 1][l] * yDotK[l][j];
        }
        yTmp[j] = y[j] + stepSize * sum;
      }
      equations.computeDerivatives(stepStart + c[k - 1] * stepSize, yTmp, yDotK[k]);
    }
  }

  private void estimateStepEndState(double[] y, double[] yTmp, double[][] yDotK, int stages) {
    for (int j = 0; j < y.length; ++j) {
      double sum = b[0] * yDotK[0][j];
      for (int l = 1; l < stages; ++l) {
        sum += b[l] * yDotK[l][j];
      }
      yTmp[j] = y[j] + stepSize * sum;
    }
  }

  private boolean handleSwitchingFunctions(AbstractStepInterpolator interpolator) {
    interpolator.storeTime(stepStart + stepSize);
    if (switchesHandler.evaluateStep((StepInterpolator) interpolator)) {
      stepSize = switchesHandler.getEventTime() - stepStart;
      return true;
    }
    return false;
  }

  private void acceptStep(double[] y, double[] yTmp) {
    stepStart += stepSize;
    System.arraycopy(yTmp, 0, y, 0, y.length);
    switchesHandler.stepAccepted(stepStart, y);
  }

  private boolean isLastStep(long stepIndex, long numberOfSteps) {
    return stepIndex == (numberOfSteps - 1);
  }

  private void updateFsalState(double[][] yDotK, int stages, int dimension) {
    if (fsal) {
      System.arraycopy(yDotK[stages - 1], 0, yDotK[0], 0, dimension);
    }
  }

  private record StepComputationResult(boolean needStepAdjustment) {}
}
